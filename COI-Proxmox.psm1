# Keep this until COI stops using self signed certificates. There's 3 solutions here:
# 1. Manually import the certificates to make Windows trust them (not happening)
# 2. Call the curl binary directly instead of Invoke-WebRequest to use the -k certificate check skip option (It'd be better to keep everything in PowerShell)
# 3. The best option: Create a custom C# class to ignore certificate errors and import this policy which effectively makes Windows trust all SSL certificates.
# Obviously this isn't very secure, but these settings only persist for the current session so it'll be fine until COI stops using self-signed certificates.
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$Script:Vars = @{
    Credentials = $null
}

class ApiException : System.Exception {
    [int]$StatusCode
    [string]$response

    ApiException([string]$message, [int]$statuscode, [string]$response) : base($message) {
        $this.StatusCode = $statuscode
        $this.response = $response
    }

    [string] ToString() {
        return "Web request error: Status $($this.StatusCode) - $($this.message)`nResponse: $($this.response)"
    }
}

function Get-DAUser {
	if (($env:USERNAME).StartsWith("da_")) {
		return $env:USERNAME
	}
	return "da_$env:USERNAME"
}

function Invoke-PVEAPI {
    Param (
        [Parameter(Mandatory)][string]$Route,
        [Parameter(Mandatory)][hashtable]$Params,
        [switch]$Silent,
        [string]$ErrorBehavior = "Continue"
    )

    $err = $false
    # Insert the URI and ContentType header into the Params hashtable
    $Params["Uri"] = "https://172.28.116.111:8006/api2/json/$route"
    $Params["ContentType"] = "application/x-www-form-urlencoded"

    try {
        # Send an HTTP request to the Proxmox API
        $response = Invoke-WebRequest @Params
        if (($response.StatusCode -ne 200) -and ($response.StatusCode -ne 201)) {
            throw [ApiException]::new("Request failed", $response.StatusCode, $response.StatusDescription)
        }
        # Convert the JSON response into a PowerShell object
        $to_return = $response.Content | ConvertFrom-Json
    }
    # The goal is to return something even if the request fails so the calling function can decide what to do on failure
    catch [System.Net.WebException] {
        $err = $true

        if (-not $Silent) {Write-Warning "$($_.Exception.Message) to route $($route) with method $($Params.Method)"}

        if ($_.Exception.Response.StatusCode.value__) {
            $to_return = @{
                Error = $true
                StatusCode = $_.Exception.Response.StatusCode.value__
                Response = $_.Exception.Response.StatusDescription
            }
        }
        else {
            $to_return = @{Error = $true}
        }
    }
    catch [ApiException] {
        if (-not $Silent) {Write-Warning "$($_.Exception.Message) to route $($route) with method $($Params.Method)"}
        $err = $true
        $to_return = @{
            StatusCode = $_.Exception.StatusCode
            Error = $true
        }
    }

    # The ErrorBehavior flag overrides the default behavior of returning something on failure and just throws an error. This is useful for when the program shouldn't continue if later processing requires certain prereq data or for objects to exist in Proxmox
    if ((-not $err) -or ($ErrorBehavior -eq "Continue")) {
        return $to_return
    }
    else {
        throw "Unable to proceed without the data required or created from the previous API call."
    }
}

function Get-AccessTicket {
    # To prevent re-authenticating within the same PowerShell session, the access ticket and CSRF token are stored in shell variables
    # Note that tickets only last for 2 hours. So it might be possible that someone leaves a terminal open and tries to clone VMs again, only to be met with 401 errors. If that happens just restart the terminal.
    if (-not ($env:ACCESS_TICKET -and $env:CSRF_TOKEN)) {
        if (-not $Vars.Credentials) {
            $Vars.Credentials = (Get-Credential -Credential (Get-DAUser))
        }

        # Obtain the session ticket and CSRF prevention token
        $ticket = Invoke-PVEAPI -Route "access/ticket" -ErrorBehavior "Stop" -Params @{
            Method = "POST"
            Body = @{
                username = $Vars.Credentials.UserName
                password = $Vars.Credentials.GetNetworkCredential().Password
                realm = "NKU"
            }
        }

        if ($ticket.data.ticket -and $ticket.data.CSRFPreventionToken) {
            $env:ACCESS_TICKET = "PVEAuthCookie=$($ticket.data.ticket)"
            $env:CSRF_TOKEN = $ticket.data.CSRFPreventionToken
    
            Write-Host "Session API keys successfully obtained" -ForegroundColor Green
        }
        else {
            throw "Could not obtain session ticket and CSRF token. Make sure you have the right permissions on Proxmox."
        }
    }

    # Authorization headers don't use the environment variables directly, rather this function just returns them as a hashtable. This is because environment variables have to be strings and I don't want to construct the hashtable every time I need to use them.
    return @{
        Authorization = $env:ACCESS_TICKET
        CSRFPreventionToken = $env:CSRF_TOKEN
    }
}

function Create-Pool {
    Param (
        [Parameter(Mandatory)][string]$id
    )

    $pools = Invoke-PVEAPI -Route "pools" -Params @{Headers = (Get-AccessTicket); Method="GET"} -ErrorBehavior "Stop"

    # Check if the pool exists before creating it
    if ($id -in ($pools.data | Select -ExpandProperty poolid)) {
        Write-Warning "Pool $id already exists. Skipping creation..."
    } 
    else {
        # Try to create the pool, retry one time in case it fails for a reason other than invalid authorization
        $response = Invoke-PVEAPI -Route "pools" -Params @{Headers = (Get-AccessTicket); Method="POST"; Body=@{poolid=$id}}
        if ($response.Error -and ($response.StatusCode -ne 401)) {
            Write-Host "Retrying once..." -ForegroundColor White
            Invoke-PVEAPI -Route "pools" -Params @{Headers = (Get-AccessTicket); Method="POST"; Body=@{poolid=$id}} -ErrorBehavior Stop
        }
        elseif ($response.StatusCode -eq 401) {
            throw "Unrecoverable HTTP status 401 returned; make sure you have the correct privileges on Proxmox."
        }
        else {
            Write-Host "Created pool with ID $id" -ForegroundColor Green
        }
    }
}

function Get-NextNode {
    # Round robin load balancing. Not a perfect solution: Doesn't take into account VM/cluster performance at all, but it provides a basic level of load balancing
    Param (
        [Parameter(Mandatory)][int]$LastIndex,
		[Parameter(Mandatory)][object]$nodes
    )

    $next_index = ($LastIndex + 1) % $nodes.length

    # Return the next node to use and the index of that node in the $nodes array. This will loop around the array, going back to 0 after the last has been used.
    return $nodes[$next_index], $next_index
}

function New-VXLAN {
	Param (
		[Parameter(Mandatory)][string]$ID
	)

	$cluster = @((Invoke-PVEAPI -Route "cluster/config/nodes" -Params @{Headers = (Get-AccessTicket); Method = "GET"} -ErrorBehavior "Stop").data)
	$nodes = @($cluster | Select -ExpandProperty name) -join ","
	$peers = @($cluster | Select -ExpandProperty ring0_addr) -join ","
	$vxlan_config = @{
		"type" = "vxlan"
		"zone" = $ID
		"peers" = $peers
		"mtu" = 1450
		"nodes" = $nodes
		"ipam" = "pve"
	}
	
	Write-Host "    [+] Creating new VXLAN with ID $ID" -ForegroundColor Green
	$net = Invoke-PVEAPI -Route "cluster/sdn/zones" -Params @{
		Headers = (Get-AccessTicket)
		Method = "POST"
		Body = $vxlan_config
	}
	
	if ($net.Error) {
		Write-Warning "Failed to create a new VXLAN with ID $ID. $($net.Response)"
		return $null
	}
	return $vxlan_config
}

function New-VirtualNetwork {
	Param (
		[Parameter(Mandatory)][hashtable]$VXLAN,
		[Parameter(Mandatory)][string]$ID,
		[Parameter(Mandatory)][string]$Alias
	)

	Write-Host "    [+] Creating new VNET bound to $($VXLAN.zone); Alias: $Alias" -ForegroundColor Green
	$vnet_config = @{
		"vnet" = $ID
		"zone" = $VXLAN.zone
		"alias" = $Alias
		"tag" = [int]($ID.Trim("v"))
	}
	$net = Invoke-PVEAPI -Route "cluster/sdn/vnets" -Params @{
		Headers = (Get-AccessTicket)
		Method = "POST"
		Body = $vnet_config
	}
	
	if ($net.Error) {
		Write-Warning "Failed to create a new VNET with ID $ID bound to $($VXLAN.zone). $($net.Response)"
		return $null
	}
	return $vnet_config
}

function Set-SDN {
	Param (
		[Parameter(Mandatory)][string]$SDN,
		[Parameter(Mandatory)][string]$Node,
		[Parameter(Mandatory)][object]$VNETs,
		[Parameter(Mandatory)][int]$VM_ID,
		[switch]$Router
	)
	
	function Get-MacAddress {
		Param (
			[Parameter(Mandatory)][string]$Interface
		)
		
		$config = (invoke-pveapi -route "nodes/$Node/qemu/$VM_ID/config" -Params @{
			Headers = (Get-AccessTicket)
			Method = "GET"
		}).data | Select $Interface
		
		return ($config.$Interface).Split(',')[0].Split('=')[1]
	}
	
	$Body = @{
		node = $Node
		vmid = $VM_ID
	}
	
	if ($VNETs.length -eq 0) {
		Write-Warning "FATAL: Could not apply SDN $SDN to $VM_ID; No VNET specified!"
		return $null
	}
	elseif ($VNETs.length -eq 1) {
		$vnet = $VNETs
		if ($Router) {
			$Body["net1"] = "virtio=$(Get-MacAddress -Interface "net1"),bridge=$($vnet.vnet),mtu=1"
		}
		else {
			$Body["net0"] = "virtio=$(Get-MacAddress -Interface "net0"),bridge=$($vnet.vnet),mtu=1"
		}
	}
	elseif ($VNETs.length -eq 2) {
		if ($Router) {
			$internal_bridge = $VNETs | ? {$_.alias -match "internal"}
			$dmz_bridge = $VNETs | ? {$_.alias -match "dmz"}
			$Body["net1"] = "virtio=$(Get-MacAddress -Interface "net1"),bridge=$($internal_bridge.vnet),mtu=1"
			$Body["net2"] = "virtio=$(Get-MacAddress -Interface "net2"),bridge=$($dmz_bridge.vnet),mtu=1"
		}
		else {
			$bridge = $VNETs | ? {$_.alias -match $SDN}
			$Body["net0"] = "virtio=$(Get-MacAddress -Interface "net0"),bridge=$($bridge.vnet),mtu=1"
		}
	}
	
	Invoke-PVEAPI -Route "nodes/$Node/qemu/$VM_ID/config" -Params @{
		Headers = (Get-AccessTicket)
		Method = "POST"
		Body = $Body
	} | Out-Null
	
	Write-Host "    [+] SDN set for $VM_ID; $SDN" -ForegroundColor Green
}

# -------- Exported Functions --------

function Get-PVEClassRoster {
    Param (
        [Parameter(Mandatory)][string]$Class,
        [string]$Path = $null
    )

    if (-not $Path) {
        $Path = "\\hh.nku.edu\departments$\College of Informatics\Dean's Office\Current Dean COI\Griffin Hall\Class Lists\Auto Generated Informatics Roster - Class.csv"
    }

    try {
        $csv = Import-CSV -Path $Path
		$dept, $sec = $Class.Split(" ")
    
		$students = $csv | ? {$_.Department -match $dept -and $_.Section -match $sec} | Select -ExpandProperty Student_ID
		$professor = $csv | ? {$_.Department -match $dept -and $_.Section -match $sec} | Select -ExpandProperty Instructor | Get-Unique
		
		if ((-not $students) -or (-not $professor)) {
			throw "Empty student or professor list returned for $($Class). Make sure it is correct."
		}
        Write-Host "Roster successfully imported" -ForegroundColor Green
    }
    catch {
        Write-Warning "Unable to import class roster list to find $($Class)."
    }

	return $students, $professor
}

function Get-Templates {
    Param (
        [Parameter(Mandatory)][string]$Class
    )

    # Given a class code, return all the templates this class uses.
    $Class = $Class.Split("-")[0] -replace ' ',''
    $data = Invoke-PVEAPI -Route "pools/Templates" -Params @{Headers = (Get-AccessTicket); Method="GET"} -ErrorBehavior "Stop"
    $template_list = @($data.data.members | ? {$_.name -match $Class} | Select name,vmid,node)
	$template_list | % {$_ | Add-Member -MemberType NoteProperty -Name "SDN" -value $false}
	
	foreach ($template in $template_list) {
		$config = Invoke-PVEAPI -Route "nodes/$($template.node)/qemu/$($template.vmid)/config" -Params @{Headers = (Get-AccessTicket); Method="GET"}
		
		# An example tag is "internal;router;template". This line just removes "template" and any leading/trailing semicolons from that string.
		$sdn_tags = (($config.data.tags).Split(';') | ? {$_ -ne "template"}) -join ';'
		if (-not $sdn_tags -eq "") {
			$template.SDN = $sdn_tags
		}
	}

    return $template_list
}

function Set-ClassTA {
    Param (
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$Class,
        [switch]$CloneVM
    )

    # Check if the TA is synced to Proxmox
    $config = Invoke-PVEAPI -Route "access/users/$User@NKU" -Silent -Params @{
        Headers = (Get-AccessTicket)
        Body = @{
            userid = "$User@NKU"
        }
    }

    if ($config.Response -match "no such user") {
        Write-Host "TA $user not synced with Proxmox realm. Syncing now..." -ForegroundColor Yellow
        try {
            Get-ADUser -Identity $User | Out-Null
            Sync-Realm -Students $User | Out-Null
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Host "User $User does not exist in AD" -BackgroundColor Red -ForegroundColor Black
            return $null
        }
    }

    $professor = (Get-PVEClassRoster -Class $Class)[1]
    $pool_id = $Class -replace ' ', ''

    # Get all VMs in the class
    $pool_members = (Invoke-PVEAPI -Route "pools" -Params @{
        Headers = (Get-AccessTicket)
        Body = @{
            poolid = $pool_id
        }
    } -ErrorBehavior "Stop").data.members | Select -ExpandProperty vmid

    foreach ($id in $pool_members) {
        Set-ProxmoxACL -Professor $professor -User $User -ID $id
    }

    if ($CloneVM) {
        Clone-UserVMs -User $User -Professor $professor -Pool $pool_id -Templates (Get-Templates -Class $Class)
    }
}

function Set-ProxmoxACL {
    Param (
        [Parameter(Mandatory)][string]$Professor,
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$ID
    )

    # Update the access control list to include student/professor permissions for a VM.
    $response = Invoke-PVEAPI -Route "access/acl" -Params @{
        Headers = (Get-AccessTicket)
        Method = "PUT"
        Body = @{
            path = "/vms/$id"
            users = "$user@NKU,$professor@NKU"
            roles = "Faculty-Students"
        }
    } -Silent

    if ($response.Response -match "ACL update failed: user '($User@NKU|$Professor@NKU)' does not exist") {
        Write-Warning "$($response.Response). The user likely has not been synced to the NKU realm or does not exist in AD."
    }
    elseif (($response.StatusCode) -and ($response.StatusCode -ne 200)) {
        Write-Warning "Failed to set ACL for $($User): $($response.StatusCode)"
    }
    else {
        Write-Host "    [+] ACL set for $ID; $User, $Professor" -ForegroundColor Green
    }
}

function Sync-Realm {
    Param (
        [Parameter(Mandatory)][object]$Students,
        [string]$Professor
    )

    if (-not $Vars.Credentials) {
        $Vars.Credentials = (Get-Credential -Credential (Get-DAUser))
    }

    $students_group = Get-ADGroupMember -Identity "Proxmox_Students" -Credential $Vars.Credentials | Select -ExpandProperty Name
    $faculty_group = Get-ADGroupMember -Identity "Proxmox_Faculty" -Credential $Vars.Credentials | Select -ExpandProperty Name
	$admin_group = Get-ADGroupMember -Identity "Proxmox_Admins" -Credential $Vars.Credentials | Select -ExpandProperty Name

    # To avoid sync issues we check if the user or professor are already in the designated Proxmox group or the Proxmox_Admins group
    if ($Professor) {
        if ((-not ($Professor -in $faculty_group)) -and (-not ($Professor -in $admin_group))) {
            Write-Host "Adding professor $Professor to Proxmox_Faculty AD group"
    
            # If this fails, it will cause every later ACL update to fail because the professor gets added to every VM. So no error handling here.
            Add-ADGroupMember -Identity "Proxmox_Faculty" -Members $Professor -ErrorAction Stop -Credential $Vars.Credentials 
        }
    }

    foreach ($user in $Students) {
        # The only reason a student should be in the Proxmox_Admins group is if they're a student worker
        if ((-not ($user -in $students_group)) -and (-not ($user -in $admin_group))) {
            try {
                Add-ADGroupMember -Identity "Proxmox_Students" -Members $user -ErrorAction Stop -Credential $Vars.Credentials
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                Write-Host "Failed to add $user to Proxmox_Students AD group. They do not exist in AD. This will likely cause a failure when updating their VM permissions."
            }
        }
    }

    # Once the relevant AD groups are updated we can proceed with the realm sync against the LDAP query:
    # (|(memberOf=CN=Proxmox_Admins,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu)(memberOf=CN=Proxmox_Faculty,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu)(memberOf=CN=Proxmox_Students,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu))

    Write-Host "Syncing realm..." -ForegroundColor Green
    Invoke-PVEAPI -Route "access/domains/NKU/sync" -ErrorBehavior "Stop" -Params @{
        Headers = (Get-AccessTicket)
        Method = "POST"
        Body = @{
            "realm" = "NKU"
            "enable-new" = 1
            "scope" = "both"
            "remove-vanished" = "acl;properties;entry"
        }
    }
}

function Clone-VM {
    Param (
        [Parameter(Mandatory)][int]$ID,
        [Parameter(Mandatory)][int]$TemplateID,
        [Parameter(Mandatory)][string]$Node,
        [Parameter(Mandatory)][string]$Pool,
        [Parameter(Mandatory)][string]$TemplateNode,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$ACL
    )

    # Check if the VM already exists before cloning it
    $vms = (Invoke-PVEAPI -Route "cluster/resources?type=vm" -Params @{Headers = (Get-AccessTicket)}).data
    $does_exist = [bool]($vms | ? {$_.name -eq $name})

    if ($does_exist) {
        Write-Warning "VM $name already exists. Skipping..."
        return $null
    }

    # Clone the VM
    Write-Host "[+] Creating $Name with ID $ID on host $Node" -ForegroundColor Green
    $vm = Invoke-PVEAPI -Route "nodes/$TemplateNode/qemu/$TemplateID/clone" -Params @{
        Headers = (Get-AccessTicket)
        Method = "POST" 
        Body = @{
            newid = $ID
            node = $TemplateNode
            vmid = $TemplateID
            pool = $Pool
            target = $Node
            name = $name
            full = 1
        }
    }

    # The Proxmox API is asynchronous, which is overall good. But there's also not any callbacks or event driven ways to check if a VM is actually done cloning before proceeding.
    # So the best option is to simply poll the API every few seconds to see if its done or not. 
    # If the VMs aren't done before the next step which is to configure the tags, that API call will fail.

    $encoded_parameters = [System.Net.WebUtility]::UrlEncode($vm.data)
    $complete = $false
    $timeout_seconds = 45
    $start_time = Get-Date
    
    Write-Host "    Waiting for VM to finish..." -ForegroundColor Gray
    do {
        if ((Get-Date) - $start_time -gt (New-TimeSpan -Seconds $timeout_seconds)) {
            Write-Warning "Timeout for VM clone exceeded for $name. Subsequent operations will likely fail."
            break
        }
    
        $status = Invoke-PVEAPI -Route "nodes/$TemplateNode/tasks/$encoded_parameters/status" -Params @{
            Method = "GET"
            Headers = (Get-AccessTicket)
        } -Silent
    
        if ($status.data.status -eq "stopped") {
            Write-Host "    [+] Done" -ForegroundColor Green
            $complete = $true
        }
        else {
            Start-Sleep 3
        }
    }
    while (-not $complete)

    # Configure the tags
	Invoke-PVEAPI -Route "nodes/$Node/qemu/$ID/config" -Params @{
		Headers = (Get-AccessTicket)
		Method = "POST"
		Body = @{
			node = $Node
			vmid = $ID
			tags = $Pool
        }
    }

    # Configure the access control list
    Set-ProxmoxACL -Professor $ACL.Professor -User $ACL.User -ID $ID
	
    return $vm
}

function Clone-UserVMs {
	Param (
		[Parameter(Mandatory)][string]$User,
		[Parameter(Mandatory)][string]$Professor,
		[Parameter(Mandatory)][string]$Pool,
		[Parameter(Mandatory)][object]$Templates
	)
	
	$last_index = -1
	$Nodes = @((Invoke-PVEAPI -Route "cluster/config/nodes" -Params @{Headers = (Get-AccessTicket); Method = "GET"} -ErrorBehavior "Stop").data | Select -ExpandProperty name)
	$sdn_required = $Templates.SDN -match "router"
	$vnets = @()
	
	if ($sdn_required) {
		Write-Host "Configuring SDN(s) for $User" -ForegroundColor Black -BackgroundColor White
		$sdns = ($sdn_required.Split(";") | ? {$_ -ne "router"}) -join ';'
		$num_sdns = @($sdns.Split(";")).length
		
		# This isn't pretty but it just queries the cluster for all VNETs and gets the current highest tag in use
		# For some reason, the name for VNETs and VXLANs can only be a maximum of 8 characters. 
		# You can include numbers, but for whatever reason, the name can't START with a number.
		# So that's why the ID is "v$id". The "v" is stripped when applying the tag on the VNET. 
		# For all intents and purposes, the VNETs tag is the same as its name, and the same as the VXLAN its bound to.
		$id = ((((Invoke-PVEAPI -route "cluster/sdn/vnets" -params @{
			Headers = (Get-AccessTicket)
			Method = "GET"
		}).data | Select tag).tag | % {[int]$_}) | Measure-Object -Maximum | Select -ExpandProperty Maximum)
		
		foreach ($sdn in $sdns.Split(";")) {
			Write-Host "[+] Creating SDN $sdn for $User" -ForegroundColor Green
	
			$id = $id + 1
			$sdn_id += $id
			$alias = "$sdn VNET for $User"
			$vnet = New-VirtualNetwork -VXLAN (New-VXLAN -ID "v$id") -Alias $alias -ID "v$id"
			$vnets += $vnet
		}
		
		Invoke-PVEAPI -Route "cluster/sdn" -Params @{
			Headers = (Get-AccessTicket)
			Method = "PUT"
		} | Out-Null
	}
	
	foreach ($template in $Templates) {
		Write-Host "Cloning from template $($template.name); $($template.vmid); $($template.node)..." -BackgroundColor White -ForegroundColor Black
		
		[int]$vm_id = (Invoke-PVEAPI -Route "cluster/nextid" -Params @{Headers = (Get-AccessTicket)}).data
		$node, $last_index = Get-NextNode -LastIndex $last_index -nodes $Nodes
        $name = "$($Pool)-$($User)-$($template.name.Split('-')[-1])"
		
		$acl = @{
            Professor = $Professor
            User = $User
        }
		
		$vm = Clone-VM -TemplateID $template.vmid -Node $node -Pool $Pool -ID $vm_id -TemplateNode $template.node -Name $name -ACL $acl

		if ($template.SDN) {
			Set-SDN -SDN $template.SDN -Node $node -VNETs $vnets -VM_ID $vm_id -Router:$($template.SDN -match "router")
		}	
	}
}

function Clone-ProxmoxClassVMs {
    Param (
        [Parameter(Mandatory)][string]$Class,
        [string]$CustomRosterPath = $null
    )

    # STEP 1: Gather a list of students and the professor for the given class
    $class_roster = Get-ClassRoster -Class $Class -Path $CustomRosterPath
    $student_list, $professor = $class_roster[0], $class_roster[1]
    $users = @($student_list) + $professor

    # STEP 2: Create a pool for the new VMs
    $pool_id = $Class -replace ' ', ''
    Create-Pool -id $pool_id

    # STEP 3: Add each student to the Proxmox_Students AD group, the professor to Proxmox_Faculty, and sync the Proxmox realm
    Sync-Realm -Students $student_list -Professor $professor | Out-Null

    # STEP 4: For each template used by the class, clone a VM for each student in the class, and update the ACL to include the student and professor for the new VM
	foreach ($user in $users) {
        Write-Host "------- Starting config for $user -------" -ForegroundColor Magenta
		Clone-UserVMs -User $User -Professor $professor -Pool $pool_id -Templates (Get-Templates -Class $Class)
	}
}