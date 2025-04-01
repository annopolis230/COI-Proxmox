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

# Custom exception class to be thrown in case of rare HTTP errors
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

# If the current user is the DA user, return their username. Otherwise return da_<user>
function Get-DAUser {
	if (($env:USERNAME).StartsWith("da_")) {
		return $env:USERNAME
	}
	return "da_$env:USERNAME"
}

# Given a route and a table of parameters, make a request to the Proxmox VE API
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

# Almost every API request requires an access ticket and a CSRF prevention token. If these haven't been cached for the PS session yet, this function will do that.
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
    
            Write-Host "API keys loaded into current session. They will expire in 2 hours." -ForegroundColor Black -BackgroundColor Green
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

# Create a new resource pool to hold the class's VMs
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
        # Create the pool
        Invoke-PVEAPI -Route "pools" -Params @{
            Headers = (Get-AccessTicket)
            Method="POST"
            Body=@{
                poolid=$id
            }
        } -ErrorBehavior "Stop"

        Write-Host "Created pool with ID $id" -ForegroundColor Green
    }
}

# Round robin load balancing. Not a perfect solution: Doesn't take into account VM/cluster performance at all, but it provides a basic level of load balancing
function Get-NextNode {
    Param (
        [Parameter(Mandatory)][int]$LastIndex,
		[Parameter(Mandatory)][object]$nodes
    )

    $next_index = ($LastIndex + 1) % $nodes.length

    # Return the next node to use and the index of that node in the $nodes array. This will loop around the array, going back to 0 after the last has been used.
    return $nodes[$next_index], $next_index
}

# Creates a new VXLAN and returns its config if successful
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

# Creates a new VNET and returns its config if successful
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

# Given a VM and SDN config, this function will figure out which network interface to configure to use the newly created SDN
function Set-SDN {
	Param (
		[Parameter(Mandatory)][string]$SDN,
		[Parameter(Mandatory)][string]$Node,
		[Parameter(Mandatory)][object]$VNETs,
		[Parameter(Mandatory)][int]$VM_ID,
		[switch]$Router
	)
	
    # Unfortunately the MAC address is required when changing a network interface, so this function simply returns the MAC address given an interface on the VM.
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
    # If there is one VNET given, one SDN is assumed for the class. Therefore, change the bridge on net1 on the router and net0 on every other VM.
	elseif ($VNETs.length -eq 1) {
		$vnet = $VNETs
		if ($Router) {
			$Body["net1"] = "virtio=$(Get-MacAddress -Interface "net1"),bridge=$($vnet.vnet),mtu=1"
		}
		else {
			$Body["net0"] = "virtio=$(Get-MacAddress -Interface "net0"),bridge=$($vnet.vnet),mtu=1"
		}
	}
    # If there's 2 VNETs, both net1 and net2 on the router needs to be configured. net1 goes to the internal SDN, and net2 goes to the dmz.
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
# Returns an array with two members: the first is an array containing the list of students, the second is a string representing the professor
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
    }
    catch {
        Write-Warning "Unable to import class roster list to find $($Class)."
    }

	return $students, $professor
}

# Given a class code, return all the templates this class uses. This function also determines whether SDNs are required.
function Get-Templates {
    Param (
        [Parameter(Mandatory)][string]$Class
    )

	$original_class = $Class.Split('-')[0]
    $Class = $Class.Split("-")[0] -replace ' ',''
    $data = Invoke-PVEAPI -Route "pools/Templates" -Params @{Headers = (Get-AccessTicket); Method="GET"} -ErrorBehavior "Stop"
    $template_list = @($data.data.members | ? {$_.name -match $Class} | Select name,vmid,node)
	$template_list | % {$_ | Add-Member -MemberType NoteProperty -Name "SDN" -value $false}
	
	foreach ($template in $template_list) {
		$config = Invoke-PVEAPI -Route "nodes/$($template.node)/qemu/$($template.vmid)/config" -Params @{Headers = (Get-AccessTicket); Method="GET"}
		
		# An example tag is "internal;router;template;cit-371". This line just removes "template", "<class>" and any leading/trailing semicolons from that string.
		$sdn_tags = (($config.data.tags).Split(';') | ? {$_ -ne "template" -and $_ -ne ($original_class -replace ' ','-')}) -join ';'
		if (-not $sdn_tags -eq "") {
			$template.SDN = $sdn_tags
		}
	}

    return $template_list
}

# Add a TA to the class, give them permissions on every student's VMs. Optionally, clone them the VMs required for the class.
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

# Update the access control list to include user and professor permissions on a VM
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

# Users aren't automatically imported to Proxmox via AD. You must do a realm sync first, which checks against a few AD groups. This happens each time Clone-ProxmoxClassVMs is called to prevent ACL update errors.
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

# Clone a single VM, configure its tags, and update the ACL. This waits for the VM to finish cloning before proceeding because a lot of subsequent configurations will fail if the VM isn't done.
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

# Clone every VM required for the class for a single user. Returns the index of the last node used. This function will load balance each template.
function Clone-UserVMs {
	Param (
		[Parameter(Mandatory)][string]$User,
		[Parameter(Mandatory)][string]$Professor,
		[Parameter(Mandatory)][string]$Pool,
		[Parameter(Mandatory)][object]$Templates,
        [Parameter(Mandatory)][array]$Nodes,
        [Parameter(Mandatory)][int]$StartingNodeIndex
	)
	
	$sdn_required = $Templates.SDN -match "router"
	$vnets = @()
	
	if ($sdn_required) {
		Write-Host "Configuring SDN(s) for $User" -ForegroundColor Black -BackgroundColor White
		$sdns = ($sdn_required.Split(";") | ? {$_ -ne "router"}) -join ';'
		
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
			$alias = "$sdn VNET for $User"
			$vnet = New-VirtualNetwork -VXLAN (New-VXLAN -ID "v$id") -Alias $alias -ID "v$id"
			$vnets += $vnet
		}
		
		Invoke-PVEAPI -Route "cluster/sdn" -Params @{
			Headers = (Get-AccessTicket)
			Method = "PUT"
		} | Out-Null
	}
	
    $last_index = $StartingNodeIndex
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
    return $last_index
}

# Do a realm sync and clone VMs for the entire class. Load balances each user's VMs.
function Clone-ProxmoxClassVMs {
    # Entrypoint; start here for debugging
    Param (
        [Parameter(Mandatory)][string]$Class,
        [string]$CustomRosterPath = $null
    )

    # STEP 1: Gather a list of students and the professor for the given class
    $class_roster = Get-PVEClassRoster -Class $Class -Path $CustomRosterPath
    $student_list, $professor = $class_roster[0], $class_roster[1]
    $users = @($student_list) + $professor

    # STEP 2: Create a pool for the new VMs
    $pool_id = $Class -replace ' ', ''
    Create-Pool -id $pool_id

    # STEP 3: Add each student to the Proxmox_Students AD group, the professor to Proxmox_Faculty, and sync the Proxmox realm
    Sync-Realm -Students $student_list -Professor $professor | Out-Null

    # STEP 4: Set up the round robin load balancing by initilizating the last_index variable to -1 (the index of the first node to use in the $Nodes array), and gather a list of each node.
    $last_index = -1
	$Nodes = @((Invoke-PVEAPI -Route "cluster/config/nodes" -Params @{Headers = (Get-AccessTicket); Method = "GET"} -ErrorBehavior "Stop").data | Select -ExpandProperty name)

    # STEP 5: For each template used by the class, clone a VM for each student in the class, and update the ACL to include the student and professor for the new VM
	foreach ($user in $users) {
        Write-Host "------- Starting config for $user -------" -ForegroundColor Magenta

        $does_exist = (Invoke-PVEAPI -Route "pools/$pool_id" -Params @{Headers=(Get-AccessTicket);Method="GET"}).data.members | ? {
            $_.name -match $user
        }
        
        if ($does_exist) {
            Write-Warning "User $user already exists in $Class. Skipping config..."
        }
        else {
            $last_index = Clone-UserVMs -User $User -Professor $professor -Pool $pool_id -Templates (Get-Templates -Class $Class) -StartingNodeIndex $last_index -Nodes $Nodes
        }
	}
}