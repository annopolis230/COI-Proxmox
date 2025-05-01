#####################
# This essentially makes the current PowerShell session trust all certificates. There's no skip certificate check option in PowerShell 5.
# KEEP THIS UNTIL COI STOPS USING SELF-SIGNED CERTIFICATES
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
# Remove from HERE up 
#####################

$Script:Vars = @{
    Credentials = $null
}
$Script:RuntimeContext = @{}

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

# ------- Caching Functions -------
# Reset the runtime cache. This cache should only persist for the current run, not the entire session (VERY important distinction!). The credentials in $Vars should persist throughout the session.
# Note: This function MUST be called at the beginning of an exported function if at some point during that function's execution it uses something from the cache. Even if that function doesn't directly use it (i.e. it calls another function that does)
function Initialize-RuntimeCache {
    Write-Host "Initializing runtime cache..."

    $Script:RuntimeContext = @{
        Start_Time = Get-Date
        VMs_Cloned = 0
        API_Count = 0
        API_Polls = 0
        Cache_Hits = 0
        API_Call_List = @()
        RuntimeCache = @{}
    }
}

# Cache whatever is returned from $FetchBlock as $Key in the runtime cache. If it's already in there, it won't try to re-cache it.
function Get-RuntimeCacheValue {
    Param (
        [string]$Key,
        [string]$Step,
        [ScriptBlock]$FetchBlock
    )

    if (-not $Script:RuntimeContext.RuntimeCache.ContainsKey($Key)) {
        Write-Host "Caching $Key, Step: $Step"
        $Script:RuntimeContext.RuntimeCache[$Key] = & $FetchBlock
    }
    else {
        $Script:RuntimeContext.Cache_Hits += 1
    }

    return $Script:RuntimeContext.RuntimeCache[$Key]
}

function Generate-CacheReport {
    $time = (Get-Date) - ($Script:RuntimeContext.Start_Time)

    Write-Host "-----------------------------------------------"
    Write-Host "Total Time: $($time.Minutes) minutes and $($time.Seconds) seconds" -ForegroundColor White
    Write-Host "VMs Cloned: $($Script:RuntimeContext.VMs_Cloned)" -ForegroundColor White
    Write-Host "API Calls: $($Script:RuntimeContext.API_Count)" -ForegroundColor White
    Write-Host "API Polls: $($Script:RuntimeContext.API_Polls)" -ForegroundColor White
    Write-Host "Cache Hits: $($Script:RuntimeContext.Cache_Hits)" -ForegroundColor White
}

# ------- Utilities -------
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
    # CHANGE THIS IF THE IP ADDRESS OR DNS NAME CHANGES (Keep the /api2/json/$route)
    # for example: $Params["Uri"] = "https://$newip:8006/api2/json/$route"
    $Params["Uri"] = "https://172.28.116.111:8006/api2/json/$route"
    $Params["ContentType"] = "application/x-www-form-urlencoded"
    $Script:RuntimeContext.API_Count += 1
    #$Script:RuntimeContext.API_Call_List += "$($Params.Method) $($Params.Uri)"

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
        throw "Unable to proceed without the data returned or created from the previous API call."
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

# ------- Non-Exported Proxmox Functions -------
# Create a new resource pool to hold the class's VMs
function Create-Pool {
    Param (
        [Parameter(Mandatory)][string]$id,
        [Parameter(Mandatory)][string]$Professor
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
        } -ErrorBehavior "Stop" | Out-Null

        Write-Host "Created pool with ID $id" -ForegroundColor Green
        Start-Sleep -Seconds 2

        Invoke-PVEAPI -Route "access/acl" -Params @{
            Headers = (get-accessticket)
            Method = "PUT"
            Body = @{
                path = "/pool/$id"
                roles = "Faculty-Students"
                users = "$Professor@NKU"
                propagate = 1
            }
        } | Out-Null
    }
}

# Creates a new VXLAN and returns its config if successful
# As of 4/22/25 this function isn't being used because all VNETs are bound to the "vxlntst" zone. 
# If this changes and every VNET needs its own zone, you can change this by uncommenting the "VXLAN" parameter in the New-VirtualNetwork function and uncommenting the -VXLAN parameter when New-VirtualNetwork is called in Clone-UserVMs
# Also, there's logic in the Remove-ClassVMs function to delete these VXLANs so you'll have to change that too.
function New-VXLAN {
	Param (
		[Parameter(Mandatory)][string]$ID
	)

    $cluster = (Get-RuntimeCacheValue -Key "Available_Nodes" -FetchBlock {
        @((Invoke-PVEAPI -Route "cluster/config/nodes" -Params @{Headers = (Get-AccessTicket); Method = "GET"} -ErrorBehavior "Stop").data)
    } -Step "New-VXLAN")
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
		#[Parameter(Mandatory)][hashtable]$VXLAN,
		[Parameter(Mandatory)][string]$ID,
		[Parameter(Mandatory)][string]$Alias
	)

	Write-Host "    [+] Creating new VNET - Alias: $Alias - ID: $ID" -ForegroundColor Green
	$vnet_config = @{
		"vnet" = $ID
		"zone" = "vxlntst"
		"alias" = $Alias
		"tag" = [int]($ID.Trim("v"))
	}
	$net = Invoke-PVEAPI -Route "cluster/sdn/vnets" -Params @{
		Headers = (Get-AccessTicket)
		Method = "POST"
		Body = $vnet_config
	}
	
	if ($net.Error) {
		Write-Warning "Failed to create a new VNET with ID $ID. $($net.Response)"
		return $null
	}
	return $vnet_config
}

# Given a VM and SDN config, this function will figure out which network interface to configure to use the newly created SDN
# CURRENTLY only supports a max of 2 SDNs per student. If more are required, you could add another elseif or just do it the right way and programatically determine how many are needed
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
	
	if ($VNETs.length -eq 0 -or -not $VNETs) {
		Write-Warning "FATAL: Could not apply SDN $SDN to $VM_ID; No VNET specified!"
		return $null
	}
    # If there is one VNET given, one SDN is assumed for the class. Therefore, change the bridge on net1 on the router and net0 on every other VM.
    # This has been tested and works as intended
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
    # I never got a chance to test if this actually works for a class that needs more than 1 SDN, so if issues are arising, it's probably from here
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
# Note: This function sucks. There's really no reason for this function to need the professor, but it's only required because the other functions need to know.
# You might be saying "just import the roster and get the professor from there", but that won't work because custom rosters exist. 
# Honestly I don't really care enough to "fix" it because it works just fine. Just not the optimal solution.
function Set-ClassTA {
    Param (
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$Pool,
        [Parameter(Mandatory)][string]$Professor,
        [switch]$CloneVM
    )

    Initialize-RuntimeCache
    # Check if the TA is synced to Proxmox
    $config = Invoke-PVEAPI -Route "access/users/$User@NKU" -Silent -Params @{Headers = (Get-AccessTicket); Method = "GET"}

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

    $pool_id = $Pool
    #$pool_id = $Class -replace ' ', ''

    # Set permissions on the resource pool
    # Yes, the 'propagate' parameter is used here, but this doesn't allow users with permissions on the POOL to do anything other than simply view the VMs inside the pool.
    # This is because Proxmox's ACL is path based, and when it checks for inheritance, it uses that path. The path for pool and VM permissions are different. 
    Invoke-PVEAPI -Route "access/acl" -Params @{
        Headers = (get-accessticket)
        Method = "PUT"
        Body = @{
            path = "/pool/$pool_id"
            roles = "Faculty-Students"
            users = "$User@NKU"
            propagate = 1
        }
    } -ErrorBehavior "Stop" | Out-Null

    # Get all VMs in the class
    $pool_members = (Get-RuntimeCacheValue -Key "Initial_VM_State" -FetchBlock {
        Invoke-PVEAPI -Route "cluster/resources?type=vm" -Params @{
            Headers = (Get-AccessTicket)
            Method = "GET"
        } -ErrorBehavior "Stop"
    } -Step "VM Discovery in Set-ClassTA").data | ? {$_.pool -eq $pool_id} | Select -ExpandProperty vmid

    if ($pool_members.length -eq 0) {
        Write-Warning "No pool members found for $Pool. Make sure the spelling is correct. Ending program..."
        return $null
    }
    else {
        Write-Host "Permissions on $pool_id set for $User" -ForegroundColor Green
    }

    # Explicitly set permissions on each VM
    foreach ($id in $pool_members) {
        Set-ProxmoxACL -Professor $Professor -User $User -ID $id
    }

    if ($CloneVM) {
        $Nodes = (Get-RuntimeCacheValue -Key "Available_Nodes" -FetchBlock {
            @((Invoke-PVEAPI -Route "cluster/config/nodes" -Params @{Headers = (Get-AccessTicket); Method = "GET"} -ErrorBehavior "Stop").data)
        } -Step "Available nodes in Set-ClassTA") | Select -ExpandProperty name

        $Class = ($Pool.Split('-')[0]) -replace '(\D)(\d)', '$1 $2'
        Clone-UserVMs -User $User -Professor $Professor -Pool $pool_id -Templates (Get-Templates -Class $Class) -Nodes $Nodes -StartingNodeIndex -1 | Out-Null
    }
    Generate-CacheReport
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

    $update = $false

    $students_group = Get-ADGroupMember -Identity "Proxmox_Students" -Credential $Vars.Credentials | Select -ExpandProperty Name
    $faculty_group = Get-ADGroupMember -Identity "Proxmox_Faculty" -Credential $Vars.Credentials | Select -ExpandProperty Name
	$admin_group = Get-ADGroupMember -Identity "Proxmox_Admins" -Credential $Vars.Credentials | Select -ExpandProperty Name

    # To avoid sync issues we check if the user or professor are already in the designated Proxmox group or the Proxmox_Admins group
    if ($Professor) {
        if ((-not ($Professor -in $faculty_group)) -and (-not ($Professor -in $admin_group))) {
            Write-Host "Adding professor $Professor to Proxmox_Faculty AD group"
    
            # If this fails, it will cause every later ACL update to fail because the professor gets added to every VM. So no error handling here.
            Add-ADGroupMember -Identity "Proxmox_Faculty" -Members $Professor -ErrorAction Stop -Credential $Vars.Credentials 
            $update = $true
        }
    }

    foreach ($user in $Students) {
        # The only reason a student should be in the Proxmox_Admins group is if they're a student worker
        if ((-not ($user -in $students_group)) -and (-not ($user -in $admin_group))) {
            try {
                Add-ADGroupMember -Identity "Proxmox_Students" -Members $user -ErrorAction Stop -Credential $Vars.Credentials
                $update = $true
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                Write-Host "Failed to add $user to Proxmox_Students AD group. They do not exist in AD. This will likely cause a failure when updating their VM permissions."
            }
        }
    }

    # Once the relevant AD groups are updated we can proceed with the realm sync against the LDAP query:
    # (|(memberOf=CN=Proxmox_Admins,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu)(memberOf=CN=Proxmox_Faculty,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu)(memberOf=CN=Proxmox_Students,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu))

    # We only actually do the realm sync if it found users that weren't already in the relevant AD groups. If they're in those groups before syncing, it assumes a previous sync already imported them.
    # This is because adding someone to an AD group takes time, so the script will wait 10 seconds before making an API request to go through with the sync.
    if ($update) {
        Write-Host "Realm sync required. Syncing now..." -ForegroundColor Green
        Start-Sleep -Seconds 10
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
}

# Remove all VMs and other configuration items such as HA and SDNs for a given class, with the option to skip certain students if necessary
# I didn't include fallback logic to avoid unecessary API overhead and keep the deletion process fast and predictable.
# If deletion fails, that's a signal of underlying storage issues that should fixed at the infrastructure level.
# But you can get around those errors by using the -SkipUnreferencedDisks option.
function Remove-ClassVMs {
    Param (
        [Parameter(Mandatory)]$Pool,
        [array]$Skip,
        [switch]$SkipUnreferencedDisks
    )

    #$pool_id = $Class -replace ' ', ''
    $pool_id = $Pool
    # Get a list of VMs in the class
    $vms = (Invoke-PVEAPI -Route "pools/$pool_id" -Params @{Headers=(Get-AccessTicket);Method="GET"} -ErrorBehavior "Stop").data.members
    # Get a list of all VXLANs
    #$sdn_zones = (Invoke-PVEAPI -Route "cluster/sdn/zones" -Params @{Headers = (Get-AccessTicket);Method="GET"}).data
    # Get a list of VNETs
    $sdn_vnets = (Invoke-PVEAPI -Route "cluster/sdn/vnets" -Params @{Headers = (Get-AccessTicket);Method="GET"}).data
    # Filter the VM list to not include students in the $Skip array. This ensures those students won't have their VMs or SDNs deleted.
    $vms_to_delete = $vms | ? {-not ($_.name.Split('-')[-2] -in $Skip)}
    # Filter the VNET list to only include VNETs used by that class, and not those used by students in the $Skip array
    $sdns_to_delete = @($sdn_vnets | ? {($_.alias -match $pool_id) -and (-not ($_.alias.Split('_')[-1] -in $Skip))})

    if ($SkipUnreferencedDisks) {
        $Params = "?purge=1"
        Write-Warning "Unreferenced disks not being destroyed from all enabled storages. This could result in orphaned images!" 
    }
    else {
        $Params = "?purge=1&destroy-unreferenced-disks=1"
    }
    # Delete the VMs
    foreach ($vm in $vms_to_delete) {
        if ($vm.status -eq "running") {
            Write-Warning "VM $($vm.name) is running. Stopping now..."

            Invoke-PVEAPI -Route "nodes/$($vm.node)/qemu/$($vm.vmid)/status/stop" -Params @{
                Headers = (Get-AccessTicket)
                Method = "POST"
            } | Out-Null

            Start-Sleep -Seconds 3
            $complete = $false

            do {
                $status = Invoke-PVEAPI -Route "nodes/$($vm.node)/qemu/$($vm.vmid)/status/current" -Params @{
                    Headers = (Get-AccessTicket)
                    Method = "GET"
                }

                if ($status.data.status -eq "stopped") {
                    $complete = $true
                }
                else {
                    Start-Sleep -Seconds 3
                }
            } while (-not $complete)
        }

        Write-Host "[-] Deleting $($vm.name)" -ForegroundColor DarkYellow
        Invoke-PVEAPI -Route "nodes/$($vm.node)/qemu/$($vm.vmid)$Params" -Params @{
            Headers = (Get-AccessTicket)
            Method = "DELETE"
        } | Out-Null

        # Waiting a couple seconds before the next delete operation ensures ceph has enough time to process the last. This prevents delete fails although they're still possible
        Start-Sleep -Seconds 3
    }

    if (-not $Skip) {
        # Delete the pool if all members were deleted
        Write-Host "[-] Deleting pool $pool_id" -ForegroundColor DarkYellow
        Invoke-PVEAPI -Route "pools/?poolid=$pool_id" -Params @{
            Headers = (Get-AccessTicket)
            Method = "DELETE"
        } | Out-Null
    }

    # Delete the VNETs and VXLANs
    foreach ($vnet in $sdns_to_delete) {
        #$vxlan = $sdn_zones | ? {$_.zone -eq $vnet.zone}

        # Delete the VNET
        Write-Host "[-] Deleting VNET $($vnet.vnet)" -ForegroundColor DarkYellow
        Invoke-PVEAPI -Route "cluster/sdn/vnets/$($vnet.vnet)" -Params @{
            Headers = (Get-AccessTicket)
            Method = "DELETE"
        } | Out-Null

        <#if ($vxlan) {
            # Delete the VXLAN
            Write-Host "[-] Deleting VXLAN $($vxlan.zone)" -ForegroundColor DarkYellow
            Invoke-PVEAPI -Route "cluster/sdn/zones/$($vxlan.zone)" -Params @{
                Headers = (Get-AccessTicket)
                Method = "DELETE"
            } | Out-Null
        }#>

        # Remove the deleted VXLAN from the $sdn_zones list. This is because some classes may have more than one VNET per zone, so the first VNET will delete the zone. We don't want it trying to delete the zone a 2nd time.
        # didn't actually test this. If you noticed issues relating to SDNs not being deleted for a class that requires more than 1 per student, this is probably the culprit.
        
        #$sdn_zones = $sdn_zones | ? {$_.zone -ne $vxlan.zone}
    }
    Invoke-PVEAPI -Route "cluster/sdn" -Params @{
        Headers = (Get-AccessTicket)
        Method = "PUT"
    } | Out-Null
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
    $vms = (Get-RuntimeCacheValue -Key "Initial_VM_State" -FetchBlock {
        Invoke-PVEAPI -Route "cluster/resources?type=vm" -Params @{
            Headers = (Get-AccessTicket)
            Method = "GET"
        }
    } -Step "Clone-VM with name $Name").data
    
    $does_exist = [bool]($vms | ? {$_.name -eq $Name})

    if ($does_exist) {
        Write-Warning "VM $Name already exists. Skipping..."
        return $null
    }

    Write-Host "Cloning $Name from template $($template.vmid)..." -BackgroundColor White -ForegroundColor Black
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
            storage = "COIVMSTORAGE"
        }
    }

    # The Proxmox API is asynchronous. There aren't any callbacks or event driven ways to check if a VM is actually done cloning before proceeding.
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

        $Script:RuntimeContext.API_Polls += 1
    
        if ($status.data.status -eq "stopped") {
            Write-Host "    [+] Done" -ForegroundColor Green
            $Script:RuntimeContext.VMs_Cloned += 1
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

    # Add the VM to HA
    Invoke-PVEAPI -Route "cluster/ha/resources" -Params @{
        Headers = (Get-AccessTicket)
        Method = "POST"
        Body = @{
            sid = "vm:$id"
            state = "stopped"
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
        [Parameter(Mandatory)][int]$StartingNodeIndex,
        [switch]$SkipSDN
	)
	
	$sdn_required = $Templates.SDN -match "router"
	$vnets = @()
	
	if ($sdn_required) {
        if ($SkipSDN) {
            Write-Warning "SDN creation being skipped for $User"
        }
        else {
            Write-Host "Configuring SDN(s) for $User" -ForegroundColor Black -BackgroundColor White
            $sdns = ($sdn_required.Split(";") | ? {$_ -ne "router"}) -join ';'
            
            $id = ((((Invoke-PVEAPI -route "cluster/sdn/vnets" -Params @{
                Headers = (Get-AccessTicket)
                Method = "GET"
            }).data | Select tag).tag | % {[int]$_}) | Measure-Object -Maximum | Select -ExpandProperty Maximum)
            
            # This is what will create more than one SDN per user if the class needs it
            foreach ($sdn in $sdns.Split(";")) {
                Write-Host "[+] Creating SDN $sdn for $User" -ForegroundColor Green
        
                $id = $id + 1
                $alias = "$($Pool)_$($sdn)_$($User)"
                $vnet = New-VirtualNetwork -Alias $alias -ID "v$id" # -VXLAN (New-VXLAN -ID "v$id")
                $vnets += $vnet
            }
            
            Invoke-PVEAPI -Route "cluster/sdn" -Params @{
                Headers = (Get-AccessTicket)
                Method = "PUT"
            } | Out-Null
        }
	}
	
    $last_index = $StartingNodeIndex
	foreach ($template in $Templates) {
		[int]$vm_id = (Invoke-PVEAPI -Route "cluster/nextid" -Params @{Headers = (Get-AccessTicket); Method = "GET"}).data
		$node, $last_index = Get-NextNode -LastIndex $last_index -nodes $Nodes
        $name = "$($Pool)-$($User)-$($template.name.Split('-')[-1])"
		
		$acl = @{
            Professor = $Professor
            User = $User
        }
		
		$vm = Clone-VM -TemplateID $template.vmid -Node $node -Pool $Pool -ID $vm_id -TemplateNode $template.node -Name $name -ACL $acl

		if ($vm -and $template.SDN) {
            # Part 2 of the logic to automatically re-acquire missing VMs. The key here is that Clone-VM will skip individual VMs that already exist, thus I don't actually have to determine which VMs are missing.
            # But, if the SkipSDN flag was passed to this function, that means the calling function knows that at least 1 VM needs to be reacquired. 
            # The following logic will do the SDN configuration for that VM if necessary.
            if ($SkipSDN) {
                $existing_vnets = @((Invoke-PVEAPI -Route "cluster/sdn/vnets" -Params @{
                    Headers = (Get-AccessTicket)
                    Method = "GET"
                }).data | ? {$_.alias -match "$Pool_?_$User"})
                Set-SDN -SDN $template.SDN -Node $node -VNETs $existing_vnets -VM_ID $vm_id -Router:$($template.SDN -match "router")
            }
            else {
                Set-SDN -SDN $template.SDN -Node $node -VNETs $vnets -VM_ID $vm_id -Router:$($template.SDN -match "router")
            }
		}	
	}
    return $last_index
}

# Do a realm sync and clone VMs for the entire class. Load balances each user's VMs.
function Clone-ProxmoxClassVMs {
    # Entrypoint; start here for debugging
    Param (
        [Parameter(Mandatory)][string]$Class,
        [Parameter(Mandatory)][string]$Semester,
        [string]$CustomRosterPath = $null
    )

    Initialize-RuntimeCache

    # STEP 1: Gather a list of students and the professor for the given class
    $class_roster = Get-PVEClassRoster -Class $Class -Path $CustomRosterPath
    $student_list, $professor = $class_roster[0], $class_roster[1]
    $users = @($student_list) + $professor

    # STEP 2: Create a pool for the new VMs
    $pool_id = "$Class-$Semester" -replace ' ',''
    #$pool_id = $Class -replace ' ', ''
    Create-Pool -id $pool_id -Professor $professor

    # STEP 3: Add each student to the Proxmox_Students AD group, the professor to Proxmox_Faculty, and sync the Proxmox realm
    Sync-Realm -Students $student_list -Professor $professor | Out-Null

    # STEP 4: Set up the round robin load balancing by initializing the last_index variable to -1 (the index of the first node to use in the $Nodes array), and gather a list of each node.
    $last_index = -1
    $Nodes = (Get-RuntimeCacheValue -Key "Available_Nodes" -FetchBlock {
        @((Invoke-PVEAPI -Route "cluster/config/nodes" -Params @{Headers = (Get-AccessTicket); Method = "GET"} -ErrorBehavior "Stop").data)
    } -Step "Available nodes in Clone-ProxmoxClassVMs") | Select -ExpandProperty name

    # STEP 5: For each template used by the class, clone a VM for each student in the class, and update the ACL to include the student and professor for the new VM
    $templates = Get-Templates -Class $Class
    # This could probably be multithreaded, but then again probably not. Don't be a hero.
	foreach ($user in $users) {
        Write-Host "------- Starting config for $user -------" -ForegroundColor Magenta

        # Part 1 of the logic to automatically re-acquire missing VMs. This assumes that if a VM is missing, and the class requires SDNs, those SDNs already exist!
        # IF for some reason the SDN doesn't already exist (or its alias doesn't follow the standard format), it will fail to set the SDN and fail with an error like "No VNET Specified!"
        # Part 2 of this logic is in the Clone-UserVMs function
        $does_exist = (Get-RuntimeCacheValue -Key "Initial_VM_State" -FetchBlock {
            Invoke-PVEAPI -Route "cluster/resources?type=vm" -Params @{
                Headers = (Get-AccessTicket)
                Method = "GET"
            } -ErrorBehavior "Stop"
        } -Step "VM Discovery in Clone-ProxmoxClassVMs").data | ? {$_.name -match $user -and $_.pool -eq $pool_id}

        if ($does_exist) {
            if ($does_exist.length -eq $templates.length) {
                Write-Warning "Full config for $user already exists in $Class. Skipping..."
            }
            else {
                Write-Warning "One or more VMs for $user are missing and will be reacquired..."
                $last_index = Clone-UserVMs -User $User -Professor $professor -Pool $pool_id -Templates $templates -StartingNodeIndex $last_index -Nodes $Nodes -SkipSDN
            }
        }
        else {
            $last_index = Clone-UserVMs -User $User -Professor $professor -Pool $pool_id -Templates $templates -StartingNodeIndex $last_index -Nodes $Nodes
        }
	}
    Generate-CacheReport
}