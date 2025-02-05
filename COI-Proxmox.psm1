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
        $to_return = $response.Content | ConvertFrom-Json
    }
    # The goal is to return something even if the request fails so the calling function can decide what to do on failure
    catch [System.Net.WebException] {
        $err = $true

        if (-not $Silent) {Write-Warning "$($_.Exception.Message) to route $($route) with method $($Params.Method)"}

        if ($_.Exception.Response.StatusCode.value__) {
            $to_return = @{Error = $true; StatusCode = $_.Exception.Response.StatusCode.value__; Response = $_.Exception.Response.StatusDescription}
        }
        else {
            $to_return = @{Error = $true}
        }
    }
    catch [ApiException] {
        if (-not $Silent) {Write-Warning "$($_.Exception.Message) to route $($route) with method $($Params.Method)"}
        $err = $true
        $to_return = @{StatusCode = $_.Exception.StatusCode; Error = $true}
    }

    # The ErrorBehavior flag overrides the default behavior of returning something on failure and just throws an error. This is useful for when the program shouldn't continue if later processing requires certain data/objects to exist in Proxmox
    if ((-not $err) -or ($ErrorBehavior -eq "Continue")) {
        return $to_return
    }
    else {
        throw "Unable to proceed without the data required or created from the previous API call."
    }
}

function Get-AccessTicket {
    # To prevent re-authenticating within the same PowerShell session, the access ticket and CSRF token are stored in (ephemeral) environment variables
    # Note that tickets only last for 2 hours. So it might be possible that someone leaves a terminal open and tries to clone VMs again, only to be met with 401 errors. If that happens just restart the terminal.
    if (-not ($env:ACCESS_TICKET -and $env:CSRF_TOKEN)) {
        $Credentials = (Get-Credential -Credential $env:USERNAME)
        $params = @{
            Method = "POST"
            Body = @{
                username = $Credentials.UserName
                password = $Credentials.GetNetworkCredential().Password
                realm = "NKU"
            }
        }

        $ticket = Invoke-PVEAPI -Route "access/ticket" -Params $params -ErrorBehavior "Stop"
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

    return $template_list
}

function Clone-VM {
    Param (
        [Parameter(Mandatory)][int]$ID,
        [Parameter(Mandatory)][int]$TemplateID,
        [Parameter(Mandatory)][string]$Node,
        [Parameter(Mandatory)][string]$Pool,
        [Parameter(Mandatory)][string]$TemplateNode
    )

    Write-Host "[+] Creating VM with ID $ID on host $Node" -ForegroundColor Green
    $vm = Invoke-PVEAPI -Route "nodes/$TemplateNode/qemu/$TemplateID/clone" -Params @{
        Headers = (Get-AccessTicket)
        Method = "POST" 
        Body = @{
            newid = $ID
            node = $TemplateNode
            vmid = $TemplateID
            pool = $Pool
            target = $Node
            full = 1
        }
    }
    return $vm
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
            Get-ADUser -Identity $User
            #Sync-Realm -Students $User
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Host "User $User does not exist in AD" -BackgroundColor Red -ForegroundColor Black
            return $null
        }
    }

    $professor = (Get-PVEClassRoster -Class $Class)[1]
    $pool_id = $Class -replace ' ', ''

    if ($CloneVM) {
        $nodes = @((Invoke-PVEAPI -Route "cluster/config/nodes" -Params @{Headers = (Get-AccessTicket); Method = "GET"} -ErrorBehavior "Stop").data | Select -ExpandProperty name)
        $last_index = -1
        foreach ($template in (Get-Templates -Class $Class)) {
            [int]$vm_id = (Invoke-PVEAPI -Route "cluster/nextid" -Params @{Headers = (Get-AccessTicket)}).data
            Write-Host "Cloning from template $($template.name); $($template.vmid); $($template.node)..." -BackgroundColor White -ForegroundColor Black

            $node, $last_index = Get-NextNode -LastIndex $last_index -nodes $nodes
            Clone-VM -TemplateID $template.vmid -Node $node -Pool $pool_id -ID $vm_id -TemplateNode $template.node | Out-Null

            Set-ProxmoxACL -Professor $professor -User $User -ID $vm_id
        }
    }

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
}

function Set-ProxmoxACL {
    Param (
        [Parameter(Mandatory)][string]$Professor,
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$ID
    )

    $acl_body = @{
        path = "/vms/$id"
        users = "$user@NKU,$professor@NKU"
        roles = "Faculty-Students"
    }

    # Update the access control list to include student/professor permissions for a VM.
    $response = Invoke-PVEAPI -Route "access/acl" -Params @{Headers = (Get-AccessTicket); Method = "PUT"; Body = $acl_body} -Silent

    if ($response.Response -match "ACL update failed: user '($User@NKU|$Professor@NKU)' does not exist") {
        Write-Warning "$($response.Response). The user likely has not been synced to the NKU realm or does not exist in AD."
    }
    elseif (($response.StatusCode) -and ($response.StatusCode -ne 200)) {
        Write-Warning "Failed to set ACL for $($User): $($response.StatusCode)"
    }
    else {
        Write-Host "[+] ACL set for $ID; $User, $Professor" -ForegroundColor Gray
    }
}

function Sync-Realm {
    Param (
        [Parameter(Mandatory)][object]$Students,
        [string]$Professor
    )

    $students_group = Get-ADGroupMember -Identity "Proxmox_Students" -Credential $cred | Select -ExpandProperty Name
    $faculty_group = Get-ADGroupMember -Identity "Proxmox_Faculty" -Credential $cred | Select -ExpandProperty Name
	$admin_group = Get-ADGroupMember -Identity "Proxmox_Admins" -Credential $cred | Select -ExpandProperty Name

    # To avoid sync issues we check if the user or professor are already in the designated Proxmox group or the Proxmox_Admins group
    if ($Professor) {
        if ((-not ($Professor -in $faculty_group)) -and (-not ($Professor -in $admin_group))) {
            Write-Host "Adding professor $Professor to Proxmox_Faculty AD group"
    
            # If this fails, it will cause every later ACL update to fail because the professor gets added to every VM. So no error handling here.
            Add-ADGroupMember -Identity "Proxmox_Faculty" -Members $Professor -ErrorAction Stop -Credential $cred 
        }
    }

    foreach ($user in $Students) {
        # The only reason a student should be in the Proxmox_Admins group is if they're a student worker
        if ((-not ($user -in $students_group)) -and (-not ($user -in $admin_group))) {
            try {
                Add-ADGroupMember -Identity "Proxmox_Students" -Members $user -ErrorAction Stop -Credential $cred 
            }
            catch {
                Write-Host "Failed to add $user to Proxmox_Students AD group. This will likely cause a failure when updating their VM permissions."
            }
        }
    }

    # Once the relevant AD groups are updated we can proceed with the realm sync against the LDAP query:
    # (|(memberOf=CN=Proxmox_Admins,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu)(memberOf=CN=Proxmox_Faculty,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu)(memberOf=CN=Proxmox_Students,OU=Proxmox,OU=Security,OU=Groups,OU=HH,OU=NKU,DC=hh,DC=nku,DC=edu))

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

function Clone-PVEClassVMs {
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

    # STEP 3: Get an array containing each in-use host in the cluster, initialize the index of this array to -1 because the Get-NextNode function will increment it.
    $nodes = @((Invoke-PVEAPI -Route "cluster/config/nodes" -Params @{Headers = (Get-AccessTicket); Method = "GET"} -ErrorBehavior "Stop").data | Select -ExpandProperty name)
    $last_index = -1

    # STEP 4: Add each student to the Proxmox_Students AD group, the professor to Proxmox_Faculty, and sync the Proxmox realm
    #Sync-Realm -Students $student_list -Professor $professor

    # STEP 5: For each template used by the class, clone a VM for each student in the class, and update the ACL to include the student and professor for the new VM
    foreach ($template in (Get-Templates -Class $Class)) {
        Write-Host "Cloning from template $($template.name); $($template.vmid); $($template.node)..." -BackgroundColor White -ForegroundColor Black

        foreach ($user in $users) {
            # Get the next available VM ID and the next node to use
            [int]$vm_id = (Invoke-PVEAPI -Route "cluster/nextid" -Params @{Headers = (Get-AccessTicket)}).data
            $node, $last_index = Get-NextNode -LastIndex $last_index -nodes $nodes

            #$name = "$($pool_id)-$($user)-$($template.name -replace '.*\d+','')"
            #$vm = Clone-VM -TemplateID $template.vmid -Node $node -Pool $pool_id -ID $vm_id -TemplateNode $template.node
            
            if ($vm.Error) {
                Write-Warning "Failed to create VM for $user with template $($template.name)"
            }
            else {
                #Set-ProxmoxACL -Professor $professor -User $user -ID $vm_id
            }
        }
    }
}
