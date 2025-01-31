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

$script:Vars = @{
    Credentials = $null
    Headers = @{
        Authorization = $null
        CSRFPreventionToken = $null
    }
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

function Get-ClassRoster {
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

function Invoke-PVEAPI {
    Param (
        [Parameter(Mandatory)][string]$Route,
        [Parameter(Mandatory)][hashtable]$Params,
        [string]$ErrorBehavior = "Continue"
    )

    $err = $false
    $Params["Uri"] = "https://172.28.116.111:8006/api2/json/$route"
    $Params["ContentType"] = "application/x-www-form-urlencoded"

    try {
        $response = Invoke-WebRequest @Params
        if (($response.StatusCode -ne 200) -and ($response.StatusCode -ne 201)) {
            throw [ApiException]::new("Request failed", $response.StatusCode, $response.StatusDescription)
        }
        $to_return = $response.Content | ConvertFrom-Json
    }
    catch [System.Net.WebException] {
        $err = $true

        Write-Warning "$($_.Exception.Message) to route $($route) with method $($Params.Method)"

        if ($_.Exception.Response.StatusCode.value__) {
            $to_return = @{Error = $true; StatusCode = $_.Exception.Response.StatusCode.value__}
        }
        else {
            $to_return = @{Error = $true}
        }
    }
    catch [ApiException] {
        Write-Warning "$($_.Exception) to route $($route) with method $($Params.Method)"
        $err = $true
        $to_return = @{StatusCode = $_.Exception.StatusCode; Error = $true}
    }

    if ((-not $err) -or ($ErrorBehavior -eq "Continue")) {
        return $to_return
    }
    else {
        throw "Unable to proceed without the data required or created from the previous API call."
    }
}

function Get-AccessTicket {
    Param (
        [Parameter(Mandatory)][pscredential]$Credentials
    )

    $params = @{
        Method = "POST"
        Body = @{
            username = $Credentials.UserName
            password = $Credentials.GetNetworkCredential().Password
            realm = "NKU"
        }
    }

    $ticket = Invoke-PVEAPI -Route "access/ticket" -Params $params -ErrorBehavior "Stop"
    
    $Vars.Headers.Authorization = "PVEAuthCookie=$($ticket.data.ticket)"
    $Vars.Headers.CSRFPreventionToken = $ticket.data.CSRFPreventionToken

    if ($Vars.Headers.Authorization -and $Vars.Headers.CSRFPreventionToken) {
        Write-Host "Session API key successfully obtained" -ForegroundColor Green
    }
}

function Create-Pool {
    Param (
        [Parameter(Mandatory)][string]$id
    )

    $pools = Invoke-PVEAPI -Route "pools" -Params @{Headers = $Vars.Headers; Method="GET"} -ErrorBehavior "Stop"

    if ($id -in ($pools.data | Select -ExpandProperty poolid)) {
        Write-Warning "Pool $id already exists. Skipping creation..."
    } 
    else {
        $response = Invoke-PVEAPI -Route "pools" -Params @{Headers = $Vars.Headers; Method="POST"; Body=@{poolid=$id}}
        if ($response.Error -and ($response.StatusCode -ne 401)) {
            Write-Host "Retrying once..." -ForegroundColor White
            Invoke-PVEAPI -Route "pools" -Params @{Headers = $Vars.Headers; Method="POST"; Body=@{poolid=$id}} -ErrorBehavior Stop
        }
        elseif ($response.StatusCode -eq 401) {
            throw "Unrecoverable HTTP status 401 returned; make sure you have the correct privileges on Proxmox."
        }
        else {
            Write-Host "Created pool with ID $($id -replace ' ','')" -ForegroundColor Green
        }
    }
}
function Get-NextNode {
    Param (
        [Parameter(Mandatory)][int]$LastIndex
    )

    $nodes = @("COIVMHOST1", "COIVMHOST2", "COIVMHOST3", "COIVMHOST4")
    $next_index = ($LastIndex + 1) % $nodes.length

    return $nodes[$next_index], $next_index
}

function Get-Templates {
    Param (
        [Parameter(Mandatory)][string]$Class
    )

    $Class = $Class.Split("-")[0] -replace ' ',''
    $data = Invoke-PVEAPI -Route "pools/Templates" -Params @{Headers = $Vars.Headers; Method="GET"} -ErrorBehavior "Stop"
    $template_list = @($data.data.members | ? {$_.name -match $Class} | Select name,vmid)

    return $template_list
}

function Clone-ClassVMs {
    Param (
        [Parameter(Mandatory)][string]$Class,
        [string]$CustomRosterPath = $null
    )

    $last_index = -1

    $class_roster = Get-ClassRoster -Class $Class -Path $CustomRosterPath
    $student_list, $professor = $class_roster[0], $class_roster[1]
    $users = @($student_list) + $professor

    $current_vms = Invoke-PVEAPI -Route "nodes/COIVMHOST1/qemu" -Params @{Headers = $Vars.Headers; Method="GET"}
    $vm_id = ($current_vms.data | Select -ExpandProperty vmid | Sort)[-1] + 1

    $pool_id = $Class -replace ' ', ''
    Create-Pool -id $pool_id

    foreach ($template in (Get-Templates -Class $Class)) {
        Write-Host "Cloning from template $($template.name);$($template.vmid)..." -BackgroundColor White -ForegroundColor Black
        foreach ($user in $users) {
            $node, $last_index = Get-NextNode $last_index
            $name = "$($pool_id)-$($user)-$($template.name -replace '.*\d+','')"

            Write-Host "Creating VM for $user with ID $vm_id on host $node with name $name"
            
            $body = @{
                newid = $vm_id
                node = $node
                vmid = $template.vmid
                pool = $pool_id
                name = $name
            }
            #$vm = Invoke-PVEAPI -Route "nodes/$node/qemu/$($template.vmid)/clone" -Params @{Headers = $Vars.Headers; Method="POST"; Body = @{newid=373;node="COIVMHOST1";vmid=$($template.vmid)}}
            $vm_id++
        }
    }
}
Get-AccessTicket -Credentials (Get-Credential -Credential $env:USERNAME)

#write-host $Vars.Headers.Authorization
#write-host $Vars.Headers.CSRFPreventionToken
Clone-ClassVMs -Class "CIT 371-001" -CustomRosterPath "$HOME\Documents\custom.csv"
#Invoke-PVEAPI -Route "pools/Templates" -Params @{Headers = $Vars.Headers; Method="GET"}

#$vm = Invoke-PVEAPI -Route "nodes/COIVMHOST1/qemu/129/clone" -Params @{Headers = $Vars.Headers; Method="POST"; Body = @{newid=373;node="COIVMHOST1";vmid=129}}
#if ($vm.Error) {
#}


#Create-Pool -id "test"