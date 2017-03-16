########################################################################
#
# ISAM-Policy
#
########################################################################

function Set-Headers {
    
    Param([Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$password)

    # Set the IDontCarePolicy on certificate errors
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    
    public class IDontCarePolicy : ICertificatePolicy {
        public IDontCarePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@
    #$pass = Convert-Pass -password $password

    # Set headers
    $authInfo = ("{0}:{1}" -f $username,$password)
    $authInfo = [System.Text.Encoding]::UTF8.GetBytes($authInfo)
    $authInfo = [System.Convert]::ToBase64String($authInfo)
    $headers = @{Accept=("application/json");Contenttype=("application/json");Authorization=("Basic {0}" -f $authInfo)}

    return $headers
}

function Deploy-Changes{
    
    <#
    
    .SYNOPSIS 
    Sends a command to the target ISAM appliance to deploy all changes

    .DESCRIPTION
    The Deploy-Changes function uses the functionality of Invoke-RestMethod to contact a ISAM appliance and issue a command to deploy all changes that are currently stored.
    Certain parameters are required before the function will execute

    .PARAMETER machines
    This parameter is required by default and can contain an array of different ISAM appliances, the command to deploy changes will be issued to all of the ISAM appliances in the array
    Please be aware that the array will only accept IP addresses

    .PARAMETER username
    This parameter is required by default, this parameter should contain a user id that is avaliable to the ISAM appliance and has the correct permissions to issue the command

    .EXAMPLE
    Deploy-Changes -machines 10.79.10.1,10.79.10.2,10.79.50.1,10.79.50.2 -user admin@local

    .NOTES
    On execution you will be asked to provide the password for the selected account

    #>

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username)

    foreach($machine in $machines){

        $password = Read-Host "Enter password for $machine for $username"
        $headers = Set-Headers -username $username -password $password

        $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/isam/pending_changes/deploy" -Headers $headers -Method GET

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
        $responseBody
        $res
    }
}

#
# PDAdmin
#

function New-PDAdminCommand {

 Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Password,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$PDAdminUser,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$PDAdminPass,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$command)

    $headers = Set-Headers -username $username -password $password

    $body = "{'admin_id':'$PDAdminUser','admin_pwd':'$PDAdminPass','commands':['$command']}"

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/isam/pdadmin/" -Headers $headers -Method POST -Body $body

    } catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
    }
    $responseBody
    Return $res
}