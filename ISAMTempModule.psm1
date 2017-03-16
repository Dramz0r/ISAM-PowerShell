#
#
#  TempModule
#
#


function Amend-BlockIPPop {

 Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Password,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$PDAdminUser,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$PDAdminPass,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$IPAddresses)

    $IPs = Get-Content $IPAddresses

    $headers = Set-Headers -username $username -password $password

    foreach($IP in $IPs){
        
        $command = "pop modify BlockIP set ipauth add $IP 255.255.255.255 2"
        $body = "{'admin_id':'$PDAdminUser','admin_pwd':'$PDAdminPass','commands':['$command']}"

        $res = try {
                
            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

            Invoke-RestMethod -Uri "https://$machine/isam/pdadmin/" -Headers $headers -Method POST -Body $body

        } catch {
               $error[0]
        }
        Write-Host $res
    }
}