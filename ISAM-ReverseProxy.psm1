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

    # Set headers
    $authInfo = ("{0}:{1}" -f $username,$password)
    $authInfo = [System.Text.Encoding]::UTF8.GetBytes($authInfo)
    $authInfo = [System.Convert]::ToBase64String($authInfo)
    $headers = @{Accept=("application/json");Contenttype=("application/json");Authorization=("Basic {0}" -f $authInfo)}

    return $headers
}

#
# Reverse Proxy Management
#

Function Get-ReverseProxy {
        
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$password)

    # Set headers
    $headers = Set-Headers -username $username -password $password
    
    $instances = try {
                
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

    Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/" -Headers $headers -Method GET

    }catch {
        $exception = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($exception)
        $responseBody = $reader.ReadToEnd();
    }
    $responseBody

    return $instances

}

Function Set-ReverseProxy {

    param(        
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instances,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][array]$operation)




    foreach ($machine in $machines){
        $password = Read-Host "Password for $machine"

        # Set headers
        Set-Headers -username $username -password $password

        #If instances var isn't empty
        if ($instances -ne $null){

            #Restart all instances specified in instances var
            foreach ($instance in $instances){  
    
                $instName = $instance
                Write-Host -ForegroundColor Yellow "Sending '$operation' command to $instance on $machine"
                
                $uri = "https://$machine/wga/reverseproxy/$instName"
                $res = try { 

                    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
          
                    Invoke-RestMethod -Uri $uri -Headers $headers -Method PUT -Body "{'operation':'$operation'}" -ContentType "application/json"
                    
                } catch {
                    $exception = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($exception)
                    $responseBody = $reader.ReadToEnd();
                }
                $res
                $responseBody
            }
        } 

        #else restart all instances on machine
        else {

            #Get WebSEAL instances
            $instances = Get-ReverseProxy -machine $machine -username $username -password $password

            #Reboot all instances
            foreach ($instance in $instances){  
    
                $instName = $instance.instance_name
                Write-Host -ForegroundColor Yellow "Sending '$operation' command to $instance on $machine"

                $uri = "https://$machine/wga/reverseproxy/$instName"
                $res = try { 

                    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
          
                    Invoke-RestMethod -Uri $uri -Headers $headers -Method PUT -Body "{'operation':'$operation'}" -ContentType "application/json"
                    
                } catch {
                    $exception = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($exception)
                    $responseBody = $reader.ReadToEnd();
                }
                $responseBody
            }
        }
    }
}

Function Stop-ReverseProxy {

    param(        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instances)

        Set-ReverseProxy -machines $machines -username $username -instances $instances -operation "stop"
    
}

Function Restart-ReverseProxy {

    param(        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instances)

    foreach ($machine in $machines){
        $password = Read-Host "Password for $machine"

        # Set headers
        $headers = Set-Headers -username $username -password $password

        #If instances var isn't empty
        if ($instances -ne $null){

            #Restart all instances specified in instances var
            foreach ($instance in $instances){  
    
                $instName = $instance
                Write-Host -ForegroundColor Yellow "Restarting $instance on $machine"
                
                $uri = "https://$machine/wga/reverseproxy/$instName"
                $res = try { 

                    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
          
                    Invoke-RestMethod -Uri $uri -Headers $headers -Method PUT -Body "{'operation':'restart'}" -ContentType "application/json"
                    
                } catch {
                    $exception = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($exception)
                    $responseBody = $reader.ReadToEnd();
                }
                $res
                $responseBody
            }
        } 

        #else restart all instances on machine
        else {

            #Get WebSEAL instances

            $instances = Get-WebSEAL -machine $machine -username $username -password $password

            #Reboot all instances
            foreach ($instance in $instances){  
    
                $instName = $instance.instance_name
                Write-Host -ForegroundColor Yellow "Restarting $instName on $machine"

                $uri = "https://$machine/wga/reverseproxy/$instName"
                $res = try { 

                    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
          
                    Invoke-RestMethod -Uri $uri -Headers $headers -Method PUT -Body "{'operation':'restart'}" -ContentType "application/json"
                    
                } catch {
                    $exception = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($exception)
                    $responseBody = $reader.ReadToEnd();
                }
                $responseBody
            }
        }
    }
}

Function Start-ReverseProxy {

    param(        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instances)

        Set-ReverseProxy -machines $machines -username $username -instances $instances -operation "start"
        
}

Function Remove-ReverseProxy {

    param(        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instances)

        Set-ReverseProxy -machines $machines -username $username -instances $instances -operation "unconfigure"

}

#
# Logging
#

Function Get-ReverseProxyLogsByDate{

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instances,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$date,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$dir)
   
    foreach ($machine in $machines){
        
        $password = Read-Host "Password for $machine"

        # Set headers
        $headers = Set-Headers -username $username -password $password
        
        Write-Debug "Checking server $machine" 
        #Get machine instances if var is empty
        if ($instances -eq $null){

            $instances = Get-ReverseProxy -machine $machine -username $username -password $password

        }
        
        #create Dirs for saved logs
        foreach ($instance in $instances){

            $instanceName = $instance.instance_name
            new-item "$Dir\$machine\$instanceName\" -ItemType directory -Force | Out-Null

        }

        #get logs
        foreach ($instance in $instances){
            if ($instance -eq $null){

                Write-Debug "Null object in array"
                Continue

            }

            $instanceName = $instance.instance_name
            Write-Debug "Checking instance $instanceName on $machine"

            #get all file for associated instance
            $result = try {
                
            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

            Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instanceName" -Headers $headers -Method GET

            } catch {
                $exception = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($exception)
                $responseBody = $reader.ReadToEnd();
            }
            $responseBody
            $responseBody = $null

            foreach ($file in $result){

                if($file.id -like "*$date*"){
                
                    #and download it to the appropriate e:\logs\* folder
                    $FileID = $File.id
                    Write-Debug "Downloading file: $FileID"

                    $result = try {
                
                        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

                        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instanceName/${FileID}?export" -Headers $headers -Method GET -OutFile "${dir}\${machine}\${instanceName}\${fileID}"

                    } catch {
                        $exception = $_.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($exception)
                        $responseBody = $reader.ReadToEnd();
                    }
                    $responseBody
                    $responseBody = $null
                                        
                    #Confirm the file has been downloaded
                    $worked = $false
                    do{

                        $test = test-path $Dir\$Box\$instance\$FileID -IsValid

                        if ($test -eq $true){

                            #Now the file has been downloaded and confirmed, we can remove it from SAM
                            Write-Debug "File has been downloaded successfully"
                            $worked = $true
                            
                            $result = try {
                            
                            Write-Debug "Deleting $fileID from $machine"

                            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

                            #Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instance/${FileID}?export" -Headers $headers -Method DELETE

                            } catch {
                                $exception = $_.Exception.Response.GetResponseStream()
                                $reader = New-Object System.IO.StreamReader($exception)
                                $responseBody = $reader.ReadToEnd();
                            }
                            $responseBody
                            $responseBody = $null

                        } else {

                            #If the file isn't found, re-download the file from SAM.
                            Write-Debug "Warning: File not found"
                            $result = try {
                
                            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

                            Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instance" -Headers $headers -Method GET

                            } catch {
                                $exception = $_.Exception.Response.GetResponseStream()
                                $reader = New-Object System.IO.StreamReader($exception)
                                $responseBody = $reader.ReadToEnd();
                            }
                            $responseBody
                            $responseBody = $null

                            }

                    } while ($worked = $false)
                } else {

                    Write-Debug "File does not match $date"

                }
            }
        }
    } 
}

#
# Reverse Proxy Configuration
#

Function Add-ReverseProxyConfigItem {}

Function Add-ReverseProxyStanza {}

Function Remove-ReverseProxyStanza {}

Function Remove-ReverseProxyConfigItemValue {}

Function Get-ReverseProxyStanza {}

Function Get-ReverseProxyConfigItemValue {}

Function Get-ReverseProxyStanzaConfig {}

Function Set-ReverseProxyConfigItemValue {}

#
# Reverse Proxy Junctions
#

Function Add-Junction {}

Function Remove-Junction {}

Function Add-JunctionBackend {}

Function Remove-JunctionBackend {}

Function Get-Junctions {}

Function Get-JunctionConfig {}

#
# Distributed Session Cache
#

Function Get-ReplicaSets {}

Function Get-ReplicaSetServers {}

Function Get-Session {}

Function Remove-SessionByID {}

Function Remove-SessionByUser {}







Export-ModuleMember -function 'Get-*'
Export-ModuleMember -function 'Set-*'
Export-ModuleMember -function 'Add-*'
Export-ModuleMember -function 'Remove-*'
Export-ModuleMember -Function 'Stop-*'
































