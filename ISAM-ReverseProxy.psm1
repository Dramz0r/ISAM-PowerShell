﻿function Set-Headers {
    
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
# Reverse Proxy Management
#

Function Get-ReverseProxy {
       
    <#
    
    .SYNOPSIS 
    Send a GET request to the a target ISAM appliance to retrieve information about the local Reverse Proxy instances

    .DESCRIPTION
    The Get-ReverseProxy function uses the functionality of Invoke-RestMethod to contact a ISAM appliance and retrieve information on the local Reverse Proxies.
    Certain parameters are required before the function will execute

    .PARAMETER machine
    This parameter is required by default and must contain an IP addresses of a target ISAM appliance

    .PARAMETER username
    This parameter is required by default, this parameter should contain a user id that is avaliable to the ISAM appliance and has the correct permissions to issue the command

    .PARAMETER password
    This parameter is required by default and must match the password of the target user id

    .EXAMPLE
    Deploy-Changes -machines 10.79.10.1 -username admin@local -password dummypass

    .NOTES
    The return value from the ISAM appliance is in a JSON format, this is automatically changed into a hash table

    #>
       
        
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username)

    $password = Read-Host "Enter password for $username"

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

        #If instances var isn't empty
        if ($instances -ne $null){

            foreach($machine in $machines){
                
                $password = Read-Host "Password for $machine"
                $headers = Set-Headers -username $username -password $password

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
        }

        else {

            foreach($machine in $machines){

                $password = Read-Host "Password for $machine"
                $headers = Set-Headers -username $username -password $password
                $instances = Get-ReverseProxy -machine $machine -username $username -password $password

                #Reboot all instances
                foreach ($instance in $instances){  
                    
                    if ($instance -eq $null){

                        Write-Debug "Null object in array"
                        Continue

                    }

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

Function Add-ReverseProxy {

    param(        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$instance,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$hostname,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$listenport,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$domain = "Default",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$secmasterpw,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateSet('Yes','No')][string]$ldapssl = "No",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$ldapkdb,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$ldaplabel,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$ldapsslport = "636",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateSet('Yes','No')][string]$http = "Yes",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$httpPort = "80",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateSet('Yes','No')][string]$https = "Yes",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$httpsPort = "443",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$IPAddress
        )

        foreach($machine in $machines){

        $password = Read-Host "Password for $machine"

        Set-Headers -username $username -password $password
         
        $body = "{'inst_name':'$instance',
        'host':'$HostName',
        'listening_port':'$ListenPort',
        'domain':'$domain',
        'admin_id':'sec_master',
        'admin_pwd':'$SecMaster',
        'ssl_yn':'$ldapssl',
        'key_file':'$ldapkdb',
        'cert_label':'$ldaplabel',
        'ssl_port':'$ldapsslport',
        'http_yn':'$http',
        'http_port':'$httpPort',
        'https_yn':'$https',
        'https_port':'$httpsPort',
        'nw_interface_yn':'yes',
        'ip_address':'$IPAddress'}"

                

        }


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
        $headers = Set-Headers -username $username -password $password
        
        Write-Debug "Checking server $machine" 

        if ($instances -eq $null){

            $instances = Get-ReverseProxy -machine $machine -username $username -password $password

        }
        
        foreach ($instance in $instances){

            $instanceName = $instance.instance_name
            new-item "$Dir\$machine\$instanceName\" -ItemType directory -Force | Out-Null

        }

        foreach ($instance in $instances){
            if ($instance -eq $null){

                Write-Debug "Null object in array"
                Continue

            }

            $instanceName = $instance.instance_name
            Write-Debug "Checking instance $instanceName on $machine"

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
                                        
                    $worked = $false
                    do{

                        $test = test-path $Dir\$Box\$instance\$FileID -IsValid

                        if ($test -eq $true){

                            Write-Debug "File has been downloaded successfully"
                            $worked = $true
                            
                            $result = try {
                            
                            Write-Debug "Deleting $fileID from $machine"

                            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

                            Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instance/${FileID}?export" -Headers $headers -Method DELETE

                            } catch {
                                $exception = $_.Exception.Response.GetResponseStream()
                                $reader = New-Object System.IO.StreamReader($exception)
                                $responseBody = $reader.ReadToEnd();
                            }
                            $responseBody
                            $responseBody = $null

                        } else {

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

Function Get-ReverseProxyLogs {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instances,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$dir)
   
    foreach ($machine in $machines){
        
        $password = Read-Host "Password for $machine"

        $headers = Set-Headers -username $username -password $password
        
        Write-Debug "Checking server $machine" 
        if ($instances -eq $null){

            $instances = Get-ReverseProxy -machine $machine -username $username -password $password

        }
        
        foreach ($instance in $instances){

            $instanceName = $instance.instance_name
            new-item "$Dir\$machine\$instanceName\" -ItemType directory -Force | Out-Null

        }

        foreach ($instance in $instances){
            if ($instance -eq $null){

                Write-Debug "Null object in array"
                Continue

            }

            $instanceName = $instance.instance_name
            Write-Debug "Checking instance $instanceName on $machine"

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
                                        
                $worked = $false
                do{

                    $test = test-path $Dir\$Box\$instance\$FileID -IsValid

                    if ($test -eq $true){

                        Write-Debug "File has been downloaded successfully"
                        $worked = $true
                            
                        $result = try {
                            
                        Write-Debug "Deleting $fileID from $machine"

                        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

                        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instance/${FileID}?export" -Headers $headers -Method DELETE

                        } catch {
                            $exception = $_.Exception.Response.GetResponseStream()
                            $reader = New-Object System.IO.StreamReader($exception)
                            $responseBody = $reader.ReadToEnd();
                        }
                        $responseBody
                        $responseBody = $null

                    } else {

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
            }
        }
    }
}

Function Remove-ReverseProxyLog {

        Param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machine,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$password,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instance,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$FileID)

        Set-Headers -username $username -password $password
        Write-Debug "Deleting $fileID from $machine"

        $res = try {

            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

            Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instance/${FileID}?export" -Headers $headers -Method DELETE

        } catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
        $responseBody
        $responseBody = $null

}

#
# Reverse Proxy Configuration
#

Function Add-ReverseProxyConfigItem {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Stanza,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Entry,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$value)

    foreach ($machine in $machines){

        $password = Read-Host "Enter password for $machine for $username"
        $headers = Set-Headers -username $username -password $password

        $body = "{entries:['$Entry','$value']}"

        $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Write-Debug "POST https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza/entry_name/$Entry - $body"
        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza/entry_name/$Entry" -Headers $headers -Method POST -Body $body -ContentType "application/json"

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
        $responseBody
    }

    Return $res

}

Function Add-ReverseProxyStanza {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Stanza)

    foreach ($machine in $machines){

        $password = Read-Host "Enter password for $machine for $username"
        $headers = Set-Headers -username $username -password $password

        $res = try {
                
            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

            Write-Debug "POST https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza"
            Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza" -Headers $headers -Method POST

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
        $responseBody

        Return $res
    }
}

Function Remove-ReverseProxyStanza {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Stanza)

    foreach ($machine in $machines){

        $password = Read-Host "Enter password for $machine for $username"
        $headers = Set-Headers -username $username -password $password

        $res = try {
                
            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

            Write-Debug "DELETE https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza"
            Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza" -Headers $headers -Method DELETE

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
        $responseBody
    }
}

Function Remove-ReverseProxyConfigItemValue{

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Stanza,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Entry)

    foreach ($machine in $machines){

        $password = Read-Host "Enter password for $machine for $username"
        $headers = Set-Headers -username $username -password $password

        $res = try {
                
            [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

            Write-Debug "DELETE https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza/entry_name/$Entry"
            Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza/entry_name/$Entry" -Headers $headers -Method DELETE

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
        $responseBody
    }

}

Function Get-ReverseProxyStanzas {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance)

    $password = Read-Host "Enter password for $machine for $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Write-Debug "GET https://$machine/wga/reverseproxy/$Instance/configuration/stanza"
        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$Instance/configuration/stanza" -Headers $headers -Method GET

    }catch {
        $exception = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($exception)
        $responseBody = $reader.ReadToEnd();
    }
    $responseBody

    return $res

}

Function Get-ReverseProxyConfigItemValue {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Stanza,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Entry)

    $password = Read-Host "Enter password for $machine for $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Write-Debug "GET https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza/entry_name/$Entry"
        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza/entry_name/$Entry" -Headers $headers -Method GET

    }catch {
        $exception = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($exception)
        $responseBody = $reader.ReadToEnd();
    }
    $responseBody

    return $res

}

Function Get-ReverseProxyStanzaConfig {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Stanza)

    $password = Read-Host "Enter password for $machine for $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Write-Debug "GET https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza"
        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza" -Headers $headers -Method GET

    }catch {
        $exception = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($exception)
        $responseBody = $reader.ReadToEnd();
    }
    $responseBody

    return $res
}

Function Set-ReverseProxyConfigItemValue {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Stanza,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Entry,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$EntryChange)

    foreach ($machine in $machines){

        $password = Read-Host "Enter password for $machine for $username"
        $headers = Set-Headers -username $username -password $password

        $body = "{'value':'$EntryChange'}"

        $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Write-Debug "PUT https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza/entry_name/$Entry - $body"
        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$Instance/configuration/stanza/$Stanza/entry_name/$Entry" -Headers $headers -Method PUT -Body $body -ContentType "application/json"

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
# Reverse Proxy Junctions
#

Function Add-Junction {}

Function Remove-Junction {}

Function Add-JunctionBackend {

Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$Machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$BackendServer,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Junction,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateSet('tcp','ssl','tcpproxy','sslproxy','local','mutual')][string]$JunctionType,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$ServerPort,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$VirtualHostname,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$VirtualHttpsHostname,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$ServerDN,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$QueryContents,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateSet('Yes','No')][string]$StatefulJunction = "no",
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateSet('Yes','No')][string]$CaseSensitiveURL = "no",
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateSet('Yes','No')][string]$WindowsStyleURL = "no",
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$httpsPort,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$httpPort,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$ProxyHostname,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$ProxyPort,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$smsEnvironment,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][string]$vHostLabel)

    $password = Read-Host "Enter password for $Username"
    
    $headers = Set-Headers -username $Username -password $password

    $body = "{
        'server_hostname':'$BackendServer',
        'junction_point':'$Junction',
        'junction_type':'$JunctionType',
        'server_port':'$ServerPort',
        'virtual_hostname':'$VirtualHostname',
        'virtual_https_hostname':'$VirtualHttpsHostname',
        'server_dn':'$ServerDN',
        'query_contents':'$QueryContents',
        'stateful_junction':'$StatefulJunction',
        'case_sensitive_url':'$CaseSensitiveURL',
        'windows_style_url':'$WindowsStyleURL',
        'https_port':'$httpsPort',
        'http_port':'$httpPort',
        'proxy_hostname':'$ProxyHostname',
        'proxy_port':'$ProxyPort',
        'sms_environment':'$smsEnvironment',
        'vhost_label':'$vHostLabel'
        }"


    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$instance/junctions" -Headers $headers -Method PUT -Body $body

    }catch {
        $exception = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($exception)
        $responseBody = $reader.ReadToEnd();
    }
    $responseBody

    return $res
}

Function Remove-JunctionBackend {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$junction,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$serverUUID)
        
    $password = Read-Host "Enter password for $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

    Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$instance/junctions?junctions_id=$junction&servers_id=$serverUUID" -Headers $headers -Method DELETE

    }catch {
        $exception = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($exception)
        $responseBody = $reader.ReadToEnd();
    }
    $responseBody

    return $res

}

Function Get-Junctions {
    
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$instance)


    $password = Read-Host "Enter password for $machine for $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

    Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$instance/junctions" -Headers $headers -Method GET

    }catch {
        $exception = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($exception)
        $responseBody = $reader.ReadToEnd();
    }
    $responseBody

    return $res
}

Function Get-JunctionConfig {

Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$instance,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$junction)

    foreach ($machine in $machines){
        
        $password = Read-Host "Enter password for $machine for $username"
        $headers = Set-Headers -username $username -password $password

        $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy/$instance/junctions?junctions_id=$junction" -Headers $headers -Method GET

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
        $responseBody

        return $res
    }
}

#
# Distributed Session Cache
#

Function Get-ReplicaSets {
Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username)

    $password = Read-Host "Password for user $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/isam/dsc/admin/replicas" -Headers $headers -Method GET

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
    $responseBody
    return $res
}

Function Get-ReplicaSetServers {
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$replicaSet)

    $password = Read-Host "Password for user $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/isam/dsc/admin/replicas/$replicaSet/servers" -Headers $headers -Method GET

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
    $responseBody
    return $res
}

Function Get-Session {
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$replicaSet,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Pattern = "*",
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$maxReturn = "100")

    $password = Read-Host "Password for user $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/isam/dsc/admin/replicas/$replicaSet/sessions?user=${Pattern}&max=$maxReturn" -Headers $headers -Method GET

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
    $responseBody

    $result = $res.matched_sessions | ConvertFrom-Json

    return $result
}

Function Remove-SessionByID {
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$replicaSet,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$SMSUser)

    $password = Read-Host "Password for user $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/isam/dsc/admin/replicas/$replicaSet/sessions/user/$SMSUser" -Headers $headers -Method DELETE

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
    $responseBody
    return $res
}

Function Remove-SessionByUser {
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$replicaSet,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$SMSUser)

    $password = Read-Host "Password for user $username"
    $headers = Set-Headers -username $username -password $password

    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/isam/dsc/admin/replicas/$replicaSet/sessions/user/$SMSUser" -Headers $headers -Method DELETE

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
    $responseBody
    return $res
}

#
# Additional functionality
#

Function Get-AverageResponseTime{
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][string]$machine,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$duration,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$startTime,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$Instance)

    $password = Read-Host "Password for user $username"
    $headers = Set-Headers -username $username -password $password
    $time = [datetime]::ParseExact($startTime,'dd/MM/yyyy-HH:mm:ss',$null)
    $UnixTimeStamp = [System.Math]::Truncate((Get-Date -Date $time -UFormat %s))


    $res = try {
                
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

        Invoke-RestMethod -Uri "https://$machine/analysis/reverse_proxy_traffic/reqtime?duration=$duration&date=$UnixTimeStamp&instance=$Instance" -Headers $headers -Method GET

        } catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
    $responseBody
    #return $res

    $recordmain = $res.records
    foreach ($rec in $recordmain){

        $juntion = $rec.junction
        $recordloop = $rec.records

        write-host -ForegroundColor Yellow "Junction point: " $juntion
        if($recordloop -eq $null){
            write-host "No records for this junction"
        } else { 
            foreach($record in $recordloop){
                
                    $time = $record.t
                    $origin = get-date "1970-01-01 00:00:00"
                    $time = $origin.AddSeconds($time).ToLocalTime()

                    Write-Host "Average response time of: " $record.r "ms @ " $time " calculated by " $record.n " requests"
            } 
        }
    }
}



Export-ModuleMember -function 'Get-*'
Export-ModuleMember -function 'Set-*'
Export-ModuleMember -function 'Add-*'
Export-ModuleMember -function 'Remove-*'
Export-ModuleMember -Function 'Stop-*'