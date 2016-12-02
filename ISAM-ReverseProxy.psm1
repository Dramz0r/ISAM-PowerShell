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

                            Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instance/${FileID}?export" -Headers $headers -Method DELETE

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

Function Get-ReverseProxyLogs {

    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateScript({$_ -match [IPAddress]$_ })][array]$machines,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$username,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=0)][array]$instances,
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

                        Invoke-RestMethod -Uri "https://$machine/wga/reverseproxy_logging/instance/$instance/${FileID}?export" -Headers $headers -Method DELETE

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

        Invoke-RestMethod -Uri "https://$machine/isam/dsc/admin/replicas/$replicaSet/sessions?user=${Pattern}max=$maxReturn" -Headers $headers -Method GET

        }catch {
            $exception = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($exception)
            $responseBody = $reader.ReadToEnd();
        }
    $responseBody
    return $res
}

Function Remove-SessionByID {}

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







Export-ModuleMember -function 'Get-*'
Export-ModuleMember -function 'Set-*'
Export-ModuleMember -function 'Add-*'
Export-ModuleMember -function 'Remove-*'
Export-ModuleMember -Function 'Stop-*'