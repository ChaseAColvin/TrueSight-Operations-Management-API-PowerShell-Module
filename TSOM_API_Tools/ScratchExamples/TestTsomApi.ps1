Import-Module "" <# Path to the TSOM_API_Tools.psm1 module here #> -force
<# Can also just use the module name here ^^^ if it is in an existing module search directory #>

$creds = Get-Credential

$tsps = ''<# Presentation Server hostname here (If you have an alias, use that) #>
$tsim = ''<# TSIM hostname here (If you have an alias, use that) #>

$token = (Request-TspsApiAuthToken -ApiHost $tsps -Credentials $creds).response.authToken


#Confirm-TspsApiAuthToken -ApiHost $tsps -Token $token

#$userGroups = Get-TspsApiTokenUserGroup -ApiHost $tsps -Token $token
#$userGroups <# ^^^ This route does not work as it should #>

#Get-TspsApiMonitorInstanceConfiguration -ApiHost $tsps -Tenant "*" -MonUniqName "_PATROL__NT_PROCESS" -Token $token | convertto-json -Depth 100

<#
$keylist = [hashtable]@{serverId=9; monTypeId=501022; monInstId=36381}
$output = Get-TspsApiMonitorInstanceConfiguration -ApiHost $tsps -Tenant "*" -InstKeyList $keylist -Token $token | convertto-json -Depth 100
$output
#>

#Get-TspsApiMonitorInstanceConfiguration -ApiHost $tsps -Tenant "*" -ServerId 9 -MonTypeId 501026 -MonInstId 16549 -Token $token
#(Get-TspsApiDevice -ApiHost $tsps -Tenant "*" -Token $token).responseContent.deviceList | Where-Object {$_.deviceId -eq 337}

#Get-TspsApiMonitorInstance -ApiHost $tsps -Tenant "*" -Token $token -InstKeyList @{serverId=9; monTypeId=501022; monInstId=49103}

<#
#$output = Get-TspsApiMonitorInstance -ApiHost $tsps -Tenant "*" -Token $token -ServerId $keylist.serverId -MonTypeId $keylist.monTypeId -MonInstId $keylist.monInstId
#$output = Get-TspsApiMonitorInstance -ApiHost $tsps -Tenant "*" -Token $token -DeviceId "337" -MonUniqName "_PATROL__NT_PROCESS"
$output.responseContent.instanceList
#>


#Get-TspsApiMonitorType -ApiHost $tsps -Tenant "*" -Token $token | ConvertTo-Json -Depth 100
#Get-TspsApiTenants -ApiHost $tsps -Token $token | ConvertTo-Json -Depth 100
#Get-TspsApiMonitorInstancePerformanceData -ApiHost $tsps -Tenant "*" -Token $token -serverId 9 -monTypeId 501022 -monInstId 49103 -StartTime 1571176800 -EndTime 1571259600 -AttribUniqNameList @("PROCStatus")


<#
$QueryParameters = [hashtable]@{
    idType = 'IPAddress'
}

$params = [hashtable]@{
    ApiHost = $tsim
    Token = $token
    Method = 'GET'
    ResourceType = 'Device'
    ResourceId = '10.232.150.93'
    Action = 'configdata'
    QueryParameters = $QueryParameters
}

$output = Invoke-TsimApiResource @params

$output.response
#>

<#
$output = Get-TspsApiAllPolicies -ApiHost $tsps -Token $token
$output
#>

<#
$output = Get-TspsApiPolicyDetails -ApiHost $tsps -Token $token -PolicyId '999_ApiManagementTestPolicy' -PolicyIdType name
$output.monitoringPolicy
#>

#Set-TspsApiPolicyDetails -ApiHost $tsps -Token $token -PolicyId '999_ApiManagementTestPolicy' -PolicyIdType name -PolicyData $updateJson

<#
$output = Get-TspsApiPolicyDetails -ApiHost $tsps -Token $token -PolicyId '999_ApiManagementTestPolicy' -PolicyIdType name
$output
#>

<#
$output = Get-TspsApiServerDetails -ApiHost $tsps -Token $token -AgentFilter 'OS CONTAINS "Windows"'
$output | ConvertTo-Json -Depth 100
#>

$output = Get-TspsApiPatrolAgentDetails -ApiHost $tsps -Token $token -AgentFilter 'OS CONTAINS "Windows"'
$output | ConvertTo-Json -Depth 100

Clear-TspsApiAuthToken -ApiHost $tsps -Token $token | out-null
Clear-Variable 'token'