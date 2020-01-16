### Set TsomApiToolsPath to the path of TSOM_API_Tools.psm1.
$TsomApiToolsPath = ""
Import-Module $TsomApiToolsPath -Force

######################################################################

### Uncomment the line below and run once, then comment it out
### again. This is not necessary, but it will prevent you from
### having to enter your credentials each time you run the script
### while you are testing.
$creds = Get-Credential

######################################################################

### Presentation Server hostname here. (If you have an alias, use that)
$tsps = ''
### TSIM hostname here. (If you have an alias, use that)
$tsim = ''

######################################################################

### Calls the authentication route of API, stores token in variable.
$token = Request-TspsApiAuthToken -PresentationServer $tsps -Credentials $creds

######################################################################

### Confirms the validity of an auth token.
Confirm-TspsApiAuthToken -PresentationServer $tsps -Token $token

######################################################################

### REQUIRES UNDOCUMENTED PERMISSIONS
Get-TspsApiTokenUserGroup -PresentationServer $tsps -Token $token

######################################################################

### Pulls monitor instance configuration data by the 'MonUniqName'.
### Can be used to find a MonInstKey, which can be used like in
### the examples below.

Get-TspsApiMonitorInstanceConfiguration -PresentationServer $tsps `
   -MonUniqName "NTProcessInfo" -Token $token

### instKey variable is set to a MonInstKey, which can be found
### via the above call example, as well as through several others.
### Values set here are examples from my development environment
### and likely will not work for others.

$instKey = [hashtable]@{serverId=1; monTypeId=21023; monInstId=5}

### Uses a MonInstKey assinged to the instKey variable to pull
### configuration information for a specific monitoring instance.

Get-TspsApiMonitorInstanceConfiguration -PresentationServer $tsps `
   -InstKeyList $instKey -Token $token

### Can also pull multiple monitoring instances if an array (list)
### of InstKeyLists is provided to the InstKeyList parameter.

$instKeyList = @(
   @{serverId=1; monTypeId=21023; monInstId=5},
   @{serverId=1; monTypeId=21023; monInstId=3}
)

Get-TspsApiMonitorInstanceConfiguration -PresentationServer $tsps `
   -InstKeyList $instKeyList -Token $token

### Uses a the three individual values of a MonInstKey (serverId 
### monTypeId, and monInstId) to pull configuration information for
### a specific monitoring instance. Note these are the same values
### assigned to the instKey variable above. This is to demonstrate
### that the function can be used both ways.

Get-TspsApiMonitorInstanceConfiguration -PresentationServer $tsps `
   -ServerId 1 -MonTypeId 21023 -MonInstId $instKey.monInstId `
   -Token $token
   
######################################################################

### Pulls details for monitored instances for DeviceId 1, with a
### MonUniqName of NTProcessInfo. The tenant is specified as *,
### though this is not necessary as * is the default value.
### This is to demonstrate that the tenant can be specified.

Get-TspsApiMonitorInstance -PresentationServer $tsps -Tenant "*" `
   -DeviceId 1 -MonUniqName 'NTProcessInfo' -Token $token

### BROKEN. Should pull a monitored instane by the MonInstKey,
### however there is a defect with the API that prevents this.
### That said, whenever the defect is patched, this will work.

Get-TspsApiMonitorInstance -PresentationServer $tsps `
   -InstKey $instKey -Token $token -FullResponse

######################################################################

### Pulls performance data for monitored instances that share the
### MonUniqName of NTProcessInfo, and has the PROC_CPU attribute.

Get-TspsApiMonitorInstancePerformanceData -PresentationServer $tsps `
-MonUniqName 'NTProcessInfo' -StartTime (Get-Date).AddHours(-12) `
-EndTime (Get-Date) -AttribUniqNameList "PROC_CPU" -Token $token

### Pulls performance data for the PROC_CPU attribute of a specific
### monitored instances, designated by the 'MonInstKey' provided via
### the instKeyList variable, which is defined in an example above.

Get-TspsApiMonitorInstancePerformanceData -PresentationServer $tsps `
-InstKeyList $instKeyList -StartTime (Get-Date).AddHours(-12) `
-EndTime (Get-Date) -AttribUniqNameList "PROC_CPU" -Token $token

######################################################################

### Pulls a list of all available monitor types, including their
### name, monUniqName, and monitorCategory. Tenant is specified
### as *, even though * is the default, in order to demonstrate
### it can be set.

Get-TspsApiMonitorType -PresentationServer $tsps -Tenant "*" `
   -Token $token

######################################################################

### Pulls a list of all monitored devices. Tenant default
### is *, and does not need to be specified unless you are
### calling a different tenant.

Get-TspsApiDevices -PresentationServer $tsps -Tenant "*" `
   -Token $token

######################################################################

### Pulls a list of all available tenants.

Get-TspsApiTenants -PresentationServer $tsps -Token $token

######################################################################

### Pulls a list of all policies. MonitoringPolicies by default,
### but can be specified using the PolicyType parameter.

Get-TspsApiAllPolicies -PresentationServer $tsps -Token $token

######################################################################

### This example pulls a policy named 999_ApiManagementTestPolicy
### and saves it to a variable. This variable is used in a later
### example, but is not necessary.

$policy = Get-TspsApiPolicyDetails -PresentationServer $tsps -PolicyIdType name `
   -PolicyId '999_ApiManagementTestPolicy' -Token $token
$policy

######################################################################

### Pulls a valid policy with updated parameters from a file
### called testUpdate.json, the updates the policy named
### 999_ApiManagementTestPolicy with that data.

$updateJson = (Get-Content "C:\temp\testUpdate.json" | ConvertFrom-Json)
Set-TspsApiPolicyDetails -PresentationServer $tsps `
   -PolicyId '999_ApiManagementTestPolicy' -PolicyIdType name `
   -PolicyData $updateJson -Token $token

######################################################################

### Pulls a list of Infrastructure management servers,
### with their assigned integration servers, and child
### patrol agents, where patrol agents meet specified
### filter criteria.

Get-TspsApiServerDetails -PresentationServer $tsps `
   -AgentFilter 'OS CONTAINS "Windows"' -Token $token

######################################################################

### Pulls a list of patrol agents that meet specified
### filter criteria. In this case, that filter is pulled
### from the Get-TspsApiPolicyDetails example above.
### However, this could also be given directly, as seen
### in the Get-TspsApiServerDetails example above.

$policyAgentFilter = $policy.agentSelectionCriteria
Get-TspsApiPatrolAgentDetails -PresentationServer $tsps `
   -AgentFilter $policyAgentFilter -Token $token

######################################################################

### This is an example of using one of the more general
### functions used in the creation of the TSOM API Tools
### module. This specific example is used as it is the
### only function I have that works with the TSIM directly.
### Though I intend to add more specifc functions that 
### just call the function below.

$QueryParameters = [hashtable]@{
    idType = 'IPAddress'
}

$params = [hashtable]@{
    TsimServer = $tsim
    Token = $token
    Method = 'GET'
    ResourceType = 'Device'
    ResourceId = '' #Target server IP addresss, TSIM in this case
    Action = 'configdata'
    QueryParameters = $QueryParameters
}

Invoke-TsimApiResource @params

######################################################################

### If token is set, attempts to cleanly log out.
if (-not [string]::IsNullOrEmpty($token))
{
    Clear-TspsApiAuthToken -PresentationServer $tsps -Token $token | out-null
    Clear-Variable 'token'
}