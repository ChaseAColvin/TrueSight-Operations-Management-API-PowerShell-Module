### Comment/remove lines 2 through 14 to enable certificate validation
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12


#################################################################
###                    TSPS API Functions                     ###
#################################################################


function Request-TspsApiAuthToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiHost,
        [string]$Tennant="*",
        [PSCredential]$Credentials=(Get-Credential),
        [switch]$Http
    )
    
    # Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) {$prefix = $prefix.Replace('s','')}

    # Build URI
    $uri = $prefix + $ApiHost + "/tsws/api/v10.1/token"

    ### Build REST API request for POST to retrieve an auth token
    $body = @{
        username = $Credentials.UserName
        password = $Credentials.GetNetworkCredential().Password
        tenantName = $Tennant
    } | ConvertTo-Json

    $params = @{
        Uri = $uri
        Method = 'POST'
        Body = $body
        ContentType = 'application/json'
    }

    ### Invoke rest method with built parameters, store response in a variable
    $response = Invoke-RestMethod @params

    ### Validate that the the request and the authorization came back good,
    ### Then store token in a variable
    if ($response.statusCode -eq 200)
    {
        if ($response.response.authPassed)
        {
            return $response
        }
        else
        {
            Write-Error "Authentication failed."
            return $false
        }
    }
    else
    {
        Write-Error "Connection error."
        return $false
    }
}


function Confirm-TspsApiAuthToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [switch]$Http
    )

    # Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) {$prefix = $prefix.Replace('s','')}

    # Build URI
    $uri = $prefix + $ApiHost + "/tsws/api/v10.1/token"

    ### Build parameters to validate auth token via REST API
    $header = @{
        authToken = "authToken $token"
        getTokenDetails = "true"
    }

    $params = @{
        Uri = $uri
        Method = 'GET'
        Headers = $header
        ContentType = 'application/json'
    }

    ### Invoke REST method with built parameters to validate auth token
    return (Invoke-RestMethod @params)
}


### Need to consult BMC R and D on issues with this API route
### It does not appear to work
function Get-TspsApiTokenUserGroup
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [switch]$Http
    )

    # Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) {$prefix = $prefix.Replace('s','')}

    # Build URI
    $uri = $prefix + $ApiHost + "/tsws/api/v10.1/token/groups"

    ### Build parameters to get the groups of the user associated with the token
    $header = @{
        authToken = "authToken $token"
    }

    $params = @{
        Uri = $uri
        Method = 'GET'
        Headers = $header
        ContentType = 'application/json'
    }

    ### Invoke REST method with built parameters to validate auth token
    return (Invoke-RestMethod @params)
}


### OmProvider route API calls
function Invoke-TspsApiOmProvider
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$OmProvider,
        [Parameter(Mandatory=$true)]
        [hashtable]$QueryParameters,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [switch]$Http
    )

    # Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) {$prefix = $prefix.Replace('s','')}

    # Build URI
    $uri = $prefix + $ApiHost + "/tsws/10.0/api/omprovider/$($OmProvider)"
    
    if ($Method -match 'GET')
    {
        $array = [System.Collections.ArrayList]@()
        $QueryParameters.GetEnumerator() | ForEach-Object {$array.Add("$($_.Name)=$($_.Value)") | Out-Null}
        $uri += "?$($array -join '&')"
    }

    ### Build API request parameters
    $header = @{
        Authorization = "authToken $token"
    }

    $params = @{
        Uri = $uri
        Method = $Method
        Headers = $header
        ContentType = 'application/json'
    }

    if ($Method -match 'POST') {$params.Add('Body', ($QueryParameters | ConvertTo-Json))}

    ### Invoke rest method to execute query, then store response in a variable
    return (Invoke-RestMethod @params)
}


function Get-TspsApiMonitorInstanceConfiguration
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Tenant,
        [Parameter(Mandatory=$true,
        ParameterSetName='UniqName')]
        [string]$MonUniqName="",
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyList')]
        [hashtable]$InstKeyList=@{},
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [ValidateNotNullOrEmpty()]
        [string]$ServerId,
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [ValidateNotNullOrEmpty()]
        [string]$MonTypeId,
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [ValidateNotNullOrEmpty()]
        [string]$MonInstId,
        [switch]$Http
    )

    $OmProvider = 'configdata'

    if ($PSCmdlet.ParameterSetName -match 'KeyListItems')
    {
        $InstKeyList=[hashtable]@{
            serverId=$ServerId
            monTypeId=$MonTypeId
            monInstId=$MonInstId
        }
    }

    $QueryParameters = @{
        tenantId = $Tenant
        monUniqName = $MonUniqName
        instKeyList = @($InstKeyList)
    }

    $params = @{
        ApiHost = $ApiHost
        Method = 'POST'
        OmProvider = $OmProvider
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) {$params.Add('Http', $true)}

    return (Invoke-TspsApiOmProvider @params)
}


function Get-TspsApiDevice
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Tenant,
        [string]$DeviceEntityType="all",
        [string]$ParentDeviceId="-1",
        [switch]$Http
    )

    $OmProvider = 'devices'

    $QueryParameters = @{
        tenantId = $Tenant
        deviceEntityType = $DeviceEntityType
        parentDeviceId = $ParentDeviceId
    }

    $params = @{
        ApiHost = $ApiHost
        Method = 'GET'
        OmProvider = $OmProvider
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) {$params.Add('Http', $true)}

    return (Invoke-TspsApiOmProvider @params)
}


### This route of the API does not work as documented. It works if you
### the three parameters of the Monitoring Instance Key in separately,
### but passing them in combined into an hashtable does not work as it
### should. Turns out that you can make it work if you use the server
### name in place of the server ID. BMC has noted this as a defect and
### will address it in a future release.
### Current release at the time of this writing is 11.3.02
function Get-TspsApiMonitorInstance
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Tenant,
        [Parameter(ParameterSetName='DevIdOrMonName')]
        [string]$DeviceId="",
        [Parameter(ParameterSetName='DevIdOrMonName')]
        [string]$MonUniqName="",
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyList')]
        [hashtable]$InstKeyList=@{},
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [string]$ServerId="",
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [string]$MonTypeId="",
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [string]$MonInstId="",
        [switch]$Http
    )

    $OmProvider = 'instances'

    $QueryParameters = @{
        tenantId = $Tenant
    }

    Switch($PSCmdlet.ParameterSetName)
    {
        'DevIdOrMonName' {
            if ($DeviceId) {$QueryParameters.Add('deviceId', $DeviceId)}
            if ($MonUniqName) {$QueryParameters.Add('monUniqName', $MonUniqName)}
        }
        'KeyList' {
            $QueryParameters.Add('serverId', $InstKeyList.ServerId)
            $QueryParameters.Add('monTypeId', $InstKeyList.MonTypeId)
            $QueryParameters.Add('monInstId', $InstKeyList.MonInstId)
        }
        'KeyListItems' {
            $QueryParameters.Add('serverId', $ServerId)
            $QueryParameters.Add('monTypeId', $MonTypeId)
            $QueryParameters.Add('monInstId', $MonInstId)
        }
    }

    $params = @{
        ApiHost = $ApiHost
        Method = 'GET'
        OmProvider = $OmProvider
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) {$params.Add('Http', $true)}

    return (Invoke-TspsApiOmProvider @params)
}


function Get-TspsApiMonitorType
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Tenant,
        [string]$MonitorCategory="all",
        [switch]$Http
    )

    $OmProvider = 'monitortypes'

    $QueryParameters = @{
        tenantId = $Tenant
        monitorCategory = $MonitorCategory
    }

    $params = @{
        ApiHost = $ApiHost
        Method = 'GET'
        OmProvider = $OmProvider
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) {$params.Add('Http', $true)}

    return (Invoke-TspsApiOmProvider @params)
}


function Get-TspsApiTenants
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http
    )

    $OmProvider = 'tenants'

    $QueryParameters = @{}

    $params = @{
        ApiHost = $ApiHost
        Method = 'GET'
        OmProvider = $OmProvider
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) {$params.Add('Http', $true)}

    return (Invoke-TspsApiOmProvider @params)
}


function Get-TspsApiMonitorInstancePerformanceData
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Tenant,
        [Parameter(Mandatory=$true,
        ParameterSetName='UniqName')]
        [string]$MonUniqName="",
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyList')]
        [hashtable]$InstKeyList=@{},
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [ValidateNotNullOrEmpty()]
        [string]$ServerId,
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [ValidateNotNullOrEmpty()]
        [string]$MonTypeId,
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyListItems')]
        [ValidateNotNullOrEmpty()]
        [string]$MonInstId,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$StartTime,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$EndTime,
        [string]$Type="rate",
        [string]$Computation="avg",
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$AttribUniqNameList=@(""),
        [switch]$Http
    )

    $OmProvider = 'perfdata'

    if ($PSCmdlet.ParameterSetName -match 'KeyListItems')
    {
        $InstKeyList=[hashtable]@{
            serverId=$ServerId
            monTypeId=$MonTypeId
            monInstId=$MonInstId
        }
    }

    $QueryParameters = @{
        tenantId = $Tenant
        monUniqName = $MonUniqName
        instKeyList = @($InstKeyList)
        startTime = $StartTime
        endTime = $EndTime
        type = $Type
        computation = $Computation
        attribUniqNameList = $AttribUniqNameList
    }

    $params = @{
        ApiHost = $ApiHost
        Method = 'POST'
        OmProvider = $OmProvider
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) {$params.Add('Http', $true)}

    return (Invoke-TspsApiOmProvider @params)
}


### UnifiedAdmin route API calls
function Invoke-TspsApiUnifiedAdmin
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$AdminRoute,
        [Parameter(Mandatory=$true)]
        [hashtable]$QueryParameters,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [switch]$Http
    )

    ### Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) {$prefix = $prefix.Replace('s','')}

    ### Build URI
    $uri = $prefix + $ApiHost + "/tsws/10.0/api/unifiedadmin/$($AdminRoute)"
    
    if ($Method -match 'GET')
    {
        $array = [System.Collections.ArrayList]@()
        $QueryParameters.GetEnumerator() | ForEach-Object {
            $array.Add("$($_.Name)=$($_.Value)") | Out-Null
        }
        $uri += "?$($array -join '&')"
    }

    ### Build API request parameters
    $header = @{
        Authorization = "authToken $token"
    }

    $params = @{
        Uri = $uri
        Method = $Method
        Headers = $header
        ContentType = 'application/json'
    }

    if ($Method -match 'POST' -or $Method -match 'PUT') {
        $params.Add('Body', ($QueryParameters | ConvertTo-Json -Depth 100))
    }

    ### Invoke rest method to execute query, then store response in a variable
    return (Invoke-RestMethod @params)
}


function Get-TspsApiAllPolicies
{
    param(
        $ApiHost,
        $Token,
        [ValidateSet("ENABLED","DISABLED","ANY")]
        $PolicyEnabledStatus = "ANY",
        [ValidateSet("SHARED","NON_SHARED","ANY")]
        $PolicySharedStatus = "ANY",
        $MonitoringSolutionName = "",
        $MonitoringSolutionVersion = "",
        $MonitoringProfile = "",
        $MonitoringType = "",
        $TenantId = "",
        $StringToSearch = "_",
        [ValidateSet("name","description","agentSelectionCriteria","tenant","owner","userGroups")]
        $FieldToSearch = "name",
        [ValidateSet("monitoringPolicy","stagingPolicy","blackoutPolicy")]
        $PolicyType = "monitoringPolicy",
        [switch]$Http
    )

    $QueryParameters = @{
        filterCriteria = @{
            policyEnabledStatus = $PolicyEnabledStatus
            policySharedStatus = $PolicySharedStatus
            monitoringSolutionName = $MonitoringSolutionName
            monitoringSolutionVersion = $MonitoringSolutionVersion
            monitoringProfile = $MonitoringProfile
            monitoringType = $MonitoringType
            tenantId = $TenantId
        }
        stringToSearch = $StringToSearch
        fieldToSearch = $FieldToSearch
        type = $PolicyType

    }

    $params = @{
        ApiHost = $ApiHost
        Method = 'POST'
        AdminRoute = 'Policy/list?responseType=basic'
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) {$params.Add('Http', $true)}

    return (Invoke-TspsApiUnifiedAdmin @params).response.policyList
}


function Get-TspsApiPolicyDetails
{
    param(
        $ApiHost,
        $Token,
        $PolicyId,
        [ValidateSet("name","id")]
        $PolicyIdType,
        [switch]$Http
    )

    $QueryParameters = @{
        idType = $PolicyIdType
    }

    $params = @{
        ApiHost = $ApiHost
        Method = 'GET'
        AdminRoute = "Policy/$PolicyId/list"
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) {$params.Add('Http', $true)}

    return (Invoke-TspsApiUnifiedAdmin @params).response
}


### Build function to update policy. Uses PUT method, so
### I may need to edit the Invoke-TspsApiUnifiedAdmin
### function, or write a function that stands on its own.
function Set-TspsApiPolicyDetails
{
    param(
        $ApiHost,
        $Token,
        $PolicyId,
        [ValidateSet("name","id")]
        $PolicyIdType,
        $PolicyData,
        [switch]$Http
    )

    $PolicyDataHashTable = [hashtable]@{}
    $PolicyData.psobject.properties | Foreach { $PolicyDataHashTable[$_.Name] = $_.Value }

    $QueryParameters = $PolicyDataHashTable

    $params = @{
        ApiHost = $ApiHost
        Method = 'PUT'
        AdminRoute = "MonitoringPolicy/$PolicyId/update?idType=$PolicyIdType"
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) { $params.Add('Http', $true) }

    return (Invoke-TspsApiUnifiedAdmin @params)
}


### Retrieves details of ISNs, but filters off of child
### Patrol Agent details. With the lack of more detailed
### documentation on this route, I've not been able to
### build more robust options into it.
function Get-TspsApiServerDetails
{
    param(
        [string]$ApiHost,
        [string]$Token,
        [string]$AgentFilter,
        [switch]$Http
    )

    $QueryParameters = @{
        agentFilterCriteria = $AgentFilter
    }

    $params = @{
        ApiHost = $ApiHost
        Method = 'POST'
        AdminRoute = "Server/details"
        QueryParameters = $QueryParameters
        Token = $Token
    }

    if ($Http) { $params.Add('Http', $true) }

    return (Invoke-TspsApiUnifiedAdmin @params).response.serverList
}

### Uses the previous function, Get-TspsApiServerDetails,
### takes the data returned, then iterates over it to only
### return the patrol agents that match the filter in one
### consolidated array.
function Get-TspsApiPatrolAgentDetails
{
    param(
        [string]$ApiHost,
        [string]$Token,
        [string]$AgentFilter,
        [switch]$Http
    )

    $params = @{
        ApiHost = $ApiHost
        Token = $Token
        AgentFilter = $AgentFilter
    }

    if ($Http) { $params.Add('Http', $true) }

    $serverList = (Get-TspsApiServerDetails @params)
    $agents = [System.Collections.ArrayList]@()
    
    foreach ($tsim in $serverList)
    {
        foreach ($isn in $tsim.integrationServiceDetails)
        {
            foreach ($pa in $isn.patrolAgentDetails)
            {
                $agents.Add($pa) | Out-Null
            }
        }
    }

    return $agents
}


function Clear-TspsApiAuthToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http
    )

    # Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) {$prefix = $prefix.Replace('s','')}

    # Build URI
    $uri = $prefix + $ApiHost + "/tsws/api/v10.1/token"

    ### Build parameters to validate auth token via REST API
    $header = @{
        authToken = "authToken $token"
    }

    $params = @{
        Uri = $uri
        Method = 'DELETE'
        Headers = $header
        ContentType = 'application/json'
    }

    ### Invoke REST method with built parameters to validate auth token
    return (Invoke-RestMethod @params)
}




#################################################################
###                    TSIM API Functions                     ###
#################################################################


function Invoke-TsimApiResource
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiHost,
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Device","MonitorInstance","CI")]
        [string]$ResourceType,
        [Parameter(Mandatory=$true)]
        [string]$ResourceId,
        [Parameter(Mandatory=$true)]
        [ValidateSet("metadata","configdata","stats")]
        [string]$Action,
        [Parameter(Mandatory=$true)]
        [hashtable]$QueryParameters,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [switch]$Http
    )

    # Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) {$prefix = $prefix.Replace('s','')}

    # Build URI
    $uri = $prefix + $ApiHost + "/bppmws/api/$($ResourceType)/$($ResourceId)/$($Action)"
    
    if ($Method -match 'GET')
    {
        $array = [System.Collections.ArrayList]@()
        $QueryParameters.GetEnumerator() | ForEach-Object {$array.Add("$($_.Name)=$($_.Value)") | Out-Null}
        $uri += "?$($array -join '&')"
    }

    # Build API request parameters
    $header = @{
        Authorization = "authToken $token"
    }

    $params = @{
        Uri = $uri
        Method = $Method
        Headers = $header
        ContentType = 'application/json'
    }

    if ($Method -match 'POST') {$params.Add('Body', ($QueryParameters | ConvertTo-Json))}

    # Invoke rest method to execute query, then store response in a variable
    return (Invoke-RestMethod @params)
} # Might need to be edited for the posts. Depending on how posts behave for the TSIM API


