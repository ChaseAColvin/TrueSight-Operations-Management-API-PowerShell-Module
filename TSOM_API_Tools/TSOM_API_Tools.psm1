### Comment/remove lines 2 through 17 to enable certificate validation
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
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3,
[Net.SecurityProtocolType]::Tls,
[Net.SecurityProtocolType]::Tls11,
[Net.SecurityProtocolType]::Tls12


#################################################################
###                General Utility Functions                  ###
#################################################################


function Get-UnixTimeFromDateTime
{
    param(
        [datetime]$Date=(Get-Date)
    )

    $utcOffset = (Get-TimeZone).BaseUtcOffset

    $fromDate = Get-Date -Date '1970/01/01 00:00:00'

    $timespan = New-TimeSpan -Start $fromDate -End $Date

    $utcTimespan = $timespan.Add(-$utcOffset)

    $unixTime = [Math]::Floor($utcTimespan.TotalSeconds)

    return $unixTime
}


function Get-LocalDateTimeFromUnixTime
{
    param(
        [Parameter(Mandatory=$true)]
        [Int32]$UnixTime,
        [string]$Format
    )

    $utcOffset = (Get-TimeZone).BaseUtcOffset.Hours

    $date = (Get-Date -Date '1970/01/01 00:00:00').AddSeconds($UnixTime)

    Switch([string]::IsNullOrEmpty($Format))
    {
        True { $date.AddHours($utcOffset) }
        False { Get-Date -Date $date.AddHours($utcOffset) -Format $Format }
    }
}



#################################################################
###                    TSPS API Functions                     ###
#################################################################


<#
.SYNOPSIS

Requests an authorization token from the TrueSight Presentation Server.

.DESCRIPTION

Requests an authorization token from the TrueSight Presentation Server.
Requires valid TrueSight credentials with rights to access API.

.PARAMETER PresentationServer

TypeName: System.String

The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Tenant

TypeName: System.String

The TrueSight tenant that the user exists under.
Default value is "*"

.PARAMETER Credentials

TypeName: System.Management.Automation.PSCredential

A PSCredential object containing valid TrueSight credentials,
under the appropriate tenant, with rights to access the API.
Will run Get-Credential to create PSCredential object if one
is not supplied.

.PARAMETER Http

TypeName: System.Management.Automation.SwitchParameter

A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse

TypeName: System.Management.Automation.SwitchParameter

A switch that specifies whether to return the entire response
from the API, or only the 'response.authToken' property of the
response.

.INPUTS

None. You cannot pipe objects to Request-TspsApiAuthToken.

.OUTPUTS

TypeName: System.String
TypeName: System.Management.Automation.PSCustomObject

Request-TspsApiAuthToken returns a string with the auth token.

If the FullResponse switch is used, Request-TspsApiAuthToken
will return an object containing the full response from the
API, not just the 'response.authToken' property.

.EXAMPLE

PS> Request-TspsApiAuthToken -PresentationServer <TSPS Hostname> -Credentials <PSCredential Object>
_9k78f18d-b7b6-4aae-a4d7-61e43a6bafd8

.EXAMPLE

PS> Request-TspsApiAuthToken -PresentationServer <TSPS Hostname> -Tenant <Valid Tenant>
cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
<Prompt will appear to capture credentials>

_9k78f18d-b7b6-4aae-a4d7-61e43a6bafd8
#>
function Request-TspsApiAuthToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [string]$Tenant="*",
        [PSCredential]$Credentials=(Get-Credential),
        [switch]$Http,
        [switch]$FullResponse
    )
    
    ### Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) { $prefix = $prefix.Replace('s','') }

    ### Build URI
    $uri = $prefix + $PresentationServer + "/tsws/api/v10.1/token"

    ### Build REST API request for POST to retrieve an auth token
    $body = @{
        username = $Credentials.UserName
        password = $Credentials.GetNetworkCredential().Password
        tenantName = $Tenant
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
    ### Then return token, else throw an error.
    if ($response.statusCode -eq 200)
    {
        if ($response.response.authPassed)
        {
            Switch($FullResponse)
            {
                True { return $response }
                False { return $response.response.authToken }
            }
        }
        else
        {
            Write-Error "Authentication failed."
        }
    }
    else
    {
        Write-Error "Connection error."
    }
}


<#
.SYNOPSIS

Confirms the validity of an authorization token issued from the
TrueSight Presentation Server.

.DESCRIPTION

Confirms the validity of an authorization token issued from the
TrueSight Presentation Server.

.PARAMETER PresentationServer

TypeName: System.String

The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Token

TypeName: System.String

A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http

TypeName: System.Management.Automation.SwitchParameter

A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse

TypeName: System.Management.Automation.SwitchParameter

A switch that specifies whether to return the entire response
from the API, or just the 'response' property of the response.

.INPUTS

None. You cannot pipe objects to Confirm-TspsApiAuthToken.

.OUTPUTS

TypeName: System.Management.Automation.PSCustomObject

Confirm-TspsApiAuthToken returns an object containing the
authenticated user's username and tenant, if successful.
This data is just the 'response' property of the full API
response.

If the FullResponse switch is used, Confirm-TspsApiAuthToken
will return the full response from the API as an object.

.EXAMPLE

PS> Confirm-TspsApiAuthToken -PresentationServer <TSPS Hostname> -Token <Valid Token>

username  tenantName
--------  ----------
jsnover   *         
#>
function Confirm-TspsApiAuthToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    ### Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) { $prefix = $prefix.Replace('s','') }

    ### Build URI
    $uri = $prefix + $PresentationServer + "/tsws/api/v10.1/token"

    ### Build parameters to validate auth token via REST API
    $header = @{
        authToken = "authToken $Token"
        getTokenDetails = "true"
    }

    $params = @{
        Uri = $uri
        Method = 'GET'
        Headers = $header
        ContentType = 'application/json'
    }

    ### Invoke REST method with built parameters to validate auth token
    $response = Invoke-RestMethod @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.response }
    }
}


#!# TODO: Need to consult BMC R and D on issues with this API route
#.# It seems to require an account to have permissions not specified
#.# in the documentation:
#.# https://docs.bmc.com/docs/tsps113/obtaining-user-groups-for-the-authenticated-user-765456178.html
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiTokenUserGroup
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    ### Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) { $prefix = $prefix.Replace('s','') }

    ### Build URI
    $uri = $prefix + $PresentationServer + "/tsws/api/v10.1/token/groups"

    ### Build parameters to get the groups of the user
    ### associated with the token
    $header = [hashtable]@{
        authToken = "authToken $Token"
    }

    $params = [hashtable]@{
        Uri = $uri
        Method = 'GET'
        Headers = $header
        ContentType = 'application/json'
    }

    ### Invoke REST method with parameters
    $response = Invoke-RestMethod @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response }
    }
}



 #######################################
 ### TSPS OmProvider route API calls ###
 #######################################


<#
.SYNOPSIS

Simplifies calling the '.../tsws/10.0/api/omprovider/...'
routes of the TrueSight API on the Presentation Server.

.DESCRIPTION

General function meant to simplify calling the '.../tsws/10.0/api/omprovider/...'
routes of the TrueSight API on the Presentation Server. Can be used on its
own, but is mainly meant to be used for building more specific cmdlets for
unique types of tasks via the omproviders route of API.

.PARAMETER PresentationServer

TypeName: System.String

The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Method

TypeName: System.String

The HTTP method used to call the specific route of the API.

.PARAMETER OmProvider

TypeName: System.String

The specific sub-route of the omprovider route of the API.
For 'POST' Method calls, query parameters should also be
appended to this parameter.

(This will likely be reworked in the future.)

.PARAMETER QueryParameters

TypeName: System.Collections.Hashtable

The collection of query parameters for the request.
The keys and values are appended to the URI and used
as the query parameters.

Default value is @{}

.PARAMETER RequestParameters

TypeName: System.Collections.Hashtable

This hashtable is converted to JSON, and used as the body
of the request sent. In cases like that, query parameters
that are needed in addtion to the body should be appended
to the OmProvider parameter, prefixed with a '?', and
separated by a '&'. See examples for more details.

Default value is @{}

.PARAMETER Token

TypeName: System.String

A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http

TypeName: System.Management.Automation.SwitchParameter

A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.INPUTS

None. You cannot pipe objects to Invoke-TspsApiOmProvider.

.OUTPUTS

TypeName: System.Management.Automation.PSCustomObject

Invoke-TspsApiOmProvider returns an object containing the
response from the API, if the request was valid.

.EXAMPLE

PS>$QueryParameters = @{
        tenantId = <Valid Tenant>
        deviceEntityType = "all"
        parentDeviceId = "-1"
    }

PS>$params = @{
        PresentationServer = <TSPS Hostname or Alias>
        Method = 'GET'
        OmProvider = 'devices'
        QueryParameters = $QueryParameters
        Token = <Valid Auth Token>
        Http = $false
    }

PS>Invoke-TspsApiOmProvider @params

requestTimeStamp  : 2020-01-10T11:09:13
responseTimeStamp : 2020-01-10T11:09:13
statusCode        : 200
statusMsg         : OK
responseMsg       : Success
responseContent   : @{deviceList=System.Object[]}        
#>
function Invoke-TspsApiOmProvider
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OmProvider,
        [hashtable]$QueryParameters=@{},
        [hashtable]$RequestParameters=@{},
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http
    )

    ### Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) { $prefix = $prefix.Replace('s','') }

    ### Build URI
    $uri = $prefix + $PresentationServer + "/tsws/10.0/api/omprovider/$($OmProvider)"

    ### If query parameters exist, append them to the URI
    if ($QueryParameters.Count -gt 0)
    {
        $qpArray = [System.Collections.ArrayList]@()

        $QueryParameters.GetEnumerator() | ForEach-Object `
        {
            $qpArray.Add("$($_.Name)=$($_.Value)") | Out-Null
        }

        $uri += "?$($qpArray -join '&')"
    }

    ### Build API request parameters
    $header = [hashtable]@{
        Authorization = "authToken $Token"
    }

    $params = [hashtable]@{
        Uri = $uri
        Method = $Method
        Headers = $header
        ContentType = 'application/json'
    }

    if ($RequestParameters.Count -gt 0)
    {
        $params.Add('Body', ($RequestParameters | ConvertTo-Json -Depth 100))
    }

    ### Invoke rest method to execute query,
    ### then return response
    return (Invoke-RestMethod @params)
}


### Modified this function so that it can also use the separate
### components of the MonInstKey, just like Get-TspsApiMonitorInstance
<#
.SYNOPSIS

Simplifies calling the '.../tsws/10.0/api/omprovider/configdata...'
route of the TrueSight API on the Presentation Server.

.DESCRIPTION

Simplifies calling the '.../tsws/10.0/api/omprovider/configdata...'
route of the TrueSight API on the Presentation Server. Requests
configuration data about a monitoring instance using the 'MonInstKey',
provided either as a hashtable, or its three individual components.

For more details on this specific route of the API, see:
https://docs.bmc.com/docs/tsps113/retrieving-the-configuration-data-of-monitor-instances-765456179.html

.PARAMETER PresentationServer

TypeName: System.String

The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Tenant

TypeName: System.String

The TrueSight tenant that the user exists under.
Default value is "*"

.PARAMETER MonUniqName

ParameterSet: UniqName
TypeName: System.String

Unique name for a specific monitor type. Can be retrieved from
a specific monitor instance with Get-TspsApiMonitorInstance,
or via Get-TspsApiMonitorType, which leverages the 'List Monitor
Types' API route.

(This will likely be reworked in the future.)

.PARAMETER InstKeyList

ParameterSet: KeyList
TypeName: System.Collections.Hashtable

A hashtable containing the ServerId, MonTypeId and MonInstId
for a monitored instance.

.PARAMETER ServerId

ParameterSet: KeyListItems
TypeName: System.String

The ServerId for a monitored instance.

.PARAMETER MonTypeId

ParameterSet: KeyListItems
TypeName: System.String

The MonTypeId for a monitored instance

.PARAMETER MonInstId

ParameterSet: KeyListItems
TypeName: System.String

The MonInstId for a monitored instance

.PARAMETER Token

TypeName: System.String

A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http

TypeName: System.Management.Automation.SwitchParameter

A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse

TypeName: System.Management.Automation.SwitchParameter

A switch that specifies whether to return the entire response
from the API, or just the 'responseContent' property of the 
response.

.INPUTS

None. You cannot pipe objects to Get-TspsApiMonitorInstanceConfiguration.

.OUTPUTS

TypeName: System.Management.Automation.PSCustomObject

Get-TspsApiMonitorInstanceConfiguration returns an object containing the
responseContent property of the response from the API, if the request
was valid.

If the FullResponse switch is used, Get-TspsApiMonitorInstanceConfiguration
returns the full response from the API, not just the 'responseContent'
property.

.EXAMPLE

PS>$keylist = [hashtable]@{serverId=1; monTypeId=21013; monInstId=12}

PS>$params = @{
        PresentationServer = <TSPS Hostname or Alias>
        InstKeyList = $keylist
        Token = <Valid Auth Token>
    }

PS>Get-TspsApiMonitorInstanceConfiguration @params

monUniqName monInstName
----------- -----------                                                        
NTDiskSpace Drive = C:\Program Files\BMC Software\TrueSight...

.EXAMPLE

PS>$params = @{
        PresentationServer = <TSPS Hostname or Alias>
        ServerId = 1
        MonTypeId = 21013
        MonInstId = 12
        Token = <Valid Auth Token>
    }

PS>Get-TspsApiMonitorInstanceConfiguration @params

monUniqName monInstName
----------- -----------                                                        
NTDiskSpace Drive = C:\Program Files\BMC Software\TrueSight...
#>
function Get-TspsApiMonitorInstanceConfiguration
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [string]$Tenant="*",
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
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    if ($PSCmdlet.ParameterSetName -match 'KeyListItems')
    {
        $InstKeyList= [hashtable]@{
            serverId = $ServerId
            monTypeId = $MonTypeId
            monInstId = $MonInstId
        }
    }

    $RequestParameters = [hashtable]@{
        tenantId = $Tenant
        monUniqName = $MonUniqName
        instKeyList = @($InstKeyList)
    }

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'POST'
        OmProvider = 'configdata'
        RequestParameters = $RequestParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiOmProvider @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.responseContent }
    }
}


### This route of the API does not work as documented. It works if you
### use the DeviceId, the MonUniqName, or the combination of both but,
### passing in the ServerId, MonTypeId, and MonInstId does not work as it
### should. Supposedly you can make it work if you use the server name
### BMC has noted this as a defect and will address it in
### a future release.
### Current release at the time of this writing is 11.3.02.
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER Tenant
Parameter description

.PARAMETER DeviceId
Parameter description

.PARAMETER MonUniqName
Parameter description

.PARAMETER InstKeyList
Parameter description

.PARAMETER ServerId
Parameter description

.PARAMETER MonTypeId
Parameter description

.PARAMETER MonInstId
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiMonitorInstance
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [string]$Tenant="*",
        [Parameter(ParameterSetName='DevIdOrMonName')]
        [string]$DeviceId="",
        [Parameter(ParameterSetName='DevIdOrMonName')]
        [string]$MonUniqName="",
        [Parameter(ParameterSetName='KeyList')]
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
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $QueryParameters = [hashtable]@{
        tenantId = $Tenant
    }

    Switch($PSCmdlet.ParameterSetName)
    {
        'DevIdOrMonName' {
            if (-not [string]::IsNullOrEmpty($DeviceId))
            {
                $QueryParameters.Add('deviceId', $DeviceId)
            }

            if (-not [string]::IsNullOrEmpty($MonUniqName))
            {
                $QueryParameters.Add('monUniqName', $MonUniqName)
            }
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

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'GET'
        OmProvider = 'instances'
        QueryParameters = $QueryParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiOmProvider @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.responseContent.instanceList }
    }
}


<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER Tenant
Parameter description

.PARAMETER MonitorCategory
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiMonitorType #####
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [string]$Tenant="*",
        [string]$MonitorCategory="all",
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $QueryParameters = [hashtable]@{
        tenantId = $Tenant
        monitorCategory = $MonitorCategory
    }

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'GET'
        OmProvider = 'monitortypes'
        QueryParameters = $QueryParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiOmProvider @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.responseContent.monitorTypeList }
    }
}


<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER Tenant
Parameter description

.PARAMETER MonUniqName
Parameter description

.PARAMETER InstKeyList
Parameter description

.PARAMETER ServerId
Parameter description

.PARAMETER MonTypeId
Parameter description

.PARAMETER MonInstId
Parameter description

.PARAMETER StartTime
Parameter description

.PARAMETER EndTime
Parameter description

.PARAMETER Type
Parameter description

.PARAMETER Computation
Parameter description

.PARAMETER AttribUniqNameList
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiMonitorInstancePerformanceData
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [string]$Tenant="*",
        [Parameter(ParameterSetName='UniqName')]
        [string]$MonUniqName="",
        [Parameter(ParameterSetName='KeyList')]
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
        [datetime]$StartTime,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [datetime]$EndTime,
        [string]$Type="rate",
        [string]$Computation="avg",
        [ValidateNotNullOrEmpty()]
        [string[]]$AttribUniqNameList,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    if ($PSCmdlet.ParameterSetName -match 'KeyListItems')
    {
        $InstKeyList = [hashtable]@{
            serverId=$ServerId
            monTypeId=$MonTypeId
            monInstId=$MonInstId
        }
    }

    $unixStartTime = Get-UnixTimeFromDateTime -Date $StartTime
    $unixEndTime = Get-UnixTimeFromDateTime -Date $EndTime

    $RequestParameters = [hashtable]@{
        tenantId = $Tenant
        monUniqName = $MonUniqName
        instKeyList = @($InstKeyList)
        startTime = $unixStartTime
        endTime = $unixEndTime
        type = $Type
        computation = $Computation
        attribUniqNameList = $AttribUniqNameList
    }

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'POST'
        OmProvider = 'perfdata'
        RequestParameters = $RequestParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiOmProvider @params
    
    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.responseContent }
    }
}


<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER Tenant
Parameter description

.PARAMETER DeviceEntityType
Parameter description

.PARAMETER ParentDeviceId
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiDevices
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [string]$Tenant="*",
        [string]$DeviceEntityType="all",
        [string]$ParentDeviceId="-1",
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $QueryParameters = [hashtable]@{
        tenantId = $Tenant
        deviceEntityType = $DeviceEntityType
        parentDeviceId = $ParentDeviceId
    }

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'GET'
        OmProvider = 'devices'
        QueryParameters = $QueryParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiOmProvider @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.responseContent.deviceList }
    }
}


<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiTenants
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'GET'
        OmProvider = 'tenants'
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiOmProvider @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.responseContent.tenantList }
    }

}


 #########################################
 ### TSPS UnifiedAdmin route API calls ###
 #########################################
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER Method
Parameter description

.PARAMETER AdminRoute
Parameter description

.PARAMETER QueryParameters
Parameter description

.PARAMETER RequestParameters
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Invoke-TspsApiUnifiedAdmin
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$AdminRoute,
        [hashtable]$QueryParameters = @{},
        [hashtable]$RequestParameters = @{},
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [switch]$Http
    )

    ### Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) { $prefix = $prefix.Replace('s','') }

    ### Build URI
    $uri = $prefix + $PresentationServer + "/tsws/10.0/api/unifiedadmin/$($AdminRoute)"
    
    if ($QueryParameters.Count -gt 0)
    {
        $qpArray = [System.Collections.ArrayList]@()

        $QueryParameters.GetEnumerator() | ForEach-Object `
        {
            $qpArray.Add("$($_.Name)=$($_.Value)") | Out-Null
        }

        $uri += "?$($qpArray -join '&')"
    }

    ### Build API request parameters
    $header = @{
        Authorization = "authToken $Token"
    }

    $params = @{
        Uri = $uri
        Method = $Method
        Headers = $header
        ContentType = 'application/json'
    }

    if ($RequestParameters.Count -gt 0)
    {
        $params.Add('Body', ($RequestParameters | ConvertTo-Json -Depth 100))
    }

    ### Invoke rest method to execute query,
    ### then return response
    return (Invoke-RestMethod @params)
}


<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER PolicyEnabledStatus
Parameter description

.PARAMETER PolicySharedStatus
Parameter description

.PARAMETER MonitoringSolutionName
Parameter description

.PARAMETER MonitoringSolutionVersion
Parameter description

.PARAMETER MonitoringProfile
Parameter description

.PARAMETER MonitoringType
Parameter description

.PARAMETER TenantId
Parameter description

.PARAMETER StringToSearch
Parameter description

.PARAMETER FieldToSearch
Parameter description

.PARAMETER PolicyType
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiAllPolicies
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [ValidateSet("ENABLED","DISABLED","ANY")]
        [string]$PolicyEnabledStatus = "ANY",
        [ValidateSet("SHARED","NON_SHARED","ANY")]
        [string]$PolicySharedStatus = "ANY",
        [string]$MonitoringSolutionName = "",
        [string]$MonitoringSolutionVersion = "",
        [string]$MonitoringProfile = "",
        [string]$MonitoringType = "",
        [string]$TenantId = "*",
        [string]$StringToSearch = "_",
        [ValidateSet("name","description","agentSelectionCriteria",
        "tenant","owner","userGroups")]
        [string]$FieldToSearch = "name",
        [ValidateSet("monitoringPolicy","stagingPolicy","blackoutPolicy")]
        [string]$PolicyType = "monitoringPolicy",
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $QueryParameters = [hashtable]@{
        responseType = 'basic'
    }

    $RequestParameters = [hashtable]@{
        filterCriteria = [hashtable]@{
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

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'POST'
        AdminRoute = 'Policy/list'
        QueryParameters = $QueryParameters
        RequestParameters = $RequestParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiUnifiedAdmin @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.response.policyList }
    }
}


<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER PolicyId
Parameter description

.PARAMETER PolicyIdType
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiPolicyDetails
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        [Parameter(Mandatory=$true)]
        [ValidateSet("name","id")]
        [string]$PolicyIdType,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $QueryParameters = [hashtable]@{
        idType = $PolicyIdType
    }

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'GET'
        AdminRoute = "Policy/$PolicyId/list"
        QueryParameters = $QueryParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiUnifiedAdmin @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.response.monitoringPolicy }
    }
}


### Build function to update policy. Uses PUT method, so
### I may need to edit the Invoke-TspsApiUnifiedAdmin
### function, or write a function that stands on its own.
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER PolicyId
Parameter description

.PARAMETER PolicyIdType
Parameter description

.PARAMETER PolicyData
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Set-TspsApiPolicyDetails
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        [Parameter(Mandatory=$true)]
        [ValidateSet("name","id")]
        [string]$PolicyIdType,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscustomobject]$PolicyData,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $QueryParameters = [hashtable]@{
        idType = $PolicyIdType
    }

    $PolicyDataHashTable = [hashtable]@{}
    $PolicyData.psobject.properties | ForEach-Object `
    {
        $PolicyDataHashTable[$_.Name] = $_.Value
    }

    $RequestParameters = [hashtable]@{
        monitoringPolicy = $PolicyDataHashTable
    }

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'PUT'
        AdminRoute = "MonitoringPolicy/$PolicyId/update"
        QueryParameters = $QueryParameters
        RequestParameters = $RequestParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiUnifiedAdmin @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.response.monitoringPolicy }
    }
}


### Retrieves details of ISNs, but filters off of child
### Patrol Agent details. With the lack of more detailed
### documentation on this route, I've not been able to
### build more robust options into it.
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER AgentFilter
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.PARAMETER FullResponse
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiServerDetails
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentFilter,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $RequestParameters = [hashtable]@{
        agentFilterCriteria = $AgentFilter
    }

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Method = 'POST'
        AdminRoute = "Server/details"
        RequestParameters = $RequestParameters
        Token = $Token
        Http = $Http.IsPresent
    }

    $response = Invoke-TspsApiUnifiedAdmin @params

    Switch($FullResponse.IsPresent)
    {
        True { return $response }
        False { return $response.response.serverList }
    }
}


### Uses the previous function, Get-TspsApiServerDetails,
### takes the data returned, then iterates over it to only
### return the patrol agents that match the filter in one
### consolidated array.
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER AgentFilter
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-TspsApiPatrolAgentDetails
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentFilter,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http
    )

    $params = [hashtable]@{
        PresentationServer = $PresentationServer
        Token = $Token
        AgentFilter = $AgentFilter
        Http = $Http.IsPresent
    }

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


<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER PresentationServer
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Clear-TspsApiAuthToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http
    )

    ### Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) { $prefix = $prefix.Replace('s','') }

    ### Build URI
    $uri = $prefix + $PresentationServer + "/tsws/api/v10.1/token"

    ### Build parameters to validate auth token via REST API
    $header = [hashtable]@{
        authToken = "authToken $token"
    }

    $params = [hashtable]@{
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


### Might need to be edited for the POSTs, depending
### on how POSTs behave for the TSIM API
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER TsimServer
Parameter description

.PARAMETER Method
Parameter description

.PARAMETER ResourceType
Parameter description

.PARAMETER ResourceId
Parameter description

.PARAMETER Action
Parameter description

.PARAMETER QueryParameters
Parameter description

.PARAMETER RequestParameters
Parameter description

.PARAMETER Token
Parameter description

.PARAMETER Http
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Invoke-TsimApiResource
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$TsimServer,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Device","MonitorInstance","CI")]
        [string]$ResourceType,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceId,
        [Parameter(Mandatory=$true)]
        [ValidateSet("metadata","configdata","stats")]
        [string]$Action,
        [hashtable]$QueryParameters = @{},
        [hashtable]$RequestParameters = @{},
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http
    )

    ### Define prefix, if http flag used, strip 's' from prefix
    $prefix = "https://"
    if ($Http) { $prefix = $prefix.Replace('s','') }

    ### Build URI
    $uri = $prefix + $TsimServer + "/bppmws/api/$($ResourceType)/$($ResourceId)/$($Action)"
    
    if ($QueryParameters.Count -gt 0)
    {
        $qpArray = [System.Collections.ArrayList]@()

        $QueryParameters.GetEnumerator() | ForEach-Object `
        {
            $qpArray.Add("$($_.Name)=$($_.Value)") | Out-Null
        }

        $uri += "?$($qpArray -join '&')"
    }

    ### Build API request parameters
    $header = [hashtable]@{
        Authorization = "authToken $Token"
    }

    $params = [hashtable]@{
        Uri = $uri
        Method = $Method
        Headers = $header
        ContentType = 'application/json'
    }

    if ($RequestParameters.Count -gt 0)
    {
        $params.Add('Body', ($RequestParameters | ConvertTo-Json -Depth 100))
    }

    ### Invoke rest method to execute query,
    ### then return response
    return (Invoke-RestMethod @params)
}


