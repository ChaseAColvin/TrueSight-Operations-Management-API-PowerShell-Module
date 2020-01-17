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

<#
.SYNOPSIS
Converts datetime object to Unix time.

.DESCRIPTION
Converts datetime object to Unix time. Will give current datetime
in Unix time, if no other datetime object is provided.

.PARAMETER Date
Datetime object to be converted into Unix time.
Defaults to the output of Get-Date at the time
this function is called.

.INPUTS
Get-UnixTimeFromDateTime can accept a datetime object from the
pipeline.

.EXAMPLE
PS> Get-UnixTimeFromDateTime
1579108753

.EXAMPLE
PS> Get-UnixTimeFromDateTime -Date (Get-Date -Date '1991/09/17')
685090800

.EXAMPLE
PS> Get-Date -Date '1991/09/17' | Get-UnixTimeFromDateTime
685090800
#>
function Get-UnixTimeFromDateTime
{
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [datetime]$Date=(Get-Date)
    )

    $utcOffset = (Get-TimeZone).BaseUtcOffset

    $fromDate = Get-Date -Date '1970/01/01 00:00:00'

    $timespan = New-TimeSpan -Start $fromDate -End $Date

    $utcTimespan = $timespan.Add(-$utcOffset)

    $unixTime = [Math]::Floor($utcTimespan.TotalSeconds)

    return $unixTime
}


<#
.SYNOPSIS
Converts Unix time to local time as a datetime object.

.DESCRIPTION
Converts Unix time to local time as a datetime object.
A if the Format parameter is used, the date will be
returned as a string in the specified format instead.

.PARAMETER UnixTime
A unix timestamp to be converted to local time and
returned as a datetime object.
Can accept a value from the pipeline.

.PARAMETER Format
An optional parameter that specifies an output format.
If used, the date is returned as a string in the 
specified format instead of a datetime object.

.INPUTS
Get-LocalDateTimeFromUnixTime can accept a a Unix timestamp
from the pipeline for the UnixTime parameter.

.EXAMPLE
PS> Get-LocalDateTimeFromUnixTime -UnixTime 685090800

Tuesday, September 17, 1991 12:00:00 AM

.EXAMPLE
PS> 685090800 | Get-LocalDateTimeFromUnixTime -Format 'yyyy/MM/dd hh:mm:ss'
1991/09/17 12:00:00
#>
function Get-LocalDateTimeFromUnixTime
{
    param(
        [Parameter(Mandatory=$true,
        ValueFromPipeline)]
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
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Tenant
The TrueSight tenant that the user exists under.
Default value is "*"

.PARAMETER Credentials
A PSCredential object containing valid TrueSight credentials,
under the appropriate tenant, with rights to access the API.
Will run Get-Credential to create PSCredential object if one
is not supplied.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
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
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response
from the API, or just the 'response' property of the response.

.INPUTS
Confirm-TspsApiAuthToken will accept a value for the Token
parameter from the pipeline.

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

.EXAMPLE
PS> <Valid Token> | Confirm-TspsApiAuthToken -PresentationServer <TSPS Hostname>

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
        [Parameter(Mandatory=$true,
        ValueFromPipeline)]
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
Retrieves the list of groups for the token's associated user.

.DESCRIPTION
Retrieves the list of groups for the token's associated user.

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response
from the API, or just the 'response' property of the response.

.INPUTS
Get-TspsApiTokenUserGroup will accept a value for the Token
parameter from the pipeline.

.NOTES
Cannot provide a valid example yet. Waiting for input from BMC
to determine what the issue with this route of the API is.
#>
function Get-TspsApiTokenUserGroup
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PresentationServer,
        [Parameter(Mandatory=$true,
        ValueFromPipeline)]
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
        False { return $response.usergroups }
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
unique types of tasks done via the omproviders route of API.

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Method
The HTTP method used to call the specific route of the API.

.PARAMETER OmProvider
The specific sub-route of the omprovider route of the API.

.PARAMETER QueryParameters
The collection of query parameters for the request.
The keys and values are appended to the URI and used
as the query parameters.
Default value is @{}

.PARAMETER RequestParameters
This hashtable is converted to JSON, and used as the body
of the request sent. Meant to contain request parameters
that need to be sent in the body.
Default value is @{}

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.INPUTS
None. You cannot pipe objects to Invoke-TspsApiOmProvider.

.OUTPUTS
TypeName: System.Management.Automation.PSCustomObject

Invoke-TspsApiOmProvider returns an object containing the
response from the API, if the request was valid.

.EXAMPLE
PS> $QueryParameters = @{
        tenantId = <Valid Tenant>
        deviceEntityType = "all"
        parentDeviceId = "-1"
    }

PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        Method = 'GET'
        OmProvider = 'devices'
        QueryParameters = $QueryParameters
        Token = <Valid Auth Token>
        Http = $false
    }

PS> Invoke-TspsApiOmProvider @params

requestTimeStamp  : 2020-01-10T11:09:13
responseTimeStamp : 2020-01-10T11:09:13
statusCode        : 200
statusMsg         : OK
responseMsg       : Success
responseContent   : @{deviceList=System.Object[]}  

.EXAMPLE
PS> $RequestParameters = [hashtable]@{
        tenantId = <Valid Tenant>
        monUniqName = "NTProcessInfo"
        instKeyList = @([hashtable]@{serverId=1; monTypeId=21023; monInstId=5})
    }

PS> $params = [hashtable]@{
        PresentationServer = <TSPS Hostname or Alias>
        Method = 'POST'
        OmProvider = 'configdata'
        RequestParameters = $RequestParameters
        Token = <Valid Auth Token>
        Http = $false
    }

PS> Invoke-TspsApiOmProvider @params
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
Pulls configuration data for monitoring instances.

.DESCRIPTION
Simplifies calling the '.../tsws/10.0/api/omprovider/configdata...'
route of the TrueSight API on the Presentation Server. Requests
configuration data for a monitoring instance using the 'MonInstKey',
provided either as a hashtable, or its three individual components.

For more details on this specific route of the API, see:
https://docs.bmc.com/docs/tsps113/retrieving-the-configuration-data-of-monitor-instances-765456179.html

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Tenant
The TrueSight tenant that the user exists under.
Default value is "*"

.PARAMETER MonUniqName
Unique name for a specific monitor type. Can be retrieved from
a specific monitor instance with Get-TspsApiMonitorInstance,
or via Get-TspsApiMonitorType, which leverages the 'List Monitor
Types' API route.

.PARAMETER InstKeyList
An array of hashtables containing the MonInstKeys which each contain
the ServerId, MonTypeId and MonInstId for monitored instances.
Can also accept just a single MonInstKey.

.PARAMETER ServerId
The ServerId for a monitored instance.

.PARAMETER MonTypeId
The MonTypeId for a monitored instance

.PARAMETER MonInstId
The MonInstId for a monitored instance

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response from
the API, or just the 'responseContent' property of the response.

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
PS> $keylist = [hashtable]@{serverId=1; monTypeId=21013; monInstId=12}

PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        InstKeyList = $keylist
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiMonitorInstanceConfiguration @params

monUniqName monInstName
----------- -----------                                                        
NTDiskSpace Drive = C:\Program Files\BMC Software\TrueSight...

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        MonUniqName = "NTProcessInfo"
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiMonitorInstanceConfiguration @params

monUniqName   monInstName monInstKey                                   attribut
                                                                       eMap    
-----------   ----------- ----------                                   --------
NTProcessInfo mcell       @{serverId=1; monTypeId=21023; monInstId=10} @{MAT...
NTProcessInfo httpd       @{serverId=1; monTypeId=21023; monInstId=2}  @{MAT...
NTProcessInfo jserver     @{serverId=1; monTypeId=21023; monInstId=3}  @{MAT...
NTProcessInfo pronet_cntl @{serverId=1; monTypeId=21023; monInstId=4}  @{MAT...
NTProcessInfo rate        @{serverId=1; monTypeId=21023; monInstId=5}  @{MAT...
NTProcessInfo tunnelproxy @{serverId=1; monTypeId=21023; monInstId=6}  @{MAT...
NTProcessInfo services    @{serverId=1; monTypeId=21023; monInstId=7}  @{MAT...
NTProcessInfo PnAgent     @{serverId=1; monTypeId=21023; monInstId=8}  @{MAT...
NTProcessInfo PwTray      @{serverId=1; monTypeId=21023; monInstId=9}  @{MAT...

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        ServerId = 1
        MonTypeId = 21013
        MonInstId = 12
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiMonitorInstanceConfiguration @params

monUniqName monInstName
----------- -----------                                                        
NTDiskSpace Drive = C:\Program Files\BMC Software\TrueSight...

.EXAMPLE
PS> $keylistArr = @(
    @{serverId=1; monTypeId=21023; monInstId=5},
    @{serverId=1; monTypeId=21023; monInstId=3}
)

PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        InstKeyList = $keylistArr
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiMonitorInstanceConfiguration @params

monUniqName   monInstName monInstKey                                  attribute
                                                                      Map      
-----------   ----------- ----------                                  ---------
NTProcessInfo rate        @{serverId=1; monTypeId=21023; monInstId=5} @{MATC...
NTProcessInfo jserver     @{serverId=1; monTypeId=21023; monInstId=3} @{MATC...
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
        [hashtable[]]$InstKeyList=@(@{}),
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
    
    $RequestParameters = [hashtable]@{
        tenantId = $Tenant
        monUniqName = ""
        instKeyList = @(@{})
    }

    Switch($PSCmdlet.ParameterSetName)
    {
        'KeyListItems' {
            $InstKeyList= [hashtable]@{
                serverId = $ServerId
                monTypeId = $MonTypeId
                monInstId = $MonInstId
            }

            $RequestParameters.'instKeyList' = @($InstKeyList)
        }
        'KeyList' { $RequestParameters.'instKeyList' = @($InstKeyList) }
        'UniqName' { $RequestParameters.'monUniqName' = $MonUniqName }
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
### use the DeviceId, the MonUniqName, or the combination of both. But
### passing in the ServerId, MonTypeId, and MonInstId does not work as it
### should. Supposedly you can make it work if you use the server name
### BMC has noted this as a defect and will address it in
### a future release.
### Current release at the time of this writing is 11.3.02.

<#
.SYNOPSIS
Pulls a list of monitored instances.

.DESCRIPTION
Simplifies calling the '.../tsws/10.0/api/omprovider/instances' route of
the TSOM API. Pulls a list of monitored instances using the MonInstKey,
provided either as a hashtable, or its three individual components.

For more details on this specific route of the API, see:
https://docs.bmc.com/docs/tsps113/retrieving-the-list-of-monitor-instances-765456181.html

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Tenant
The TrueSight tenant that the user exists under.
Default value is "*"

.PARAMETER DeviceId
The device ID the target monitored instance belongs to.

.PARAMETER MonUniqName
Unique name for a specific monitor type. Can be retrieved from
a specific monitor instance with Get-TspsApiMonitorInstance,
or via Get-TspsApiMonitorType, which leverages the 'List Monitor
Types' API route.

.PARAMETER InstKey
A hashtable containing a MonInstKey, which contains the ServerId,
MonTypeId, and MonInstId for a single monitored instance.
Currently the use of this parameter is broken, due to a defect
with the TSOM API. BMC is working on correcting this.

.PARAMETER ServerId
The ServerId for a monitored instance.

.PARAMETER MonTypeId
The MonTypeId for a monitored instance

.PARAMETER MonInstId
The MonInstId for a monitored instance

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when calling
the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response
from the API, or just the 'responseContent.instanceList' property
of the response.

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        DeviceId = 1
        MonUniqName = 'NTProcessInfo'
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiMonitorInstance @params

deviceId          : 1
monUniqName       : NTProcessInfo
monInstName       : tunnelproxy
isMarkedForDelete : False
monInstKey        : @{serverId=1; monTypeId=21023; monInstId=6}

deviceId          : 1
monUniqName       : NTProcessInfo
monInstName       : rate
isMarkedForDelete : False
monInstKey        : @{serverId=1; monTypeId=21023; monInstId=5}
...

.NOTES
Currently the use of the InstKey parameter is broken, due to a
defect with the TSOM API. BMC is working on correcting this.
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
        [Parameter(ParameterSetName='Key')]
        [hashtable]$InstKey=@{},
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyItems')]
        [string]$ServerId="",
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyItems')]
        [string]$MonTypeId="",
        [Parameter(Mandatory=$true,
        ParameterSetName='KeyItems')]
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
        'Key' {
            $QueryParameters.Add('serverId', $InstKey.ServerId)
            $QueryParameters.Add('monTypeId', $InstKey.MonTypeId)
            $QueryParameters.Add('monInstId', $InstKey.MonInstId)
        }
        'KeyItems' {
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
Pulls the list of monitor types.

.DESCRIPTION
Pulls a list of all available monitor types, including their name,
monUniqName, and monitorCategory. Tenant is specified as *, even
though * is the default, in order to demonstrate it can be set.

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Tenant
The TrueSight tenant that the user exists under.
Default value is "*"

.PARAMETER MonitorCategory
Filters returned list by category.
Default value is "ALL"

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when calling
the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response
from the API, or just the '.responseContent.monitorTypeList'
property of the response.

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiMonitorType @params

name                          monUniqueName         monitorCategory
----                          -------------         ---------------
OVDC-Status                   OVDC_STATUS           instance       
AR Form                       _PATROL__ARS_FORM     instance       
Storage                       STORAGE               instance       
LINUX-UNIX shell script       _PATROL__TRO_SCRIPT   instance      
...
#>
function Get-TspsApiMonitorType
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
Pulls performance data about monitor instances within a
specific time window. (1 hour minimum, 72 hour max.)

.DESCRIPTION
Simplifies the calling of the '.../tsws/10.0/api/omprovider/perfdata'
route of the TSOM API. Pulls performance data about monitor instances
within a specific time window. (1 hour minimum, 72 hour max.)

For more details on this specific route of the API, see:
https://docs.bmc.com/docs/tsps113/retrieving-the-performance-data-of-monitor-instances-765456184.html

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Tenant
The TrueSight tenant that the user exists under.
Default value is "*"

.PARAMETER MonUniqName
Unique name for a specific monitor type. Can be retrieved from
a specific monitor instance with Get-TspsApiMonitorInstance,
or via Get-TspsApiMonitorType, which leverages the 'List Monitor
Types' API route.

.PARAMETER InstKeyList
An array of hashtables containing the MonInstKeys which each contain
the ServerId, MonTypeId and MonInstId for monitored instances.
Can also accept just a single MonInstKey.

.PARAMETER ServerId
The ServerId for a monitored instance.

.PARAMETER MonTypeId
The MonTypeId for a monitored instance

.PARAMETER MonInstId
The MonInstId for a monitored instance

.PARAMETER StartTime
A datetime object for start of the queried time range.

.PARAMETER EndTime
A datetime object for end of the queried time range.

.PARAMETER Type
The type of performance data.
Currently only "rate" is supported by the API.

.PARAMETER Computation
The computation method of the performance data.
Currently only "avg" is supported by the API.

.PARAMETER AttribUniqNameList
One or more attributes of the same monitor type

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response from
the API, or just the 'responseContent.instancePerfDataList' property
of the response.

.EXAMPLE
PS> $instKeyList = @(
    @{serverId=1; monTypeId=21023; monInstId=5},
    @{serverId=1; monTypeId=21023; monInstId=3}
)

PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        InstKeyList = $instKeyList
        StartTime = (Get-Date).AddHours(-72)
        EndTime = (Get-Date)
        AttribUniqNameList = "PROC_CPU"
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiMonitorInstancePerformanceData @params

monInstName instanceKey                      attribPerfDataList                            
----------- -----------                      ------------------                            
rate        @{serverId=1; monTypeId=21023... {@{attribUniqName=PROC_CPU; attribDisplayNa...
jserver     @{serverId=1; monTypeId=21023... {@{attribUniqName=PROC_CPU; attribDisplayNa...

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        MonUniqName = 'NTProcessInfo'
        StartTime = (Get-Date).AddHours(-72)
        EndTime = (Get-Date)
        AttribUniqNameList = "PROC_CPU"
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiMonitorInstancePerformanceData @params

monInstName instanceKey                       attribPerfDataList                           
----------- -----------                       ------------------                           
services    @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...
PwTray      @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...
tunnelproxy @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...
PnAgent     @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...
jserver     @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...
pronet_cntl @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...
httpd       @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...
rate        @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...
mcell       @{serverId=1; monTypeId=21023...  {@{attribUniqName=PROC_CPU; attribDisplayN...

.NOTES
The valid total time range is supposed to be between 60 minutes
and 72 hours. However, the valid floor (StartTime) does seem to
vary depending on the run cycle for the monitor being queried.
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
        [hashtable[]]$InstKeyList=@(@{}),
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
        [ValidateSet("rate")]
        [string]$Type="rate",
        [ValidateSet("avg")]
        [string]$Computation="avg",
        [ValidateNotNullOrEmpty()]
        [string[]]$AttribUniqNameList,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [switch]$Http,
        [switch]$FullResponse
    )

    $totalTimeRange = New-TimeSpan -Start $StartTime -End $EndTime

    if ($totalTimeRange.TotalSeconds -gt 259200 `
        -or $totalTimeRange.TotalSeconds -lt 3600)
    {
        Write-Error ("Invalid time range. Must be between 60 minutes " + `
            " and 72 hours. See NOTES in 'Get-Help Get-TspsApiMonitor" + `
            "InstancePerformanceData -Full' for more details.")
        return
    }

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
        monUniqName = ""
        instKeyList = @([hashtable]@{})
        startTime = $unixStartTime
        endTime = $unixEndTime
        type = $Type
        computation = $Computation
        attribUniqNameList = $AttribUniqNameList
    }

    Switch($PSCmdlet.ParameterSetName)
    {
        'KeyListItems' {
            $InstKeyList= [hashtable]@{
                serverId = $ServerId
                monTypeId = $MonTypeId
                monInstId = $MonInstId
            }

            $RequestParameters.'instKeyList' = @($InstKeyList)
        }
        'KeyList' { $RequestParameters.'instKeyList' = @($InstKeyList) }
        'UniqName' { $RequestParameters.'monUniqName' = $MonUniqName }
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
        False { return $response.responseContent.instancePerfDataList }
    }
}


<#
.SYNOPSIS
Pulls the list of devices.

.DESCRIPTION
Simplifies the calling of the '.../tsws/10.0/api/omprovider/devices'
route of the TSOM API. Pulls the list of devices accessible to the
user specified by the authToken supplied with the Token parameter.

For more details on this specific route of the API, see:
https://docs.bmc.com/docs/tsps113/retrieving-the-list-of-devices-765456180.html

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Tenant
The TrueSight tenant that the user exists under.
Default value is "*"

.PARAMETER DeviceEntityType
Entry fom the list of valid device entity types. See:
https://docs.bmc.com/docs/tsps113/retrieving-the-list-of-devices-765456180.html#Retrievingthelistofdevices-Validdeviceentitytypes

To get devices of all entity types, set the parameter to "all".
Default value is "all"

.PARAMETER ParentDeviceId
Device ID of the parent device.
    -1 ignores the parent device and displays all devices
    0 displays all devices that do not have a parent device
Default value is "-1"

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response from
the API, or just the 'responseContent.deviceList' property
of the response.

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiDevices @params

deviceId          : 1
dnsName           : hostname1.domain.com
dispName          : hostname1.domain.com
ipAddress         : 1.1.1.1
deviceEntityType  : Default
deviceType        : 0
parentDeviceId    : 0
isMarkedForDelete : False
tokenList         : {@{tokenId=; serverId=1; hostId=1}}

deviceId          : 28
dnsName           : hostname28.domain.com
dispName          : hostname28.domain.com
ipAddress         : 111.111.111.111
deviceEntityType  : Default
deviceType        : 0
parentDeviceId    : 0
isMarkedForDelete : False
tokenList         : {@{tokenId=; serverId=1; hostId=54}}
...
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
Pulls the list of tenants from the TrueSight Presentation Server.

.DESCRIPTION
Simplifies the calling of the '.../tsws/10.0/api/omprovider/tenants'
route of the TSOM API. Pulls the list of tenants from the TrueSight
Presentation Server. The permissions granted for the administrator
who makes the request determines which tenants appear in the JSON
response. For example, an administrator for the Acme account could
not see the tenants in the Calbro account.

For more details on this specific route of the API, see:
https://docs.bmc.com/docs/tsps113/retrieving-the-list-of-tenants-765456183.html

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response from
the API, or just the 'responseContent.tenantList' property
of the response.

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiTenants @params

tenantId
--------
*       
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
Simplifies calling the '.../tsws/10.0/api/unifiedadmin/...'
routes of the TrueSight API on the Presentation Server.

.DESCRIPTION
General function meant to simplify calling the '.../tsws/10.0/api/unifiedadmin/...'
routes of the TrueSight API on the Presentation Server. Can be used on its
own, but is mainly meant to be used for building more specific cmdlets for
unique types of tasks done via the unifiedadmin route of API.

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER Method
The HTTP method used to call the specific route of the API.

.PARAMETER AdminRoute
The specific sub-route of the unifiedadmin route of the API.

.PARAMETER QueryParameters
The collection of query parameters for the request.
The keys and values are appended to the URI and used
as the query parameters.
Default value is @{}

.PARAMETER RequestParameters
This hashtable is converted to JSON, and used as the body
of the request sent. Meant to contain request parameters
that need to be sent in the body.
Default value is @{}

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.EXAMPLE
PS> $QueryParameters = [hashtable]@{
    responseType = 'basic'
}

PS> $RequestParameters = [hashtable]@{
    filterCriteria = [hashtable]@{
        policyEnabledStatus = "ANY"
        policySharedStatus = "ANY"
        monitoringSolutionName = ""
        monitoringSolutionVersion = ""
        monitoringProfile = ""
        monitoringType = ""
        tenantId = "*"
    }
    stringToSearch = "Test"
    fieldToSearch = "name"
    type = "monitoringPolicy"
}

PS> $params = [hashtable]@{
    PresentationServer = <TSPS Hostname or Alias>
    Method = 'POST'
    AdminRoute = 'Policy/list'
    QueryParameters = $QueryParameters
    RequestParameters = $RequestParameters
    Token = <Valid Auth Token>
    Http = $false
}

PS> Invoke-TspsApiUnifiedAdmin @params

resourceId       : 5976e4a4-c906-4f15-968b-ef222dffc15b
resourceName     : 999_ApiManagementTestPolicy
statusCode       : 200
statusMsg        : OK
monitoringPolicy : @{id=5976e4a4-c906-4f15-968b-ef222dffc15b; name=999_ApiManagementTestPolicy; 
                   type=monitoring; description=Blah blah blah, this is a test 2.; tenant=; 
                   precedence=999; agentSelectionCriteria=agentOS CONTAINS "Windows" ; 
                   associatedUserGroup=Administrators; owner=jsnover; creationTime=1577487083395; 
                   enabled=False; shared=False}
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


#!# TODO: Build a function that leverages the '.../tsws/10.0/api/unifiedadmin/Solutions/list'
#.# route of the API. The need for this is called out in the description for the
#.# monitoringSolutionName parameter in the help information for Get-TspsApiAllPolicies below.

<#
.SYNOPSIS
Pulls information about all the policies

.DESCRIPTION
Simplifies the calling of the '.../tsws/10.0/api/unifiedadmin/Policy/list?...'
route of the TSOM API. Pulls information about all the policies.

For more details on this specific route of the API, see:
https://docs.bmc.com/docs/TSInfrastructure/113/listing-details-for-all-the-policies-774798606.html

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER TenantId
Lists all the policies based on the tenant name included in the policy.
Default value is "*"

.PARAMETER PolicyEnabledStatus
Lists all the policies based on the policy status.
Can be one of the following:
    ENABLED: Lists all the policies that are enabled.
    DISABLED: Lists all the policies that are disabled.
    ANY: Lists all the policies irrespective of whether they are enabled or
         disabled.
Default value is "ANY"

.PARAMETER PolicySharedStatus
Lists all the policies based on whether those policies are shared with a user
group.
Can be one of the following:
    SHARED: Lists all the policies that are shared with a user group.
    NON_SHARED: Lists all the policies that are not shared with a user group.
    ANY: Lists all the policies irrespective of whether they are shared with
         a user group or not.
Default value is "ANY"

.PARAMETER MonitoringSolutionName
Lists all the policies based on the monitoring solution name specified.

To understand the valid values for the monitoring solution name, you need to
run the function/API that lists all the solution names.
(A function for this is not built out, as of 2020/01/16)

For more information, see:
https://docs.bmc.com/docs/TSInfrastructure/113/listing-monitoring-solution-details-for-policies-809537412.html

.PARAMETER MonitoringSolutionVersion
Lists all the policies based on the monitoring solution version.

Note: If you specify the monitoring solution name, then this value must correspond
to the monitoring solution name specified.

.PARAMETER MonitoringProfile
Lists all the policies based on the monitor profile.

Note: If you specify the monitoring solution name, then this value must correspond
to the monitoring solution name specified.

.PARAMETER MonitoringType
Lists all the policies based on the monitor type.

Note: If you specify the monitoring solution name, then this value must correspond
to the monitoring solution name specified.

.PARAMETER StringToSearch
Lists policies based on a string of characters included in a list of selected fields in the policies.

The FieldToSearch parameter determines the fields in which the string is searched.
Default value is "". Will pull all policies with this value.

.PARAMETER FieldToSearch
Lists policies based on whether the string specified in the stringToSearch parameter
is present in the field names specified.
This value can be a comma-separated list of field names.

Valid values:
    name: Refers to the Name field.
    description: Refers to the Description field.
    agentSelectionCriteria: Refers to the Agent Selection Criteria field.
    tenant: Refers to the Tenant field.
    owner: Refers to the Owner field.
           (Column name on the Infrastructure Policies page)
    userGroups: Refers to the User Group field.
                (Column name on the Infrastructure Policies page)

.PARAMETER PolicyType
Lists policies based on the policy type.
Can be one of the following:
    BLACKOUTPOLICY: Refers to blackout policies.
    MONITORINGPOLICY: Refers to monitoring policies.
    STAGINGPOLICY: Refers to staging policies.
Default value is "MONITORINGPOLICY"

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response from
the API, or just the 'response.policyList' property
of the response.

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiAllPolicies @params

resourceId       : 5976e4a4-c906-4f15-968b-ef222dffc15b
resourceName     : 999_ApiManagementTestPolicy
statusCode       : 200
statusMsg        : OK
monitoringPolicy : @{id=5976e4a4-c906-4f15-968b-ef222dffc15b; name=999_ApiManagementTestPolicy; 
                   type=monitoring; description=Blah blah blah, this is a test 2.; tenant=; 
                   precedence=999; agentSelectionCriteria=agentOS CONTAINS "Windows" ; 
                   associatedUserGroup=Administrators; owner=jsnover; creationTime=1577487083395; 
                   enabled=False; shared=False}

resourceId       : 95a16c04-48eb-43f4-b0de-beb749f914b0
resourceName     : 510_Windows-Common
statusCode       : 200
statusMsg        : OK
monitoringPolicy : @{id=95a16c04-48eb-43f4-b0de-beb749f914b0; name=510_Windows-Common; 
                   type=monitoring; description=Common OS monitors for Windows operating systems; 
                   tenant=; precedence=510; agentSelectionCriteria=agentOS CONTAINS "Windows" ; 
                   associatedUserGroup=Administrators; owner=jsnover; creationTime=1575925212590; 
                   enabled=False; shared=False}
...

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        StringToSearch = "Test"
        FieldToSearch = "name,description"
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiAllPolicies @params

resourceId       : 5976e4a4-c906-4f15-968b-ef222dffc15b
resourceName     : 999_ApiManagementTestPolicy
statusCode       : 200
statusMsg        : OK
monitoringPolicy : @{id=5976e4a4-c906-4f15-968b-ef222dffc15b; name=999_ApiManagementTestPolicy; 
                   type=monitoring; description=Blah blah blah, this is a test 2.; tenant=; 
                   precedence=999; agentSelectionCriteria=agentOS CONTAINS "Windows" ; 
                   associatedUserGroup=Administrators; owner=jsnover; creationTime=1577487083395; 
                   enabled=False; shared=False}

.NOTES
This function still needs to be expanded to take advantage of the withCount
and forSearch header parameters. Currently these are not specified, and thus
use the defaults specified by the API itself.
#>
function Get-TspsApiAllPolicies
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PresentationServer,
        [string]$TenantId = "*",
        [ValidateSet("ENABLED","DISABLED","ANY")]
        [string]$PolicyEnabledStatus = "ANY",
        [ValidateSet("SHARED","NON_SHARED","ANY")]
        [string]$PolicySharedStatus = "ANY",
        [string]$MonitoringSolutionName = "",
        [string]$MonitoringSolutionVersion = "",
        [string]$MonitoringProfile = "",
        [string]$MonitoringType = "",
        [string]$StringToSearch = "",
        [ValidateSet("name","description","agentSelectionCriteria",
        "tenant","owner","userGroups")]
        [string[]]$FieldToSearch = @("name"),
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
        fieldToSearch = (@($FieldToSearch) -join ',')
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
Pulls configuration data for a specific policy.

.DESCRIPTION
Simplifies the calling of the '.../tsws/10.0/api/unifiedadmin/Policy/'.
Pulls configuration data for a specific policy.

For more details on this specific route of the API, see:
https://docs.bmc.com/docs/TSInfrastructure/113/listing-details-for-a-specific-policy-774798607.html

.PARAMETER PresentationServer
The hostname or alias for the TrueSight Presentation Server.

.PARAMETER PolicyId
Identifier of the policy. You can provide multiple identifiers, separated by commas.
The supported identifiers are as follows:
    name of the policy
    ID of the policy

.PARAMETER PolicyIdType
Type of the identifier that you have provided in the request.
The supported values are as follows:
    "name"
    "id"

Default value is "name"

.PARAMETER Token
A valid authorization token returned from Request-TspsApiAuthToken.

.PARAMETER Http
A switch that specifies to use HTTP instead of HTTPS when
calling the TrueSight API

.PARAMETER FullResponse
A switch that specifies whether to return the entire response from
the API, or just the 'response.monitoringPolicy' property
of the response.

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        PolicyIdType = 'id'
        PolicyId = '5976e4a4-c906-4f15-968b-ef222dffc15b'
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiPolicyDetails @params

id                     : 5976e4a4-c906-4f15-968b-ef222dffc15b
name                   : 999_ApiManagementTestPolicy
type                   : monitoring
description            : Blah blah blah, this is a test 2.
tenant                 : @{name=*; id=*}
precedence             : 999
agentSelectionCriteria : agentOS CONTAINS "Windows" 
associatedUserGroup    : Administrators
owner                  : jsnover
creationTime           : 1577487083395
agentConfiguration     : @{agentDefaultAccountCredentials=DOMAIN\_Dev_Patrol_Agent_B/fakePa
                         ssword; tag=; restartAgent=False; eventConfiguration=; 
                         pollConfiguration=}
monitorConfiguration   : @{configurations=System.Object[]}
rulesetConfiguration   : @{rulesets=System.Object[]}
enabled                : False
shared                 : False

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        PolicyIdType = 'name'
        PolicyId = '999_ApiManagementTestPolicy'
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiPolicyDetails @params

id                     : 5976e4a4-c906-4f15-968b-ef222dffc15b
name                   : 999_ApiManagementTestPolicy
type                   : monitoring
description            : Blah blah blah, this is a test 2.
tenant                 : @{name=*; id=*}
precedence             : 999
agentSelectionCriteria : agentOS CONTAINS "Windows" 
associatedUserGroup    : Administrators
owner                  : jsnover
creationTime           : 1577487083395
agentConfiguration     : @{agentDefaultAccountCredentials=DOMAIN\_Dev_Patrol_Agent_B/fakePa
                         ssword; tag=; restartAgent=False; eventConfiguration=; 
                         pollConfiguration=}
monitorConfiguration   : @{configurations=System.Object[]}
rulesetConfiguration   : @{rulesets=System.Object[]}
enabled                : False
shared                 : False

.EXAMPLE
PS> $params = @{
        PresentationServer = <TSPS Hostname or Alias>
        PolicyIdType = 'name'
        PolicyId = '999_ApiManagementTestPolicy,510_Windows-Common'
        Token = <Valid Auth Token>
    }

PS> Get-TspsApiPolicyDetails @params

id                     : 5976e4a4-c906-4f15-968b-ef222dffc15b
name                   : 999_ApiManagementTestPolicy
type                   : monitoring
description            : Blah blah blah, this is a test 2.
tenant                 : @{name=*; id=*}
precedence             : 999
agentSelectionCriteria : agentOS CONTAINS "Windows" 
associatedUserGroup    : Administrators
owner                  : jsnover
creationTime           : 1577487083395
agentConfiguration     : @{agentDefaultAccountCredentials=DOMAIN\_Dev_Patrol_Agent_B/fakePa
                         ssword; tag=; restartAgent=False; eventConfiguration=; 
                         pollConfiguration=}
monitorConfiguration   : @{configurations=System.Object[]}
rulesetConfiguration   : @{rulesets=System.Object[]}
enabled                : False
shared                 : False

id                     : 95a16c04-48eb-43f4-b0de-beb749f914b0
name                   : 510_Windows-Common
type                   : monitoring
description            : Common OS monitors for Windows operating systems
tenant                 : @{name=*; id=*}
precedence             : 510
agentSelectionCriteria : agentOS CONTAINS "Windows" 
associatedUserGroup    : Administrators
owner                  : jsnover
creationTime           : 1575925212590
agentConfiguration     : @{agentDefaultAccountCredentials=DOMAIN\_Patrol_Agent/fakePa
                         ssword; tag=; restartAgent=True; eventConfiguration=; 
                         pollConfiguration=}
monitorConfiguration   : @{configurations=System.Object[]}
rulesetConfiguration   : @{rulesets=System.Object[]}
enabled                : False
shared                 : False
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
        [string[]]$PolicyId,
        [ValidateSet("name","id")]
        [string]$PolicyIdType="name",
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
        AdminRoute = "Policy/$(@($PolicyId) -join ',')/list"
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


