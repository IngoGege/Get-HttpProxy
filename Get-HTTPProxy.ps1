<#

.SYNOPSIS

Created by: ingo.gegenwarth[at]sap.com
Version:	42 ("What do you get if you multiply six by nine?")
Changed:	27.10.2014

.DESCRIPTION

The Get-HttpProxy.ps1 script is enumerating all Exchange 2013 CAS servers in the current or given AD site and parse all HttpProxy log files within the given time range.

As output you will get several CSV files which could be used for analysis.

.PARAMETER UserID

filter for a specific user. Cannot be combined with UserIDs

.PARAMETER UserIDs

filter for multiple users. Cannot be combined with UserID

.PARAMETER StartDate

this is used for filtering the logfiles to be parsed. The format must be yyMMdd. If omitted current date will be used.

.PARAMETER EndDate

this is used for filtering the logfiles to be parsed. The format must be yyMMdd. If omitted current date will be used.

.PARAMETER Logparser

this is used for the path to LogParser.exe

.PARAMETER ADSite

here you can define in which ADSite is searched for Exchange server. If omitted current AD site will be used.

.PARAMETER Outpath

where the output will be found. If omitted $env:temp will be used.

.PARAMETER Protocols

which protocol logs will be parsed. By default logs for all protocols will be parsed

.PARAMETER ErrorReport

create a report of errors

.PARAMETER Localpath

if you have log files in a local folder. There is no filtering by date! All files will be analyzed.

.EXAMPLE 

To parse all logs for a sepcific user
.\Get-HttpProxy.ps1 -UserID daisy -Outpath c:\temp -StartDate 141021 -EndDate 141023

To parse all logs for a sepcific user for errors
.\Get-HttpProxy.ps1 -UserID daisy -Outpath c:\temp -StartDate 141021 -EndDate 141023 -ErrorReport

To parse all logs for multiple users
.\Get-HttpProxy.ps1 -UserIDs daisy,goofy -Outpath c:\temp -StartDate 141021 -EndDate 141023 -ErrorReport

To generate a report for all errors
.\Get-HttpProxy.ps1 -ErrorReport

.NOTES

You need to run this script in the same AD site where the servers are.

#>

[CmdletBinding(DefaultParameterSetName = "ALL")]

param(

	[parameter( ParameterSetName="USER")]
	[parameter(Mandatory=$false, Position=0)]
	[string]$UserID,

	[parameter( ParameterSetName="USERS")]
	[parameter(Mandatory=$false, Position=1)]
	[array]$UserIDs,
		
	[parameter( Mandatory=$false, Position=2)]
	[int]$StartDate="$((get-date).ToString("yyMMdd"))",
	
	[parameter( Mandatory=$false, Position=3)]
	[int]$EndDate="$((get-date).ToString("yyMMdd"))",

	[parameter( Mandatory=$false, Position=4)]
	[ValidateScript({If (Test-Path $_ -PathType leaf) {$True} Else {Throw "Logparser could not be found!"}})]
	[string]$Logparser="C:\Program Files (x86)\Log Parser 2.2\LogParser.exe",

	[parameter( Mandatory=$false, Position=5)]
	[string]$ADSite="$(([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name)",
	
	[parameter( Mandatory=$false, Position=6)]
	[ValidateScript({If (Test-Path $_ -PathType container) {$True} Else {Throw "$_ is not a valid path!"}})]
	[string]$Outpath = $env:temp,

	[parameter( Mandatory=$false, Position=7)]
	[array]$Protocols=@("Autodiscover","Eas","Ecp","Ews","Mapi","Oab","Owa","OwaCalendar","Powershell","RpcHttp"),

	[parameter( ParameterSetName="ALL")]
	[parameter( ParameterSetName="USER")]
	[parameter( ParameterSetName="USERS")]
	[parameter( Mandatory=$false, Position=8)]
	[switch]$ErrorReport,
	
	[parameter( Mandatory=$false, Position=9)]
	[ValidateScript({If (Test-Path $_ -PathType container) {$True} Else {Throw "$_ is not a valid path!"}})]
	[string]$Localpath
)

# check for elevated PS
If (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

# function to get the Exchangeserver from AD site
Function GetExchServer {
	#http://technet.microsoft.com/en-us/library/bb123496(v=exchg.80).aspx on the bottom there is a list of values
	param([array]$Roles,[string]$ADSite)
	Process {
		$valid = @("2","4","16","20","32","36","38","54","64","16385","16439")
		ForEach ($Role in $Roles){
			If (!($valid -contains $Role)) {
				Write-Output -fore red "Please use the following numbers: MBX=2,CAS=4,UM=16,HT=32,Edge=64 multirole servers:CAS/HT=36,CAS/MBX/HT=38,CAS/UM=20,E2k13 MBX=54,E2K13 CAS=16385,E2k13 CAS/MBX=16439"
				Break
			}
		}
		Function GetADSite {
			param([string]$Name)
			If (!($Name)) {
				[string]$Name = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name
			}
			$FilterADSite = "(&(objectclass=site)(Name=$Name))"
			$RootADSite= ([ADSI]'LDAP://RootDse').configurationNamingContext
			$SearcherADSite = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$RootADSite")
			$SearcherADSite.Filter = "$FilterADSite"
			$SearcherADSite.pagesize = 1000
			$ResultsADSite = $SearcherADSite.FindOne()
			$ResultsADSite
		}
		$Filter = "(&(objectclass=msExchExchangeServer)(msExchServerSite=$((GetADSite -Name $ADSite).properties.distinguishedname))(|"
		ForEach ($Role in $Roles){
			$Filter += "(msexchcurrentserverroles=$Role)"
		}
		$Filter += "))"
		$Root= ([ADSI]'LDAP://RootDse').configurationNamingContext
		$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Root")
		$Searcher.Filter = "$Filter"
		$Searcher.pagesize = 1000
		$Results = $Searcher.FindAll()
		$Results
	}
}

# function to build string for Logparser if multiple userIDs or deviceIDs given
function buildstring {
	param(
	[array]$strings
	)
	ForEach ($string in $strings) {
		$temp += "'" + $string + "';"
	}
	$temp.TrimEnd(";").ToLower()
}

# function to build string for stamp if multiple users given
function buildstamp {
	param(
	[array]$strings
	)
	ForEach ($string in $strings) {
		$temp += $string + "_"
	}
	$temp.ToLower()
}

If (!($Localpath)) {
	# get CAS servers
	[array]$Servers = GetExchServer -Role 16385,16439 -ADSite $ADSite
	If ($Servers) {
		Write-Output "Found the following Exchange 2013 servers:" $($Servers | %{$_.Properties.name})
		ForEach ($Server in $Servers) {
		[array]$TempPath += "\\" + $Server.Properties.name + "\" + ($Server.Properties.msexchinstallpath -as [string]).Replace(":","$") + "\Logging\HttpProxy"
		}
	}
	Else {
		Write-Output "No server found!"
		Break
	}
}	
Else {
	Write-Output "Using the following path:" $Localpath
	[array]$TempPath = $Localpath
	$ADSite = "localfiles"
}
$TempPath
# set variables
$Path = $null
[array]$LogFiles = $null
[array]$TempLogs = $null
[string]$LogsFrom = $null
$outputfiles = $null

# validate all path
Foreach ($Path in $TempPath) { 
	If (Test-Path -LiteralPath $Path) {
	[array]$ValidPath += $Path
	}
}
# get all items in final path
If ($ValidPath) {
	ForEach ($Item in $ValidPath) {
		If (Test-Path -LiteralPath $Item){
		$LogFiles += Get-ChildItem -Recurse -LiteralPath $Item -Filter "*.log"
		}
	}
}
Else {
	Write-Output "No logs found!"
	Break
}

If (!($Localpath)) {
	$LogFiles = $LogFiles | ?{$_.name.substring(($_.name.length -14),6) -ge $startdate -and $_.name.substring(($_.name.length -14),6) -le $enddate}
	ForEach ($Protocol in $Protocols) {
		Write-Output "Found the following files for protocol:$Protocol" 
		$LogFiles | ?{$_.FullName -like "*\$Protocol\*"} | select FullName
		$LogFiles | ?{$_.FullName -like "*\$Protocol\*"} | %{$LogsFrom += "'" + $_.FullName + "',"}
	}
}
Else {
	$LogFiles | %{$LogsFrom += "'" + $_.FullName + "',"}
}

$LogsFrom = $LogsFrom.TrimEnd(",")

# check for header from logs
Write-Host "Get headers from file" ($logsfrom.Split(",") | select -First 1 ).Replace("'","")
[string]$fields = gc ($logsfrom.Split(",") | select -First 1 ).Replace("'","") -TotalCount 1 #5 | ?{$_ -like "#Fields*"}
$fields = $fields.Replace("DateTime","Day,Time")

If ($userid -OR $userids) {
	# set stamps
	If ($UserID){
		If ($ErrorReport){
			$stamp = $UserID + "_ErrorReport_" + $ADSite + "_" + $(Get-Date -Format HH-mm-ss)
		}
		Else {
			$stamp = $UserID + "_" + $ADSite + "_" + $(Get-Date -Format HH-mm-ss)
		}
	}
	ElseIf ($UserIDs){
		If ($ErrorReport){
			$stamp = "multiple_users_ErrorReport_" + $ADSite + "_" + $(Get-Date -Format HH-mm-ss)
		}
		Else {
			$string = buildstamp -strings $UserIDs
			If ($string.Length -gt 30) {
				$stamp = "multiple_users_" + $ADSite + "_" + $(Get-Date -Format HH-mm-ss)
			}
			Else {
				$stamp = $string + $ADSite + "_" + $(Get-Date -Format HH-mm-ss)
			}
		}
	}
}	
Else {
	If ($ErrorReport){
		$stamp = "ErrorReport_" + $ADSite + "_" + $(Get-Date -Format HH-mm-ss)
	}
	Else {
		$stamp = $ADSite + "_" + $(Get-Date -Format HH-mm-ss)
	}
}

$query_HttpProxy = @"
		Select $fields

		USING
		TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: DateTime],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
		TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: DateTime],0,'T')),0,'.'), 'hh:mm:ss') AS Time,
		TO_LOWERCASE(EXTRACT_SUFFIX(AuthenticatedUser,0,'\\')) AS AuthenticatedUser2

		INTO	$outpath\*_HttpProxy_$stamp.csv
		From
"@
$query_HttpProxy += $Logsfrom 

If ($ErrorReport){
	If ($UserID){
		Write-Host -fore yellow "Query for user $UserID and ErrorReport!"
		$query_HttpProxy += @"
		WHERE (AuthenticatedUser LIKE '%$UserID%' AND ErrorCode IS NOT NULL)
"@
	}
	ElseIf ($UserIDs){
		$string = buildstring -strings $UserIDs
		Write-Host -fore yellow "Query for users $string and ErrorReport!"
		$query_HttpProxy += @"
		WHERE AuthenticatedUser2 IN ($string) AND ErrorCode IS NOT NULL
"@
	}
	Else {
		Write-Host -fore yellow "Query for ErrorReport!"
		$query_HttpProxy += @"
		WHERE (ErrorCode IS NOT NULL AND Time IS NOT NULL)
"@
	
	}
}
Else {
	If ($UserID){
		Write-Host -fore yellow "Query for user $UserID!"
		$query_HttpProxy += @"
		WHERE AuthenticatedUser LIKE '%$UserID%'
"@
	}

	If ($UserIDs){
		$string = buildstring -strings $UserIDs
		Write-Host -fore yellow "Query for users $string!"
		$query_HttpProxy += @"
		WHERE AuthenticatedUser2 IN ($string)
"@
	}
}

$query_HttpProxy += @"
		GROUP BY $fields
"@
# workaround for limitation of path length, therefore we put the query into a file
sc -value $query_HttpProxy $Outpath\query.txt -force

Write-Output "Start query!"
& $Logparser file:$Outpath\query.txt -i:csv -nSkipLines:5 -e:100 -dtLines:0
Write-Output "Query done!"
# clean query file
Get-ChildItem -LiteralPath $Outpath -Filter query.txt | Remove-Item -Confirm:$false | Out-Null