<#
.SYNOPSIS
    The script remove defined identities from the ACL of AD Objects.
    
.DESCRIPTION
    The script can run in recursive mode or non recursive mode.
    None recursive mode will only process the spcified OU and remove the spcified identies from the ACL for this OU.
    The process is to read the ACL verifiy the identiy is part of the ACL remove the specific ACEs for this identity from the ACL and write back this ACL to the AD object.
    Recursive mode will do the same as the none recursive mode but will process all AD objects found inside the OU including the OU itself.
    As of now there are problems with the function Set-ACL and Get-ACL as soon the Distinguished Name contains an special charcter which need to be escaped the function doesn't find the object anymore.
    This problem seams only with this functions. Get-ADObject don't have the problem.
    Du to this behaviour the Script will skip such OUs when the function failed to get the acl and add the DistinguishedName to a list of failed Objects.
    At the end of the script if such objects were found the script will fail and write the full list of failed objects to the logfile.
    Further information about special characters in DN's can be found here:
    https://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
    Special characters which need to be escaped are the follwoing: ,\#+<>;"= or leading or trailing spaces.

.PARAMETER RemoveIdentityReferences
    S-1-5-32-548 = ACCOUNT_OPERATORS: A built-in group that exists only on domain controllers.
    Account Operators have permission to create, modify, and delete accounts for users, groups, and computers
    in all containers and organizational units of Active Directory except the Built-in container and the Domain Controllers OU.
    Account Operators do not have permission to modify the Administrators and Domain Administrators groups,
    nor do they have permission to modify the accounts for members of those groups.

    S-1-5-32-550 = PRINTER_OPERATORS: A built-in group that exists only on domain controllers. Print Operators can manage printers and document queues.
    
    For RemoveIdenttiyReferences any SID can be provided. The SID is resolved during execution of the script to a sAMAccountname.
    This sAMAccountname is used to verify the ACL and remove the specific Identity from the ACL.

.PARAMETER OUDistinguishedName
    Specifies the distinguished name of the organizational unit.

.PARAMETER Recurse
   Indicates that the ACL will be applied to the specified OU and all child objects underneath that OU.

.EXAMPLE
    .\Remove-AccAndPrintOpsfromOU.ps1 -RemoveIdentityReferences "S-1-5-32-548","S-1-5-32-550" -OUDistinguishedName "OU=Tier0,DC=test-teal,DC=internal,DC=test" -Recurse
        This command will remove the User "S-1-5-32-548","S-1-5-32-550" from the ACL of all objects found in "OU=TTier0,DC=test-teal,DC=internal,DC=test"

.EXAMPLE
    .\Remove-AccAndPrintOpsfromOU.ps1 -RemoveIdentityReferences "S-1-5-32-548","S-1-5-32-550" -OUDistinguishedName "OU=Tier0,DC=test-teal,DC=internal,DC=test" -Recurse -Verbose
        This command will remove the Users "S-1-5-32-548" and "S-1-5-32-550" from the ACL of all objects found in "OU=Tier0,DC=test-teal,DC=internal,DC=test"
        Additional you will see commandline output as the script supports debug mode. Additional to the logging.

.NOTES
    This script is published under the "MIT No Attribution License" (MIT-0) license.

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so.

    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [array]
    $RemoveIdentityReferences,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $OUDistinguishedName,

    [switch]$Recurse
)

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

Set-StrictMode -Version latest
Import-Module ActiveDirectory

If ($PSBoundParameters['Debug']) {
    $DebugPreference = 'Continue'
}

if ($PSScriptRoot.Length -eq 0) {
    $Scriptlocation = (get-location).path
}
else {
    $Scriptlocation = $PSScriptRoot
}
[string]$component = (Get-Item -Path $MyInvocation.MyCommand.Source).BaseName
[string]$Global:LogPath = $null
$Global:LogPath = $Scriptlocation
[string]$Global:LogFilePath = $null
$Global:LogfilePath = $(Join-Path -Path $Global:LogPath  -ChildPath "$($component).log")

[array]$ADObjectsFailed = @()

#region Functions
function Write-Log
{
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogText,

        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [string]$Component = '',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Information','Warning','Error')]
        [string]$Type = 'Information',

        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [int]$Thread = $PID,

        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [string]$File = '',

        [Parameter(Mandatory = $false)]
        [int]$LogMaxSize = 5.0MB,

        [Parameter(Mandatory = $false)]
        [int]$LogMaxHistory = 5
    )
    
    Begin
    {
        switch ($Type)
        {
            'Information' { $TypeNum = 1 }
            'Warning'     { $TypeNum = 2 }
            'Error'       { $TypeNum = 3 }
        }
    
        if (-not $Global:LogFilePath) {
            Write-Error -Message 'Variable $LogFilePath not defined in scope $Global:'
            exit 1
        }
        
        if (-not (Test-Path -Path $Global:LogFilePath -PathType Leaf)) {
            New-Item -Path $Global:LogFilePath -ItemType File -ErrorAction Stop | Out-Null
        }
        
        $LogFile = Get-Item -Path $Global:LogFilePath
        if ($LogFile.Length -ge $LogMaxSize) {
            $NewFileName = "{0}-{1:yyyyMMdd-HHmmss}{2}" -f $LogFile.BaseName, $LogFile.LastWriteTime, $LogFile.Extension
            $LogFile | Rename-Item -NewName $NewFileName
            New-Item -Path $Global:LogFilePath -ItemType File -ErrorAction Stop | Out-Null

            $ArchiveLogFiles = Get-ChildItem -Path $LogFile.Directory -Filter "$($LogFile.BaseName)*.log" | Where-Object {$_.Name -match "$($LogFile.BaseName)-\d{8}-\d{6}\.log"} | Sort-Object -Property BaseName
            if ($ArchiveLogFiles) {
                if ($ArchiveLogFiles.Count -gt $LogMaxHistory) {
                    $ArchiveLogFiles | Sort-Object lastwritetime -Descending | Select-Object -Skip ($LogMaxHistory) | Remove-Item
                }
            }
        }
    }
    
    Process
    {
        $now = Get-Date
        $Bias = ($now.ToUniversalTime() - $now).TotalMinutes
        [string]$Line = "<![LOG[{0}]LOG]!><time=`"{1:HH:mm:ss.fff}{2}`" date=`"{1:MM-dd-yyyy}`" component=`"{3}`" context=`"`" type=`"{4}`" thread=`"{5}`" file=`"{6}`">" -f $LogText, $now, $Bias, $Component, $TypeNum, $Thread, $File
        $Line | Out-File -FilePath $Global:LogFilePath -Encoding utf8 -Append -ErrorAction Stop
		Write-Verbose $Line
    }
    
    End
    {
    }
}

function invoke-GetADObjectIdentityReference
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADObjectDistinguishedName
    )
    try {
        Write-Verbose -Message "Create empty ACL Objekt."
        $ADObjectACL = New-Object -TypeName 'System.DirectoryServices.ActiveDirectorySecurity'
        Write-Verbose -Message "Read the ACL for the ADObjekt: $ADObjectDistinguishedName"
        $ADObjectACL = Get-Acl -Path ("ActiveDirectory:://RootDSE/" + $ADObjectDistinguishedName)
        if ($ADObjectACL.Access.Count -gt 0) {
            Write-Verbose -Message "Successfully read ACL"
            Write-Output $ADObjectACL.Access.IdentityReference
        }
        else {
            Write-Verbose -Message "Successfully read ACL"
            Write-Error -Message "There was a problem reading the ACL, no ACL found on Object."
            Exit 99
        }
    }
    catch {
        Write-Verbose -Message "There was a problem reading the ACL, no ACL found on Object."
         Write-Output $null
    }
}

function invoke-ModifyACL
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADObjectDistinguishedName,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemoveIdentityReferenceSamAccountName
    )
    $component = $MyInvocation.MyCommand
    Write-Log -LogText "Create a new empty ACL object and read the ACL from object: $ADObjectDistinguishedName" -Component $component -Type Information
    Write-Verbose -Message "Create a new empty ACL object and read the ACL from object: $ADObjectDistinguishedName"
    $ADObjectACL = New-Object -TypeName 'System.DirectoryServices.ActiveDirectorySecurity'
    $ADObjectACL = Get-Acl -Path ("ActiveDirectory:://RootDSE/" + $ADObjectDistinguishedName)
    if ($ADObjectACL.Access.Count -gt 0) {
        Write-Log -LogText "Successfully read ACL." -Component $component -Type Information
        Write-Verbose -Message "Successfully read ACL."
        Write-Log -LogText "The following ACE Rules were found on the object:" -Component $component -Type Information
        Write-Verbose -Message "The following ACE Rules were found on the object:"
        foreach ($ACE in $ADObjectACL.Access) {
            Write-Log -LogText "$(($ACE | Select-Object *) -join ';')" -Component $component -Type Information
            Write-Verbose -Message "$(($ACE | Select-Object *) -join ';')"
        }
        Write-Log -LogText "Create a new Objekt and filter the ACE for the object: ^.*$RemoveIdentityReferenceSamAccountName" -Component $component -Type Information
        Write-Verbose -Message "Create a new Objekt and filter the ACE for the object: ^.*$RemoveIdentityReferenceSamAccountName"
        [array]$RemoveACES = @()
        $RemoveACES = $ADObjectACL.Access | Where-Object { $_.IdentityReference -match  "^.*$RemoveIdentityReferenceSamAccountName"}
        if ($RemoveACES.Length -gt 0){
            Write-Log -LogText "Found ACEs, start removing the ACEs from the ACL." -Component $component -Type Information
            Write-Verbose -Message "Found ACEs, start removing the ACEs from the ACL."
            Foreach ($RemoveACE in $RemoveACES){
                if (!($RemoveACE.IsInherited)) {
                    Write-Log -LogText "Object to remove:" -Component $component -Type Information
                    Write-Log -LogText "$(($RemoveACE | Select-Object *) -join ';')" -Component $component -Type Information
                    Write-Verbose -Message "Object to remove:"
                    Write-Verbose -Message "$(($RemoveACE | Select-Object *) -join ';')"
                    if ($ADObjectACL.RemoveAccessRule($RemoveACE)) {
                        Write-Log -LogText "ACL Successfully modified." -Component $component -Type Information
                        Write-Verbose -Message "ACL Successfully modified."
                    }
                    else {
                        Write-Error -Message "There was a problem modifying the ACL."
                        Exit 99
                    }
                }
            }        
        }
        else {
            Write-Log -LogText "Object to remove:" -Component $component -Type Information
            Write-Log -LogText "$(($RemoveACES | Select-Object *) -join ';')" -Component $component -Type Information
            Write-Verbose -Message "Object to remove:"
            Write-Verbose -Message "$(($RemoveACES | Select-Object *) -join ';')"
            $ADObjectACL.RemoveAccessRule($RemoveACES)
        }
        Write-Log -LogText "Write back the ACL:" -Component $component -Type Information
        Write-Verbose -Message "Write back the ACL:"
        foreach ($ACE in $ADObjectACL.Access) {
            Write-Log -LogText "$(($ACE | Select-Object *) -join ';')" -Component $component -Type Information
            Write-Verbose -Message "$(($ACE | Select-Object *) -join ';')"
        }
        Set-Acl -Path ("ActiveDirectory:://RootDSE/" + $ADObjectDistinguishedName) -AclObject $ADObjectACL
    }
    else {
        Write-Error -Message "There was a problem reading the ACL, no ACL found on Object."
        Exit 99
    }
}

#endregion Functions

#region main script
Write-Log -LogText "Start Script:" -Component $component -Type Information
Write-Verbose -Message "Start Script:"

try {
    Write-Log -LogText "Check if the runs in recurse mode or not." -Component $component -Type Information
    Write-Verbose -Message "Check if the runs in recurse mode or not."
    if ($Recurse) {
        Write-Log -LogText "Script runs in recurse mode." -Component $component -Type Information
        Write-Verbose -Message "Script runs in recurse mode."
        [Microsoft.ActiveDirectory.Management.ADObject[]]$AdObjects = Get-ADObject -Filter * -SearchBase $OUDistinguishedName -SearchScope Subtree
    }
    else {
        Write-Log -LogText "Script runs not in recurse mode." -Component $component -Type Information
        Write-Verbose -Message "Script runs not in recurse mode."
        [Microsoft.ActiveDirectory.Management.ADObject[]]$AdObjects = Get-ADObject -Filter * -SearchBase $OUDistinguishedName -SearchScope Base
    }
    Write-Log -LogText "Start processing of Active Directory Objects." -Component $component -Type Information
    Write-Verbose -Message "Start processing of Active Directory Objects."
    [int]$i = $null
    $i = 0
    foreach ($ADObject in $AdObjects)
    {
        Write-Log -LogText "Check ACL for Object Name: $($ADObject.DistinguishedName)" -Component $component -Type Information
        Write-Log -LogText "Check ACL for Object Class: $($ADObject.ObjectClass)" -Component $component -Type Information
        Write-Log -LogText "Check ACL for Object GUID: $($ADObject.ObjectGUID)" -Component $component -Type Information
        Write-Verbose -Message "Check ACL for Object Name: $($ADObject.DistinguishedName)"
        Write-Verbose -Message "Check ACL for Object Class: $($ADObject.ObjectClass)"
        Write-Verbose -Message "Check ACL for Object GUID: $($ADObject.ObjectGUID)"
        [array]$ADObjectIdentityReferences = @()
        $ADObjectIdentityReferences = invoke-GetADObjectIdentityReference -ADObjectDistinguishedName $ADObject.DistinguishedName
        if ($null -eq $ADObjectIdentityReferences) {
            Write-Log -LogText "Could not get the ACL. Add AD object to failed list." -Component $component -Type Information
            Write-Verbose -Message "Could not get the ACL. Add AD object to failed list."
            $ADObjectsFailed += $ADObject.DistinguishedName
        }
        else {
            Write-Log -LogText "The following Identity Referendes were found: $($ADObjectIdentityReferences -join ";")" -Component $component -Type Information        
            Write-Verbose "The following Identity Referendes were found: $($ADObjectIdentityReferences -join ";")"
            foreach ($RemoveIdentityReference in $RemoveIdentityReferences) {
                Write-Log -LogText "Translate SID to SamAccountname:" -Component $component -Type Information
                Write-Verbose -Message "Translate SID to SamAccountname:"
                [string]$RemoveIdentityReferenceSamAccountName = $null
                $RemoveIdentityReferenceSamAccountName = ( Get-ADObject -Filter { (ObjectSid -eq $RemoveIdentityReference) } -properties SAMAccountName ).samaccountname
                Write-Log -LogText "SID of Identity to remove: $RemoveIdentityReference" -Component $component -Type Information
                Write-Log -LogText "SAMAccountname of Identity to remove: $RemoveIdentityReferenceSamAccountName" -Component $component -Type Information
                Write-Verbose -Message "SID of Identity to remove: $RemoveIdentityReference"
                Write-Verbose -Message "SAMAccountname of Identity to remove: $RemoveIdentityReferenceSamAccountName"
                Write-Log -LogText "Verify if the Identity is part of the ACL." -Component $component -Type Information
                Write-Verbose -Message "Verify if the Identity is part of the ACL." 
                if ($ADObjectIdentityReferences -match "^.*$RemoveIdentityReferenceSamAccountName") {
                    Write-Log -LogText "Identity found in ACL start to modify the ACL." -Component $component -Type Information
                    Write-Verbose -Message "Identity found in ACL start to modify the ACL."
                    invoke-ModifyACL -ADObjectDistinguishedName $ADObject.DistinguishedName -RemoveIdentityReferenceSamAccountName $RemoveIdentityReferenceSamAccountName
                    Write-Log -LogText "ACL Successfully modified." -Component $component -Type Information
                    Write-Verbose -Message "ACL Successfully modified."
                }
                elseif ($ADObjectIdentityReferences -match "^.*$RemoveIdentityReference") {
                    Write-Log -LogText "The identity wasn't found with the SamAccount Name, found the identy with the SID." -Component $component -Type Information
                    Write-Verbose -Message "The identity wasn't found with the SamAccount Name, found the identy with the SID."
                    Write-Log -LogText "Identity found in ACL start to modify the ACL." -Component $component -Type Information
                    Write-Verbose -Message "Identity found in ACL start to modify the ACL."
                    invoke-ModifyACL -ADObjectDistinguishedName $ADObject.DistinguishedName -RemoveIdentityReferenceSamAccountName $RemoveIdentityReference
                    Write-Log -LogText "ACL Successfully modified." -Component $component -Type Information
                    Write-Verbose -Message "ACL Successfully modified."
                }
                else {
                    Write-Log -LogText "Identity not found in ACL continue with next Identity." -Component $component -Type Information
                    Write-Verbose -Message "Identity not found in ACL continue with next Identity."
                }
            }
        
        }
        # update counter and write progress
        $i++
        Write-Progress -activity "Checking ACL ... " -status "Processed: $i of $($AdObjects.Count) AD objects" -percentComplete (($i / $AdObjects.Count)  * 100)
    }
}

catch {
    write-log -LogText $_ -Component $component -Type Error
    write-log -LogText "Error in script line: $($_.InvocationInfo.ScriptLineNumber)" -Component $component -Type Error
    Write-Error $_
}

if (0 -ne $ADObjectsFailed.count) {
    Write-Log -LogText "There were a total of: $($ADObjectsFailed.count) AD objects which failed to process. Please check the Logfile." -Component $component -Type Information
    Write-Log -LogText "The following AD objects were not changed: $($ADObjectsFailed -join ";")" -Component $component -Type Information        
    Write-Error  -Message "There were a total of: $($ADObjectsFailed.count) AD Objects which failed to process. Please check the Logfile."
    Exit 99
}

Write-Log -LogText "Finished script." -Component $component -Type Information
Write-Verbose -Message "Finished script."
#endregion main script