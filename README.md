# 1. Remove-AccAndPrintOpsFromOU
The PowerShell script **Remove-AccAndPrintOpsFromOU.ps1** removes defined identities from the ACL of AD Objects.
    
The script can run in recursive mode or non-recursive mode.
None-recursive mode will only process the spcified OU and remove the specified identies from the ACL for this OU.
The process is to read the ACL verifiy the identiy is part of the ACL remove the specific ACEs for this identity from the ACL and write back this ACL to the AD object.
Recursive mode will do the same as none-recursive mode but will process all AD objects found inside the OU including the OU itself.
As of now there are problems with the function Set-ACL and Get-ACL as soon the Distinguished Name contains an special charcter which need to be escaped the function doesn't find the object anymore.

This problem only seems to apply with this functions. Get-ADObject don't have the problem.
Due to this behaviour, the script will skip such OUs when the function failed to get the ACL and add the DistinguishedName to a list of failed objects.
At the end of the script if such objects were found, the script will fail and write the full list of failed objects to the logfile.
Further information about special characters in DN's can be found here:
https://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx

Special characters which need to be escaped are the following: ,\#+<>;"= or leading or trailing spaces.

## 1.1. Parameters
**RemoveIdentityReferences**:
S-1-5-32-548 = ACCOUNT_OPERATORS: A built-in group that exists only on domain controllers. Account Operators have permission to create, modify, and delete accounts for users, groups, and computers in all containers and organizational units of Active Directory except the Built-in container and the Domain Controllers OU. Account Operators do not have permission to modify the Administrators and Domain Administrators groups, nor do they have permission to modify the accounts for members of those groups.

S-1-5-32-550 = PRINTER_OPERATORS: A built-in group that exists only on domain controllers. Print Operators can manage printers and document queues.
    
For RemoveIdenttiyReferences any SID can be provided. The SID is resolved during execution of the script to a sAMAccountname. This sAMAccountname is used to verify the ACL and remove the specific Identity from the ACL.

**OUDistinguishedName**:
Specifies the distinguished name of the organizational unit.

**Recurse**:
Indicates that the ACL will be applied to the specified OU and all child objects underneath that OU.

# 1.2. Examples

This command will remove the User "S-1-5-32-548","S-1-5-32-550" from the ACL of all objects found in "OU=TTier0,DC=test-teal,DC=internal,DC=test"

        .\Remove-AccAndPrintOpsfromOU.ps1 -RemoveIdentityReferences "S-1-5-32-548","S-1-5-32-550" -OUDistinguishedName "OU=Tier0,DC=test-teal,DC=internal,DC=test" -Recurse

This command will remove the Users "S-1-5-32-548" and "S-1-5-32-550" from the ACL of all objects found in "OU=Tier0,DC=test-teal,DC=internal,DC=test"
In addition, you will see commandline output as the script supports debug mode. Additional to the logging.

        .\Remove-AccAndPrintOpsfromOU.ps1 -RemoveIdentityReferences "S-1-5-32-548","S-1-5-32-550" -OUDistinguishedName "OU=Tier0,DC=test-teal,DC=internal,DC=test" -Recurse -Verbose
