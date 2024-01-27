# crtp

| DATE | LIVE SESSIONS |
| --- | --- |
| 04 Feb 2024 | Enumeration & LPE, Hunt for local admin privileges on machines in the target domain using multiple methods / Bypass AV + Pivoting different machines |
| 11 Feb 2024 | Lateral Movement, Domain PE and Persistence |
| 18 Feb 2024 | Domain Persistence, Dominance and Escalation to Enterprise Admins |
| 25 Feb 2024 | Defenses, Monitoring and Bypassing Defenses |

**Module I: Active Directory Enumeration**

- Use scripts, built-in tools and Active Directory module to enumerate the target domain.
- Understand and practice how useful information like users, groups, group memberships, computers, user properties etc. from the domain controller is available to even a normal user.
- Understand and enumerate intra-forest and inter-forest trusts. Practice how to extract information from the trusts.
- Enumerate Group policies.
- Enumerate ACLs and learn to find out interesting rights on ACLs in the target domain to carry out attacks.

**Module II: Lateral Movement, Domain Privilege Escalation and Persistence**

- Learn to find credentials and sessions of high privileges domain accounts like Domain Administrators, extracting their credentials and then using credential replay attacks to escalate privileges, all of this with just using built-in protocols for pivoting
- Learn to extract credentials from a restricted environment where application whitelisting is enforced. Abuse derivative local admin privileges and pivot to other machines to escalate privileges to domain level
- Understand the classic Kerberoast and its variants to escalate privileges
- Understand and exploit delegation issues
- Learn how to abuse privileges of Protected Groups to escalate privileges
- Abuse Kerberos functionality to persist with DA privileges. Forge tickets to execute attacks like Golden ticket and Silver ticket to persist
- Subvert the authentication on the domain level with Skeleton key and custom SSP
- Abuse the DC safe mode Administrator for persistence
- Abuse the protection mechanism like AdminSDHolder for persistence

**Module III: Domain Persistence, Dominance and Escalation to Enterprise Admins**

- Abuse minimal rights required for attacks like DCSync by modifying ACLs of domain objects
- Learn to modify the host security descriptors of the domain controller to persist and execute commands without needing DA privileges
- Learn to elevate privileges from Domain Admin of a child domain to Enterprise Admins on the forest root by abusing Trust keys and krbtgt account
- Execute intra-forest trust attacks to access resources across forest
- Abuse database links to achieve code execution across forest by just using the databases

**Module IV: Monitoring, Architecture Changes, Bypassing Advanced Threat Analytics and Deception**

- Learn about useful events logged when the discussed attacks are executed
- Learn briefly about architecture changes required in an organization to avoid the discussed attacks. We discuss Temporal group membership, ACL Auditing, LAPS, SID Filtering, Selective Authentication, credential guard, device guard (WDAC), Protected Users Group, PAW, Tiered Administration and ESAE or Red Forest
- Learn how Microsoft's Advanced Threat Analytics and other similar tools detect domain attacks and the ways to avoid and bypass such tools
- Understand how Deception can be effective deployed as a defense mechanism in AD

---

**Domain Enumeration**

| Description | Command |
| --- | --- |
| Get current domain / Get object from another domain | Get-NetDomain -Domain <target_domain>  |
| Get current domain / Get object from another domain | Get-ADDomain -Identity <target_domain>  |
| Get domain SID for the current domain | Get-DomainSID ⭐ |
| Get domain SID for the current domain | (Get-ADDomain).DomainSID | Select Value |
| Get domain policy for the current domain | Get-DomainPolicy ⭐ |
| Get domain policy for a domain | (Get-DomainPolicy -domain <domain>).”SystemAccess” ⭐ |
| Returns MaxTicketAge, MaxServiceAge, MaxClockSkew, etc. | (Get-DomainPolicy)."kerberosPolicy” |
| Get domain controllers for current domain | Get-NetDomainContoller |
| Get domain controllers for another domain | Get-DomainController -Domain <DOMAIN> ⭐ |
| Get domain controllers  | Get-ADDomainController -DomainName <target_domain> -Discover ⭐ |

**Users Enumeration**

| Description | Command |
| --- | --- |
| 1 | Get-NetUser  |
| 1 Get all users in a domain | Get-ADUser -Filter * -Properties *  |
| 2 specific user | Get-NetUser -Name helpdesk  |
| 2 get all properties for a specific user | Get-ADUser -Identity helpdesk -Properties *  |
|  | Get-ADUser -Filter {SamAccountName -eq “helpdesk”} |
| Get a list of all properties for users in the current domain | Get a list of all properties for users in the current domain |
| NOT | Get-UserProperty |
| NOT | Get-UserProperty -Properties pwdlastset |
| NOT | Get-UserPropertiy -Properties badpwdcount |
| List all properties available for the first user in Active Directory | Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | Select Name
 |
| Retrieve specific properties for all users in AD
such as: pwdLastSet, badPwdCount, logonCount | Get-ADUser -Filter * -Properties * | select Name, @{Name="PasswordLastSet"; Expression={[datetime]::fromFileTime($_.pwdlastset)}}, badPwdCount, logonCount |
| NOT (Search for a particular string in a user’s attributes:) | Find-UserField -SearchField Description -SearchTerm “built” |
| (Search for a particular string in a user’s attributes:) | Get-ADUser -Filter ‘Description -like “*pass*”’ -Properties Description | select Name,Description |

Get-ADUser -Filter * -Properties * | Select-Object Name, @{Name="LastLogon"; Expression={[datetime]::fromFileTime($*.lastLogon)}}, @{Name="PasswordLastSet"; Expression={[datetime]::fromFileTime($*.pwdlastset)}}, logonCount, badPwdCount | Format-Table -AutoSize

**Computers Enumeration**:

| Description | Command |
| --- | --- |
| List all computer objects in a domain | Get-NetComputer -Domain $DOMAIN |
| List all computer names | Get-ADComputer -Filter * | select Name ⭐ |
| List all computer objects | Get-ADComputer -Filter * -Properties * |
| Only machines that responds to a ping (could cause false negatives) | Get-NetComputer -Ping | select cn ⭐ |
|  | Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName} ⭐ |
|  | Get-NetComputer | select OperatingSystem |
|  | Get-ADComputer -Filter * -Properties OperatingSystem | select Name, OperatingSystem  |
|  | Get-NetComputer -OperatingSystem “*10*” |
| NOT | Get-NetComputer -FullData |

**Groups Enumeration**

See groups user is a member of `Get-ADPrincipalGroupMemberShip -Identity $USER`

return users part of specified group `Get-ADGroupMember -Identity <GROUP_NAME> -Recursive`

| Description | Command |
| --- | --- |
|  Get all groups in current domain | Get-Netgroup |
|  Get all groups in a domain | Get-Netgroup -Domain <target_domain> |
| NOT  | Get-Netgroup -FullData |
| Get all groups name | Get-ADGroup -Filter * | select Name |
| Get all groups with all properties | Get-ADGroup -Filter * -Properties * |
| Get all groups containing the word “admin” in group name | Get-NetGroup *admin* |
| Get all groups containing the word “admin” in group name | Get-ADGroup -Filter ‘Name -like “*admin*”’ | select name |
| Get all the members of the “Domain Admins” group | Get-NetGroupMember -Name “Domain Admins” -Recurse |
| Get all the members of the “Domain Admins” group, in a specific targeted domain | Get-NetGroupMember -Name “Domain Admins” -Domain $DOMAIN |
|  | Get-ADGroupMember -Identity “Domain Admins” -Recursive |
| Get the group membership for a user | Get-NetGroup -Username “helpdesk” |
| ! same as the above one ? | Get-ADPrincipalGroupMemberShip -Identity helpdesk |
| List all the local groups on a machine (needs administrator privs on non-dc machines): | Get-NetLocalGroup -ComputerName DC.nirvana-group.local -ListGroups |
| Get members of all the local groups on a machine (needs administrator privs on non-dc machines) | Get-NetLocalGroup -ComputerName DC.nirvana-group.local -Recurse |

`Get-NetGroup -UserName “simo-six” | select cn`

`Get-NetGroupMember -Name cluster-1 | select membername`

**File Share Enum**

---

| Description | Command |
| --- | --- |
| Find shares on hosts in the current domain | Invoke-ShareFinder -Verbose |
|  | Invoke-ShareFinder -Verbose -ExecludeStandard -ExecludePrint -ExecludeIPC |
| Find sensitive files on computers in the domain | Invoke-FileFinder -Verbose |
| Get all fileservers of the domain | Get-NetFileServer |

**Decoys:**

- many orgs   detecting the carless attackers that is if you are directly going in for the lowest hanging fruit uw where are you dont enumerate a domain properly for example you log on to you get a foothold box and you start looking for a machine where a domain admin is logged in you immediately get a machine you try to use those credentials and turns out that those credentials were not the correct ones what were honey credits or decoys
- Many organizations are focused on identifying careless attackers. For instance, if you're targeting the easiest and most obvious vulnerabilities, where you shouldn't be, without properly enumerating a domain. Let's say you gain access to a foothold box and start searching for a machine where a domain administrator is logged in. You might quickly gain access to a machine, attempt to use those credentials, only to find out that they were actually honey credentials or decoys
- … the org want to target your enumeration phase of your attack they would create some users which looks very entising, and very useful, but as soon as you interact or enumerate those users there would be an alert and you may get detected.
- so properties like this for example password last set `pwdlastset` or bad password  count `badpwdcount`, these properties can be used to differentiate an actual users from a decoy user right.
- Get-UserProperties -Properties pwdlastset
- users with less logon count `logoncount` and users dont have bad password count that means those users may be decoys.
