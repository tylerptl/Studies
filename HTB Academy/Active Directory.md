

# Context

## NT AUTHORITY \ SYSTEM
* Built in windows account used by the service manager.
* Highest level access in the OS - can be further increased with `Trusted Installer Privileges`
	* Very typical for 3rd party services to run in the context of this system by default.
* `SYSTEM` can enumerate AD by impersonating the computer account on a domain-joined system
	* Getting system access is very nearly the same as having domain user account - biggest limit is inability to kerberoast.


##### Getting SYSTEM level access
* EternalBlue (MS17-010), BlueKeep
-   Abusing a service running in the context of the SYSTEM account.
-   Abusing SeImpersonate privileges using [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) against older Windows systems, [Juicy Potato](https://github.com/ohpe/juicy-potato), or [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) if targeting [Windows 10/Windows Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/).
-   Local privilege escalation flaws in Windows operating systems such as the [Windows 10 Task Scheduler 0day](https://blog.0patch.com/2019/06/another-task-scheduler-0day-another.html).
-   PsExec with the `-s` flag

##### Capabilities with SYSTEM-level access.
-   Enumerate the domain and gather data such as information about domain users and groups, local administrator access, domain trusts, ACLs, user and computer properties, etc., using `BloodHound`, and `PowerView`/`SharpView`.
-   Perform Kerberoasting / ASREPRoasting attacks.
-   Run tools such as [Inveigh](https://github.com/Kevin-Robertson/Inveigh) to gather Net-NTLM-v2 hashes or perform relay attacks.
-   Perform token impersonation to hijack a privileged domain user account.
-   Carry out ACL attacks.


##  LDAP
* AD stores the user account and security information, and facilitates sharing this with devices on the network
* LDAP is the language used by apps to communicate with other servers that provide directory services.
	* Similar to how Apache is a web server that uses HTTP. AD is a directory server that uses LDAP.

##### AD LDAP Auth

* LDAP authenticates creds against AD using `BIND` operations to set the auth state for a LDAP session. There are two types:
	* **Simple Auth**: includes anonymous auth, unauthenticated, and usn/pw auth. A username//password combo creates a BIND request to authenaticate to the LDAP server.
	* **SASL Auth**: The [Simple Authentication and Security Layer (SASL)](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer) framework uses other authentication services, such as Kerberos, to bind to the `LDAP` server and then uses this authentication service (Kerberos in this example) to authenticate to `LDAP`. The `LDAP` server uses the `LDAP` protocol to send an `LDAP` message to the authorization service which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication. SASL can provide further security due to the separation of authentication methods from application protocols.
* LDAP auth messages are cleartext by default - encrypt in transit with TLS or something.

### LDAP Queries
* Allows a user to query LDAP service to ask for information.
* Plug these into powershell's `Get-ADObject -LDAPFilter 'QUERY' | select cn`
	* Ex. Get all workstations `(objectCategory=computer)` or get all DCs `(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))`
	* [More queries from MS](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)
	* LDAPWiki for [Computers](https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query), [Users](https://ldapwiki.com/wiki/Active%20Directory%20User%20Related%20Searches), and [Groups](https://ldapwiki.com/wiki/Active%20Directory%20Group%20Related%20Searches)
	* [Bit values to use with OID searches](https://ldapwiki.com/wiki/User-Account-Control%20Attribute%20Values) 
		* `(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))` will search for all disabled user accounts - this has a bit value of 2 per the docs, and the UAC search has a string identifier of `LDAP_MATCHING_RULE_BIT_AND`


### Active Directory Search Filters

##### Filter Insatlled Software
* This will display all installed software that is not from Microsoft

````powershell-session
get-ciminstance win32_product -Filter "NOT Vendor like '%Microsoft%'" | fl
````

* Search AD based on some set of parameters example. 
```powershell
Get-ADUser -Filter "name -eq 'sally jones'"
Get-ADUser -Filter {name -eq 'sally jones'}
Get-ADUser -Filter'name -eq "sally jones"'
Get-ADUser -Filter * -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl

Get-ADComputer  -Filter "DNSHostName -like 'SQL*'"
Get-ADGroup -Filter "adminCount -eq 1" | select Name

Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | fl

# Accounts with no pw
Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl

```

##### Attributes to filter on
[User attr](http://www.kouti.com/tables/userattributes.htm)
[Base attr](http://www.kouti.com/tables/baseattributes.htm)

##### Recursive Search
* Example: A user is a member of **Security Operations** which in turn is a member of **Domain Admins**. A normal search will not reveal that the user has **Domain Admins** rights, but `-RecursiveMatch` will show the derivative rights that the user inherits.
	* `Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name`
	* Alternatively, use `LDAPFilter` like `Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name`

##### Limiting Search Scope with "SearchBase"
* `SearchBase` specifies an AD path to search under and permits searches in specific OUs.
* The param accepts an OI distinguishedName like `OU=Employees,DC=INLANEFREIGHT,DC=LOCAL`
* Use with `SearchScope n` to specify how deep the search should go inside the OU
	* `OneLevel` (1) searches only in the container defined by `SearchBase`
	* `SubTree` (2) searches in the specified container and all children - recursive throughout all grandchildren as well.

##### Checking userAccessControl settings
* The following search will spit out userAccountControl flag properties that can be found [here](https://ldapwiki.com/wiki/User-Account-Control%20Attribute%20Values)

```powershell-session
Get-ADUser -Filter {adminCount -gt 0} -Properties admincount,useraccountcontrol | select Name,useraccountcontrol
```


### Rights and Privs in AD

---

* Enumerate groups with `Get-AdGroup -Identity "GROUP_NAME" -Properties *`


### MS Remote Server Admin Tools (RSAT)

---

* RSAT tools can be installed on Win 10 1809, 1903, 1909 with [this script](https://gist.github.com/dually8/558fcfa9156f59504ab36615dfc4856a)
* Check which tools are active on the system with `Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property Name, State`
	* Can install missing tools piecemeal or as a bundle with `Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online`
* A lot of these tools need domain context (params/creds) to run - this context can be altered for a user if you have access to a pw/hash.
	* `runas /netonly /user:htb.local\firstname.lastname powershell`
	* Rubeus: `rubeus.exe asktgt /user:jackie.may /domain:htb.local /dc:10.10.110.100 /rc4:ad11e823e1638def97afa7cb08156a94`
	* Mimikatz: `mimikatz.exe sekurlsa::pth /domain:htb.local /user:jackie.may /rc4:ad11e823e1638def97afa7cb08156a94`

##### Enumeration with RSAT
* Requires a compromised domain-joined system.
* Alternatively, we can enumerate from a non domain-joined host - assuming its sharing a subnet that talks with a DC - by running any RSAT snapins w/`runas`. Useful during internal assessments in which we have AD creds assigned to us and want to work from a windows VM.
* Can also open the Microsoft MGMT Console (MMC) from a non-domain joined host with `runas /netonly /user:DOMAIN_NAME\DOMAIN_USER mmc`






# Tools

### PowerView

* Used to enumerate AD
* Import with `Import-Module ./Powerview.ps1`
* Returns something like
```Powershell
PS C:\tools> Get-DomainUser * -AdminCount | select samaccountname,useraccountcontrol

samaccountname                                                     useraccountcontrol
--------------                                                     ------------------
Administrator                                    NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD
krbtgt                           ACCOUNTDISABLE, NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD
daniel.carter                                                         NORMAL_ACCOUNT
sqlqa                                                                 NORMAL_ACCOUNT
svc-backup                                       NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD
svc-secops                                       NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD
cliff.moore                                      NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD
svc-ata                                                               NORMAL_ACCOUNT
svc-sccm                                                              NORMAL_ACCOUNT
mrb3n                                                                 NORMAL_ACCOUNT
sarah.lafferty                                                        NORMAL_ACCOUNT
jenna.smith     PASSWD_NOTREQD, NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD,DONT_REQ_PREAUTH
harry.jones                      PASSWD_NOTREQD, NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD
trisha.duran                                                          NORMAL_ACCOUNT
pixis                                                                 NORMAL_ACCOUNT
Cry0l1t3                                                              NORMAL_ACCOUNT
knightmare                                                            NORMAL_ACCOUNT```

### Windapsearch.py
* Enumerate users with `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U`
* Enumerate computer info with `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C`
* Get functional levels with `./windapsearch.py --dc-ip 10.129.44.46 -u "" --functionality`
* You can combine custom filters from powershell like  `windapsearch --dc 10.129.44.46 -d inlanefreight -m custom --filter '(&(objectClass=person)(userAccountControl:1.2.840.113556.1.4.803:=262144))' --attrs dn`  - this will show users that require SMARTCARD_REQUIRED uac.
* Ex. Find user accounts w/`userAccountControl` set to `ENCRYPTED_TEXT_PWD_ALLOWED`
	```bash
	windapsearch --dc 10.129.42.188 -d inlanefreight -m custom --filter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' --attrs dn
	
dn: CN=wilford.stewart,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
	```

	```bash
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.44.46
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Functionality Levels:
[+]      domainControllerFunctionality: 2016
[+]      forestFunctionality: 2016
[+]      domainFunctionality: 2016
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[*] Bye!

	```


##### Credentialed LDAP Enumeration with Windapsearch
# Questions

##### LDAP Overview
![](Pasted%20image%2020220116213511.png)

##### Active Directory Sarch Filters
1. `Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'}`
2. `Get-ADComputer -Filter "DNSHostName -like 'WS*'"`
3. `Get-ADUser -Filter * -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl`

##### LDAP Search Filters
```powershell
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' |select Name
```


```powershell-session
Get-AdUser -Filter {(TrustedForDelegation -eq $True)} | select *
```

![First get all sub groups of employees, then get the cound of IT](Pasted%20image%2020220117183202.png)

`Get-ADUser -SearchBase "OU=Pentest,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *` => Clark.Thompson user

##### LDAP Anon bind

```bash
windapsearch --dc 10.129.44.46 -m groups -s 'Protected Users' --full -m unconstrained

dn: CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
objectClass: top
objectClass: group
cn: Protected Users
description: Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
member: CN=sqldev,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
distinguishedName: CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
instanceType: 4
whenCreated: 20201207164337.0Z
whenChanged: 20201207191403.0Z
uSNCreated: 12445
uSNChanged: 12889
name: Protected Users
objectGUID: 8fwTFyP990G0Q9KPi6DUFw==
objectSid: AQUAAAAAAAUVAAAAyFFXTuerf1LSWAaZDQIAAA==
sAMAccountName: Protected Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
isCriticalSystemObject: TRUE
dSCorePropagationData: 20201207193350.0Z
dSCorePropagationData: 20201207193325.0Z
dSCorePropagationData: 20201207193300.0Z
dSCorePropagationData: 20201207164337.0Z
dSCorePropagationData: 16010714223233.0Z

```

```bash
windapsearch --dc 10.129.44.46 -m users -s 'Kevin'                                   
dn: CN=kevin.gregory,OU=Finance,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL
cn: kevin.gregory
sAMAccountName: kevin.gregory

```


##### Credential enumeration
```bash
./ldapsearch-ad.py -l 10.129.42.188 -d inlanefreight -u james.cross -p Academy_Student! -t all                                                   3 ⨯ 1 ⚙

### Server infos ###
[+] Forest functionality level = Windows 2016
[+] Domain functionality level = Windows 2016
[+] Domain controller functionality level = Windows 2016
[+] rootDomainNamingContext = DC=INLANEFREIGHT,DC=LOCAL
[+] defaultNamingContext = DC=INLANEFREIGHT,DC=LOCAL
[+] ldapServiceName = INLANEFREIGHT.LOCAL:dc01$@INLANEFREIGHT.LOCAL
[+] naming_contexts = ['DC=INLANEFREIGHT,DC=LOCAL', 'CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL', 'CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL', 'DC=DomainDnsZones,DC=INLANEFREIGHT,DC=LOCAL', 'DC=ForestDnsZones,DC=INLANEFREIGHT,DC=LOCAL']
### Result of "admins" command ###
All members of group "Domain Admins":
[*]     mrb3n (DONT_EXPIRE_PASSWORD)
[*]     Administrator (DONT_EXPIRE_PASSWORD)
All members of group "Administrators":
[*]     mrb3n (DONT_EXPIRE_PASSWORD)
[*]     Administrator (DONT_EXPIRE_PASSWORD)
All members of group "Enterprise Admins":
[*]     Administrator (DONT_EXPIRE_PASSWORD)
### Result of "pass-pols" command ###
Default password policy:
[+] |___Minimum password length = 7
[+] |___Password complexity = Disabled
[*] |___Lockout threshold = Disabled
[+] No fine grained password policy found (high privileges are required).


```

```bash
windapsearch --dc 10.129.42.188 -d inlanefreight -m custom --filter '(&(objectClass=person)(userAccountControl:1.2.840.113556.1.4.803:=262144))' --attrs dn

dn: CN=sarah.lafferty,CN=Users,DC=INLANEFREIGHT,DC=LOCAL

```

```bash
windapsearch --dc 10.129.42.188 -d inlanefreight -m custom --filter '(objectClass=domainDNS)' --attrs pwdHistoryLength                             147 ⨯

dn: DC=INLANEFREIGHT,DC=LOCAL
pwdHistoryLength: 5

```

```bash
windapsearch --dc 10.129.42.188 -d inlanefreight -m custom --filter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' --attrs dn

dn: CN=wilford.stewart,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```



## Skill Assessment

--- 

1. Find the one user who has a useraccountcontrol attribute equivalent to 262656.
```powershell
Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=262656)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | fl
```

2. Using built-in tools enumerate a user that has the PASSWD_NOTREQD UAC value set.
```powershell
Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=32)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | fl
```

3. What group is the IT Support group nested into?
![](Pasted%20image%2020220119223523.png)

4.Who is a part of this group through nested group membership?
 ```powershell
 get-adgroup -LDAPFilter '(&(objectClass=group)(DistinguishedName=CN=IT Support,CN=Users,DC=INLANEFREIGHTENUM1,DC=LOCAL))' -Properties *
 ```

 5. What is the name of the computer that starts with RD?
 ![](Pasted%20image%2020220119230002.png)

 6. How many groups exist where the admincount attribute is set to 1?
 
![](Pasted%20image%2020220119230058.png)

7 . What user could be subjected to an ASREPRoasting attack and is NOT a protected user? (first.last)
* Requires `DONT_REQUIRE_PREAUTH useraccountcontrol`

`get-aduser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'`

![](Pasted%20image%2020220119231944.png)

8. What is the samaccountname of the one SPN set in the domain?
 `Get-ADUser -Filter * -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl`

![](Pasted%20image%2020220119232143.png)