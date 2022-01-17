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

---

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






# Questions

##### LDAP Overview
![](Pasted%20image%2020220116213511.png)