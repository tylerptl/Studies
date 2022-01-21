(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))


Get-ADObject -LDAPFilter'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' | select samaccountname,useraccountcontrol


Get count of users in INLANEFREIGHT.LOCAL domain
	`Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user))' | measure-object -line`


`Get-ADGroup -LDAPFilter '(&(objectClass=group)(name=*Admin*))' -Properties * | select name, members