```bash
# Nmap 7.92 scan initiated Thu Jan 13 22:05:39 2022 as: nmap -p- --min-rate=2000 -T4 -vv -oA open_ports 10.10.109.58
Nmap scan report for 10.10.109.58
Host is up, received syn-ack (0.17s latency).
Scanned at 2022-01-13 22:05:40 EST for 33s
Not shown: 65508 closed tcp ports (conn-refused)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
3389/tcp  open  ms-wbt-server    syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
47001/tcp open  winrm            syn-ack
49664/tcp open  unknown          syn-ack
49665/tcp open  unknown          syn-ack
49666/tcp open  unknown          syn-ack
49669/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49675/tcp open  unknown          syn-ack
49676/tcp open  unknown          syn-ack
49679/tcp open  unknown          syn-ack
49684/tcp open  unknown          syn-ack
49689/tcp open  unknown          syn-ack
49704/tcp open  unknown          syn-ack

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Jan 13 22:06:13 2022 -- 1 IP address (1 host up) scanned in 34.07 seconds

```