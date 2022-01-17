```bash
└─$ nmap -sV -sC -p 53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49669,49674,49675,49676,49679,49684,49689,49704 10.10.109.58 -vv -oA targeted_ports 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-13 22:09 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:09
Completed NSE at 22:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:09
Completed NSE at 22:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:09
Completed NSE at 22:09, 0.00s elapsed
Initiating Ping Scan at 22:09
Scanning 10.10.109.58 [2 ports]
Completed Ping Scan at 22:09, 0.16s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:09
Completed Parallel DNS resolution of 1 host. at 22:09, 0.01s elapsed
Initiating Connect Scan at 22:09
Scanning 10.10.109.58 [27 ports]
Discovered open port 53/tcp on 10.10.109.58
Discovered open port 80/tcp on 10.10.109.58
Discovered open port 445/tcp on 10.10.109.58
Discovered open port 47001/tcp on 10.10.109.58
Discovered open port 139/tcp on 10.10.109.58
Discovered open port 135/tcp on 10.10.109.58
Discovered open port 3389/tcp on 10.10.109.58
Discovered open port 49664/tcp on 10.10.109.58
Discovered open port 636/tcp on 10.10.109.58
Discovered open port 593/tcp on 10.10.109.58
Discovered open port 49684/tcp on 10.10.109.58
Discovered open port 49676/tcp on 10.10.109.58
Discovered open port 49665/tcp on 10.10.109.58
Discovered open port 88/tcp on 10.10.109.58
Discovered open port 389/tcp on 10.10.109.58
Discovered open port 49666/tcp on 10.10.109.58
Discovered open port 49679/tcp on 10.10.109.58
Discovered open port 9389/tcp on 10.10.109.58
Discovered open port 5985/tcp on 10.10.109.58
Discovered open port 3268/tcp on 10.10.109.58
Discovered open port 49669/tcp on 10.10.109.58
Discovered open port 49704/tcp on 10.10.109.58
Discovered open port 3269/tcp on 10.10.109.58
Discovered open port 49674/tcp on 10.10.109.58
Discovered open port 49675/tcp on 10.10.109.58
Discovered open port 49689/tcp on 10.10.109.58
Discovered open port 464/tcp on 10.10.109.58
Completed Connect Scan at 22:09, 0.35s elapsed (27 total ports)
Initiating Service scan at 22:09
Scanning 27 services on 10.10.109.58
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 51.85% done; ETC: 22:09 (0:00:07 remaining)
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 51.85% done; ETC: 22:09 (0:00:08 remaining)
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 51.85% done; ETC: 22:09 (0:00:08 remaining)
Stats: 0:00:46 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 62.96% done; ETC: 22:10 (0:00:27 remaining)
Stats: 0:00:47 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 62.96% done; ETC: 22:10 (0:00:28 remaining)
Completed Service scan at 22:10, 62.74s elapsed (27 services on 1 host)
NSE: Script scanning 10.10.109.58.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:10
Completed NSE at 22:10, 9.53s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:10
Completed NSE at 22:10, 5.36s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:10
Completed NSE at 22:10, 0.00s elapsed
Nmap scan report for 10.10.109.58
Host is up, received conn-refused (0.17s latency).
Scanned at 2022-01-13 22:09:35 EST for 78s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2022-01-14 03:09:43Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-01-13T03:01:49
| Not valid after:  2022-07-15T03:01:49
| MD5:   9498 f3f6 f8c4 a609 8c05 2000 9c25 6eec
| SHA-1: f667 a208 c7de 37a4 13ae 55f3 5b77 0318 48d7 e09e
| -----BEGIN CERTIFICATE-----
| MIIDCjCCAfKgAwIBAgIQGnD8Ca9BTapKRbNNXSSBdzANBgkqhkiG9w0BAQsFADAu
| MSwwKgYDVQQDEyNBdHRhY2t0aXZlRGlyZWN0b3J5LnNwb29reXNlYy5sb2NhbDAe
| Fw0yMjAxMTMwMzAxNDlaFw0yMjA3MTUwMzAxNDlaMC4xLDAqBgNVBAMTI0F0dGFj
| a3RpdmVEaXJlY3Rvcnkuc3Bvb2t5c2VjLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEArgkM1una+cyccCOl9ICN2lj+8yWPd0vLugms2aOAIVgo
| nakx6M+hkw6tVBqTvdxUr1St6uKa+m3TfrxCNTK7ubduWPJXExaMd8AK/fXmRq6l
| QaNdW5Tl0nD0WZYB+tiirhfffVaTlrCV5vtTembrOjZCWSGv5evP1PXwW72QRHbf
| iL0eykUeAtnBHG3GIr5jz+lmYsTgoMQf09LQZSwW4h9AwgskP586DXosn+iPlMdw
| nuBZhoI4Hn+agsbux0KEvACXlI1ZTvkMWWcw3ERx0+9gCJbyc1KCNSamZ3NFoE8M
| j2ZxI8kyJytL2144ePe2X92skXgs7BJtqi51lKslEQIDAQABoyQwIjATBgNVHSUE
| DDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAG7W
| UvsC3LgwnS1PfGkcsgTb+IKuCAgnPh+kbU1tKM7GYnaUhdkNt8pYMvbnDARGajBG
| ZqznB54Yj/sjeC3dfWT2/ZEPo0qwLCxQlJtRq9C9c7qFSotYMrcEtr3bPV6wAEOT
| vs+gAMqBvTfobPOLUP5xU9sbUTt4xn0fpLNc0OryVkL+wnn2hH4BzzT6uvOhDiVo
| c7L5G6YmsPFDEy3Js1rznwTROmNKcak9jpGM7CqfEqu/q1w/zmpx5E5FsoirYUHb
| 5+++nQNcW144gY0g2hQfd+PqR4weJLN8FLnOQkT6SASK+3w34xGHKciobSB6VC8+
| LdneqbsGrdGLNie3C60=
|_-----END CERTIFICATE-----
|_ssl-date: 2022-01-14T03:10:49+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-01-14T03:10:40+00:00
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49684/tcp open  msrpc         syn-ack Microsoft Windows RPC
49689/tcp open  msrpc         syn-ack Microsoft Windows RPC
49704/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 21094/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 61571/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 26451/udp): CLEAN (Timeout)
|   Check 4 (port 33901/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-01-14T03:10:43
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:10
Completed NSE at 22:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:10
Completed NSE at 22:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:10
Completed NSE at 22:10, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.55 seconds

```