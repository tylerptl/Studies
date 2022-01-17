```nmap
nmap -sV -sC -T4 -p 22,80,3306 10.10.236.120 -vv -oA targeted_ports
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-11 19:50 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Initiating Ping Scan at 19:50
Scanning 10.10.236.120 [2 ports]
Completed Ping Scan at 19:50, 0.17s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:50
Completed Parallel DNS resolution of 1 host. at 19:50, 0.01s elapsed
Initiating Connect Scan at 19:50
Scanning 10.10.236.120 [3 ports]
Discovered open port 3306/tcp on 10.10.236.120
Discovered open port 80/tcp on 10.10.236.120
Discovered open port 22/tcp on 10.10.236.120
Completed Connect Scan at 19:50, 0.17s elapsed (3 total ports)
Initiating Service scan at 19:50
Scanning 3 services on 10.10.236.120
Completed Service scan at 19:50, 6.45s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.236.120.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 6.06s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 1.17s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Nmap scan report for 10.10.236.120
Host is up, received syn-ack (0.17s latency).
Scanned at 2022-01-11 19:50:16 EST for 13s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbp89KqmXj7Xx84uhisjiT7pGPYepXVTr4MnPu1P4fnlWzevm6BjeQgDBnoRVhddsjHhI1k+xdnahjcv6kykfT3mSeljfy+jRc+2ejMB95oK2AGycavgOfF4FLPYtd5J97WqRmu2ZC2sQUvbGMUsrNaKLAVdWRIqO5OO07WIGtr3c2ZsM417TTcTsSh1Cjhx3F+gbgi0BbBAN3sQqySa91AFruPA+m0R9JnDX5rzXmhWwzAM1Y8R72c4XKXRXdQT9szyyEiEwaXyT0p6XiaaDyxT2WMXTZEBSUKOHUQiUhX7JjBaeVvuX4ITG+W8zpZ6uXUrUySytuzMXlPyfMBy8B
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKb+wNoVp40Na4/Ycep7p++QQiOmDvP550H86ivDdM/7XF9mqOfdhWK0rrvkwq9EDZqibDZr3vL8MtwuMVV5Src=
|   256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4TcvlwCGpiawPyNCkuXTK5CCpat+Bv8LycyNdiTJHX
80/tcp   open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-title: Home
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
3306/tcp open  mysql   syn-ack MariaDB (unauthorized)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.62 seconds

```