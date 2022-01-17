## Enumeration
* Get joomla version
	* https://www.itoctopus.com/how-to-quickly-know-the-version-of-any-joomla-website
	* ![](Pasted%20image%2020220111200947.png)
* /robots.txt
![](Pasted%20image%2020220111195609.png)




## Exploiting

* Version 3.7.0 of joomla is vulnerable to SQLi
* Exploiting with [this python script](https://github.com/stefanlucas/Exploit-Joomla), gives us:
![](Pasted%20image%2020220111204634.png)

* Of note is a user and their PW hash
	* `Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']`
* Running the hash through john gives us `spiderman123` as the password
![](Pasted%20image%2020220111205945.png)

* Login to `/administrator` with those creds and look to setup a reverse shell.
	* To do so, edit the `beez3/index.php` to be a basic php-reverse shell from pentestmonkey.
	* Stand up the listender and catch the shell when navigating to `/templates/beez3/index.php`
![](Pasted%20image%2020220111211302.png)

* Since this is an apache server, check `/var/www/html` for any interesting files - we find `configuration.php`. It also contains a `root` user and password (`nv5uz9r3ZEDzVjNu`)
	* Cant SSH with the root creds
![](Pasted%20image%2020220111211858.png)

### Exploiting creds

* The creds found in `/var/www/html/configuration.php` didnt match for the `root` user on ssh or mysql. There was another user in the `/home` - jjameson.
	* Running the above password against `jjameson` with ssh got us a shell
	![](Pasted%20image%2020220111212517.png)

* From here, do standard initial recon for SUID binaries and sudo privs.
	* `sudo -l` shows that we can run `yum` as root, gtfobins gives us [this](https://gtfobins.github.io/gtfobins/yum/), and we quickly get root.
	![](Pasted%20image%2020220111212806.png)

![](Pasted%20image%2020220111212849.png)