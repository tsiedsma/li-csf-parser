![](https://lithiumhosting.com/images/logo_new_black.png)

## PHP CSF Deny Parser
**from Lithium Hosting**  
We're always open to pull requests, feel free to make this your own or help us make it better.

### Copyright
(c) Lithium Hosting, llc

### License
This library is licensed under the MIT license; you can find a full copy of the license itself in the file /LICENSE

### Requirements
* PHP 5.5.9 or newer
* [Carbon](http://carbon.nesbot.com) *installed via composer

### Description
CSF is Config Server Firewall, most commonly used on cPanel servers.  
CSF can be obtained [here](http://configserver.com/cp/csf.html).

* * *

### Usage

The purpose of this script is to provide an easy way to parse the Deny file and output the important bits to an array.  
The initial commit was written in a few hours, so it probably needs some work.

**Installation**  
Installation is easy, just add the following to your composer.json and then run composer update
```
"lhdev/li-csf-parser": "dev-master"
```

Example csf.deny file  
Path: /etc/csf/csf.deny 
```
###############################################################################
# Copyright 2006-2015, Way to the Web Limited
# URL: http://www.configserver.com
# Email: sales@waytotheweb.com
###############################################################################
# The following IP addresses will be blocked in iptables
# One IP address per line
# CIDR addressing allowed with a quaded IP (e.g. 192.168.254.0/24)
# Only list IP addresses, not domain names (they will be ignored)
#
# Note: If you add the text "do not delete" to the comments of an entry then
# DENY_IP_LIMIT will ignore those entries and not remove them
#
# Advanced port+ip filtering allowed with the following format
# tcp/udp|in/out|s/d=port|s/d=ip
#
# See readme.txt for more information regarding advanced port filtering
#
127.0.0.1 # lfd: (ftpd) Failed FTP login from 127.0.0.1 (CN/China/-): 20 in the last 300 secs - Sat Oct 31 18:05:33 2015
127.0.0.1 # lfd: (sshd) Failed SSH login from 127.0.0.1 (MU/Mauritius/-): 20 in the last 300 secs - Sat Oct 31 18:37:08 2015
127.0.0.1 # lfd: (cpanel) Failed cPanel login from 127.0.0.1 (PL/Poland/-): 20 in the last 300 secs - Sat Oct 31 18:45:36 2015
```

**Standard Usage**
```php
<?php
$data = 'The example file contents above';
$csf = new LithiumDev\CSFParser\CSFParser($data);
$results = $csf->parse();
die('<pre>' . print_r($results, 1) . '</pre>');
```
Produces:
```
Array
(
    [0] => Array
        (
            [ip] => 127.0.0.1
            [host] => 
            [reason] => Failed FTP login
            [count] => 20
            [date] => 2015-10-31 18:05:33
        )

    [1] => Array
        (
            [ip] => 127.0.0.1
            [host] => 
            [reason] => Failed SSH login
            [count] => 20
            [date] => 2015-10-31 18:37:08
        )

    [2] => Array
        (
            [ip] => 127.0.0.1
            [host] => 
            [reason] => Failed cPanel login
            [count] => 20
            [date] => 2015-10-31 18:45:36
        )

)
```

**Optional Usage cases**  
Return the hostname along with IP:
```php
// This optional boolean variable will cause the host value in the array to contain the results of gethostbyaddr
// When doing a large import, this will take a lot of time and depending on your server settings can lead to script timeouts.
$csf = new LithiumDev\CSFParser\CSFParser($data, true);
$results = $csf->parse();
```
Set the default timezone:
```php
// This sets the timezone so all dates are set properly.
$csf = new LithiumDev\CSFParser\CSFParser($data);
$csf->setTimeZone('America\Chicago');
$results = $csf->parse();
```
Chaining Methods:
```php
$results = new LithiumDev\CSFParser\CSFParser($data, true)->setTimeZone('America\Chicago')->parse();
```