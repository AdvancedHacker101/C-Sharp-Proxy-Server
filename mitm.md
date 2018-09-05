# Man in the Middle attacks
## Blocking a server by hostname  
This tutorial will walkthrough the process of blacklisting a specific hostname.  
Let's say we want to block all hostnames, which begin with *mail.*  
Commands:  
`mitm up` - Start the MITM service  
`mitm` - Enter interactive mode  
`create_filters` - Create all filters required for blocking actions  
`exit` - exit interactive mode  
`filter_manager up` - Start filter manager service  
`filter_manager` - Enter interactive mode  
`setup mitm_hostblock_black startsWith mail.` - Add a rule to the filters which will return true when a host *startsWith* *mail.*  
`exit` - Leave interactive mode  
`mitm` - Again enter MITM...  
`check_filters` - Check if the filters a working correctly  
`mitm_hostblock up` - Enable the MITM host blocking service  
`exit` - Leave interactive mode  
`start` - Start the server  
(Optional) `set mode http mitm` - if you want to tamper http requests/responses  
(Optional) `set mode https mitm` - if you want to decrypt and view https requests/responses  
And that's it, do either one or two of the optional commands.  
if you choose http the client will not be alerted only http traffic will get handled by mitm manager, the https traffic remains to be forwarded normally  
if you choose https the client will get presented with a big alert, if the client accepts the alert then the data will continue to flow and mitm manager can handle https stuff  
## Setting up HTTPs MITM Attacks  
The program has a built in help for this  
Just type `help int config_ssl_mitm` - to run that help!  
## Setting up POST Request Dump  
Also a built in help exists, just type `help int config_post_dump` - to run that help.  
To get more help menus type `help int` to list available names!  
## Setting up Cookie Dump  
Dump all cookies sent by the client:  
`mitm up` - Enable MITM service
`mitm` - Enter interactive mode  
`create_dumpers` - Create all dump entries required for the dumps to work  
`mitm_cookie_dump up` - Enable the cookie dumping  
`exit` - exit interactive mode  
`start` - Start the server  
Set MITM mode for one or all protocols with the above methods.  
You can read the cookies at Dump\cookie_dump.txt.  
## Setup automatic injection  
If it doesn't matter what response, or where the content get's injected in, then type `help int config_inject` - to get help about auto injection  
## Setup matching injection  
If it does matter, then use match injection for a line-by-line scan for the injection's location
Just follow through the code:  
```
mitm up
mitm
mitm_inject_core up
inject_manager
set match_option [Match Option]
set match_mode [Match Mode]
set macth_engine [Match Engine]
exit
exit
```  
Based on the Match Engine you choose you have (filter or regex).  
Filter:  
```
filter_manager up
filter_manager
setup mitm_inject_match_and startswith [for example <p id="2">]
exit
mitm
bind filter mitm_inject_match_and
```  
Regex:  
```
regex_manager up
regex_manager
add exp mitm_inject_match_and [Regex]
exit
mitm
bind regex mitm_inject_match_and inject_and
```  
Then doesn't matter what you choose continue with:  
```
exit
start
```
Enable MITM on one or all protocols using one of the methods above!  
An you are set! (Inject some leet beef h00ks?) :)
