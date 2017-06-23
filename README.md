# C\# Proxy Server
This is an open source proxy server for windows machines with .NET Framework installed.  
The server can act as a normal proxy server, forwarding all traffic to the destination without any tampering.  
But the server can also act as a MITM Proxy Server, intercepting, modifying traffic automatically, or based on patterns.  
This program is a console like program.  
## Using it as Normal:
Type `set ip any` and press enter, to set the IP of the server to any, open out to the internet.  
Then type `set port 8080` to set the port of the server to 8080 (most proxy servers use port 8080).  
Then type `start` to start the server, accept any firewall warnings, the server will not work without accepting the firewall pop-up.  
That's it, your server is now working normally, to save the current settings type:  
`save normal` - This will create a normal.xml file under the profiles folder.  
Any time you close the program and re-open it just type:  
`load normal` - this wil load the previously saved settings.  
**Loading a settings file will NOT start the server, you need to start it by using the start command**  
For advanced settings read: [Advanced Settings](https://github.com/AdvancedHacker101/C-Sharp-Proxy-Server/blob/master/advanced.md)  
For MITM stuff read: [MITM Mode](https://github.com/AdvancedHacker101/C-Sharp-Proxy-Server/blob/master/mitm.md)  
Features planned to be added:  
- [ ] Capture HTTP Basic Auth Requests
- [ ] SOCKS5 Mode
- [ ] Communication with the [C# R.A.T Client](https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client)
## More information
You can read the licence [here](https://github.com/AdvancedHacker101/C-Sharp-Proxy-Server/blob/master/LICENSE)  
You can read the code of conduct [here](https://github.com/AdvancedHacker101/C-Sharp-Proxy-Server/blob/master/CODE_OF_CONDUCT.md)  
You can read how to contribute [here](https://github.com/AdvancedHacker101/C-Sharp-Proxy-Server/blob/master/CONTRIBUTING.md)
