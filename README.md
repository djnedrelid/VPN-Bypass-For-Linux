## VPN Bypass For Linux  
A .NET version I made for GNU/Linux a while ago as a side-project to the Windows version. YMMV. 

## DISCLAIMER  
While this software has been tested working on Debian 9 and Ubuntu 16.04 before 
being released, it comes without any kind of warranty or promise, use at your 
own risk.  

## INSTALLATION (as root or with sudo) 
```
NOTE: In addition to the VPN Bypass software, install.sh will update apt and 
      install the requisites needed: dnsutils, iproute2, mono-complete if they 
      are missing. I realize Mono (http://www.mono-project.com/) is a big 
      package (400MB), but this was mainly a Windows project to begin with and 
      it made it possible for me to quickly adapt and offer the same 
      functionality to GNU/Linux. I may create or convert other projects in the 
      future that take advantage of this framework as well.  

    $ unzip VPNBypassForLinux.zip; cd VPNBypassForLinux  
    $ chmod 755 Install.sh  
    $ sudo ./Install.sh -i  
    (!) Edit settings in: /etc/VPNBypassForLinux.conf (!)  
    $ sudo service VPNBypassLinuxService start  
    
## FAQ
Q: What exactly does the program do?
A: It resolves configured domains to bypass the VPN gateway that becomes 
   default when connected to VPN, by using the local instead. It keeps the 
   hosts file and routing table updated and creates a secondary gateway table 
   and ip rule to route incoming/outgoing traffic to the selected interface.

Q: Where is the log located?
A: /var/log/VPNBypassForLinux.log

Q: How do I uninstall?
A: $ sudo ./Install.sh -r

Q: How do I check the version?
A: $ mono /usr/local/bin/VPNBypassLinux.exe /version

Q: How do I check the routing status? 
A: Manually or with the 'VPNB' command.
   
Q: How much RAM does it use?
A: As a Mono process about 25-30 MiB physical memory during testing.
   
Q: My hosts file does not seem to be prioritized by my OS.
A: Check /etc/nsswitch.conf and /etc/host.conf

Q: IT DOESN'T WORK!
A: I'm sorry! Maybe check port forwarding and firewall setup.
   There's also the possibility that more outgoing connections 
   needs to be added. You can trace those with e.g. tcpdump.

Q: What systems is it supposed to work on?
A: It's designed for Debian and Ubuntu primarily, but should work on most 
   GNU/Linux distributions that supports System V init scripts with basic 
   LSB header configuration for the service. 

Q: There seems to be a lot of extra IP addresses in the routing table?
A: Restart the service to get rid of them if you want. If the domain you're 
   bypassing has a very active load balacing scheme, there will be a few IP 
   addresses from it, but this is normally a good thing and what you'd want. 
   If you decide to remove a domain in the configuration, the service restart 
   will automatically clean old stuff up for you.

Tux says hi.
```