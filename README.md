-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

Official Site: https://github.com/nahualito/trapper
For tutorials, screenshots, videos and more.

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

---:[ Programmed by ]:---

Jorge A. Trujillo <crypkey@0hday.org>
F. Javier Carlos Rivera <nediam@nediam.com.mx>
Enrique A. Sanchez Montellano <nahual@0hday.org>

This is propietary code of 0hday.org for enciclopedia
pentestica, this is is released under beerware license
don't remove this headers and send comments to nahualito@cthuluhsecurity.com
(YES it does exist, ping emails will not be answered) 

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

---:[ Trapper Requires ]:---

-DBI
-Getopt::Std
-Time::HiRes
-Proc::Simple
-NetPacket::IP
-NetPacket::TCP
-NetPacket::Ethernet
-Net::IP
-Net::RawIP
-Net::Pcap
-Net::Ping
-Net::ARP
-Net::Frame
-Net::Frame::Layer
-Net::Frame::Layer::ARP
-Net::Frame::Simple
-Net::Frame::Dump
-Net::Frame::Dump::Online2


---:[ Disclaimer ]:---

THIS PROJECT WAS DEVELOPED FOR TESTING PURPOSES AND IT'S STILL IN BETA PHASE.

---:[ Before using || Installation ]:---

Just run 'perl install.pl' if everything is ok
you can continue and use trapper otherwise you will need to
install all the modules needed.

Note: If you having troubles installing any modules or have some
tests error with cpan, just search and install the module
manually http://search.cpan.org/

---:[ Configuration ]:---

Edit trapper.conf pretty basic configuration so ;)
The only thing that probably you need to know is if you using
cookie injector feature you need to enable change:

"monster" from off to on.

And change also the path of "monsterhome", example:

monsterhome = /home/linuxuser

NOTE: Since firefox uses sqlite to manage cookies, COOKIE INJECTOR IS STILL ON
EXPERIMENTAL stage, so it may work or not, report any bugs.

---:[ Usage ]:---

Well it's pretty simple..

# perl trapper.pl -i <interface> -m <mode> [-v msn,cookie,irc] [-f fake_mac || random]

Example: # trapper -i eth0 -m apr -v cookie -f 00:11:22:33:44:55

-> FAKE MAC STILL ON BETA <- We support most of the distros on linux
if you have any problems with it please contact us so we can take a look into it.

Sniffed data will be showed on the terminal and saved.
If you choose random on mac option, trapper will generate a random mac to use it.

---:[ Sniff MODE ]:---

This option will give you this output:

[*] MODE SELECT
trapper typing Ctrl+C.

---:[ Verbose ]:---

You can use -v msn || cookie || irc
	  or
  -v msn,cookie,irc for all

This option is only to show their output and avoid
flood on the screen but you can enable them if
you want =).

---:[ Trapper will save all the info ]:---

All the important info is saved in the files:

/irc
/irc.txt
/telnet.txt
/http.txt
/cookies.txt
/ftp.txt 
/smb.txt
/pop3.txt
/imap.txt
/teamspeak_msgs.txt

MSN conversations, e-mails and irc conversations are saved in:

/msn/
/mails/
/$server/$channel
/irc/private_msg/

---:[ Bug Report/Suggestions/Troubles ]:---

Official site - https://github.com/nahualito/trapper

Or contact us at: (We might not respond)

crypkey@gmail.com (status unknown)
nediam@nediam.com.mx (dead domain alive hacker)
nahual@0hday.org (alive still never read emails)

---:[ EOF ]:---

Have fun!
