#!/usr/bin/perl
#
# Installer for trapper ;)
#
# Jorge A. Trujillo <crypkey@0hday.org>
# F. Javier Carlos Rivera <nediam@nediam.com.mx>
# Enrique A. Sanchez Montellano <nahual@0hday.org>
#
# Special thanks to: nitr0us 
#

use CPAN;

if (($> != '0')) { die ("\nError: You need to be root in order to run this program!\n\n"); }
print "\n[*] Trapper Installer\n";
print "[*] Make sure your CPAN is upgraded\n\n";
print "Are you ready to continue? (Y/N) [Y]: ";
$response=<STDIN>;

if($response=~/n/i){ exit; }

for $mod (qw(Proc::Simple Getopt::Std Time::HiRes Net::Pcap NetPacket::IP NetPacket::TCP NetPacket::Ethernet Net::IP Net::ARP Net::RawIP Net::Ping Net::Frame Net::Frame::Layer Net::Frame::Layer::ARP Net::Frame::Simple Net::Frame::Dump Net::Frame::Dump::Online2 MIME::Base64 Tie::File DBI DBD::SQLite URI::Escape JSON Config::Simple IO::Uncompress::Gunzip)) {

	print "[*] Checking for: $mod...\t";
	eval "use $mod";
	if(!$@){
		print "[OK]\n";
		next;
	}
	else { 
		print "[Failed]\n\n"; 
		sleep(2);
		if($mod ne "Net::Pcap") {
			my $obj = CPAN::Shell->install($mod);
			eval "use $mod";
			if($@) { die("\n\nCould not install $mod for some reason. Try it manually and run again the installer."); }
			else {
				print "\n\nInstallation complete, continuing with setup\n";
			}
		}
		else {
			print "\n\n[*] Downloading Net-Pcap...\n";
			`wget http://search.cpan.org/CPAN/authors/id/S/SA/SAPER/Net-Pcap-0.16.tar.gz`;
			`tar -xzvf Net-Pcap-0.16.tar.gz`;
			`cd Net-Pcap-0.16/ ; perl Makefile.PL ; make ; make install`;
			eval "use $mod";
			if($@) { die("\n\nCould not install $mod for some reason. Try it manually and run again the installer."); }
			else { print "\n\nInstallation complete, continuing with setup\n"; }
		}
	}
}

for(@INC){
	if(-d $_) {
                for $tr_pm (<*.pm>){
                         print "[*] Copying $tr_pm in $_...\t";
                        `cp modules/$tr_pm $_`;
                         `chmod 644 $_/$tr_pm`;
                        print "[OK]\n";
                }
                last;
        }
}

`rm -rf Net-Pcap-0.16`;
`rm -rf Net-Pcap-0.16.tar.gz`;

print "[*] Installation done, you can run now trapper =)\n\n";
