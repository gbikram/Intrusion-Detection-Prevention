#!/usr/bin/perl
# sneeze.pl v 1.0
# 8/3/2001
# Don Bailey (baileydl@mitre.org) and Brian Caswell (bmc@mitre.org)

require 'getopts.pl';

# require destination and rule file or help
Getopts('d:f:c:s:p:i:h:x');
if ($opt_h || (!$opt_d && !$opt_f)) {
die "Usage $0 -d <dest host> -f <rule file> [options]\
\t-c count\tLoop X times. -1 == forever. Default is 1.\
\t-s ip\t\tSpoof this IP as source. Default is your IP.\
\t-p port\t\tForce use of this source port.\
\t-i interface\tOutbound interface. Default is eth0.\
\t-x debug\tTurn on debugging information.\
\t-h help\t\tDuh? This is it.\n";
}

use Net::RawIP;

# setup our sneeze objects for tcp, icmp, and udp
$sneeze_tcp = new Net::RawIP ({tcp => {}});
$sneeze_icmp = new Net::RawIP ({icmp => {}});
$sneeze_udp = new Net::RawIP ({udp => {}});
$sneeze_ip = new Net::RawIP ({generic => {}});

my $DEBUG = 0;
if ($opt_x) { $DEBUG = 1; }

my $refurls;
$refurls{bugtraq} = "http://www.securityfocus.com/bid/";
$refurls{cve} = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=";
$refurls{arachnids} = "http://www.whitehats.com/info/IDS";
$refurls{mcafee} = "http://vil.nai.com/vil/dispVirus.asp?virus_k=";
$refurls{url} = "http://";

# parse some options if they exist or set default values

chomp($forcesrc = `hostname`);

$setsrc = $opt_s;
if ($opt_p) { $srcport = $opt_p; }
if($opt_i) {
$sneeze_tcp->ethnew($opt_i);
$sneeze_icmp->ethnew($opt_i);
$sneeze_udp->ethnew($opt_i);
$sneeze_ip->ethnew($opt_i);
}
$loop = ($opt_c) ? $opt_c : 1;

# add rules
my @rulez = add_rules($opt_f);

sub add_rules
{
   my ($file) = @_;
   my @rules;

   open(RULES,$file) || die "Cannot open $file!\n";
   my @lines = <RULES>;
   close (RULES);

   foreach my $line (@lines) {
      chomp ($line);
      if ($line =~ /^include (.*)$/) {
          if ($opt_x) { print "Adding include of $1\n";}
          my @line_rules = add_rules($1);
          push (@rules,@line_rules);
      }
      else {push (@rules,$line);}
   }
   return (@rules);
}

@rulez = set_vars(@rulez);

sub set_vars
{
   my (@rules) = @_;
   my @returns;
   my $vars;
   foreach my $line (@rulez)
   {
      if ($line =~ /^var ([\w]+)(.*)/)
      {
         if ($DEBUG) { print "Got variable $1 set to $2\n";}
         $vars{$1} = $2;
      }
      foreach my $key (keys (%vars))
      {
         $line =~ s/\$$key/$vars{$key}/g;
      }
      push (@returns, $line);
   }
   return (@returns);
}




# for every rule in rule file, parse and send a packet like that to dest
foreach $rule (@rulez) {

my $dsize;
        if ($rule =~ /^\s*#/ || $rule eq "\n") {
                next;
        }

        # only use "alert" and "log" rules
        # if ($rule !~ /^(alert|log)/) { next; }

        # ALERT|LOG PROTO src srcport direction dst dstport
        $rule =~ /(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>|<-)\s+(\S+)\s+(\S+)(.*)$/;
  $attack = $1;
        $proto = $2;
        $rule_src = $3;
        if (!$setsrc) {
if ($rule_src =~ /^(\d+\.\d+\.\d+\.\d+)/ ) { $src = $1; }
else { $src = $forcesrc; }
        }

        $srcport = $4;
        $direction = $5;
        #$dst = $6;
        $dstport = $7;
        $rest = $8;

        $content = undef;
        if ($rest =~ /msg\s*:\s*"([^"]+)/i) { $msg = $1; }
        if ($rest =~ /flags\s*:\s*([^;]+)/i ) { $flags = $1; }
        if ($rest =~ /dsize\s*:\s*([^;]+)/i ) { $dsize= $1; }
        if ($rest =~ /classtype\s*:\s*([^;]+)/i ) {$type= $1; }
        if ($rest =~ /depth\s*:\s*([^;]+)/g ) {$depth = $1; }
        if ($rest =~ /sameip;/i) { $src = $opt_d; }
        $rest =~ s/nocase;//g;


        my $payload;
        my $contents = $rest;

        if ($contents =~ /content\s*:\s*"[^"]+.*content\s*:\s*"[^"]+/)
        {
           while ($contents =~ /content/)
           {
           if ($contents =~ s/content:"([^"]+)\"\;\s+offset:(\d+)\;(.*)/$3/i)
           {
              my $tmp = $1;
my $offset = $2;
              my $pad = 'A' x $offset;
push (@contents,parse_content($pad . $tmp));
}
           elsif ($contents =~ s/content\s*:\s*"([^"]+)(.*)/$2/i)
           {
              push (@contents,parse_content($1));
}
           }
  }
foreach (@contents) { $payload = $payload . $_; }

        $ref = $rest;
        my @refs;
        while ($ref =~ s/(.*)reference:([^\;]+)(.*)$/$1 $3/)
        {
           my $tmp = $2;
           if ($tmp =~ /(\w+),(.*)/i) { $tmp = $refurls{$1} . $2; }
           push (@refs,$tmp);
        }

if($dsize) {
                my $dsize_len = $dsize;
                $dsize_len =~ s/dsize: //;
                $dsize_len =~ /([\D]{0,1})(\d+)$/;
                $dsize_len = $2;
                my $gtolt = $1;
                my $length = length ($payload);
                my $need = $dsize_len - $length;
                if ($gtolt eq ">") {
                        $need++;
                } elsif ($gtolt eq "<") {
                        $need--;
                }

                my $pad = 'A' x $need;
                $payload = $payload . $pad;
        }

push @attacks, { src => $src, dst => $opt_d, dstport => $dstport,
srcport => $srcport, payload => $payload,
msg => $msg, proto => $proto, refs => \@refs,
type => $type, sig => $rule
};
}


# loop for loop amount of times or forever if loop was -1
$count = 0;
while (($count < $loop) || ($loop == -1)) {
foreach my $attack (@attacks)
{
   if ($attack->{srcport} !~ /\d+/) {
      $attack->{srcport} = int(rand(65535));
   }

   if ($attack->{dstport} !~ /\d+/) {
      $attack->{dstport} = int(rand(65535));
   }

   print "ATTACK: $attack->{msg}\n";
   if ($attack->{type}) { print "ATTACK TYPE: $attack->{type}\n"; }
   print "$attack->{proto} $attack->{src}:$attack->{srcport} -> $attack->{dst}:$attack->{dstport}\n";
   $refs = $attack->{refs};
   if ($refs) { foreach (@$refs) { print "Reference => $_\n"; } }
   if ($DEBUG) { print "SIGNATURE $attack->{sig}\n"; }
   print "\n";

   if ($attack->{proto} =~ /tcp/i) {
     $sneeze_tcp->set({ip =>{saddr => $attack->{src}, daddr => $attack->{dst}},
tcp => {source => $attack->{srcport} ,dest => $attack->{dstport},
        ack => 1, data => $attack->{payload} }});
      $sneeze_tcp->send;
   } elsif ($attack->{proto} =~ /icmp/i ) {
      $sneeze_icmp->set({ip => {saddr =>$attack->{src},daddr =>$attack->{dst}},
          icmp => {data => $attack->{payload} }});
      $sneeze_icmp->send;
   } elsif ($attack->{proto} =~ /udp/i ) {
$sneeze_udp->set({ip =>{saddr => $attack->{src},daddr =>$attack->{dst}},
udp => {source => $attack->{srcport},dest => $attack->{dstport},
data =>$attack->{payload} }});
$sneeze_udp->send;
   } else {
$sneeze_ip->set({ip => {saddr => $attack->{src},daddr =>$attack->{dst}},
generic => {data => $attack->{payload} }});
   } # end if elsif for packet gen stuff
} # end foreach

$count++;
} # end while


sub parse_content
{
   my ($content) = @_;
   my $end; my $hex2a;
   $content =~ s/([^|]*)(.*)/$2/;
   my $pre = $1;
   if ($content =~ /\|/) {
      $content =~ s/([^|]+)\|(.*)/$1/;
      my $hex = $1; my $post = $2;
      while ($hex =~ s/(\w{2})(.*)/$2/) {
         $hex2a .= chr(hex $1);
      }
     if ($post) { $end = parse_content($post); }
   }
   return ($pre . $hex2a . $end);
}

