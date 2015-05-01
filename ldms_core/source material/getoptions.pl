use Getopt::Long;

my $ver = 0;
my $usage = <<"EOD";

Usage: $prog [-d] [-u] [-h] [-x=10] -db_type=[SQL|ORA] 
			 -db_user=USER -db_pass=PASS -db_name=DB [-db_instance=SERVER] 
			 -m=ADDRESS -f=ADDRESS -s=SERVER -m_user=USER -m_pass=PASS
             -m_type=TYPE
             [-nmap="x:\\foo"] [-nmap_options="-bar -baz"]
             [-v=(1-5)] [-update=(0-7)] [-map]
			 
	-d(ebug)	 debug
	-x=[number]	 delete scans and patches more than [number] days old. Files go
                  to the Recycle Bin. Default is off. This option also controls
                  removal of unmanaged device records which are no longer on
                  the network.
	-m=me\@here	 email address to send output report to.
	-f=ld\@here	 email address to send output report from.
	-s=host		 email server to send output report through.
    -v           verbosity threshold for email sending.
    -m_user=user email server username for TLS authentication.
    -m_pass=pass email server password for TLS authentication.
    -m_type=type email server authentication type for TLS authentication.
	-setup		 setup the product.
	-h(elp)		 this display
	db_instance  is only necessary for SQL Servers, Oracle environments will
                  pick it up from a properly configured client.
	nmap         By default, "C:/Program Files/nmap/nmap.exe"
	nmap_options By default, "-A T4 -P0 -n
	-u			 Should NMAP rescan devices it couldn't identify earlier?
	-update      Days before checking online for an updated version
    -map         Should ldms_core generate a network topology map?

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program maintains your LANDesk core server. It provides HTML reports 
and will email you if there's something important.
The latest version lives at http://www.droppedpackets.org/scripts/ldms_core.

EOD


my $DEBUG = '';	# option variable with default value (false)
my $help = '';	# option variable with default value (false)
my $map = '';
my $setup = '';

GetOptions ('/',
    'debug' => \$DEBUG, 
    'help' => \$help, 
    'map' => \$map, 
    'setup' => $setup);

if ($DEBUG) { print "you said debug\n"; }
if ($help) { print $usage; }
if ($map) { print "you said map\n"; }
if ($setup) { print "you said setup\n"; }

my $deletiondays = 14;
my $time = time() - ($deletiondays * 86400);
print "time is $time\n";
