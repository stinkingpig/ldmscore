#!perl -w
#############################################################################
# ldms_errorscan_parser.pl, v 2.0                                           #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_errorscan_parser              #
# Thanks to $Bill Luebkert for the command-line handling.                   #
# Thanks to Ken Hansen for debugging.                                       #
# Thanks to Charles Tank for Oracle support.                                #
#############################################################################
#
# See README_ldms_errorscan_parser.txt for documentation.
#

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
package PerlSvc;
use strict;
use warnings;
use DBI;
use Win32;
use Win32::EventLog::Message;
Win32::EventLog::Message::RegisterSource( 'Application', 'ldms_errorscan_parser' );
my $event = Win32::EventLog->new( 'ldms_errorscan_parser') || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
{
	Source => 'ldms_errorscan_parser'
};
use POSIX qw(floor);
use File::Copy;
use File::Remove qw(trash);

#############################################################################
# Variables                                                                 #
#############################################################################
our %A;		# get commandline switches into %A
for (my $ii = 0; $ii < @ARGV; ) {
	last if $ARGV[$ii] =~ /^--$/;
	if ($ARGV[$ii] !~ /^-{1,2}(.*)$/) { $ii++; next; }
	my $arg = $1; splice @ARGV, $ii, 1;
	if ($arg =~ /^([\w]+)=(.*)$/) { $A{$1} = $2; } else { $A{$1}++; }
}

#my $DEFDIR = 'C:\Program Files\LANDesk\ManagementSuite\ldscan\errorscan';
my $DEFDIR = 'G:\ldscan\errorscan';
my $errordir = shift || $DEFDIR;
my $dir = Win32::GetShortPathName($errordir);
my $db_type = $A{db_type} || 'SQL';
my $db_user = $A{db_user} || 'sa';
my $db_pass = $A{db_pass} || 'landesk';
my $db_name = $A{db_name} || 'lddb';
my $db_instance;
if ($db_type eq "SQL") {
	$db_instance = $A{db_instance} || 'GRANITE\LDMSDATA';
} else {
	$db_instance = 'null'; 
}
my ($trashcount,$renamecount,$undocount);
my $DEBUG = $A{d} || 0;
my $x = $A{x} || 0;
my $UNDO = $A{u};
(my $prog = $0) =~ s/^.*[\\\/]//;
my $ver = "1.7";
my $newname;
my $file;
my $marker;
my $usage = <<EOD;

Usage: $prog [-d] [-u] [-h] [-x=10] -db_type=[SQL|ORA] 
			 -db_user=USER -db_pass=PASS -db_name=DB [-db_instance=SERVER] 
			 <error_dir>
	-d			debug
	-u			undo any previous changes
	-x=[number]	delete scans more than [number] days old. Files go to the Recycle Bin.
	-h(elp)		this display
	db_instance is only necessary for SQL Servers, Oracle environments will pick it up from a properly configured client.
	<error_dir>	directory to find scan files (Def:
			$DEFDIR)

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This script will rename the scan files in ErrorScan to the computer name, for
easier troubleshooting.
The latest version lives at 
http://www.monkeynoodle.org/comp/landesk/ldms_errorscan_parser.

EOD

my $service = 'ldms_errorscan_parser';
my $delay   = 60;

# turn on autoflush
$|=1;

(my $progname = $0) =~ s/.*?([^\\]+?)(\.\w+)$/$1/;
our(%Config,$Verbose);

# These assignments will allow us to run the script with `perl ldms_errorscan_parser.pl`
unless (defined &ContinueRun) {
    # Don't delay the very first time ContinueRun() is called
    my $sleep;
    *ContinueRun = sub {
	Win32::Sleep(1000*shift) if $sleep && @_;
	$sleep = 1;
	return 1
    };
    *RunningAsService = sub {return 0};

    # Interactive() would be called automatically if we were running
    # the compiled ldms_errorscan_parser.exe
    Interactive();
}

sub get_options {
    require Getopt::Long;
    my @options = @_;
    my $usage = pop @options;
    $SIG{__WARN__} = sub { print "$usage\n$_[0]"; exit 1 };
    Getopt::Long::GetOptions(@options);
    $SIG{__WARN__} = 'DEFAULT';
}

# The --install and --remove options are implemented by PerlSvc and
# cannot be simulated when running via `perl ldms_errorscan_parser.pl`
sub unsupported {
    my $option = shift;
    die "The '--$option' option is only supported in the compiled script.\n";
}

sub configure {
    %Config = (ServiceName => $service,
	       DisplayName => "Ping Monitor of $host",
	       Parameters  => "--host $host --delay $delay --log $logfile",
	       Description => "Ping $ host every $delay seconds and ".
	                      "report availability to $logfile.");
}

# The Interactive() function is called whenever the ldms_errorscan_parser.exe is run from the
# commandline, and none of the --install, --remove or --help options were used.
sub Interactive {
    # These entries are only used when the program is run with
    # `perl ldms_errorscan_parser.pl` and is not compiled into a service yet.
    push(@options,
	 'help'    => \&Help,
	 'install' => \&unsupported,
	 'remove'  => \&unsupported);

    # Setup the %Config hash based on our configuration parameter
    configure();
    Startup();
}

# The Startup() function is called automatically when the service starts
sub Startup {
    get_options(@options, <<__USAGE__);
Try `$progname --help` to get a list of valid options.
__USAGE__

    Log("Interactive ping monitor of $host every $delay seconds\n");
    #print "Press Ctrl-C to stop...\n";

    Log("\n$Config{DisplayName} starting at: ".localtime);

    # $offline will contain the time that the host became unreachable
    my $offline;

    # Ping the host every 60 seconds.  ContinueRun() will return early
    # if the service receives a STOP, PAUSE or SHUTDOWN command.
    while (ContinueRun($delay)) {
	my $p = Net::Ping->new("icmp");

	if ($p->ping($host,8)) {
	    if ($offline) {
		Log(" unreachable for: ". (time()-$offline) ." s");
		$offline = 0;
	    }
	    # Give some feedback when running interactively
	    Log("$host is alive ".localtime) unless RunningAsService();
	}
	elsif (!$offline) {
	    Log("$host not reachable ".localtime);
	    $offline = time();
	}

	$p->close();
    }

    if ($offline) { # this outputs the downtime if the service is stopped
	Log(" unreachable for: ". (time() - $offline) ." s");
    }
    Log("$Config{DisplayName} stopped at: ".localtime);
}

sub Log {
    my $msg = shift;
    unless (RunningAsService()) {
		print "$msg\n";
		return;
    }

    # we should always check the return code to see if the open
    # failed.  die() might be a little harsh here, as it will
    # kill the service if there is a problem opening the log
    # file, but if the service can't log, then it isn't of much use.
    open(my $f, ">>$logfile") or die $!;
    print $f "$msg\n";
    close $f;
}

sub Install {
    get_options('name=s' => \$service, @options, <<__USAGE__);
Valid --install suboptions are:

  auto       automatically start service
  --name     service name                     [$service]
  --host     host name                        [$host]
  --log      log file name                    [$logfile]
  --delay    delay between pings in seconds   [$delay]

For example:

  $progname --install auto --name PingFoo --host www.foo.org --delay 120

__USAGE__

    configure();
}

sub Remove {
    get_options('name=s' => \$service, <<__USAGE__);
Valid --remove suboptions are:

  --name     service name                     [$service]

For example:

  $progname --remove --name PingFoo
__USAGE__

    # Let's be generous and support `PingSvc --remove PingFoo` too:
    $service = shift @ARGV if @ARGV;

    $Config{ServiceName} = $service;
}

sub Help {
    print <<__HELP__;
PingMonitor -- pings $host every $delay seconds and logs downtime in $logfile

Run it interactivly with configurable HOSTNAME, LOGFILE and DELAY:

    $progname --host HOSTNAME --log LOGFILE --delay SECONDS

or install it as a service:

    $progname --install auto
    net start $service

You can pause and resume the service with:

    net pause $service
    net continue $service

To remove the service from your system, stop und uninstall it:

    net stop $service
    $progname --remove
__HELP__

    # Don't display standard PerlSvc help text
    $Verbose = 0;
}

sub Pause {
    Log("$Config{ServiceName} is about to pause at ".localtime);
}

sub Continue {
    Log("$Config{ServiceName} is continuing at ".localtime);
}
