#############################################################################
# ldms_nmap_udd.pl, v 2.9                                                   #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/networking/ldms_nmap                        #
# Thanks to $Bill Luebkert for the command-line handling.                   #
#############################################################################
#
# See README_ldms_nmap_udd.txt for documentation.

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use warnings;
use strict;
use DBI;
use Win32::API::Prototype; # http://www.roth.net/perl/packages
use Win32::TieRegistry (Delimiter=>"/", ArrayValues=>1);
my ($RegRoot, $RegKey);
use Win32::EventLog::Message;

# suppress all output -- otherwise NMAP's occasional noise will end up in the event viewer
use File::Spec;
open(STDOUT, '> ' . File::Spec->devnull);
open(STDERR, '> ' . File::Spec->devnull);


#############################################################################
# Variables                                                                 #
#############################################################################
my $sql;
my @row;
my (@Computer, @OS, @Address);

our %A;		# get commandline switches into %A
for (my $ii = 0; $ii < @ARGV; ) {
	last if $ARGV[$ii] =~ /^--$/;
	if ($ARGV[$ii] !~ /^-{1,2}(.*)$/) { $ii++; next; }
	my $arg = $1; splice @ARGV, $ii, 1;
	if ($arg =~ /^([\w]+)=(.*)$/) { $A{$1} = $2; } else { $A{$1}++; }
}

my $DEBUG = $A{d} || 0;
my $delete = $A{x} || 0;
our $goodcount = 0;
our $badcount = 0;

# where does NMAP live?
my $nmap = $A{nmap} || Win32::GetShortPathName("C:/Program Files/nmap/nmap.exe");
my $nmap_options = $A{nmap_options} || "-A -T4 -P0 -n";

# how do I get into the database?
$RegRoot = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite"};
my ($db_type, $db_user, $db_pass, $db_name, $db_instance);
$RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Core/Connections/Local"};
if ($RegKey) {
	my $oracle = $RegKey->GetValue("IsOracle");
	if ($oracle =~ m/true/i) {
		$db_type = "ORA";
	} else {
		$db_type = "SQL";
	}
	$db_name = $RegKey->GetValue("Database");
	$db_instance = $RegKey->GetValue("Server");
	$db_user = $RegKey->GetValue("User");
}

# Allow command-line to override registry-provided values
if ($A{db_type}) { $db_type = $A{db_type}; }
if ($A{db_user}) { $db_user = $A{db_user}; }
$db_pass = $A{db_pass} || 'landesk';
if ($A{db_name}) { $db_name = $A{db_name}; }
if ($db_type eq "SQL") {
	if ($A{db_instance}) { $db_instance = $A{db_instance}; }
}

(my $prog = $0) =~ s/^.*[\\\/]//;
my $ver = "2.9";
Win32::EventLog::Message::RegisterSource( 'Application', $prog);
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
{
	Source => $prog
};

my $usage = <<EOD;

Usage: $prog [-d=1] [-h] [-x=N] [-nmap="x:\\foo"] [-nmap_options="-bar -baz"] [-u=1]
			 -db_user=USER -db_pass=PASS -db_name=DB -db_instance=SERVER -db_type=[SQL|ORA]
	-d			debug
	-h(elp)		this display
	-x=N		delete machines that haven't been seen in N days
	-u			skip machines that NMAP was unable to identify in the past
	db_instance is probably the name of the SQL Server, but may have \\LDMSDATA
	nmap		By default, "C:/Program Files/nmap/nmap.exe"
	nmap_options By default, "-A T4 -P0 -n"

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This script will properly identify the OS of the machines in Unmanaged Devices
The latest version lives at 
http://www.droppedpackets.org/networking/ldms_nmap

EOD

#############################################################################
# The Main Loop -- Casual Users Shouldn't Edit Past Here                    #
#############################################################################
die $usage if $A{h} or $A{help};
if (!-e $nmap) { croak "Cannot find NMAP at $nmap\n"; }

# Suppress DOS Windows
BEGIN {
    Win32::SetChildShowWindow(0) if defined &Win32::SetChildShowWindow;
}

# Set the process priority so we don't murderize the CPU.
ApiLink( 'kernel32.dll', "BOOL SetPriorityClass( HANDLE hThread, DWORD dwPriorityClass )" ) || croak "Unable to load SetPriorityClass()";
ApiLink( 'kernel32.dll', "HANDLE OpenProcess()" ) || croak "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "HANDLE GetCurrentProcess()" ) || croak "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "BOOL CloseHandle( HANDLE )" ) || croak "Unable to load CloseHandle()";
my $hProcess = GetCurrentProcess();
if ( 0 == SetPriorityClass( $hProcess, 0x00000040) ) {
	Log("Unable to set master PID scheduling priority to low.");
} else {
	Log("$prog $ver starting: master PID scheduling priority set to low.");
}
CloseHandle( $hProcess );

# Open the database
my ($DSN,$dbh,$sth);
if ($db_type eq "SQL") {
	$dbh = DBI->connect("dbi:ODBC:driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass") or croak "$DBI::errstr\n";
} elsif ($db_type eq "ORA") {
	$dbh = DBI->connect("DBI:Oracle:$db_name",$db_user,$db_pass) or croak "$DBI::errstr\n";
} else {
	croak "Cannot connect, Database type is not specified!\n";
}

# Delete if it's older than X days
if ($delete) {
	if ($DEBUG) {
		$sql = "select count(*) from UNMANAGEDNODES where LASTSCANTIME < GetDate()-$delete";
		$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
		$sth->execute or die "$DBI::errstr\n";
		my $deletecount = $sth->fetchrow;
		Log("Deleting $deletecount records which have not been scanned in $delete days.");
	}
	$sql = "delete from UNMANAGEDNODES where LASTSCANTIME < GetDate()-$delete";
	$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
	$sth->execute or die "$DBI::errstr\n";
}

# Get all nodes with no osname or meaningless osname, unless xddexception is set
$sql="select UNMANAGEDNODES_IDN,IPADDRESS from UNMANAGEDNODES where XDDEXCEPTION='0' and OSNAME is null or OSNAME='' or OSNAME='UNKNOWN' or OSNAME='UNIX' ";
# Skip the ones NMAP had trouble with before, if the admin so desires
if ($A{u}) {
	$sql.="or OSNAME='Unidentified' ";
}
# Ordered by most-recently seen
$sql.="order by LASTSCANTIME desc";
my $count=0;
$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
while (@row = $sth->fetchrow) {
	$Computer[$count] = &trim($row[0]);
	$Address[$count] = &trim($row[1]);
	$count ++;
}
$sth->finish();

# If we've got target nodes, we've got work to do.
if ($count >= 1) {
	Log("Scanning $count unmanaged nodes without OS Names.");
	my $x = 0;
	while ($x <= $count) {
		if ($Address[$x] && $Computer[$x]) { 
			&nmap($Computer[$x],$Address[$x]); 
		}
		$x++;
	}
}

# and clean up.
Log("Finished scanning all records in the database. There were $goodcount successful scans and $badcount failed scans.");
$dbh->disconnect;
exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################
sub Log {
	my $msg = shift;
	$event->Report(
		{
			EventID => 0,
			Strings => $msg,
			EventType => "Information",
		}
	);
}

sub nmap($$) {
	my $OS = "Unidentified";
	my $newmac;
	my @results = `"$nmap" $nmap_options $_[1]`;
	foreach my $line (@results) {
		my @parts;
		# Sometimes UNMANAGEDNODES doesn't have the MAC address, so let's save that now
		if ($line =~ m/^MAC Address/) {
			@parts = split(/\:/,$line);
			$newmac = "$parts[1]";
			# Sanitize the new MAC Address
			$newmac =~ s/://;
			$newmac =~ s/-//;
			chomp($newmac);
		}
		if ($line =~ m/^Running/) {
			@parts = split(/\:/,$line);
			$OS = "$parts[1]";
			last;
		} elsif (($line =~ m/^OS details/) || ($line =~ m/^Aggressive OS guesses/)) {
			@parts = split(/\:/,$line);
			$OS = "Guess: "."$parts[1]";
			last;
		}
		if (($line =~ m/^Service Info/) && ($OS =~ m/Unidentified/)) {
			@parts = split(/\:/,$line);
			$OS = "$parts[2]";
		}			
		if ($line =~ m/^No exact OS matches for host/) {
			$OS = "UNKNOWN";
		}
	}
	# Update the MAC Address if it didn't exist before
	my @row;
	$sql = "select top 1 PHYSADDRESS from UNMANAGEDNODES WHERE UNMANAGEDNODES_IDN='$A{id}' and IPADDRESS='$A{ip}';";
	$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
	$sth->execute or die "$DBI::errstr\n";
	@row = $sth->fetchrow;
	my $oldmac = $row[0];
	$sth->finish();
	if (length($oldmac) < 2) {
		$sql = "update UNMANAGEDNODES set PHYSADDRESS='$newmac' where UNMANAGEDNODES_IDN='$A{id}';";
		$sth = $dbh->prepare($sql) or die "$OS caused $DBI::errstr\n";
		$sth->execute or die "$DBI::errstr\n";
		$sth->finish();
	}
	# And now let's look at the OS Name
	if ($OS) {
		if (length($OS) > 254) {
			$OS = substr($OS,0,255);
		}
		chomp($OS);
		&trim($OS);
		$sql = "update UNMANAGEDNODES set OSNAME='$OS' where UNMANAGEDNODES_IDN='$_[0]';";
		$sth = $dbh->prepare($sql) or carp "$OS caused $DBI::errstr\n";
		$sth->execute or carp "$DBI::errstr\n";
		$sth->finish();	
		if ($DEBUG) { Log("Scanned $_[1] at ".localtime()); }
		$goodcount++;
	} else {
		if ($DEBUG) { Log("Failed scan of $_[1] at ".localtime().". NMAP Results: ".@results ); }
		$badcount++;
	}
}

sub trim($) {
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

