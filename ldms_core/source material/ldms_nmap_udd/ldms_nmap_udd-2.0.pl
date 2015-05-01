#############################################################################
# ldms_nmap_udd.pl, v 2.0                                                   #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_nmap                          #
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
use Win32::EventLog::Message;
Win32::EventLog::Message::RegisterSource( 'Application', 'ldms_nmap_udd' );
my $event = Win32::EventLog->new( 'ldms_nmap_udd') || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
{
	Source => 'ldms_nmap_udd'
};

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

# where does NMAP live?
my $nmap = $A{nmap} || Win32::GetShortPathName("C:/Program Files/nmap/nmap.exe");
my $nmap_options = $A{nmap_options} || "-O -P0 -n";
# how do I get into the database?
my $db_user = $A{db_user} || 'sa';
my $db_pass = $A{db_pass} || 'landesk';
my $db_name = $A{db_name} || 'lddb';
my $db_instance = $A{db_instance} || 'GRANITE\LDMSDATA';
(my $prog = $0) =~ s/^.*[\\\/]//;
my $ver = "2.0";
my $usage = <<EOD;

Usage: $prog [-d] [-h] [-nmap="foo"] [-nmap_options="bar"]
			 -db_user=USER -db_pass=PASS -db_name=DB -db_instance=SERVER
	-d			debug
	-h(elp)		this display
	db_instance is probably the name of the SQL Server, but may have \LDMSDATA
	nmap		By default, "C:/Program Files/nmap/nmap.exe"
	nmap_options By default, "-O -P0 -n"

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

# Set the process priority so we don't murderize the CPU.
ApiLink( 'kernel32.dll', "BOOL SetPriorityClass( HANDLE hThread, DWORD dwPriorityClass )" ) || croak "Unable to load SetPriorityClass()";
ApiLink( 'kernel32.dll', "HANDLE OpenProcess()" ) || croak "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "HANDLE GetCurrentProcess()" ) || croak "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "BOOL CloseHandle( HANDLE )" ) || croak "Unable to load CloseHandle()";
my $hProcess = GetCurrentProcess();
if ( 0 == SetPriorityClass( $hProcess, 0x00000040) ) {
	Log("Unable to set master PID scheduling priority to low.");
} else {
	Log("master PID scheduling priority set to low.");
}
CloseHandle( $hProcess );

# Open the database
my $DSN = "driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass";
my $dbh = DBI->connect("dbi:ODBC:$DSN") or croak "$DBI::errstr\n";

Log("Scanning all unmanaged nodes without OS Names in the database.");
$sql="select UNMANAGEDNODES_IDN,IPADDRESS from UNMANAGEDNODES where OSNAME is null or OSNAME=''";

my $count=0;
my $sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
while (@row = $sth->fetchrow) {
	$Computer[$count] = &trim($row[0]);
	$Address[$count] = &trim($row[1]);
	$count ++;
}
$sth->finish();

# If we've got target nodes, we've got work to do.
if ($count >= 1) {
	my $x = 0;
	while ($x <= $count) {
		if ($Address[$x] && $Computer[$x]) { 
			&nmap($Computer[$x],$Address[$x]); 
		}
		$x++;
	}
}

# and clean up.
Log("Finished scanning all records in the database.");
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
	my $OS;
	my @results = `"$nmap" $nmap_options $_[1]`;
	foreach my $line (@results) {
		if ($line =~ m/^OS details/) {
			my @parts = split(/\:/,$line);
			$OS = &trim($parts[1]);
		}
	}
	if ($OS) {
		$sql = "update UNMANAGEDNODES set OSNAME='$OS' where UNMANAGEDNODES_IDN='$_[0]';";
		$sth = $dbh->prepare($sql) or carp "$DBI::errstr\n";
		$sth->execute or carp "$DBI::errstr\n";
		$sth->finish();	
		Log("Scanned $_[1] at ".localtime());
	} else {
		Log("Failed scan of $_[1] at ".localtime());
	}
}

sub trim($) {
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

