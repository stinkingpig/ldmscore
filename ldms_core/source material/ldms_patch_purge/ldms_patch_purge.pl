#############################################################################
# ldms_patch_purge.pl, v 1.2                                                #
# (c) 2007 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/                                            #
#############################################################################

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use DBI;
use Win32;
use Win32::TieRegistry (Delimiter=>"/", ArrayValues=>1);
my ($RegRoot, $RegKey);
use Win32::API::Prototype;
use Win32::EventLog::Message;
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

my $DEFDIR;
my ($db_type, $db_user, $db_pass, $db_name, $db_instance);

# Check the registry for ErrorDir
$RegRoot = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite"};
$RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
if ($RegKey) {
	$DEFDIR = $RegKey->GetValue("LDMainPath");
	$DEFDIR .= "ldlogon\\patch";
}

# Check the registry for Database information
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
# set the directory
my $errordir = shift || $DEFDIR;
my $dir = Win32::GetShortPathName($errordir);
if ($A{db_type}) { $db_type = $A{db_type}; }
if ($A{db_user}) { $db_user = $A{db_user}; }
$db_pass = $A{db_pass} || 'landesk';
if ($A{db_name}) { $db_name = $A{db_name}; }
if ($db_type eq "SQL") {
	if ($A{db_instance}) { $db_instance = $A{db_instance}; }
}

my $trashcount = 0;
my $count = 0;
my $totalsize = 0;
my $DEBUG = $A{d} || 0;
my $x = $A{x} || 10;
(my $prog = $0) =~ s/^.*[\\\/]//;
my $ver = "1.2";
my $usage = <<EOD;

Usage: $prog [-d] [-h] [-x=10] -db_type=[SQL|ORA] 
			 -db_user=USER -db_pass=PASS -db_name=DB [-db_instance=SERVER] 
			 <patch_dir>
	-d			debug
	-x=[number]	delete patches more than [number] days old. Files go to the Recycle Bin. Default is 10.
	-h(elp)		this display
	db_instance is only necessary for SQL Servers, Oracle environments will pick it up from a properly configured client.
	<patch_dir>	directory to find patch files in (Default:
			$DEFDIR)

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This script will purge patches which are (hopefully) not needed any more.
The latest version lives at http://www.droppedpackets.org.

EOD

Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
{
	Source => $prog
};

#############################################################################
# Main Loop                                                                 #
#############################################################################
die $usage if $A{h} or $A{help};

# Set the process priority so we don't murderize the CPU.
ApiLink( 'kernel32.dll', "BOOL SetPriorityClass( HANDLE hThread, DWORD dwPriorityClass )" ) || croak "Unable to load SetPriorityClass()";
ApiLink( 'kernel32.dll', "HANDLE OpenProcess()" ) || croak "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "HANDLE GetCurrentProcess()" ) || croak "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "BOOL CloseHandle( HANDLE )" ) || croak "Unable to load CloseHandle()";
my $hProcess = GetCurrentProcess();
if ( 0 == SetPriorityClass( $hProcess, 0x00000040) ) {
	Log("Unable to set master PID scheduling priority to low.\n");
} else {
	Log("$prog $ver master PID scheduling priority set to low.\n");
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
### Set the trace output back to STDERR at level 9 and prepare()
if ($DEBUG) { 
	DBI->trace( 9, undef ); 
}

# Get the patch names & store them in @files
my (@rows,@files,$key,$value);
my $sql = "select patch from computervulnerability where detected=0";
$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
while (@rows = $sth->fetchrow_array()) {
	push(@files,$rows[0]);
}

# Close the database
$dbh->disconnect;

# Work on the files
foreach my $patch (@files) {
	my $file = $dir."\\".$patch;
	if (-w $file) {
		$count++;
		my $time = eval(time()-eval($x*86400));
		# stat, 7 is SIZE, 8 is ATIME
		my $atime=(stat($file))[8] or carp "stat($file) failed: $!";
		if ($atime < $time) { 
			#delete this file
			if ($DEBUG) { 
				my $days = floor(eval(eval(time()-$atime)/86400));
				Log("$file is $days days old, should be deleted\n");
			} else {
				my $size = (stat($file))[7] or carp "stat($file) failed: $!";
				$totalsize += $size;
				trash($file);
				$trashcount++;
				next;
			}
		}
	}
}
if ($trashcount > 0) {
	$totalsize = commify($totalsize);
	Log("Deleted $trashcount patches, recovered $totalsize bytes.");
} else {
	Log("Evaluated $count patches, deleted none.");
}

exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################
sub trim($) {
	my $string = shift;
	$string =~ s/^\s+|\s+$//;
	$string =~ s/\'|\"//g;
	$string =~ s/\n|\r//g;
	$string =~ s/ //g;
	return $string;
}

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

sub commify {
    local($_) = shift;
    1 while s/^(-?\d+)(\d{3})/$1,$2/;
    return $_;
}

