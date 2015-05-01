#############################################################################
# ldms_errorscan_parser.pl, v 1.7                                           #
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
use strict;
use warnings;
use DBI;
use Win32;
use Win32::FileOp;
use Win32::API::Prototype;
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
	Log("master PID scheduling priority set to low.\n");
}
CloseHandle( $hProcess );

if ($UNDO) {
	opendir(DIR,"$dir");
	$undocount = 0;
	while (my $source=readdir(DIR)) {
		# Next file if we're at the top
		if ($source =~ /^\.\.?$/) { next; }
		# Skip it if it was already done
		if (!$source =~ /^_/) { next; }
		if ($source =~ /^_/) {
			my $newname = $source;
			# if filename begins with an _, select everything that isn't
			# an underscore to the end of the filename
			if ($newname =~ s/(_.*_)(.*)/$2/g) {
				my $newfile = $dir."\\".$newname;
				my $oldfile = $dir."\\".$source;
				if ($DEBUG) { 
					carp "I would be copying $oldfile to $newfile\n";
				} else {
					if (copy("$oldfile","$newfile")) {
						unlink($oldfile) || carp "unlink $oldfile: $!";
						$undocount++;
					} else {
						carp "copy $oldfile, $newfile: $!";
					}
				}
			}
		}
	}
	Log("Undid $undocount rename operations");
	exit;
}

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

# Get the deviceid>computer mappings & store them in @nodes
my ($rows, @rows,%nodes,@nodes,$nodes,$key,$value);
my $sql = "select deviceid,devicename from computer";
$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
my ($deviceid,$devicename);
while (@rows = $sth->fetchrow_array()) {
	if ($rows[0]) { $deviceid = &trim($rows[0]); }
	if ($rows[1]) { $devicename = &trim($rows[1]); }
	$nodes{$deviceid} = $devicename;
	if ($DEBUG) { Log("$deviceid $devicename "); }
}

# Work on the files
$trashcount = 0;
$renamecount = 0;
opendir(DIR,"$dir");
while (my $source=readdir(DIR)) {
	# Next file if we're at the top or the file was already done
	next if $source =~ /^\.\.?$/;
	# Delete it if it's older than X days
	if ($x) {
		my $time = eval(time()-eval($x*86400));
		my $mtime=(stat($dir."/".$source))[9] or die "stat($dir."/".$source) failed: $!\n";
		if ($mtime < $time) { 
			#delete this file
			if ($DEBUG) { 
				my $days = floor(eval(eval(time()-$mtime)/86400));
				Log("$source is $days days old, should be deleted\n");
			} else {
				trash($dir."/".$source);
				$trashcount++;
				next;
			}
		}
	}
	next if $source =~ /^_/;
	$file = $dir."\\".$source;
	open(FILE, "$file") or die "Can't open file $file: $!\n";
	for my $line (<FILE>) {
		my @parts = split(/=/,$line);
		# If the UUID is in the database, get the device name
		if ($parts[0] =~ m/^Device ID/) {
			my $uuid = &trim($parts[1]);
			my $devicename;
			$devicename=$nodes{$uuid};
			if ($devicename) {
				$newname = $dir."\\_".$devicename."_".$source;
				last;
			} else { 
				# If there was no UUID in the database, move along to the next line of the file
				next;
			}
		} else {
			# If the first line didn't have Device ID in it, we'll try each of these.
			# The first one to match wins.
			if ($parts[0] =~ m/^Device Name/) {
				$marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker."_".$source;
				last;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Host Name/) {
				$marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker."_".$source;
				last;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Address/) {
				$marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker."_".$source;
				last;
			}
			# If all else fails, undef $newname
			if ($DEBUG) { 
				Log("couldn't get anything from $source"); 
			}
			$newname = undef;
		}
	}
	close(FILE);
	# if we weren't able to get something, we don't move the file.
	# if debug is off, try to move the file and fail safely if we can't.
	# if debug is on, just print what would have been done.
	if ($newname) {
		if ($DEBUG) { 
			Log("I would be copying $file to $newname");
		} else {
			if (copy("$file","$newname")) {
				unlink($file) || carp "unlink $file: $!";
			} else {
				carp "copy $file, $newname: $!";
			}
		}
	}
}
if ($trashcount > 0) {
	Log("Deleted $trashcount scan files");
}
if ($renamecount > 0) {
	Log("Renamed $renamecount scan files");
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
