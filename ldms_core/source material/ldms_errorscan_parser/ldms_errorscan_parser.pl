#############################################################################
# ldms_errorscan_parser.pl, v 1.9.2                                         #
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
use Win32::TieRegistry (Delimiter=>"/", ArrayValues=>1);
my ($RegRoot, $RegKey);
use Win32::API::Prototype;
use Win32::EventLog::Message;
use POSIX qw(floor);
use File::Copy;
use File::Remove qw(trash);
use Archive::Zip qw( :ERROR_CODES );

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

(my $prog = $0) =~ s/^.*[\\\/]//;
my $ver = "1.9.2";
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
{
	Source => $prog
};

my $DEFDIR;
my $STORAGEDIR;
my ($db_type, $db_user, $db_pass, $db_name, $db_instance);

# Check the registry for ErrorDir
$RegRoot = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite"};
$RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
if ($RegKey) {
	$DEFDIR = $RegKey->GetValue("LDMainPath");
	$DEFDIR .= "\\ldscan\\errorscan";
	$STORAGEDIR = $RegKey->GetValue("LDMainPath");
	$STORAGEDIR .= "\\ldscan\\storage";
	$STORAGEDIR = Win32::GetShortPathName($STORAGEDIR);
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

my ($trashcount,$renamecount,$undocount,$compresscount);
my $DEBUG = $A{d} || 0;
my $x = $A{x} || 0;
my $UNDO = $A{u};
my $newname;
my $file;
my $marker;
my $time = eval(time()-eval($x*86400));
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
	opendir(DIR,"$dir") or croak "Can't open directory: $!\n";
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
	if ($rows[0]) { $deviceid = &Trim($rows[0]); }
	if ($rows[1]) { $devicename = &Trim($rows[1]); }
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
		# stat, 9 is MTIME
		my $mtime=(stat($dir."\\".$source))[9] or die "$!\n";
		if ($mtime < $time) { 
			#delete this file
			if ($DEBUG) { 
				my $days = floor(eval(eval(time()-$mtime)/86400));
				Log("$source is $days days old, should be deleted\n");
			} else {
				trash($dir."\\".$source);
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
			my $uuid = &Trim($parts[1]);
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
				$marker = &Trim($parts[1]);
				$newname = $dir."\\_".$marker."_".$source;
				last;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Host Name/) {
				$marker = &Trim($parts[1]);
				$newname = $dir."\\_".$marker."_".$source;
				last;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Address/) {
				$marker = &Trim($parts[1]);
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

# Compress Storage Files
if (-e $STORAGEDIR) {
	$compresscount=0;
	my @filestokill;
	opendir(DIR,"$STORAGEDIR");
	my $zip = Archive::Zip->new();
	while (my $source=readdir(DIR)) {
		# Next file if we're at the top or the file was already done
		next if $source =~ /^\.\.?$/;
		next if $source =~ /\.zip$/i;
		# Compress it if it's older than X days
		if ($x) {
			# stat, 9 is MTIME, 10 is CTIME
			my $ctime=(stat($STORAGEDIR."\\".$source))[10] or die "$!\n";
			if ($ctime < $time) { 
				#delete this file
				if ($DEBUG) { 
					my $days = floor(eval(eval(time()-$ctime)/86400));
					Log("$source is $days days old, should be compressed\n");
				} else {
					my $file_member = $zip->addFile($STORAGEDIR."\\".$source, $source);
					$filestokill[$compresscount] = $STORAGEDIR."\\".$source;
					$compresscount++;
					next;
				}
			}
		}
	}
	
	# prepare the new zip path 
	#
	if ($compresscount > 0) {
		my $newzipfile = genfilename();
		my $newzippath = $STORAGEDIR."\\".$newzipfile;
		# write the new zip file
		#
		my $status = $zip->writeToFileNamed($newzippath);
		if ($status == AZ_OK) {
			Log("Created file $newzippath");
		} else {
			Log("Failed to create file $newzippath"); 
		}
	}
	closedir(DIR);

	# Delete Storage Files
	foreach (@filestokill) {
		trash($_);
	}

	if ($compresscount > 0) {
		Log("Compressed  and deleted $compresscount stored scan files");
	}
}

exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################
sub Trim($) {
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

sub genfilename {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
    sprintf "%04d%02d%02d-%02d%02d%02d.zip", $year+1900, $mon+1, $mday, $hour, $min, $sec;
}

