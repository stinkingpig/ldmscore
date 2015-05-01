#############################################################################
# ldms_core.pl, v 2.0                                                       #
# (c) 2005,2006,2007 Jack Coates, jack@monkeynoodle.org                     #
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
my $ver = "2.0";
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
{
	Source => $prog
};

my ($SCANDIR, $STORAGEDIR, $PATCHDIR);
my ($db_type, $db_user, $db_pass, $db_name, $db_instance);
my ($sql,$DSN,$dbh,$sth);
my (@rows,%nodes,@files,$key,$value);

# Check the registry for ErrorDir
$RegRoot = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite"};
$RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
if ($RegKey) {
	$STORAGEDIR = $PATCHDIR = $SCANDIR = $RegKey->GetValue("LDMainPath");
	$SCANDIR .= "\\ldscan\\errorscan";
	$SCANDIR = Win32::GetShortPathName($SCANDIR);
	$STORAGEDIR .= "\\ldscan\\storage";
	$STORAGEDIR = Win32::GetShortPathName($STORAGEDIR);
	$PATCHDIR .= "ldlogon\\patch";
	$PATCHDIR = Win32::GetShortPathName($PATCHDIR);
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
if ($A{db_type}) { $db_type = $A{db_type}; }
if ($A{db_user}) { $db_user = $A{db_user}; }
$db_pass = $A{db_pass} || 'landesk';
if ($A{db_name}) { $db_name = $A{db_name}; }
if ($db_type eq "SQL") {
	if ($A{db_instance}) { $db_instance = $A{db_instance}; }
}

my ($count,$trashcount,$renamecount,$undocount,$compresscount);
my $totalsize;
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
	-d			debug
	-x=[number]	delete scans and patches more than [number] days old. Files go to the Recycle Bin. Default is 10.
	-h(elp)		this display
	db_instance is only necessary for SQL Servers, Oracle environments will pick it up from a properly configured client.

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program will rename the scan files in ErrorScan to the computer name, for
easier troubleshooting. It also compresses old scans in the Storage directory, and deletes patches that are no longer needed.
The latest version lives at http://www.droppedpackets.org.

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
	Log("$prog $ver starting, scheduling priority set to low.\n");
}
CloseHandle( $hProcess );

# Open the database
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
$sql = "select deviceid,devicename from computer";
$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
my ($deviceid,$devicename);
while (@rows = $sth->fetchrow_array()) {
	if ($rows[0]) { $deviceid = &Trim($rows[0]); }
	if ($rows[1]) { $devicename = &Trim($rows[1]); }
	$nodes{$deviceid} = $devicename;
	if ($DEBUG) { Log("$deviceid $devicename "); }
}

# Get the patch names & store them in @files
$sql = "select patch from computervulnerability where detected=0";
$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
while (@rows = $sth->fetchrow_array()) {
	push(@files,$rows[0]);
}

# Close the database
$dbh->disconnect;

# Work on the scan files
$trashcount = 0;
$renamecount = 0;
opendir(DIR,"$SCANDIR");
while (my $source=readdir(DIR)) {
	# Next file if we're at the top or the file was already done
	next if $source =~ /^\.\.?$/;
	# Delete it if it's older than X days
	if ($x) {
		my $time = eval(time()-eval($x*86400));
		# stat, 8 is ATIME
		my $mtime=(stat($SCANDIR."\\".$source))[8] or die "$!\n";
		if ($mtime < $time) { 
			#delete this file
			if ($DEBUG) { 
				my $days = floor(eval(eval(time()-$mtime)/86400));
				Log("$source is $days days old, should be deleted\n");
			} else {
				trash($SCANDIR."\\".$source);
				$trashcount++;
				next;
			}
		}
	}
	next if $source =~ /^_/;
	$file = $SCANDIR."\\".$source;
	open(FILE, "$file") or die "Can't open file $file: $!\n";
	for my $line (<FILE>) {
		my @parts = split(/=/,$line);
		# If the UUID is in the database, get the device name
		if ($parts[0] =~ m/^Device ID/) {
			my $uuid = &Trim($parts[1]);
			my $devicename;
			$devicename=$nodes{$uuid};
			if ($devicename) {
				$newname = $SCANDIR."\\_".$devicename."_".$source;
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
				$newname = $SCANDIR."\\_".$marker."_".$source;
				last;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Host Name/) {
				$marker = &Trim($parts[1]);
				$newname = $SCANDIR."\\_".$marker."_".$source;
				last;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Address/) {
				$marker = &Trim($parts[1]);
				$newname = $SCANDIR."\\_".$marker."_".$source;
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
closedir(DIR);
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

# Work on the patch files
if (-e $PATCHDIR) {
	foreach my $patch (@files) {
		my $file = $PATCHDIR."\\".$patch;
		if (-w $file) {
			$count++;
			my $time = eval(time()-eval($x*86400));
			# stat, 7 is SIZE, 8 is ATIME
			my $atime=(stat($file))[8] or carp "stat($file) failed: $!";
			if ($atime < $time) { 
				#delete this file
				if ($DEBUG) { 
					my $days = floor(eval(eval(time()-$atime)/86400));
					Log("$patch is $days days old and no computers need it, so it should be deleted.\n");
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

sub commify {
    local($_) = shift;
    1 while s/^(-?\d+)(\d{3})/$1,$2/;
    return $_;
}

