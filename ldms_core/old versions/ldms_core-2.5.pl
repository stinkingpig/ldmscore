#############################################################################
# ldms_core.pl, v 2.5                                                       #
# (c) 2005-2008 Jack Coates, jack@monkeynoodle.org                          #
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
use Crypt::Blowfish;
use Win32;
use Win32::FileOp;
use Win32::GUI();
use Win32::TieRegistry (Delimiter=>"/", ArrayValues=>1);
use Win32::API::Prototype;
use Win32::EventLog::Message;
use Win32::Security::SID;
use POSIX qw(floor);
use File::Copy;
use File::Remove qw(trash);
use Archive::Zip qw( :ERROR_CODES );
use Net::SMTP;
use Sys::Hostname;

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
my $ver = "2.5";
my $DEBUG = $A{d} || 0;

# Prepare logging system
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
{
	Source => $prog
};

my ($ldmain, $SCANDIR, $STORAGEDIR, $PATCHDIR, $ldscan, $xddscan, $sdscan);
my ($db_type, $db_user, $db_pass, $db_name, $db_instance, $db_check);
my ($sql,$DSN,$dbh,$sth);
my (@rows,%nodes,@files,$key,$value);
my ($mailserver, $mailfrom, $mailto, $mailmessage, $sendemail);
my $deletiondays = 0;
my ($main, $lbl_Instructions, $form_db_instance, $form_db_name, $form_db_user, $form_db_pass, $lbl_db_type, $form_db_type, $db_type_binary, $btn_default, $btn_cancel, $sb);
my ($second, $lbl_email, $form_mailserver, $form_mailfrom, $form_mailto, $form_deletiondays, $btn_seconddefault, $btn_secondcancel, $sb2);
my ($w, $h, $ncw, $nch, $dw, $dh, $desk, $wx, $wy);

my $mailhostname = hostname;

# Prepare encryption system
my @SIDTYPE = qw(
    ERROR
  SidTypeUser
  SidTypeGroup 
  SidTypeDomain
  SidTypeAlias
  SidTypeWellKnownGroup
  SidTypeDeletedAccount
  SidTypeInvalid
  SidTypeUnknown
  SidTypeComputer
  SidTypeLabel
);
my ( $system, $account );
$system  = Win32::NodeName;
$account = Win32::LoginName;
my $Blowfish_Key = &GetSID($system, $system);
if ($DEBUG) { Log("Machine SID is $Blowfish_Key\n"); }
my $Blowfish_Cipher = new Crypt::Blowfish $Blowfish_Key;

# Check the registry for ErrorDir
my $RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
if ($RegKey) {
	$ldmain = $RegKey->GetValue("LDMainPath");
	if ($DEBUG) { Log("LDMAIN is $ldmain"); }
	$STORAGEDIR = $PATCHDIR = $SCANDIR = $ldscan = $xddscan = $sdscan = Win32::GetShortPathName($ldmain);
	$SCANDIR .= "\\ldscan\\errorscan";
	$STORAGEDIR .= "\\ldscan\\storage";
	$PATCHDIR .= "ldlogon\\patch";
	$ldscan  .= "ldscan";
	$xddscan .= "xddfiles";
	$sdscan  .= "sdstatus";
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

# Check the registry for Database password and email information
# Allow ldms_core specific configuration to override LANDesk specific configuration if present
my $myHive = new Win32::TieRegistry "LMachine" or croak "Can't open registry key! $!\n";
$RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/Monkeynoodle/ldms_core"};
if ($RegKey) {
	$db_type = $RegKey->GetValue("db_type");
	$db_instance = $RegKey->GetValue("db_instance");
	$db_name = $RegKey->GetValue("db_name");
	$db_pass = $RegKey->GetValue("db_pass");
	# Decrypt what we got from the registry
	$db_pass = &Decrypt($db_pass);
	$db_user = $RegKey->GetValue("db_user");
	$mailserver = $RegKey->GetValue("mailserver");
	$mailfrom = $RegKey->GetValue("mailfrom");
	$mailto = $RegKey->GetValue("mailto");
	$deletiondays = $RegKey->GetValue("deletiondays");
}

# Allow command-line to override any registry-provided values
# set the directory
if ($A{db_type}) { $db_type = $A{db_type}; }
if ($A{db_user}) { $db_user = $A{db_user}; }
if ($A{db_pass}) { $db_pass = $A{db_pass}; }
if ($A{db_name}) { $db_name = $A{db_name}; }
if ($db_type eq "SQL") {
	if ($A{db_instance}) { $db_instance = $A{db_instance}; }
}
if ($A{m}) { $mailto = $A{m}; }
if ($A{f}) { $mailfrom = $A{f}; }
if ($A{s}) { $mailserver = $A{s}; }
if ($A{x}) { $deletiondays = $A{x}; }

my ($count,$trashcount,$renamecount,$undocount,$compresscount);
my $totalsize;
my $UNDO = $A{u};
my $newname;
my $file;
my $marker;
my $time = eval(time()-eval($deletiondays*86400));
my $usage = <<EOD;

Usage: $prog [-d] [-u] [-h] [-x=10] -db_type=[SQL|ORA] 
			 -db_user=USER -db_pass=PASS -db_name=DB [-db_instance=SERVER] 
	-d			debug
	-x=[number]	delete scans and patches more than [number] days old. Files go to the Recycle Bin. Default is off.
	-m=me\@here	email address to send output report to.
	-f=ld\@here	email address to send output report from.
	-s=host		email server to send output report through.
	-setup		setup the product.
	-h(elp)		this display
	db_instance is only necessary for SQL Servers, Oracle environments will pick it up from a properly configured client.

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program will rename the scan files in ErrorScan to the computer name, for
easier troubleshooting. It also compresses old scans in the Storage directory, and deletes patches that are no longer needed. It also checks a few important thresholds.
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
	Log("Unable to set master PID scheduling priority to low.");
} else {
	Log("$prog $ver starting, scheduling priority set to low.");
}
CloseHandle( $hProcess );

# Should we do setup?
if ($A{setup}) {
	&Setup;
	exit 0;
}

# Things are okay so far...
$sendemail = 0;

# Open the database
if ($db_type eq "SQL") {
	$dbh = DBI->connect("dbi:ODBC:driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass") or croak "$DBI::errstr\n";
	if ($DEBUG) { Log("Opening database with: $db_type, $db_name, $db_instance, $db_user, db_pass"); }
} elsif ($db_type eq "ORA") {
	$dbh = DBI->connect("DBI:Oracle:$db_name",$db_user,$db_pass) or croak "$DBI::errstr\n";
	if ($DEBUG) { Log("Opening database with: $db_type, $db_name, $db_user, db_pass"); }
} else {
	croak "Cannot connect, Database type is not specified!\n";
}

# Get the deviceid>computer mappings & store them in @nodes
$sql = "select deviceid,devicename from computer";
$sth = $dbh->prepare($sql) or croak "$DBI::errstr\n";
$sth->execute or croak "$DBI::errstr\n";
my ($deviceid,$devicename);
while (@rows = $sth->fetchrow_array()) {
	if ($rows[0]) { $deviceid = &Trim($rows[0]); }
	if ($rows[1]) { $devicename = &Trim($rows[1]); }
	$nodes{$deviceid} = $devicename;
}

# Get the patch names & store them in @files
$sql = "select patch from computervulnerability where detected=0";
$sth = $dbh->prepare($sql) or croak "$DBI::errstr\n";
$sth->execute or croak "$DBI::errstr\n";
while (@rows = $sth->fetchrow_array()) {
	push(@files,$rows[0]);
}

# How many machines are there?
$sql="select count(*) from computer where deviceid != 'Unassigned'";
$sth = $dbh->prepare($sql) or croak "$DBI::errstr\n";
$sth->execute or croak "$DBI::errstr\n";
my $allmachines=$sth->fetchrow();
$sth->finish();

# How many scans came in over the last 24 hours?
if ($db_type eq "SQL") {
	$sql="select count(*) FROM computer where hwlastscandate >= GetDate()-1 and deviceid != 'Unassigned'";
} else {
	# Oracle Support
	$sql="select count(*) FROM computer where hwlastscandate >= current_date-1 and deviceid != 'Unassigned'";
}
$sth = $dbh->prepare($sql) or croak "$DBI::errstr\n";
$sth->execute or croak "$DBI::errstr\n";
my $dbscans = $sth->fetchrow();
$sth->finish();

# How many scans came in over the last 7 days?
if ($db_type eq "SQL") {
	$sql="select count(*) FROM computer where hwlastscandate >= GetDate()-7 and deviceid != 'Unassigned'";
} else {
	# Oracle Support
	$sql="select count(*) FROM computer where hwlastscandate >= current_date-7 and deviceid != 'Unassigned'";
}
$sth = $dbh->prepare($sql) or croak "$DBI::errstr\n";
$sth->execute or croak "$DBI::errstr\n";
my $dbscansweek = $sth->fetchrow();
$sth->finish();

# Close the database
if ($DEBUG) { Log("Closing database."); }
$dbh->disconnect;

# X% of your machines scanned in today
my $daypercent = int(($dbscans/$allmachines)*100);
my $weekpercent = int(($dbscansweek/$allmachines)*100);
Log("$allmachines computers in the database, $dbscans ($daypercent\%) reported in the last day, $dbscansweek ($weekpercent\%) reported within the week.");

# Work on the scan files
$trashcount = 0;
$renamecount = 0;
opendir(DIR,"$SCANDIR");
while (my $source=readdir(DIR)) {
	# Next file if we're at the top or the file was already done
	next if $source =~ /^\.\.?$/;
	# Delete it if it's older than X days
	if ($deletiondays) {
		my $time = eval(time()-eval($deletiondays*86400));
		# stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
		my $mtime=(stat($SCANDIR."\\".$source))[8] or croak "$!\n";
		if ($mtime < $time) { 
			#delete this file
			if ($DEBUG) { 
				my $days = floor(eval(eval(time()-$mtime)/86400));
				Log("$source is $days days old, should be deleted.");
			} else {
				trash($SCANDIR."\\".$source);
				$trashcount++;
				next;
			}
		}
	}
	next if $source =~ /^_/;
	$file = $SCANDIR."\\".$source;
	open(FILE, "$file") or croak "Can't open file $file: $!\n";
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
		if ($deletiondays) {
			# stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
			my $ctime=(stat($STORAGEDIR."\\".$source))[10] or croak "$!\n";
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
		Log("Compressed and deleted $compresscount stored scan files");
	}
}

# Work on the patch files
if (-e $PATCHDIR) {
	if ($DEBUG) { Log("Analyzing patches in $PATCHDIR"); }
	if ($deletiondays) {
		foreach my $patch (@files) {
			my $file = $PATCHDIR."\\".$patch;
			if (-w $file) {
				$count++;
				my $time = eval(time()-eval($deletiondays*86400));
				# stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
				my $atime=(stat($file))[8] or carp "stat($file) failed: $!";
				if ($atime < $time) { 
					#delete this file
					if ($DEBUG) { 
						my $days = floor(eval(eval(time()-$atime)/86400));
						Log("$patch is $days days old and no computers need it, so it should be deleted.\n");
					} else {
						# stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
						my $size = (stat($file))[7] or carp "stat($file) failed: $!";
						$totalsize += $size;
						trash($file);
						$trashcount++;
						next;
					}
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

# Check for exceeded thresholds
&CountPendingScans();

if ($sendemail == 1 || $DEBUG) { 
	Log("Sending email report to $mailto."); 
	&SendEmail; 
}

exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################

### Trim subroutine ########################################################
sub Trim($) {
	my $string = shift;
	$string =~ s/^\s+|\s+$//;
	$string =~ s/\'|\"//g;
	$string =~ s/\n|\r//g;
	$string =~ s/ //g;
	return $string;
}

### Logging subroutine ########################################################
sub Log {
	my $msg = shift;
	$event->Report(
		{
			EventID => 0,
			Strings => $msg,
			EventType => "Information",
		}
	);
	$mailmessage .= "$msg\n";
}

### Generate zip archive file names based on the date #########################
sub genfilename {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
    sprintf "%04d%02d%02d-%02d%02d%02d.zip", $year+1900, $mon+1, $mday, $hour, $min, $sec;
}

### Format numbers with commas ################################################
sub commify {
    local($_) = shift;
    1 while s/^(-?\d+)(\d{3})/$1,$2/;
    return $_;
}

### Count pending scans subroutine ############################################
sub CountPendingScans() {
    opendir( DIR, "$ldscan" ) or croak "Can't open directory!: $!\n";
    my $scancount = 0;
    while ( my $source = readdir(DIR) ) {

        # Next file if we're at the top
        if ( $source =~ /^\.\.?$/ ) { next; }
        if ( $source =~ /\.SCN$/i ) { $scancount++; }
        if ( $source =~ /\.IMS$/i ) { $scancount++; }
        if ( $scancount > 200 ) {
            Log("There are more than 200 inventory scans pending database insertion. You should investigate database performance.");
			$sendemail = 1;
			&RestartService("LANDesk Inventory Server");
            last;
        }
    }
    closedir(DIR);
	if ($DEBUG) { Log("Found $scancount inventory scans in $ldscan."); }
    opendir( DIR, "$xddscan" ) or croak "Can't open directory!: $!\n";
    my $xddcount = 0;
    while ( my $source = readdir(DIR) ) {

        # Next file if we're at the top
        if ( $source =~ /^\.\.?$/ ) { next; }
        if ( $source =~ /\.XDD$/i ) { $xddcount++; }
        if ( $xddcount > 200 ) {
            Log("There are more than 200 extended device discovery scans pending database insertion. You should investigate $ldmain\\XDDFiles2DB.exe.log.");
			$sendemail = 1;
            last;
        }
    }
    closedir(DIR);
	if ($DEBUG) { Log("Found $xddcount discovery scans in $xddscan."); }
    opendir( DIR, "$sdscan" ) or croak "Can't open directory!: $!\n";
    my $sdcount = 0;
    while ( my $source = readdir(DIR) ) {

        # Next file if we're at the top
        if ( $source =~ /^\.\.?$/ ) { next; }
        if ( $source =~ /\.XML$/i ) { $sdcount++; }
        if ( $sdcount > 200 ) {
            Log("There are more than 200 scheduled tasks pending transfer to global scheduler. You should investigate scheduler configuration.");
			$sendemail = 1;
            last;
        }
    }
    closedir(DIR);
	if ($DEBUG) { Log("Found $sdcount scheduler tasks in $sdscan."); }
    Log("Pending scans: $scancount\nPending discoveries: $xddcount\nPending tasks: $sdcount\n");
}

### Service restart subroutine ################################################
sub RestartService($) {
	my $target = shift;
	Log "Stopping $target service.";
	Win32::Service::StopService( '', $target )
		|| carp("Having some trouble with $target");
	sleep 3;
	Log("Starting $target service.");
	my $retval = Win32::Service::StartService( '', $target );
	if ($retval) {
		Log("$target service restarted successfully.");
	}
}

### Email subroutine ##########################################################
# Send email if there was an email address to send it to
sub SendEmail() {
	if ($mailto && $mailfrom && $mailserver) {
		my $smtp = Net::SMTP->new("$mailserver",
			Hello => "$mailhostname", 
			Timeout => 60);
		$smtp->mail("$mailfrom");
		$smtp->to("$mailto");
		$smtp->data;
		# The envelope
		$smtp->datasend("From: $mailfrom\n");
		$smtp->datasend("To: $mailto\n");
		$smtp->datasend("Subject: $prog $ver output report\n");
		$smtp->datasend("\n");
		# The message
		$smtp->datasend($mailmessage);
		# Clean up
		$smtp->dataend;
		$smtp->quit;
	} else {
		Log("Can't send email from $mailfrom to $mailto via $mailserver. Please check configuration.");
	}
}

### Encryption subroutine #####################################################
sub Encrypt {
	my $String = shift;
	my $Temp = $String;
	my $Encrypted = "";
	while (length $Temp > 0) {
		#If less than 8 characters, pad it with tabs
		while (length $Temp < 8) {$Temp .= "\t";}
		# Encrypt the 8 character segment
		my $Temp2 = $Blowfish_Cipher->encrypt(substr($Temp,0,8));
		# Add it to the result
		$Encrypted .= $Temp2; 
		# If there's more than 8 get the next segment
		if (length $Temp > 8) {$Temp = substr($Temp,8);} else {$Temp = "";}
	}
	my $Unpacked = unpack("H*",$Encrypted);
	return ($Unpacked);
}

### Decryption subroutine #####################################################
sub Decrypt {
	my $String = shift;
	my $Packed = pack("H*",$String);
	my $Temp = $Packed;
	my $Decrypted = "";
	while (length $Temp > 0) {
		my $Temp2 = substr($Temp,0,8);
		### In theory, we could up with less than 8 characters, check
		if (length $Temp2 == 8) {
			my $Temp3 = $Blowfish_Cipher->decrypt($Temp2);
			$Decrypted .= $Temp3;
		} 
		if (length $Temp > 8) {$Temp = substr($Temp,8);} else {$Temp = "";}
	}
	# Unpad any tabs at the end, which could be a bad thing in theory.
	$Decrypted =~ s/\t+$//g;
	return ($Decrypted);
}

### Setup subroutine ##########################################################
sub Setup() { 
	# Hide console window
	my ($DOS) = Win32::GUI::GetPerlWindow();
    Win32::GUI::Hide($DOS);
	# Get database info
	&Show_MainWindow;
	Win32::GUI::Dialog();
	if ($DEBUG) { Log("Returned to Setup from Show_MainWindow"); }
	# Get mail server info
	&Show_SecondWindow;
	Win32::GUI::Dialog();
	if ($DEBUG) { Log("Returned to Setup from Show_SecondWindow"); }
	# Encrypt password
	my $db_pass_storage = &Encrypt($db_pass);
	# Write discovered data
	$Registry->{"LMachine/Software/Monkeynoodle/"}= {
		"ldms_core/" => { 
			"/db_type" => $db_type,
			"/db_instance" => $db_instance,
			"/db_name" => $db_name,
			"/db_user" => $db_user,
			"/db_pass" => $db_pass_storage,
			"/mailserver" => $mailserver,
			"/mailfrom" => $mailfrom,
			"/mailto" => $mailto,
			"/deletiondays" => $deletiondays,
		},
	};
	if ($DEBUG) { Log("Wrote $db_type, $db_instance, $db_name, $db_user, $db_pass_storage, $mailserver, $mailfrom, $mailto, $deletiondays into Monkeynoodle registry key."); }
	Win32::GUI::MessageBox(0, "Please create a scheduled task to run ldms_core.exe", "Setup complete!", 64);
	# Restore console window
	Win32::GUI::Show($DOS);
}

# Get the machine's SID for use as an encryption key
sub GetSID {
	my $system = shift;
	my $account = shift;
	my $domain = shift;
	no warnings 'uninitialized';
	my ( $sid, $sidtype );
	Win32::LookupAccountName( $system, $account, $domain, $sid, $sidtype );
   	my $sidstring = Win32::Security::SID::ConvertSidToStringSid( $sid ); 
   	return $sidstring;
}

## Windowing Subroutines  ###################################################
sub Show_MainWindow {
	# build window
	$main = Win32::GUI::Window->new(
		-name   => 'Main',
		-text   => 'ldms_core database setup',
		-width  => 350,
		-height => 220,
	);

	# Add some stuff
	$lbl_Instructions = $main->AddLabel(
		-name    => "lblInstructions",
		-text    => "Please enter the required database information.",
		-pos     => [5, 5],
		-size    => [300, 20],
	);

	# Begin db_instance row
	$form_db_instance = $main->AddTextfield(
		-name    => "db_instance_field",
		-prompt  => "Database Server:",
		-text    => $db_instance,
		-tabstop => 1,
		-pos     => [110, 25],
		-size    => [200, 20],
	);

	# Begin db_name row
	$form_db_name = $main->AddTextfield(
		-name    => "db_name_field",
		-prompt  => "LANDesk Database:",
		-text    => $db_name,
		-tabstop => 1,
		-pos     => [110, 50],
		-size    => [200, 20],
	);

	# Begin db_user row
	$form_db_user = $main->AddTextfield(
		-name    => "db_user_field",
		-prompt  => "Database Username:",
		-text    => $db_user,
		-tabstop => 1,
		-pos     => [110, 75],
		-size    => [200, 20],
	);

	# Begin db_pass row
	$form_db_pass = $main->AddTextfield(
		-name    => "db_pass_field",
		-prompt  => "Database Password:",
		-text    => $db_pass,
		-tabstop => 1,
		-password => 1,
		-pos     => [110, 100],
		-size    => [200, 20],
	);

	# Begin db_type row
	$lbl_db_type = $main->AddLabel(
		-name    => "lbldb_type",
		-text    => "Is this an Oracle database?",
		-pos     => [5, 125],
		-size    => [300, 20],
	);

	$form_db_type = $main->AddCheckbox(
		-name    => "form_db_type",
		-tabstop => 1,
		-pos     => [145, 123],
		-size    => [20, 20],
	);
	
	# Convert Oracle/SQL decision to binary
	my $db_type_binary;
	if ($db_type eq "ORA") { 
		$db_type_binary = 1; 
	} else {
		$db_type_binary = 0;
	}
	$form_db_type->Checked($db_type_binary);
	# End db_type row

	# Begin button row
	$btn_default = $main->AddButton(
		-name    => 'Default',
 		-text    => 'Ok',
		-tabstop => 1,
 		-default => 1,    # Give button darker border
 		-ok      => 1,    # press 'Return' to click this button
		-pos     => [100, 150],
		-size    => [60, 20],
	);
 
	$btn_cancel = $main->AddButton(
 		-name   => 'Cancel',
 		-text   => 'Cancel',
		-tabstop => 1,
 		-cancel => 1,    # press 'Esc' to click this button
		-pos     => [170, 150],
		-size    => [60, 20],
	);
	# End button row

	$sb = $main->AddStatusBar();

	# calculate its size
	$ncw = $main->Width()  - $main->ScaleWidth();
	$nch = $main->Height() - $main->ScaleHeight();
	$w = $lbl_Instructions->Width() + 30 + $ncw;
	$h = $lbl_Instructions->Height() + $form_db_instance->Height() + $form_db_name->Height() + $form_db_user->Height() + $form_db_pass->Height() + 90 + $nch;
	# Don't let it get smaller than it should be
	$main->Change(-minsize => [$w, $h]);

	# calculate its centered position
	# Assume we have the main window size in ($w, $h) as before
	$desk = Win32::GUI::GetDesktopWindow();
	$dw = Win32::GUI::Width($desk);
	$dh = Win32::GUI::Height($desk);
	$wx = ($dw - $w) / 2;
	$wy = ($dh - $h) / 2;

	# Resize, position and display
	$main->Resize($w, $h);
	$main->Move($wx, $wy);

	$main->Show();
}

sub Main_Terminate {
	return -1;
}

sub Main_Resize {
	$sb->Move(0, $main->ScaleHeight - $sb->Height);
	$sb->Resize($main->ScaleWidth, $sb->Height);
}

sub Default_Click {
	# Read my variables
	$db_instance = $form_db_instance->GetLine(0);
	$db_name = $form_db_name->GetLine(0);
	$db_user = $form_db_user->GetLine(0);
	$db_pass = $form_db_pass->GetLine(0);
	$db_type_binary = $form_db_type->Checked();
	if ($db_type_binary == 1) { 
		$db_type = "ORA";
	} else {
		$db_type = "SQL";
	}
	# Open the database. If it fails, then put an error message up and wait for
	# another try.
	if ($db_type eq "SQL") {
		$dbh = DBI->connect("dbi:ODBC:driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass") or Win32::GUI::MessageBox(0, "$DBI::errstr", "Database connection failed", 48);
		if ($DEBUG) { Log("Okay clicked in MainWindow: Opening database with $db_type, $db_instance, $db_name, $db_user, db_pass"); }
	} else {
		$dbh = DBI->connect("DBI:Oracle:$db_name",$db_user,$db_pass) or Win32::GUI::MessageBox(0, "$DBI::errstr", "Database connection failed", 48);
		if ($DEBUG) { Log("Okay clicked in MainWindow: Opening database with $db_type, $db_name, $db_user, db_pass"); }
	}
	if (!$dbh) { 
		if ($DEBUG) { Log("Failed database connection"); }
		$sb->SetText(0,"Connection failed, please try again.");
		return 0;
	}
	# Get the mail server info & store in $mailserver and $mailfrom
	$sql = "select top 1 host,replyemail from ld_task_smtp where sendusing='2' and port='25'";
	$sth = $dbh->prepare($sql) or carp "Database connection failure.\n";
	$sth->execute or carp "Database connection failure.\n"; 
	while (@rows = $sth->fetchrow_array()) {
		$mailserver = $rows[0] || $A{s};
		$mailfrom = $rows[1] || $A{f};
	}
	# Close the database
	$dbh->disconnect;
	if ($DEBUG) { Log("Read $mailserver, $mailfrom from database connection"); }
	# If it succeeded, we're ready to close the window and move on.
	$main->Hide();
 	return -1;
}
 
sub Cancel_Click {
	if ($DEBUG) { Log("Cancel clicked in MainWindow"); }
	$main->Hide();
 	exit -1;
}

# These subroutines get email information
sub Show_SecondWindow {
	# build window
	$second = Win32::GUI::Window->new(
		-name   => 'Second',
		-text   => 'ldms_core email setup',
		-width  => 350,
		-height => 220,
	);

	# Add some stuff
	$lbl_email = $second->AddLabel(
		-name    => "lbl_email",
		-text    => "Please enter the required email information.",
		-tabstop => 1,
		-pos     => [5, 5],
		-size    => [300, 20],
	);

	# Begin mailserver row
	$form_mailserver = $second->AddTextfield(
		-name    => "mailserver_field",
		-prompt  => "Email Server:",
		-text    => $mailserver,
		-tabstop => 1,
		-pos     => [110, 25],
		-size    => [200, 20],
	);

	# Begin mailfrom row
	$form_mailfrom = $second->AddTextfield(
		-name    => "mailfrom_field",
		-prompt  => "Email From Address:",
		-tabstop => 1,
		-text    => $mailfrom,
		-pos     => [110, 50],
		-size    => [200, 20],
	);

	# Begin mailto row
	$form_mailto = $second->AddTextfield(
		-name    => "mailto_field",
		-prompt  => "Email To Address:",
		-tabstop => 1,
		-text    => $mailto,
		-pos     => [110, 75],
		-size    => [200, 20],
	);

	# Begin days to deletion row
	$form_deletiondays = $second->AddTextfield(
		-name    => "deletiondays_field",
		-prompt  => "Purge old files after X Days (0 to disable):",
		-tabstop => 1,
		-text    => $deletiondays,
		-pos     => [210, 100],
		-size    => [40, 20],
	);

	# Begin button row
	$btn_seconddefault = $second->AddButton(
		-name    => 'secondDefault',
 		-text    => 'Ok',
		-tabstop => 1,
 		-default => 1,    # Give button darker border
 		-ok      => 1,    # press 'Return' to click this button
		-pos     => [100, 125],
		-size    => [60, 20],
	);
 
	$btn_secondcancel = $second->AddButton(
 		-name   => 'secondCancel',
 		-text   => 'Cancel',
		-tabstop => 1,
 		-cancel => 1,    # press 'Esc' to click this button
		-pos     => [170, 125],
		-size    => [60, 20],
	);
	# End button row

	$sb2 = $second->AddStatusBar();

	# calculate its size
	$ncw = $second->Width() - $second->ScaleWidth();
	$nch = $second->Height() - $second->ScaleHeight();
	$w = $lbl_email->Width() + 30 + $ncw;
	$h = $lbl_email->Height() + $form_mailserver->Height() + $form_mailfrom->Height() + $form_mailto->Height() + $form_deletiondays->Height() + 90 + $nch;
	# Don't let it get smaller than it should be
	$second->Change(-minsize => [$w, $h]);

	# calculate its centered position
	# Assume we have the main window size in ($w, $h) as before
	$desk = Win32::GUI::GetDesktopWindow();
	$dw = Win32::GUI::Width($desk);
	$dh = Win32::GUI::Height($desk);
	$wx = ($dw - $w) / 2;
	$wy = ($dh - $h) / 2;

	# Resize, position and display
	$second->Resize($w, $h);
	$second->Move($wx, $wy);

	$second->Show();
}

sub Second_Terminate {
	return -1;
}

sub Second_Resize {
	$sb2->Move(0, $second->ScaleHeight - $sb->Height);
	$sb2->Resize($second->ScaleWidth, $sb->Height);
}

sub secondDefault_Click {
	# Read my variables
	$mailserver = $form_mailserver->GetLine(0);
	$mailfrom = $form_mailfrom->GetLine(0);
	$mailto = $form_mailto->GetLine(0);
	$deletiondays = $form_deletiondays->GetLine(0);
	if ($DEBUG) { Log("Okay clicked in SecondWindow, read $mailserver, $mailfrom, $mailto, $deletiondays"); }
	$second->Hide();
 	return -1;
}
 
sub secondCancel_Click {
	if ($DEBUG) { Log("Cancel clicked in SecondWindow"); }
 	exit -1;
}
## End of Windowing Subroutines  ############################################

