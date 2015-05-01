#############################################################################
# ldms_core.pl                                                              #
# (c) 2005-2008 Jack Coates, jack@monkeynoodle.org                          #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/                                            #
#############################################################################

# TODO -- keep old information and show a trend.
# TODO -- purty Charts, http://search.cpan.org/src/CHARTGRP/Chart-2.4.1/README
# TODO -- Check the core's event logs for badness
# TODO -- Check scheduled tasks and policies
# TODO -- plot non-RFC1918 addresses on a map
# TODO -- reduce RAM usage on cores with lots of nodes... temp files won't
# work unless I re-write the errorscan logic, but if I do that the database
# will get slapped around.

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use Env;
use DBI;
use Crypt::Blowfish;
use Win32;
use Win32::File::VersionInfo;
use Win32::FileOp;
use Win32::GUI();
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1 );
use Win32::API::Prototype;
use Win32::EventLog;
use Win32::EventLog::Message;
use Win32::Security::SID;
use Win32::WebBrowser;
use POSIX qw(floor);
use File::Copy;
use File::Remove qw(trash);
use Archive::Zip qw( :ERROR_CODES );
use Net::SMTP;
use Net::Ping;
use Sys::Hostname;
use Nmap::Parser;
use LWP::Simple qw(!head !getprint !getstore !mirror);

#############################################################################
# Variables                                                                 #
#############################################################################
our %A;    # get commandline switches into %A
for ( my $ii = 0 ; $ii < @ARGV ; ) {
    last if $ARGV[$ii] =~ /^--$/;
    if ( $ARGV[$ii] !~ /^-{1,2}(.*)$/ ) { $ii++; next; }
    my $arg = $1;
    splice @ARGV, $ii, 1;
    if ( $arg =~ /^([\w]+)=(.*)$/ ) { $A{$1} = $2; }
    else                            { $A{$1}++; }
}

( my $prog = $0 ) =~ s/^.*[\\\/]//;
my $ver = "2.9";

my $DEBUG = $A{d} || $A{debug} || 0;

# Prepare logging system
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";

# Check to see if there's an update available
my $url     = 'http://www.droppedpackets.org/scripts/ldms_core/version';
my $content = get $url;
if ( defined($content) ) {
    $content =~ m{<p>latest version is ([\d.]+)<br /></p>};
    my $onlineversion = $1;
    if ( $onlineversion != $ver ) {
        &LogWarn(
"Update available at http://www.droppedpackets.org/scripts/ldms_core\n"
        );
    }
}
else {
    &Log("Couldn't get $url");
}

my ( $ldmain, $SCANDIR, $STORAGEDIR, $PATCHDIR, $ldscan, $xddscan, $sdscan );
my ( $db_type, $db_user, $db_pass, $db_name, $db_instance, $db_check );
my ( $sql,     $DSN,     $dbh,     $sth );
my ( @rows,    %nodes,   @files,   $key,     $value,       @patchurls );
my ( $mailserver, $mailfrom, $mailto, $mailmessage, $sendemail );
my $deletiondays = 0;
my (
    $main,         $lbl_Instructions, $form_db_instance,
    $form_db_name, $form_db_user,     $form_db_pass,
    $lbl_db_type,  $form_db_type,     $db_type_binary,
    $btn_default,  $btn_cancel,       $sb
);
my (
    $second,            $lbl_email,        $form_mailserver,
    $form_mailfrom,     $form_mailto,      $form_deletiondays,
    $btn_seconddefault, $btn_secondcancel, $sb2,
    $form_nmap,         $form_nmap_u,      $form_nmap_options,
    $form_nmap_ulabel
);
my ( $w, $h, $ncw, $nch, $dw, $dh, $desk, $wx, $wy );

#Stats gathering variables
my ( $deviceid, $devicename, $allmachines, @dupmachines, $dbscans );
my ( $dbscansweek, $allmachines_udd, $dbscans_udd, $dbscansweek_udd );
my ( $source, $vulnlife );
my ($daypercent, $weekpercent, $forcedpercent, $forcedfullscans);

my $mailhostname = hostname;

# NMAP Variables and defaults
my ( $np, @row, $goodcount, $badcount, $nmap, $nmap_options,
    $nmap_unidentified );
my ( @Address, @Address_p, @Address_np );
$goodcount    = 0;
$badcount     = 0;
$nmap         = Win32::GetShortPathName("C:/Program Files/nmap/nmap.exe");
$nmap_options = "-A -T4 -P0 -n";

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
my $Blowfish_Key = &GetSID( $system, $system );
if ($DEBUG) { Log("DEBUG: Machine SID is $Blowfish_Key\n"); }
my $Blowfish_Cipher = new Crypt::Blowfish $Blowfish_Key;

# Check the registry for ErrorDir
my $RegKey =
  $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
if ($RegKey) {
    $ldmain = $RegKey->GetValue("LDMainPath");
    if ($DEBUG) { Log("DEBUG: LDMAIN is $ldmain"); }
    $STORAGEDIR = $PATCHDIR = $SCANDIR = $ldscan = $xddscan = $sdscan =
      Win32::GetShortPathName($ldmain);
    $SCANDIR    .= "\\ldscan\\errorscan";
    $STORAGEDIR .= "\\ldscan\\storage";
    $PATCHDIR   .= "ldlogon\\patch";
    $ldscan     .= "ldscan";
    $xddscan    .= "xddfiles";
    $sdscan     .= "sdstatus";
}

# That's a useful way to find the LANDesk version we're working with, too
my $ldms_version;
my $version =
  GetFileVersionInfo( Win32::GetShortPathName( $ldmain . "//ldinv32.exe" ) );
if ($version) {
    $ldms_version = $version->{FileVersion};

    # Remove the dots and convert to an integer so that we can do numerical
    # comparison... e.g., version 8.80.0.249 is rendered as 8800249
    $ldms_version =~ s/\.?(?=[0-9])//g;

    # LANDesk buildmasters keep screwing with the number of ordinals in the
    # version number, so this has grown unreliable with certain patches.
    # If I just use the first two numbers, that should work well enough.
    $ldms_version = substr( $ldms_version, 0, 2 );
    $ldms_version = &atoi($ldms_version);
    if ($DEBUG) { Log("DEBUG: LANDesk version is $ldms_version"); }
}
else {
    &LogWarn("Cannot determine LANDesk version!");
    return 1;
}

# Check the registry for Database information
$RegKey =
  $Registry->{
    "HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Core/Connections/Local"
  };
if ($RegKey) {
    my $oracle = $RegKey->GetValue("IsOracle");
    if ( $oracle =~ m/true/i ) {
        $db_type = "ORA";
    }
    else {
        $db_type = "SQL";
    }
    $db_name     = $RegKey->GetValue("Database");
    $db_instance = $RegKey->GetValue("Server");
    $db_user     = $RegKey->GetValue("User");
}

# Check the registry for email and nmap information
# Allow ldms_core specific configuration to override LANDesk specific configuration if present
my $myHive = new Win32::TieRegistry "LMachine"
  or &LogWarn(
    "Can't open registry key HKLM/Software/Monkeynoodle/ldms_core! $!\n");
$RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/Monkeynoodle/ldms_core"};
if ($RegKey) {
    $db_type     = $RegKey->GetValue("db_type");
    $db_instance = $RegKey->GetValue("db_instance");
    $db_name     = $RegKey->GetValue("db_name");
    $db_pass     = $RegKey->GetValue("db_pass");

    # Decrypt what we got from the registry
    $db_pass      = &Decrypt($db_pass);
    $db_user      = $RegKey->GetValue("db_user");
    $mailserver   = $RegKey->GetValue("mailserver");
    $mailfrom     = $RegKey->GetValue("mailfrom");
    $mailto       = $RegKey->GetValue("mailto");
    $deletiondays = $RegKey->GetValue("deletiondays");

    # In upgrades, we'll wipe out the useful defaults by reading
    # empty registry keys.
    if ( $RegKey->GetValue("nmap") ) {
        $nmap = $RegKey->GetValue("nmap");
    }
    if ( $RegKey->GetValue("nmap_options") ) {
        $nmap_options = $RegKey->GetValue("nmap_options");
    }
    $nmap_unidentified = $RegKey->GetValue("nmap_unidentified");
}

# Allow command-line to override any registry-provided values
if ( $A{db_type} ) { $db_type = $A{db_type}; }
if ( $A{db_user} ) { $db_user = $A{db_user}; }
if ( $A{db_pass} ) { $db_pass = $A{db_pass}; }
if ( $A{db_name} ) { $db_name = $A{db_name}; }
if ( $db_type eq "SQL" ) {
    if ( $A{db_instance} ) { $db_instance = $A{db_instance}; }
}
if ( $A{m} )            { $mailto            = $A{m}; }
if ( $A{f} )            { $mailfrom          = $A{f}; }
if ( $A{s} )            { $mailserver        = $A{s}; }
if ( $A{x} )            { $deletiondays      = $A{x}; }
if ( $A{nmap} )         { $nmap              = $A{nmap}; }
if ( $A{nmap_options} ) { $nmap_options      = $A{nmap_options}; }
if ( $A{u} )            { $nmap_unidentified = $A{nmap_unidentified}; }

my (
    $patchcount,  $nmapcount, $trashcount,
    $renamecount, $undocount, $compresscount
);
my $totalsize;
my $UNDO = $A{u};
my $newname;
my $file;
my $marker;
my $time  = eval( time() - eval( $deletiondays * 86400 ) );
my $usage = <<EOD;

Usage: $prog [-d] [-u] [-h] [-x=10] -db_type=[SQL|ORA] 
			 -db_user=USER -db_pass=PASS -db_name=DB [-db_instance=SERVER] 
             [-nmap="x:\\foo"] [-nmap_options="-bar -baz"]
			 
	-d(ebug)	 debug
	-x=[number]	 delete scans and patches more than [number] days old. Files go
                  to the Recycle Bin. Default is off. This option also controls
                  removal of unmanaged device records which are no longer on
                  the network.
	-m=me\@here	 email address to send output report to.
	-f=ld\@here	 email address to send output report from.
	-s=host		 email server to send output report through.
	-setup		 setup the product.
	-h(elp)		 this display
	db_instance  is only necessary for SQL Servers, Oracle environments will
                  pick it up from a properly configured client.
	nmap         By default, "C:/Program Files/nmap/nmap.exe"
	nmap_options By default, "-A T4 -P0 -n
	-u			 Should NMAP rescan devices it couldn't identify earlier?

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program will rename the scan files in ErrorScan to the computer name, for
easier troubleshooting, compress old scans in the Storage directory, and 
delete patches that are no longer needed. It also checks a few important 
thresholds, and uses NMAP fingerprinting to properly identify the OS of the 
machines in Unmanaged Devices.
The latest version lives at http://www.droppedpackets.org.

EOD

#############################################################################
# Main Loop                                                                 #
#############################################################################
die $usage if $A{h} or $A{help};

# Check to see if NMAP is available; otherwise, we can skip its needs
my $nmap_present = 1;
if ( !-e $nmap ) {
    LogWarn("Cannot find NMAP at $nmap\n");
    $nmap_present = 0;
}

# Set the process priority so we don't murderize the CPU.
ApiLink( 'kernel32.dll',
    "BOOL SetPriorityClass( HANDLE hThread, DWORD dwPriorityClass )" )
  || &LogDie("Unable to load SetPriorityClass()");
ApiLink( 'kernel32.dll', "HANDLE OpenProcess()" )
  || &LogDie("Unable to load GetCurrentProcess()");
ApiLink( 'kernel32.dll', "HANDLE GetCurrentProcess()" )
  || &LogDie("Unable to load GetCurrentProcess()");
ApiLink( 'kernel32.dll', "BOOL CloseHandle( HANDLE )" )
  || &LogDie("Unable to load CloseHandle()");
my $hProcess = GetCurrentProcess();
if ( 0 == SetPriorityClass( $hProcess, 0x00000040 ) ) {
    Log("Unable to set master PID scheduling priority to low.");
}
else {
    Log("$prog $ver starting, scheduling priority set to low.");
}
CloseHandle($hProcess);

# Get the window handle so we can hide it
my ($DOS) = Win32::GUI::GetPerlWindow();

if ( !$DEBUG ) {

    # Hide console window
    Win32::GUI::Hide($DOS);
}

# Should we do setup?
if ( $A{setup} ) {
    &Setup;
    Log("$prog $ver exiting");
    exit 0;
}

# Now we're running for real, so let's show off
my $systrayicon = new Win32::GUI::Icon('ldms_core.ico');
my $systraymain = Win32::GUI::Window->new(
    -name    => 'ldms_core_systray',
    -text    => 'ldms_core_systray',
    -width   => 20,
    -height  => 20,
    -visible => 0,
);
$systraymain->Enable();
my $popupMenu = Win32::GUI::Menu->new(
    "Options" => "Options",
    ">Manual" => {
        -name => "Manual",
        -onClick => sub { open_browser('http://www.droppedpackets.org/scripts/ldms_core/ldms_core-manual'); }
    },
    ">Exit" => { -name => "Exit", -onClick => \&systrayexit }
);
my $systraynotify = $systraymain->AddNotifyIcon(
    -name         => "ldms_core_systray",
    -icon         => $systrayicon,
    -tip          => "$prog $ver running\n",
    -onClick      => \&systraymenu,
    -onRightClick => \&systraymenu,

);

# Things are okay so far...
$sendemail = 0;

# Read all our database information now so we can hurry up and close it
&GetData;

# X% of your machines scanned in today
if ($dbscans) {
	$daypercent  = int( ( $dbscans / $allmachines ) * 100 );
	# Rescan forced?
	$forcedfullscans = &CountForcedScans();
	# X% of today's scans had full rescans forced on them
	if ($forcedfullscans) {
		$forcedpercent = int( ( $forcedfullscans / $dbscans ) * 100 );
		if ( $forcedpercent > 10 ) { $sendemail = 1; }
	} else {
		$forcedpercent = 0;
		}
		&Log("$forcedfullscans of today's delta scans were out of sync; new full scans were forced.");
	} else {
		$dbscans = 0;
		$daypercent = 0;
}
# X% of your machines scanned in this week
$weekpercent = int( ( $dbscansweek / $allmachines ) * 100 );
if ( $weekpercent < 50 ) {
    $sendemail = 1;
}


# Do you have duplicates?
if (@dupmachines) {
    our $dupreport = "Duplicate computer records detected:\n";
    foreach my $dup (@dupmachines) {
        $dupreport .= "$dup\n";
    }
    $sendemail = 1;
    Log("$dupreport");
}

# X% of your unmanaged nodes were pinged today
my $daypercent_udd  = int( ( $dbscans_udd / $allmachines_udd ) * 100 );
my $weekpercent_udd = int( ( $dbscansweek_udd / $allmachines_udd ) * 100 );

# Your vulnerabilities live this long
my ( $vulndays, $vulnhours, $vulnminutes, $vulnseconds, $vulnmessage );
if ($vulnlife) {
	$vulndays, $vulnhours, $vulnminutes, $vulnseconds = &ConvertSeconds($vulnlife);
	$vulnmessage = "Vulnerabilities go unpatched an average of ";
	if ($vulndays) { $vulnmessage .= "$vulndays days,"; }
    if ($vulnhours) { $vulnmessage .= "$vulnhours hours, "; } 
	if ($vulnmessage =~ m/days|hours/) { $vulnmessage .= "and "; }
	if ($vulnminutes) { $vulnmessage .= "$vulnminutes minutes."; }
	if ( $vulndays > 50 ) {
    	$sendemail = 1;
	}
} else {
	$vulnmessage = "Vulnerabilities go unpatched forever.";
    $sendemail = 1;
}

# Report all those stats
Log(
"$allmachines computers in the database, $dbscans ($daypercent\%) reported in the last day, $dbscansweek ($weekpercent\%) reported within the week. $allmachines_udd unmanaged devices in the database, $dbscans_udd ($daypercent_udd\%) were seen in the last day, $dbscansweek_udd ($weekpercent_udd\%) were seen within the week. $vulnmessage\n"
);

# Work on the scan files
&CullScanFiles;

# Report on manual patch download requirements
if (@patchurls) {
    our $patchurlsreport = "Manual patch downloads required:\n";
    foreach my $patchurl (@patchurls) {
        $patchurlsreport .= "$patchurl\n";
    }
    $sendemail = 1;
    Log("$patchurlsreport");
}

# Work on the patch files
&CullPatches;

# Check for exceeded thresholds
&CountPendingScans();

# If NMAP is around, let's go ahead and use it.
if ($nmap_present) {
    &DoNMAP;
}

# Do we need to send a message?
if ( $sendemail == 1 || $DEBUG ) {
    Log("Sending email report to $mailto.");
    &SendEmail;
}

# clean up the tray icon
$systraymain->systraynotify->Remove();

# Restore console window
Win32::GUI::Show($DOS);

Log("$prog $ver exiting.");
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

### ConvertSeconds subroutine ##############################################
sub ConvertSeconds {
    my $secs = shift;
	if ($DEBUG) { Log("ConvertSeconds received $secs"); }
	if ($secs) {
	    my ( $days, $hours, $minutes, $seconds );
    	if ( $secs < ( 60 * 60 * 24 ) ) {
        	$days = 0;
	    }
    	else {
        	$days = int( $secs / ( 60 * 60 * 24 ) );
	    }
    	if ( ( int( $secs % 60 * 60 * 24 ) ) < 60 * 60 ) {
        	$hours = 0;
	    }
    	else {
        	$hours = int( ( $secs % ( 60 * 60 * 24 ) ) / ( 60 * 60 ) );
	    }
    	if ( int( ( $secs % ( 60 * 60 * 24 ) ) % ( 60 * 60 ) ) < 60 ) {
        	$minutes = 0;
	        $seconds = int( ( $secs % ( 60 * 60 * 24 ) ) % ( 60 * 60 ) );
    	}
	    else {
    	    $minutes = int( ( ( $secs % ( 60 * 60 * 24 ) ) % 60 * 24 ) / 60 );
        	$seconds = 0;
	    }
    	return $days, $hours, $minutes, $seconds;
	} else {
		return 0,0,0,0;
	}
}

### Logging subroutine ########################################################
sub Log {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 4,
        }
    );
    $mailmessage .= "$msg\n";
}

### Logging with warning subroutine ###########################################
sub LogWarn {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 2,
        }
    );
    $mailmessage .= "WARNING: $msg\n";
}

### Logging with death subroutine #############################################
sub LogDie {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 1,
        }
    );
    $mailmessage .= "ERROR: $msg\n";
    &SendEmail or &Log($mailmessage);
    exit 1;
}

### Generate zip archive file names based on the date #########################
sub genfilename {
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
      localtime(time);
    sprintf "%04d%02d%02d-%02d%02d%02d.zip", $year + 1900, $mon + 1, $mday,
      $hour, $min, $sec;
}

### Format numbers with commas ################################################
sub commify {
    local ($_) = shift;
    1 while s/^(-?\d+)(\d{3})/$1,$2/;
    return $_;
}

### Database Reindex subroutine ###############################################
# ASSUMES DATABASE CONNECTION -- Do Not Call when there's no DBH ##############
# if you want to surgically do specific tables you can just run the command:
# dbcc dbreindex(tablename) -- Rob N.
sub DBReindex() {
    my $indexsql;
    if ( $db_type eq "SQL" ) {

        # MS SQL Reindexing Incantation
        $indexsql = <<EOD;
DECLARE \@SQL VARCHAR(255)
DECLARE DBCC_CURSOR CURSOR FOR
SELECT TABLE_NAME
FROM INFORMATION_SCHEMA.TABLES
WHERE
OBJECTPROPERTY(OBJECT_ID(QUOTENAME(TABLE_SCHEMA) + '.' + QUOTENAME(TABLE_NAME)), 'ISMSSHIPPED') = 0
AND TABLE_TYPE = 'BASE TABLE'
OPEN DBCC_CURSOR
FETCH NEXT FROM DBCC_CURSOR INTO \@SQL
WHILE \@\@FETCH_STATUS = 0
BEGIN
DBCC DBREINDEX (\@SQL)
FETCH NEXT FROM DBCC_CURSOR INTO \@SQL
END
CLOSE DBCC_CURSOR
DEALLOCATE DBCC_CURSOR

EOD

    }
    elsif ( $db_type eq "ORA" ) {

        # ORACLE Reindexing Incantation
        $indexsql = <<EOD;
DECLARE
v_indvar VARCHAR(1000);
v_command VARCHAR(255);
v_statement VARCHAR(1000);

CURSOR ind_cursor IS
SELECT UPPER(INDEX_NAME)
FROM ALL_INDEXES
WHERE
OWNER = "$db_user"' AND (INDEX_NAME like 'X%' or INDEX_NAME like 'U%');

BEGIN

OPEN ind_cursor;
LOOP
FETCH ind_cursor
INTO v_indvar;
v_statement := 'ALTER INDEX "$db_user".' || v_indvar || ' REBUILD ONLINE';
EXECUTE IMMEDIATE (v_statement);
EXIT WHEN ind_cursor%NOTFOUND;
END LOOP;

CLOSE ind_cursor;

END;

EOD

    }
    else {
        &LogDie(
"Database Reindexing cannot continue, Database type is not specified!\n"
        );
    }

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    $sth = $dbh->prepare($indexsql)
      or &LogDie("Database reindexing caused $DBI::errstr\n");
    $sth->execute or &LogDie("Database reindexing caused $DBI::errstr\n");
    &Log("Database reindexed.");
}
###############################################################################

### Count pending scans subroutine ############################################
sub CountPendingScans() {
    my ( $scancount, $xddcount, $sdcount ) = "UNKNOWN";

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ( -e $ldscan ) {
        opendir( DIR, "$ldscan" )
          or &LogDie("Can't open directory $ldscan: $!\n");
        $scancount = 0;
        while ( $source = readdir(DIR) ) {

            # Next file if we're at the top
            if ( $source =~ /^\.\.?$/ ) { next; }
            if ( $source =~ /\.SCN$/i ) { $scancount++; }
            if ( $source =~ /\.IMS$/i ) { $scancount++; }
            if ( $scancount > 200 ) {
                Log(
"There are more than 200 inventory scans pending database insertion. You should investigate database performance."
                );
                $sendemail = 1;
                &RestartService("LANDesk Inventory Server");
                last;
            }
        }
        closedir(DIR);
    }
    if ( -e $xddscan ) {
        opendir( DIR, "$xddscan" )
          or &LogDie("Can't open directory $xddscan: $!\n");
        $xddcount = 0;
        while ( $source = readdir(DIR) ) {

            # Next file if we're at the top
            if ( $source =~ /^\.\.?$/ ) { next; }
            if ( $source =~ /\.XDD$/i ) { $xddcount++; }
            if ( $xddcount > 200 ) {
                Log(
"There are more than 200 extended device discovery scans pending database insertion. You should investigate $ldmain\\XDDFiles2DB.exe.log."
                );
                $sendemail = 1;
                last;
            }
        }
        closedir(DIR);
    }
    if ( -e $sdscan ) {
        opendir( DIR, "$sdscan" )
          or &LogDie("Can't open directory $sdscan: $!\n");
        $sdcount = 0;
        while ( $source = readdir(DIR) ) {

            # Next file if we're at the top
            if ( $source =~ /^\.\.?$/ ) { next; }
            if ( $source =~ /\.XML$/i ) { $sdcount++; }
            if ( $sdcount > 200 ) {
                Log(
"There are more than 200 scheduled tasks pending transfer to global scheduler. You should investigate scheduler configuration."
                );
                $sendemail = 1;
                last;
            }
        }
        closedir(DIR);
    }
    Log(
"Pending scans: $scancount\nPending discoveries: $xddcount\nPending tasks: $sdcount\n"
    );
    if ($DEBUG) {
        Log(
"DEBUG: ldscan was $ldscan, xddscan was $xddscan, sdscan was $sdscan."
        );
    }
}
###############################################################################

### Service restart subroutine ################################################
sub RestartService($) {
    my $target = shift;
    Log "Stopping $target service.";
    Win32::Service::StopService( '', $target )
      or LogWarn "Having some trouble with $target";

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    sleep 3;
    Log("Starting $target service.");
    my $retval = Win32::Service::StartService( '', $target );
    if ($retval) {
        Log("$target service restarted successfully.");
    }
}

### Old Patch cleanup subroutine ##############################################
sub CullPatches() {
    if ( -e $PATCHDIR ) {
        if ($DEBUG) { Log("DEBUG: Analyzing patches in $PATCHDIR"); }
        if ($deletiondays) {
            foreach my $patch (@files) {
                my $file = $PATCHDIR . "\\" . $patch;

                Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

                if ( -w $file ) {
                    $patchcount++;
                    my $time = eval( time() - eval( $deletiondays * 86400 ) );

                    # stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
                    my $atime = ( stat($file) )[8]
                      or LogWarn("stat($file) failed: $!");
                    if ( $atime < $time ) {

                        #delete this file
                        if ($DEBUG) {
                            my $deldays =
                              floor( eval( eval( time() - $atime ) / 86400 ) );
                            Log(
"DEBUG: $patch is $deldays days old and no computers need it, so it should be deleted.\n"
                            );
                        }
                        else {

                          # stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
                            my $size = ( stat($file) )[7]
                              or LogWarn("stat($file) failed: $!");
                            $totalsize += $size;
                            trash($file);
                            $trashcount++;
                            next;
                        }
                    }
                }
            }
        }
        if ( $trashcount > 0 ) {
            $totalsize = commify($totalsize);
            Log("Deleted $trashcount patches, recovered $totalsize bytes.");
        }
        else {
            Log("Evaluated $patchcount patches, deleted none.");
        }
    }
}

### Look for Full scan forced in the Event Viewer #############################
# Need to limit this to a single day's data
sub CountForcedScans() {
    my ( $handle, $base, $recs, %Event, $record, $result );
	# One day ago
	my $TIME_LIMIT = time() - 86400;
	# if this is set, we also retrieve the full text of every
	# message on each Read( )
	$Win32::EventLog::GetMessageText = 0; 
	
    $handle = Win32::EventLog->new( "Application", $COMPUTERNAME )
      or &LogWarn("Can't open Application EventLog");

	while ( ( $handle->Read( EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
            0, \%Event ) ) && ( $Event{TimeGenerated} > $TIME_LIMIT ) ) {
	    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        if ( $Event{Source} eq "LANDesk Inventory Server" ) {
            if ( $Event{EventType} eq 2 and $Event{EventID} eq 2391 ) {
                $result++;
            }
        }
        $record++;
    }
	if ($result) {
	    return $result;
	} else {
		return 0;
	}
}
###############################################################################

### Scanfile rename and cleanup subroutine ####################################
sub CullScanFiles() {
    $trashcount  = 0;
    $renamecount = 0;
    opendir( DIR, "$SCANDIR" )
      or &LogDie("Can't open directory $SCANDIR: $!\n");
    while ( $source = readdir(DIR) ) {

        # Next file if we're at the top or the file was already done
        next if $source =~ /^\.\.?$/;

        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

        # Delete it if it's older than X days
        if ($deletiondays) {
            my $time = eval( time() - eval( $deletiondays * 86400 ) );

            # stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
            my $mtime = ( stat( $SCANDIR . "\\" . $source ) )[8]
              or &LogDie("Can't access file $source: $!\n");
            if ( $mtime < $time ) {

                #delete this file
                if ($DEBUG) {
                    my $days = floor( eval( eval( time() - $mtime ) / 86400 ) );
                    Log("DEBUG: $source is $days days old, should be deleted.");
                }
                else {
                    trash( $SCANDIR . "\\" . $source );
                    $trashcount++;
                    next;
                }
            }
        }
        next if $source =~ /^_/;
        $file = $SCANDIR . "\\" . $source;
        open( FILE, "$file" ) or &LogDie("Can't open file $file: $!\n");
        for my $line (<FILE>) {
            my @parts = split( /=/, $line );

            # If the UUID is in the database, get the device name
            if ( $parts[0] =~ m/^Device ID/ ) {
                my $uuid = &Trim( $parts[1] );
                my $devicename;
                $devicename = $nodes{$uuid};
                if ($devicename) {
                    $newname = $SCANDIR . "\\_" . $devicename . "_" . $source;
                    last;
                }
                else {

 # If there was no UUID in the database, move along to the next line of the file
                    next;
                }
            }
            else {

       # If the first line didn't have Device ID in it, we'll try each of these.
       # The first one to match wins.
                if ( $parts[0] =~ m/^Device Name/ ) {
                    $marker  = &Trim( $parts[1] );
                    $newname = $SCANDIR . "\\_" . $marker . "_" . $source;
                    last;
                }
                elsif ( $parts[0] =~ m/^Network - TCPIP - Host Name/ ) {
                    $marker  = &Trim( $parts[1] );
                    $newname = $SCANDIR . "\\_" . $marker . "_" . $source;
                    last;
                }
                elsif ( $parts[0] =~ m/^Network - TCPIP - Address/ ) {
                    $marker  = &Trim( $parts[1] );
                    $newname = $SCANDIR . "\\_" . $marker . "_" . $source;
                    last;
                }

                # If all else fails, undef $newname
                if ($DEBUG) {
                    Log("DEBUG: couldn't get anything from $source");
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
                Log("DEBUG: I would be copying $file to $newname");
            }
            else {
                if ( copy( "$file", "$newname" ) ) {
                    unlink($file) || LogWarn("unlink $file: $!");
                }
                else {
                    LogWarn("copy $file, $newname: $!");
                }
            }
        }
    }
    closedir(DIR);
    if ( $trashcount > 0 ) {
        Log("Deleted $trashcount scan files");
    }
    if ( $renamecount > 0 ) {
        Log("Renamed $renamecount scan files");
    }

    # Compress Storage Files
    if ( -e $STORAGEDIR ) {
        $compresscount = 0;
        my @filestokill;
        opendir( DIR, "$STORAGEDIR" )
          or LogDie("Can't open directory $STORAGEDIR: $!\n");
        my $zip = Archive::Zip->new();
        while ( $source = readdir(DIR) ) {

            # Next file if we're at the top or the file was already done
            next if $source =~ /^\.\.?$/;
            next if $source =~ /\.zip$/i;

            Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

            # Compress it if it's older than X days
            if ($deletiondays) {

                # stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
                my $ctime = ( stat( $STORAGEDIR . "\\" . $source ) )[10]
                  or &LogDie("Can't access file $source: $!\n");
                if ( $ctime < $time ) {

                    #delete this file
                    if ($DEBUG) {
                        my $days =
                          floor( eval( eval( time() - $ctime ) / 86400 ) );
                        Log(
"DEBUG: $source is $days days old, should be compressed\n"
                        );
                    }
                    else {
                        my $file_member =
                          $zip->addFile( $STORAGEDIR . "\\" . $source,
                            $source );
                        $filestokill[$compresscount] =
                          $STORAGEDIR . "\\" . $source;
                        $compresscount++;
                        next;
                    }
                }
            }
        }

        # prepare the new zip path
        #
        if ( $compresscount > 0 ) {
            my $newzipfile = genfilename();
            my $newzippath = $STORAGEDIR . "\\" . $newzipfile;

            # write the new zip file
            #
            my $status = $zip->writeToFileNamed($newzippath);
            if ( $status == AZ_OK ) {
                Log("Created file $newzippath");
            }
            else {
                Log("Failed to create file $newzippath");
            }
        }
        closedir(DIR);

        # Delete Storage Files
        foreach (@filestokill) {
            trash($_);
        }

        if ( $compresscount > 0 ) {
            Log("Compressed and deleted $compresscount stored scan files");
        }
    }
}
###############################################################################

### Email subroutine ##########################################################
# Send email if there was an email address to send it to
sub SendEmail() {
    if ( $mailto && $mailfrom && $mailserver ) {
        my $smtp = Net::SMTP->new(
            $mailserver,
            Hello   => $mailhostname,
            Timeout => 30,
            Debug   => 1,
        ) or LogWarn "ERROR creating SMTP object: $! \n";
        if ($smtp) {
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
        }
        else {
            Log("Something is wrong with email");
            return 1;
        }
    }
    else {
        Log(
"Can't send email from $mailfrom to $mailto via $mailserver. Please check configuration."
        );
        return 1;
    }
}

### NMAP subroutine ###########################################################
sub DoNMAP() {

    # If we've got target nodes, we've got work to do.
    if ($nmapcount) {
        our $np = new Nmap::Parser;
        $np->callback( \&nmap_read_results );

        # Ping systems to see which ones are easier to get, and do them first
        my $p           = Net::Ping->new();
        my $pingcount   = 0;
        my $nopingcount = 0;
        foreach my $test (@Address) {

            Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
            my $ping = $p->ping($test);
            if ($ping) {
                push( @Address_p, $test );
                $pingcount++;
            }
            else {
                push( @Address_np, $test );
                $nopingcount++;
            }
        }
        $p->close();
        if ($pingcount) {
            Log(    "Scanning "
                  . $pingcount
                  . " unmanaged nodes without OS Names which respond to ping."
            );
            $np->parsescan( $nmap, $nmap_options, @Address_p );

            # and report to the admin
            Log(
"Finished NMAP scanning ping-friendly unmanaged nodes in the database. There were $goodcount successful scans and $badcount failed scans."
            );
        }

        # Then do the ones that didn't respond to ping
        if ($nopingcount) {
            $goodcount = 0;
            $badcount  = 0;
            Log(    "Scanning "
                  . $nopingcount
                  . " unmanaged nodes without OS Names which don't respond to ping. This may take a significant amount of time to complete."
            );
            $np->parsescan( $nmap, $nmap_options, @Address_np );

            # and report to the admin
            Log(
"Finished NMAP scanning ping-unfriendly unmanaged nodes in the database. There were $goodcount successful scans and $badcount failed scans."
            );
        }
    }
    else {
        if ($DEBUG) {
            Log(
"DEBUG: NMAP binary exists, but we don't seem to have any nodes to scan. nmapcount is $nmapcount."
            );
        }
    }
}
###############################################################################

### Encryption subroutine #####################################################
sub Encrypt {
    my $String    = shift;
    my $Temp      = $String;
    my $Encrypted = "";
    while ( length $Temp > 0 ) {

        #If less than 8 characters, pad it with tabs
        while ( length $Temp < 8 ) { $Temp .= "\t"; }

        # Encrypt the 8 character segment
        my $Temp2 = $Blowfish_Cipher->encrypt( substr( $Temp, 0, 8 ) );

        # Add it to the result
        $Encrypted .= $Temp2;

        # If there's more than 8 get the next segment
        if ( length $Temp > 8 ) { $Temp = substr( $Temp, 8 ); }
        else                    { $Temp = ""; }
    }
    my $Unpacked = unpack( "H*", $Encrypted );
    return ($Unpacked);
}

### Decryption subroutine #####################################################
sub Decrypt {
    my $String    = shift;
    my $Packed    = pack( "H*", $String );
    my $Temp      = $Packed;
    my $Decrypted = "";
    while ( length $Temp > 0 ) {
        my $Temp2 = substr( $Temp, 0, 8 );
        ### In theory, we could up with less than 8 characters, check
        if ( length $Temp2 == 8 ) {
            my $Temp3 = $Blowfish_Cipher->decrypt($Temp2);
            $Decrypted .= $Temp3;
        }
        if ( length $Temp > 8 ) { $Temp = substr( $Temp, 8 ); }
        else                    { $Temp = ""; }
    }

    # Unpad any tabs at the end, which could be a bad thing in theory.
    $Decrypted =~ s/\t+$//g;
    return ($Decrypted);
}

### Zeropad subroutine ########################################################
sub zeropad {

    # Pad IP Addresses with zeroes for use in LANDesk database
    return sprintf( "%03d.%03d.%03d.%03d", split /\./, $_[0] );
}

### Database reading subroutine ###############################################
#Get as much done as quickly as possible and close the connection
sub GetData() {

    # Open the database
    if ( $db_type eq "SQL" ) {
        $dbh =
          DBI->connect(
"dbi:ODBC:driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass"
          ) or &LogDie("Database connection failed: $DBI::errstr\n");
        if ($DEBUG) {
            ### Set the trace output
            DBI->trace( 2, undef );
            Log(
"DEBUG: Opening database with: $db_type, $db_name, $db_instance, $db_user, db_pass"
            );
        }
    }
    elsif ( $db_type eq "ORA" ) {
        $dbh = DBI->connect( "DBI:Oracle:$db_name", $db_user, $db_pass )
          or &LogDie("Database connection failed: $DBI::errstr\n");
        if ($DEBUG) {
            ### Set the trace output
            DBI->trace( 2, undef );
            Log(
"DEBUG: Opening database with: $db_type, $db_name, $db_user, db_pass"
            );
        }
    }
    else {
        &LogDie("Cannot connect, Database type is not specified!\n");
    }

    # Get the deviceid>computer mappings & store them in $nodesfile
    $sql = "select deviceid,devicename from computer";
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    while ( @rows = $sth->fetchrow_array() ) {
        if ( $rows[0] ) { $deviceid   = &Trim( $rows[0] ); }
        if ( $rows[1] ) { $devicename = &Trim( $rows[1] ); }
        $nodes{$deviceid} = $devicename;
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    }

    # Get the patch names & store them in @files
    $sql = "select patch from computervulnerability where detected=0";
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    while ( @rows = $sth->fetchrow_array() ) {
        push( @files, $rows[0] );
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    }

    # Are there any manual download patch URLs I can report on?
    $sql =
"select patch.comments from patch where comments LIKE '%http%' and download='0' and vulnerability_idn in (select distinct vulnerability.vulnerability_idn from vulnerability inner join computervulnerability t1 on vulnerability.vul_id = t1.vul_id where t1.detected='1' and vulnerability.type='0' and vulnerability.fixable='3')";
	$dbh-> {'LongReadLen'} = 300;
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    while ( @rows = $sth->fetchrow_array() ) {
        push( @patchurls, $rows[0] );
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    }

    # How many machines are there?
    $sql = "select count(*) from computer where deviceid != 'Unassigned'";
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    $allmachines = $sth->fetchrow();

    # Are any of them duplicates?
    # This threw an error ORA-00936 for one user
    $sql =
"select distinct [computer].[devicename] from [computer] inner join [computer] t1 on [computer].[devicename] = t1.[devicename] where [computer].[computer_idn] <> t1.[computer_idn] order by [computer].[devicename] asc";
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    while ( @rows = $sth->fetchrow_array() ) {
        push( @dupmachines, $rows[0] );
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    }

    # How many scans came in over the last 24 hours?
    if ( $db_type eq "SQL" ) {
        $sql =
"select count(*) FROM computer where hwlastscandate >= GetDate()-1 and deviceid != 'Unassigned'";
    }
    else {

        # Oracle Support
        $sql =
"select count(*) FROM computer where hwlastscandate >= current_date-1 and deviceid != 'Unassigned'";
    }
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    my $dbscans = $sth->fetchrow();

    # How many scans came in over the last 7 days?
    if ( $db_type eq "SQL" ) {
        $sql =
"select count(*) FROM computer where hwlastscandate >= GetDate()-7 and deviceid != 'Unassigned'";
    }
    else {

        # Oracle Support
        $sql =
"select count(*) FROM computer where hwlastscandate >= current_date-7 and deviceid != 'Unassigned'";
    }
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    $dbscansweek = $sth->fetchrow();

    # How many machines are there in UNMANAGEDNODES?
    $sql = "select count(*) from unmanagednodes";
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    $allmachines_udd = $sth->fetchrow();

    # How many unmanaged nodes pinged over the last 24 hours?
    if ( $db_type eq "SQL" ) {
        $sql =
"select count(*) FROM unmanagednodes where lastscantime >= GetDate()-1";
    }
    else {

        # Oracle Support
        $sql =
"select count(*) FROM unmanagednodes where lastscantime >= current_date-1";
    }
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    $dbscans_udd = $sth->fetchrow();

    # How many unmanaged nodes pinged over the last 7 days?
    if ( $db_type eq "SQL" ) {
        $sql =
"select count(*) FROM unmanagednodes where lastscantime >= GetDate()-7";
    }
    else {

        # Oracle Support
        $sql =
"select count(*) FROM unmanagednodes where lastscantime >= current_date-7";
    }
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    $dbscansweek_udd = $sth->fetchrow();

    # What's the average lifespan of a detected vulnerability?
    if ( $db_type eq "SQL" ) {
        $sql =
"select avg(datediff(ss,datedetected,patchinstalldate)) from computervulnerability where patchinstallstatus = 'Done' and datedetected is not null and patchinstalldate is not null";
    }
    else {

        # Oracle Support
        $sql =
"select avg((patchinstalldate - datedetected) * 24 * 60 * 60) from computervulnerability where patchinstallstatus = 'Done' and datedetected is not null and patchinstalldate is not null";
    }
    $sth = $dbh->prepare($sql) or &LogDie("$sql caused $DBI::errstr\n");
    $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
    $vulnlife = $sth->fetchrow();

    # If NMAP is around, we'll need some database information for it.
    if ($nmap_present) {
        if ( $nmap_options =~ m/-oX|-oN|-oG/ ) {
            LogWarn(
"NMAP Options $nmap_options includes output specification ('-oX', '-oN' or '-oG'). Please remove that option in order to use OS fingerprinting."
            );
            $nmap_present = 0;
        }
        else {

# Get all nodes with no osname or meaningless osname, unless xddexception is set
# Note that rows with no IP address are useless.
            $sql =
"select IPADDRESS from UNMANAGEDNODES where XDDEXCEPTION='0' and IPADDRESS is not NULL ";

# If it's 8.8, WAPDISCOVERED should = 0, but if it's earlier, there is no such field
            if ( $ldms_version >= 88 ) {
                $sql .= "and WAPDISCOVERED='0' ";
            }
            $sql .=
"and OSNAME is null or OSNAME='' or OSNAME='UNKNOWN' or OSNAME='UNIX' ";

            # Add the ones NMAP had trouble with before, if the admin so desires
            if ($nmap_unidentified) {
                $sql .= "or OSNAME='Unidentified' ";
            }

            # Ordered by most-recently seen
            $sql .= "order by LASTSCANTIME desc";
            $nmapcount = 0;
            $sth       = $dbh->prepare($sql)
              or LogWarn("$sql caused $DBI::errstr\n");
            $sth->execute
              or LogWarn("$sql caused $DBI::errstr\n");
            while ( @row = $sth->fetchrow ) {
                if ($DEBUG) { Log("DEBUG: NMAP test $nmapcount, $row[0]"); }
                $Address[$nmapcount] = &Trim( $row[0] );
                $nmapcount++;
                Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
            }
            if ($DEBUG) {
                Log(    "DEBUG: found "
                      . $nmapcount
                      . " NMAP targets, SQL string was $sql" );
            }
        }
    }

# TODO -- If the database isn't busy, reindex it?
# Detecting a need to reindex the database seems to be just as intrusive as actually reindexing the database.
# More research required before this can be done safely.

    # Close the database
    if ($DEBUG) { Log("DEBUG: Closing database."); }
    $sth->finish();
    $dbh->disconnect;
}
###############################################################################


### NMAP subroutine ###########################################################
sub nmap_read_results() {
    my $host = shift;    #Nmap::Parser::Host object, just parsed
    if ($DEBUG) {
        Log( "DEBUG: NMAP callback received for " . $host->addr );
    }
    my $hostaddr = &zeropad( $host->addr );

    my $OS;
    my $newmac;
    my $status = $host->status();

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ( $status eq 'up' ) {

        # Open the database
        if ( $db_type eq "SQL" ) {
            $dbh =
              DBI->connect(
"dbi:ODBC:driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass"
              ) or &LogDie("Database connection failed: $DBI::errstr\n");
            if ($DEBUG) {
                ### Set the trace output
                DBI->trace( 2, undef );
                Log("DEBUG: Opening database for NMAP record updating");
            }
        }
        elsif ( $db_type eq "ORA" ) {
            $dbh = DBI->connect( "DBI:Oracle:$db_name", $db_user, $db_pass )
              or &LogDie("Database connection failed: $DBI::errstr\n");
            if ($DEBUG) {
                ### Set the trace output
                DBI->trace( 2, undef );
                Log("DEBUG: Opening database for NMAP record updating");
            }
        }
        else {
            &LogDie(
"Cannot connect to database for NMAP record updating, Database type is not specified!\n"
            );
        }

 # Sometimes UNMANAGEDNODES doesn't have the MAC address, so let's save that now
        $newmac = $host->mac_addr();
        if ($newmac) {

            # Sanitize the new MAC Address
            $newmac =~ s/://g;
            $newmac =~ s/-//g;
            chomp($newmac);

            # Update the MAC Address if it didn't exist before
            $sql =
              "select top 1 PHYSADDRESS from UNMANAGEDNODES WHERE IPADDRESS=?";
            $sth = $dbh->prepare($sql)
              or LogWarn "$sql caused $DBI::errstr\n";
            $sth->execute($hostaddr)
              or LogWarn "$DBI::errstr\n";
            @row = $sth->fetchrow;
            my $oldmac = $row[0];
            $sth->finish();

            if ($oldmac) {
                $sql =
                  "update UNMANAGEDNODES set PHYSADDRESS=? where IPADDRESS=?";
                $sth = $dbh->prepare($sql)
                  or LogWarn "$sql caused $DBI::errstr\n";
                $sth->execute( $newmac, $hostaddr )
                  or LogWarn "$DBI::errstr\n";
                $sth->finish();
                if ($DEBUG) {
                    Log(    "DEBUG: Set MAC Address of "
                          . $host->addr . " to "
                          . $newmac . " at "
                          . localtime() );
                }
            }

            # Get the MAC address manufacturer if available
            my $vendor_id = $host->mac_vendor();

            # Update the Manufacturer if it didn't exist before
            if ( $ldms_version >= 88 ) {
                if ($vendor_id) {
                    $sql =
"select top 1 MANUFACTURER from UNMANAGEDNODES WHERE IPADDRESS=?";
                    $sth = $dbh->prepare($sql)
                      or LogWarn "$sql caused $DBI::errstr\n";
                    $sth->execute($hostaddr)
                      or LogWarn "$DBI::errstr\n";
                    @row = $sth->fetchrow;
                    my $oldman = $row[0];
                    $sth->finish();
                    if ( length($oldman) < 2 or $oldman eq "UNKNOWN" ) {
                        $sql =
"update UNMANAGEDNODES set MANUFACTURER=? where IPADDRESS=?";
                        $sth = $dbh->prepare($sql)
                          or LogWarn "$sql caused $DBI::errstr\n";
                        $sth->execute( $vendor_id, $hostaddr )
                          or LogWarn "$DBI::errstr\n";
                        $sth->finish();
                        if ($DEBUG) {
                            Log(    "DEBUG: Set Manufacturer of "
                                  . $host->addr . " to "
                                  . $vendor_id . " at "
                                  . localtime() );
                        }
                    }
                }
            }
        }

        # And now let's look at the OS Name
        my $os = $host->os_sig();
        $OS = $os->name;
        if ($OS) {
            $OS .= " \(" . $os->name_accuracy . " percent\)";
        }
        else {
            $OS = "Unidentified";
        }

        # Make sure it fits into the database field
        if ($OS) {
            if ( length($OS) > 254 ) {
                $OS = substr( $OS, 0, 255 );
            }
            chomp($OS);
            &Trim($OS);
            $sql = "update UNMANAGEDNODES set OSNAME=? where IPADDRESS=?";
            $sth = $dbh->prepare($sql)
              or LogWarn "$sql caused $DBI::errstr\n";
            $sth->execute( $OS, $hostaddr )
              or LogWarn "$DBI::errstr\n";
            $sth->finish();
        }
        if ($DEBUG) {
            Log(    "DEBUG: Set OS Name of "
                  . $host->addr . " to "
                  . $OS . " at "
                  . localtime() );
        }
        $goodcount++;

        # Close the database
        if ($DEBUG) { Log("DEBUG: Closing database."); }
        $dbh->disconnect;
        return 0;
    }
    else {

        # target was down
        if ($DEBUG) {
            Log( "DEBUG: " . $host->addr . " was down at " . localtime() );
        }
        $badcount++;
        return 1;
    }
}
###############################################################################

### ASCII to Integer subroutine ###############################################
sub atoi() {
    my $t = 0;
    foreach my $d ( split( //, shift() ) ) {
        $t = $t * 10 + $d;
    }
    return $t;
}

### Setup subroutine ##########################################################
sub Setup() {

    # Get database info
    &Show_MainWindow;
    Win32::GUI::Dialog();
    if ($DEBUG) { Log("DEBUG: Returned to Setup from Show_MainWindow"); }

    # Get mail server info
    &Show_SecondWindow;
    Win32::GUI::Dialog();
    if ($DEBUG) { Log("DEBUG: Returned to Setup from Show_SecondWindow"); }

    # Encrypt password
    my $db_pass_storage = &Encrypt($db_pass);

    # Write discovered data
    $Registry->{"LMachine/Software/Monkeynoodle/"} = {
        "ldms_core/" => {
            "/db_type"           => $db_type,
            "/db_instance"       => $db_instance,
            "/db_name"           => $db_name,
            "/db_user"           => $db_user,
            "/db_pass"           => $db_pass_storage,
            "/mailserver"        => $mailserver,
            "/mailfrom"          => $mailfrom,
            "/mailto"            => $mailto,
            "/deletiondays"      => $deletiondays,
            "/nmap"              => $nmap,
            "/nmap_options"      => $nmap_options,
            "/nmap_unidentified" => $nmap_unidentified,
        },
    };
    if ($DEBUG) {
        Log(
"DEBUG: Wrote $db_type, $db_instance, $db_name, $db_user, $db_pass_storage, $mailserver, $mailfrom, $mailto, $deletiondays into Monkeynoodle registry key."
        );
    }
    Win32::GUI::MessageBox(
        0,
        "Please create a scheduled task to run ldms_core.exe",
        "Setup complete!", 64
    );

    # Restore console window
    Win32::GUI::Show($DOS);
}

# Get the machine's SID for use as an encryption key
sub GetSID {
    my $system  = shift;
    my $account = shift;
    my $domain  = shift;
    no warnings 'uninitialized';
    my ( $sid, $sidtype );
    Win32::LookupAccountName( $system, $account, $domain, $sid, $sidtype );
    my $sidstring = Win32::Security::SID::ConvertSidToStringSid($sid);
    return $sidstring;
}
###############################################################################

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
        -name => "lblInstructions",
        -text => "Please enter the required database information.",
        -pos  => [ 5, 5 ],
        -size => [ 300, 20 ],
    );

    # Begin db_instance row
    $form_db_instance = $main->AddTextfield(
        -name    => "db_instance_field",
        -prompt  => "Database Server:",
        -text    => $db_instance,
        -tabstop => 1,
        -pos     => [ 110, 25 ],
        -size    => [ 200, 20 ],
    );

    # Begin db_name row
    $form_db_name = $main->AddTextfield(
        -name    => "db_name_field",
        -prompt  => "LANDesk Database:",
        -text    => $db_name,
        -tabstop => 1,
        -pos     => [ 110, 50 ],
        -size    => [ 200, 20 ],
    );

    # Begin db_user row
    $form_db_user = $main->AddTextfield(
        -name    => "db_user_field",
        -prompt  => "Database Username:",
        -text    => $db_user,
        -tabstop => 1,
        -pos     => [ 110, 75 ],
        -size    => [ 200, 20 ],
    );

    # Begin db_pass row
    $form_db_pass = $main->AddTextfield(
        -name     => "db_pass_field",
        -prompt   => "Database Password:",
        -text     => $db_pass,
        -tabstop  => 1,
        -password => 1,
        -pos      => [ 110, 100 ],
        -size     => [ 200, 20 ],
    );

    # Begin db_type row
    $lbl_db_type = $main->AddLabel(
        -name => "lbldb_type",
        -text => "Is this an Oracle database?",
        -pos  => [ 5, 125 ],
        -size => [ 300, 20 ],
    );

    $form_db_type = $main->AddCheckbox(
        -name    => "form_db_type",
        -tabstop => 1,
        -pos     => [ 145, 123 ],
        -size    => [ 20, 20 ],
    );

    # Convert Oracle/SQL decision to binary
    my $db_type_binary;
    if ( $db_type eq "ORA" ) {
        $db_type_binary = 1;
    }
    else {
        $db_type_binary = 0;
    }
    $form_db_type->Checked($db_type_binary);

    # End db_type row

    # Begin button row
    $btn_default = $main->AddButton(
        -name    => 'Default',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,              # Give button darker border
        -ok      => 1,              # press 'Return' to click this button
        -pos     => [ 100, 150 ],
        -size    => [ 60, 20 ],
    );

    $btn_cancel = $main->AddButton(
        -name    => 'Cancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,              # press 'Esc' to click this button
        -pos     => [ 170, 150 ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $sb = $main->AddStatusBar();

    # calculate its size
    $ncw = $main->Width() - $main->ScaleWidth();
    $nch = $main->Height() - $main->ScaleHeight();
    $w   = $lbl_Instructions->Width() + 30 + $ncw;
    $h =
      $lbl_Instructions->Height() +
      $form_db_instance->Height() +
      $form_db_name->Height() +
      $form_db_user->Height() +
      $form_db_pass->Height() + 90 +
      $nch;

    # Don't let it get smaller than it should be
    $main->Change( -minsize => [ $w, $h ] );

    # calculate its centered position
    # Assume we have the main window size in ($w, $h) as before
    $desk = Win32::GUI::GetDesktopWindow();
    $dw   = Win32::GUI::Width($desk);
    $dh   = Win32::GUI::Height($desk);
    $wx   = ( $dw - $w ) / 2;
    $wy   = ( $dh - $h ) / 2;

    # Resize, position and display
    $main->Resize( $w, $h );
    $main->Move( $wx, $wy );

    $main->Show();
}
###############################################################################

sub Main_Terminate {
    return -1;
}

sub Main_Resize {
    $sb->Move( 0, $main->ScaleHeight - $sb->Height );
    $sb->Resize( $main->ScaleWidth, $sb->Height );
}

# What do do when the button is clicked #######################################
sub Default_Click {

    # Read my variables
    $db_instance    = $form_db_instance->GetLine(0);
    $db_name        = $form_db_name->GetLine(0);
    $db_user        = $form_db_user->GetLine(0);
    $db_pass        = $form_db_pass->GetLine(0);
    $db_type_binary = $form_db_type->Checked();
    if ( $db_type_binary == 1 ) {
        $db_type = "ORA";
    }
    else {
        $db_type = "SQL";
    }

    # Open the database. If it fails, then put an error message up and wait for
    # another try.
    if ( $db_type eq "SQL" ) {
        $dbh =
          DBI->connect(
"dbi:ODBC:driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass"
          )
          or Win32::GUI::MessageBox( 0, "$DBI::errstr",
            "Database connection failed", 48 );
        if ($DEBUG) {
            Log(
"DEBUG: Okay clicked in MainWindow: Opening database with $db_type, $db_instance, $db_name, $db_user, db_pass"
            );
        }
    }
    else {
        $dbh = DBI->connect( "DBI:Oracle:$db_name", $db_user, $db_pass )
          or Win32::GUI::MessageBox( 0, "$DBI::errstr",
            "Database connection failed", 48 );
        if ($DEBUG) {
            Log(
"DEBUG: Okay clicked in MainWindow: Opening database with $db_type, $db_name, $db_user, db_pass"
            );
        }
    }
    if ( !$dbh ) {
        if ($DEBUG) { Log("DEBUG: Failed database connection"); }
        $sb->SetText( 0, "Connection failed, please try again." );
        return 0;
    }

    # Get the mail server info & store in $mailserver and $mailfrom
    if ( $db_type eq "SQL" ) {
        $sql =
"select top 1 host,replyemail from ld_task_smtp where sendusing='2' and port='25'";
    }
    else {
        $sql =
"select * from (select host,replyemail from ld_task_smtp where sendusing='2' and port='25') where rownum = 1";
    }
    $sth = $dbh->prepare($sql)
      or LogWarn("Database connection failure.\n");
    $sth->execute
      or LogWarn("Database connection failure.\n");
    while ( @rows = $sth->fetchrow_array() ) {
        $mailserver = $rows[0] || $A{s};
        $mailfrom   = $rows[1] || $A{f};
    }

    # Close the database
    $dbh->disconnect;
    if ($DEBUG) {
        Log("DEBUG: Read $mailserver, $mailfrom from database connection");
    }

    # If it succeeded, we're ready to close the window and move on.
    $main->Hide();
    return -1;
}
###############################################################################

sub Cancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in MainWindow"); }
    $main->Hide();

    Log("$prog $ver exiting");

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

# This subroutine gets email information ######################################
sub Show_SecondWindow {

    # build window
    $second = Win32::GUI::Window->new(
        -name   => 'Second',
        -text   => 'ldms_core email and nmap setup',
        -width  => 350,
        -height => 220,
    );

    # Add some stuff
    $lbl_email = $second->AddLabel(
        -name    => "lbl_email",
        -text    => "Please enter the required email and NMAP information.",
        -tabstop => 1,
        -pos     => [ 5, 5 ],
        -size    => [ 300, 20 ],
    );

    # Begin mailserver row
    $form_mailserver = $second->AddTextfield(
        -name    => "mailserver_field",
        -prompt  => "Email Server:",
        -text    => $mailserver,
        -tabstop => 1,
        -pos     => [ 110, 25 ],
        -size    => [ 200, 20 ],
    );

    # Begin mailfrom row
    $form_mailfrom = $second->AddTextfield(
        -name    => "mailfrom_field",
        -prompt  => "Email From Address:",
        -tabstop => 1,
        -text    => $mailfrom,
        -pos     => [ 110, 50 ],
        -size    => [ 200, 20 ],
    );

    # Begin mailto row
    $form_mailto = $second->AddTextfield(
        -name    => "mailto_field",
        -prompt  => "Email To Address:",
        -tabstop => 1,
        -text    => $mailto,
        -pos     => [ 110, 75 ],
        -size    => [ 200, 20 ],
    );

    # Begin days to deletion row
    $form_deletiondays = $second->AddTextfield(
        -name    => "deletiondays_field",
        -prompt  => "Purge old files after X Days (0 to disable):",
        -tabstop => 1,
        -text    => $deletiondays,
        -pos     => [ 210, 100 ],
        -size    => [ 40, 20 ],
    );

    # Begin nmap binary row
    $form_nmap = $second->AddTextfield(
        -name    => "nmap_field",
        -prompt  => "Path to nmap binary:",
        -tabstop => 1,
        -text    => $nmap,
        -pos     => [ 110, 125 ],
        -size    => [ 200, 20 ],
    );

    # Begin nmap commandline row
    $form_nmap_options = $second->AddTextfield(
        -name    => "nmap_options_field",
        -prompt  => "nmap options:",
        -tabstop => 1,
        -text    => $nmap_options,
        -pos     => [ 110, 150 ],
        -size    => [ 200, 20 ],
    );

    # Begin nmap unidentified row (label and checkbox)
    $form_nmap_ulabel = $second->AddLabel(
        -name => "nmap_ulabel",
        -text => "Should nmap skip previously unidentified nodes?",
        -pos  => [ 5, 175 ],
        -size => [ 300, 20 ],
    );

    $form_nmap_u = $second->AddCheckbox(
        -name    => "form_nmap_u",
        -tabstop => 1,
        -Checked => $nmap_unidentified,
        -pos     => [ 245, 173 ],
        -size    => [ 20, 20 ],
    );

    # Begin button row
    $btn_seconddefault = $second->AddButton(
        -name    => 'secondDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,                 # Give button darker border
        -ok      => 1,                 # press 'Return' to click this button
        -pos     => [ 100, 200 ],
        -size    => [ 60, 20 ],
    );

    $btn_secondcancel = $second->AddButton(
        -name    => 'secondCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                 # press 'Esc' to click this button
        -pos     => [ 170, 200 ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $sb2 = $second->AddStatusBar();

    # calculate its size
    $ncw = $second->Width() - $second->ScaleWidth();
    $nch = $second->Height() - $second->ScaleHeight();
    $w   = $lbl_email->Width() + 30 + $ncw;
    $h =
      $lbl_email->Height() +
      $form_mailserver->Height() +
      $form_mailfrom->Height() +
      $form_mailto->Height() +
      $form_deletiondays->Height() +
      $form_nmap->Height() +
      $form_nmap_options->Height() +
      $form_nmap_ulabel->Height() + 90 +
      $nch;

    # Don't let it get smaller than it should be
    $second->Change( -minsize => [ $w, $h ] );

    # calculate its centered position
    # Assume we have the main window size in ($w, $h) as before
    $desk = Win32::GUI::GetDesktopWindow();
    $dw   = Win32::GUI::Width($desk);
    $dh   = Win32::GUI::Height($desk);
    $wx   = ( $dw - $w ) / 2;
    $wy   = ( $dh - $h ) / 2;

    # Resize, position and display
    $second->Resize( $w, $h );
    $second->Move( $wx, $wy );

    $second->Show();
}
###############################################################################

sub Second_Terminate {
    return -1;
}

sub Second_Resize {
    $sb2->Move( 0, $second->ScaleHeight - $sb2->Height );
    $sb2->Resize( $second->ScaleWidth, $sb2->Height );
}

sub secondDefault_Click {

    # Read my variables
    $mailserver        = $form_mailserver->GetLine(0);
    $mailfrom          = $form_mailfrom->GetLine(0);
    $mailto            = $form_mailto->GetLine(0);
    $deletiondays      = $form_deletiondays->GetLine(0);
    $nmap              = Win32::GetShortPathName( $form_nmap->GetLine(0) );
    $nmap_options      = $form_nmap_options->GetLine(0);
    $nmap_unidentified = $form_nmap_u->Checked();

    if ($DEBUG) {
        Log(
"DEBUG: Okay clicked in SecondWindow, read $mailserver, $mailfrom, $mailto, $deletiondays"
        );
    }
    $second->Hide();
    return -1;
}

sub secondCancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in SecondWindow"); }

    Log("$prog $ver exiting");

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

## System tray icon subroutines ###############################################

sub systraymain_Terminate {
    &LogDie("Killed by user");
}

sub systraymenu {
    $systraymain->TrackPopupMenu( $popupMenu->{Options} );
    return 1;
}

sub systrayexit {
    &LogDie("Killed by user");
}
## End of Windowing Subroutines  ############################################

