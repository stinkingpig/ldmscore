#############################################################################
# ldms_core.pl                                                              #
# (c) 2005-2009 Jack Coates, jack@monkeynoodle.org                          #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/                                            #
#############################################################################

# TODO -- Delete ghost devices from scheduled tasks (stuck in active because
# they reported status). If they were from a query they should be deleted from
# the list, but if they were from a static targeting they should be moved to
# pending. http://community.landesk.com/support/message/17222#17222
# TODO -- report Distribution Packages not associated with a scheduled task.
# TODO -- option not to cull IPs... duplicates could exist because of NAT,
# gateway usage
# TODO -- Check vulns in DO NOT SCAN to see if they're not fully superceded
# anymore. Vulns can get moved to do not scan for valid reasons, but later
# updated so that they should be scanned again.

package ldms_core;
#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use warnings;
use Env;
use English qw( -no_match_vars );
use Cwd;
use DBI;
use IO::Handle;
use Crypt::Blowfish;
use Graph::Easy;
use Getopt::Long;
use Tie::Comma;
use Readonly;
use Win32;
use Win32::OLE qw(in);
use Win32::OLE::NLS qw(:TIME
  :DATE
  GetLocaleInfo GetUserDefaultLCID
  LOCALE_SMONTHNAME1 LOCALE_SABBREVMONTHNAME1
  LOCALE_SDAYNAME1 LOCALE_SABBREVDAYNAME1
  LOCALE_IFIRSTDAYOFWEEK
  LOCALE_SDATE LOCALE_IDATE
  LOCALE_SGROUPING
);
use Win32::GUI::Carp;
use Win32::File::VersionInfo;
use Win32::FileOp;
use Win32::GUI();
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1 );
use Win32::API;
use Win32::EventLog;
use Win32::EventLog::Message;
use Win32::Security::SID;
use Win32::WebBrowser;
use Win32::Service;
use POSIX qw(floor);
use File::Copy;
use File::Remove qw(trash);
use File::ReadBackwards;
use Archive::Zip qw( :ERROR_CODES );
use Net::SMTP;
use Net::SMTP_auth;
use Net::Ping;
use Net::Traceroute::PurePerl;
use Sys::Hostname;
use Lingua::EN::Inflect qw(PL PL_V NUMWORDS);
use Number::Bytes::Human qw(format_bytes);
use Sort::Naturally qw(nsort);
use Nmap::Parser;
use RRD::Simple;
use LWP::Simple qw($ua get);
use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;
use Date::Parse qw(str2time);

#############################################################################
# Preparation                                                               #
#############################################################################
my $commandline;
for ( 0 .. $#ARGV ) {
    $commandline .= "$ARGV[$_] ";
}

my ( $DEBUG, $setup, $help, $map ) = ( 0, 0, 0, 0 );
Getopt::Long::Configure( "long_prefix_pattern=(--|\/)",
    "prefix_pattern=(--|-|\/)" );
GetOptions(
    'debug' => \$DEBUG,
    'setup' => \$setup,
    'help'  => \$help,
    'map'   => \$map,
);

( my $prog = $0 ) =~ s/^         # command line from the beginning
                       .*[\\\/]  # without any slashes
                       //x;
$VERSION = "3.9.3";

my $usage = <<"EOD";

Usage: $prog [/debug] [/setup] [/help] [/map]
			 
	/d(ebug)	 debug
	/s(etup)	 setup the product.
	/h(elp)		 this display
    /m(ap)       Should ldms_core generate a network topology map?

$prog v $VERSION
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program maintains your LANDesk core server. It provides HTML reports 
and will email you if there's something important.
The latest version lives at http://www.droppedpackets.org/scripts/ldms_core.

EOD
croak $usage if $help;

# It takes a long time to do all this preprocessing stuff before setup starts,
# so I want to show an hourglass cursor.
my ( $loadImage, $waitCursor, $oldCursor );
if ($setup) {
    $loadImage =
      new Win32::API( 'user32', 'LoadImage', [ 'N', 'N', 'I', 'I', 'I', 'I' ],
        'N' )
      or croak 'cannot find LoadImage function';
    $waitCursor = $loadImage->Call( 0, 32514, 2, 0, 0, 0x8040 );
    $oldCursor = Win32::GUI::SetCursor($waitCursor);    #show hourglass ...

}

#############################################################################
# Variables                                                                 #
#############################################################################

# Global variables
my (
    $ldmain,              $PATCHDIR,         $db_type,
    $db_user,             $db_pass,          $db_name,
    $db_instance,         $reportdir,        $sql,
    $dbh,                 $sth,              @row,
    @patchurls,           @patchcounts,      @autofixcounts,
    $mailserver,          $mailfrom,         $mailto,
    $mailmessage,         $mail_auth_user,   $emailsubject,
    $mail_auth_pass,      $mail_auth_type,   $mailverbosity,
    $DIR,                 $FILE,             $updatemessage,
    $nmap,                $nmap_options,     $np,
    $nmap_unidentified,   @Address,          $allmachines,
    @dupmachines,         $dbscans,          $dbscansweek,
    $allmachines_udd,     $dbscans_udd,      $vulnlife,
    $dbscansweek_udd,     @dupaddresses,     $daypercent,
    $weekpercent,         $daypercent_udd,   %rtn,
    $weekpercent_udd,     @dualboots,        $supercededvulncount,
    @supercededvulns,     $update,           $lpmdir,
    $CullVulnsAggression, $dir,              $sendemail,
    $DOS,                 $event,            $newname,
    $file,                $ldmsrrd,          $ldmsrrdfile,
    $ldmsrrd_udd,         $ldmsrrdfile_udd,  $ldssrrd,
    $ldssrrdfile,         $ldssrrd_life,     $ldssrrdfile_life,
    $ldmsrrd_life,        $ldmsrrdfile_life, $ldmsrrd_alerts,
    $ldmsrrdfile_alerts,  $logfile,          $DEBUGFILE,
    $unassignedvulns,     $nmap_do,          $patch_do,
    $netmap_url,          $dbreindex_do,     $mapfloor,
    $nmap_max,            $tasks_good,       $tasks_bad,
    $tasks_all,           $ldmsrrd_sched,    $ldmsrrdfile_sched,
    $rc_users,            $rc_machines,      $rc_all,
    $ldmsrrd_rc,          $ldmsrrdfile_rc,   $tasklife,
    $tasks_percent,       $pudcount,         $db_is_open,
    $RegKey,              $alert_all,        @staletasks,
    $cullundetectedvulns, $ldms_version,     $proxy_server,
    $proxy_user,          $proxy_pass
);

# Default to zero
my (
    $deletiondays, $osupdates,   $macupdates,  $vendorupdates,
    $goodcount,    $recentvulns, $vulncount,   $patchtotal,
    $autofixtotal, $trashcount,  $renamecount, $compresscount,
    $totalsize,    $showsystray
) = ( 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );

# GUI variables
my (
    $ldms_core_icon, $ldms_core_class, $systrayicon,
    $systraymain,    $popupMenu,       $systraynotify
);

# Setup UI variables
my (
    $DBWindow,                 $lbl_Instructions,
    $form_db_instance,         $form_db_name,
    $form_db_user,             $form_db_pass,
    $lbl_db_type,              $form_db_type,
    $db_type_binary,           $form_patchdir_override,
    $btn_DBWindowDefault,      $btn_DBWindowCancel,
    $btn_DBWindowHelp,         $btn_DBWindowDBInfo,
    $btn_browsepatchdir,       $btn_browsenmap,
    $DBWindowsb,               $ConfigWindow,
    $lbl_email,                $lbl_patch,
    $lbl_update,               $form_update,
    $form_mailserver,          $form_mailfrom,
    $form_mailto,              $form_deletiondays,
    $btn_ConfigWindowdefault,  $btn_ConfigWindowcancel,
    $ConfigWindowsb,           $form_nmap,
    $form_nmap_u,              $form_nmap_options,
    $form_nmap_ulabel,         $btn_mailauth,
    $btn_ConfigWindowHelp,     $MailAuth,
    $lbl_mailinstructions,     $form_mail_auth_user,
    $form_mail_auth_pass,      $btn_MailAuthDefault,
    $btn_MailAuthCancel,       $btn_MailAuthHelp,
    $MailAuthsb,               $form_mail_auth_type,
    $lbl_mail_auth_type,       $btn_mailtest,
    $form_mailverbosity,       $lbl_mailverbosity,
    $lbl_showsystray,          $form_showsystray,
    $lbl_cullvulnsaggression,  $lbl_cullvulnsaggression2,
    $form_cullvulnsaggression, $w,
    $h,                        $ncw,
    $nch,                      $dw,
    $dh,                       $desk,
    $wx,                       $wy,
    $ConfigWindoww,            $ConfigWindowh,
    $ConfigWindowncw,          $ConfigWindownch,
    $ConfigWindowwx,           $ConfigWindowwy,
    $MailAuthw,                $MailAuthh,
    $MailAuthncw,              $MailAuthnch,
    $MailAuthwx,               $MailAuthwy,
    $form_nmap_dolabel,        $form_nmap_do,
    $form_patch_dolabel,       $form_patch_do,
    $ConfigWindowTab,          $form_netmap_url,
    $form_dbreindex_do,        $lbl_dbreindex_do,
    $form_mapfloor,            $form_nmap_max,
    $form_cullundetectedvulns, $lbl_cullundetectedvulns,
    $form_proxy_server,        $form_proxy_user,
    $form_proxy_pass
);

&StartLogging;

# Prepare encryption system
my $Blowfish_Cipher;
&PrepareCrypto;

# Read the registry
&ReadRegistry;

# Prepare the RRD files
&PrepareRRD;

# Prepare Windows OLE object for reading WMI
my $strComputer = '.';
Readonly my $HKEY_LOCAL_MACHINE => 0x80000002;
Readonly my $EPOCH              => 25569;
Readonly my $SEC_PER_DAY        => 86400;
my $objWMIService =
  Win32::OLE->GetObject( 'winmgmts:'
      . '{impersonationLevel=impersonate}!\\\\'
      . $strComputer
      . '\\root\\cimv2' );
my $objShell = Win32::OLE->new('WScript.Shell');

my $lcid;

BEGIN {
    $lcid = GetUserDefaultLCID();
    Win32::OLE->Option( LCID => $lcid );
}

#############################################################################
# Main Loop                                                                 #
#############################################################################

# Now we're running for real, so let's show off
if ($showsystray) { &EnableSystray; }

# Check to see if there's an update available
&IsUpdate;

# Should we do setup?
if ($setup) {
    &Log("$prog $VERSION starting in setup mode");
    &Setup;
    &Log("$prog $VERSION exiting");
    exit 0;
}

# Default to something sensible
&SetSeverity( 10, "ldms_core $VERSION report" );

#Open the database at the beginning of the program
&OpenDB;

# What's the LANDesk version we're working with?
$ldms_version = &GetLDVersion;

# Should reindex the database before asking it to work hard on our behalf
if ($dbreindex_do) {
    &ChangeBalloon( "tip", "Reindexing database" );
    &DBReindex;
}

# Read all our database information now
&ChangeBalloon( "tip", "Gathering management information from the database" );
&GetLDMSData;
&ChangeBalloon( "tip", "Gathering security information from the database" );
&GetLDSSData;

# Do all that fancy calculation stuff
&ChangeBalloon( "tip", "Calculating statistics" );
&DoInventoryMath;
&DoUDDMath;
&DoTaskMath;
&DoTaskLife;
&ReportStaleTasks;
&DoRCMath;
&DoVulnLife;
&DoPatchStats;

# Report all those stats
&ChangeBalloon( "tip", "Reporting LDMS statistics" );
&ReportLDMSStats;

# Check for exceeded thresholds
&ChangeBalloon( "tip", "Checking for exceeded thresholds" );
&CountPendingScans();

# Report on LDSS Statistics
&ChangeBalloon( "tip", "Reporting LDSS statistics" );
&ReportLDSSStats;

# Work on the patch files
if ($patch_do) {

    # Work on superceded vulnerabilities
    &ChangeBalloon( "tip", "Culling orphaned vulnerability records" );
    &CullOrphanCompVulns;
    &CullOrphanPatchHistory;
    &ChangeBalloon( "tip", "Culling undetected vulnerability counts" );
    &CullUndetectedVulnCounts;
    &ChangeBalloon( "tip", "Culling superceded vulnerabilities" );
    &CullVulns;
    &ChangeBalloon( "tip", "Culling patches" );
    &CullPatches;
    &CullPatchFiles;

# purge .tmp files from vulnerabilitydata - http://community.landesk.com/support/docs/DOC-5812
    &CullTMP( $ldmain . "ldlogon\\VulnerabilityData" );
    &StuckLPM;
}

# Clean up old data
&DoCulling;
&RenameScanFiles;

# Check that all the services are running
&ChangeBalloon( "tip", "Checking service status" );
&ServiceCheckLoop;
&CullRollingLog;

# Check system health
&HealthCheck;

# Create the topology map
if ($map) {
    &ChangeBalloon( "tip", "Creating a network topology map" );
    &TopologyMap;
}

# Should we use NMAP?
if ($nmap_do) {
    &GetNMAP;
}

# Do we need to send a message?
if ( $sendemail <= $mailverbosity || $DEBUG ) {
    if ($DEBUG) {
        &LogDebug(
            "Main: sendemail is $sendemail, mailverbosity is $mailverbosity");
    }
    if (&ShouldEmail) {
        &ChangeBalloon( "tip", "Sending email" );
        &Log("Sending level $sendemail email report to $mailto.");
        &SendEmail;
    }
}

&Log("$prog $VERSION exiting.");

# Write the output into the report directory.
&WriteReport;

# Shouldn't need this anymore
&CloseDB;

# Restore console window
Win32::GUI::Show($DOS);

# clean up the tray icon
if ($showsystray) { $systraynotify->Remove(); }

#exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################

# Utility Subroutines #######################################################
#
### PrepareCrypto subroutine ################################################
# Set up the cryptographic subsystem and ensure that we have a good key
sub PrepareCrypto {
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
    my $system       = Win32::NodeName;
    my $account      = Win32::LoginName;
    my $Blowfish_Key = &GetSID( $system, $system );
    if ($DEBUG) { &LogDebug("PrepareCrypto: Machine SID is $Blowfish_Key"); }
    $Blowfish_Cipher = new Crypt::Blowfish $Blowfish_Key;
    return 0;
}

## GetSID Subroutine #######################################################
# Get the machine's SID for use as an encryption key
sub GetSID {
    my $system  = shift;
    my $account = shift;
    my $domain  = shift;
    my ( $sid, $sidtype );
    Win32::LookupAccountName( $system, $account, $domain, $sid, $sidtype );
    my $sidstring = Win32::Security::SID::ConvertSidToStringSid($sid);
    return $sidstring;
}

### Generate file names based on the date ####################################
sub GenFileName {
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
      localtime(time);
    my $return = sprintf "%04d%02d%02d-%02d%02d%02d", $year + 1900, $mon + 1,
      $mday, $hour, $min, $sec;
    return $return;
}

### Directory maker #########################################################
sub MakeDir {
    my $target = shift;
    if ( -e $target ) {

        # It already exists, my work here is through. I'm still warning and
        # returning 1 because I shouldn't have been called
        &LogWarn("MakeDir called uselessly for $target");
        return 1;
    }
    else {
        mkdir( $target, "755" )
          or &LogDie("MakeDir failed to make $target - $!");
        return 0;
    }
}

### Encryption subroutine ###################################################
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

### Decryption subroutine ###################################################
sub Decrypt {
    my $String = shift;
    my ( $Packed, $Temp, $Decrypted );
    if ( !defined($String) ) {
        &LogWarn("Decrypt routine called with nothing to do");
    }
    $Packed    = pack( "H*", $String );
    $Temp      = $Packed;
    $Decrypted = "";
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
    $Decrypted =~ s/\t+$//gx;
    return ($Decrypted);
}

### Zeropad subroutine ######################################################
sub ZeroPad {

    my $ip = shift;

    # Pad IP Addresses with zeroes for use in LANDesk database
    my $return = sprintf( "%03d.%03d.%03d.%03d", split /\./x, $ip );
    return $return;
}

### ZeroUnPad subroutine ######################################################
sub ZeroUnPad {

    my $ip = shift;
    my $return;

    # Remove padding zeroes from IP Addresses
    my @temp = split( /\./x, $ip );
    foreach my $octet (@temp) {
        $return .= &AtoI($octet);
        $return .= ".";
    }

    # knock that last period off
    $return = substr( $return, 0, -1 );
    if ($DEBUG) { &LogDebug("ZeroUnPad: turned $ip into $return"); }
    return $return;
}

# Is this core using a local SQL server? #####################################
sub LocalSQL {
    my $hostname  = hostname;
    my $SQLonCore = 0;
    if ( $hostname eq $db_instance ) {
        if ($DEBUG) {
            &LogDebug("LocalSQL: Core is using a local SQL Server.");
        }
        return 1;
    }
    return 0;
}

# How much RAM does this core have? ##########################################
sub CountRAM {
    my $output = 'unknown';
    my $SystemList =
      $objWMIService->ExecQuery("SELECT * FROM Win32_OperatingSystem");
    if ( $SystemList->Count > 0 ) {
        foreach my $System ( in $SystemList) {
            $output = int( $System->TotalVisibleMemorySize / 1024 );
            if ($DEBUG) { &LogDebug("CountRAM: Core has $output MB of RAM."); }
        }
    }
    if ( $output ne 'unknown' ) {
        return $output;
    }
    else {
        return -1;
    }
}

### Don't let email severity get reset to something less urgent #############
sub SetSeverity {

    my ( $severity, $subject ) = @_;
    if ( !defined($severity) ) {
        &LogWarn("SetSeverity: called with nothing to do!");
        return 1;
    }
    if ( !defined($subject) ) {
        &LogWarn("SetSeverity: called without a subject line!");
        return 1;
    }
    if ( !defined($sendemail) ) { $sendemail = 10; }
    if ( $severity < $sendemail ) {
        if ($DEBUG) {
            &LogDebug( "SetSeverity: resetting severity level from "
                  . "$sendemail to $severity" );
        }
        $sendemail = $severity;
        if ($subject) {
            if ($DEBUG) {
                &LogDebug( "SetSeverity: resetting subject line from "
                      . "$emailsubject to $subject" );
            }
            $emailsubject = $subject;
        }
    }
    else {
        if ($DEBUG) {
            &LogDebug(
"SetSeverity: not resetting severity from $sendemail to $severity\n"
            );
        }
    }
    return 0;
}

### IsIPAddress subroutine ##################################################
# Shamelessly lifted from http://www.perlmonks.org/?node_id=396001
# modified to support zero-padded IP addresses though.
sub IsIPAddress {
    my $target = shift;
    my $range  = qr/^
    (
     (?:                               # first 3 octets:
      (?: 2(?:5[0-5]|[0-4][0-9])\. )   # 200 - 255
      |                                # or
      (?: 1[0-9][0-9]\. )              # 100 - 199
      |                                # or
      (?: 0(?:[0-9][0-9]?|[0-9])\. )   # 0 - 99
     )
     {3}                               # above: three times
 
    (?:                                # 4th octet:
     (?: 2(?:5[0-5]|[0-4][0-9]) )      # 200 - 255
      |                                # or
     (?: 1[0-9][0-9] )                 # 100 - 199
      |                                # or
     (?: 0[0-9][0-9]?|[0-9] )          # 0 - 99
    )
 
    $)
    /x;
    if ( $target =~ /$range/x ) {

        # This is an IP
        return 1;
    }
    else {

        # This is not an IP
        if ($DEBUG) { &LogDebug("IsIPAddress: was passed a non-IP, $target"); }
        return 0;
    }
}

sub IsRFC1918 {
    my $target = shift;
    if ( &IsIPAddress($target) ) {
        my ( $a, $b, $c, $d ) = split( /\./x, $target );
        if ( $a == 10 ) { return 1; }
        if ( $a == 192 and $b == 168 ) { return 1; }
        if ( $a == 172 and ( $b <= 31 and $b >= 16 ) ) { return 1; }
    }
    else {
        return 0;
    }
}

### Trim subroutine ########################################################
sub Trim {
    my $string = shift;
    $string =~ s/^\s+      # substitute spaces from the beginning of line
                 |\s+$     # or from the end of the line
                 //x;
    $string =~ s/\'        # substitute single quotes
                 |\"       # or double quotes, globally
                 //gx;
    $string =~ s/\n        # substitute end of line or
                 |\r       # carriage returns, globally
                 //gx;
    $string =~ s/ //gx;
    return $string;
}

### ASCII to Integer subroutine ###############################################
sub AtoI {
    my $t = 0;
    foreach my $d ( split( //, shift() ) ) {
        $t = $t * 10 + $d;
    }
    return $t;
}

### ConvertSeconds subroutine ##############################################
sub ConvertSeconds {
    my $secs = shift;
    my ( $days, $hours, $minutes, $seconds ) = ( 0, 0, 0, 0 );
    if ($DEBUG) { &LogDebug("ConvertSeconds: received $secs"); }

    # This routine uses successive size filters to break a large number of
    # seconds into more readable units.
    if ($secs) {

        # total was less than one day
        if ( $secs < ( 60 * 60 * 24 ) ) {
            $days = 0;
        }
        else {
            $days = int( $secs / ( 60 * 60 * 24 ) );
        }

        # total was less than one hour
        if ( ( int( $secs % 60 * 60 * 24 ) ) < 60 * 60 ) {
            $hours = 0;
        }
        else {
            $hours = int( ( $secs % ( 60 * 60 * 24 ) ) / ( 60 * 60 ) );
        }

        # total was less than one minute
        if ( int( ( $secs % ( 60 * 60 * 24 ) ) % ( 60 * 60 ) ) < 60 ) {
            $minutes = 0;
            $seconds = int( ( $secs % ( 60 * 60 * 24 ) ) % ( 60 * 60 ) );
        }
        else {
            $minutes = int( ( ( $secs % ( 60 * 60 * 24 ) ) % 60 * 24 ) / 60 );

            # round off remaining seconds
            $seconds = 0;
        }
    }
    if ($DEBUG) {
        &LogDebug("ConvertSeconds: returned $days, $hours, $minutes, $seconds");
    }
    return $days, $hours, $minutes, $seconds;
}

### DoCulling subroutine #####################################################
# Wraps all the dead data cleanup routines into one tasty bundle #############
sub DoCulling {

    # Work on the unmanaged nodes
    &ChangeBalloon( "tip", "Culling unmanaged nodes" );
    &CullUDD;
    &CullXDD;

    # Work on the product definitions
    &ChangeBalloon( "tip", "Culling SLM Products" );
    &CullOrphanProducts;
    &CullProducts;

    # Clear out duplicate network addresses
    if (@dupaddresses) {
        &ChangeBalloon( "tip", "Culling dead IP addresses" );
        &CullIPs;
    }

    # Clear out old alerts
    &ChangeBalloon( "tip", "Culling old alert messages" );
    &PurgeAlerts;    # Force purging of alerts that alert service is choking on
    &CullAlerts;

    # Work on the scan files
    &ChangeBalloon( "tip", "Culling stale temporary scan files" );
    &CullTMP( $ldmain . "ldscan" );
    &ChangeBalloon( "tip", "Renaming and culling scan files" );
    &CullScanFiles;
    &ChangeBalloon( "tip", "Compressing stored scan files" );
    &CompressStorageFiles;

    # Hide provisioning job copies (doesn't delete them)
    &ChangeBalloon( "tip", "Hiding cloned provisioning jobs" );
    &HideProvJobClones;
    &CullOrphanTaskComps;

    return 0;
}

### HideProvJobClones subroutine ############################################
# see http://community.landesk.com/support/docs/DOC-5632 for more info
sub HideProvJobClones {

    # How many unmanaged nodes are older than $deletiondays?
    $sql =
        "select count(prov_template_def_idn) "
      . "from prov_template_def "
      . "where name like '%]' "
      . "and in_oubliette=0 "
      . "and frozen_in_time is not null";
    my $provjobclones = &GetSingleString($sql);

    if ($DEBUG) {
        &LogDebug( "HideProvJobClones: would hide "
              . $provjobclones
              . " cloned tasks from view in provisioning." );
    }
    else {

        # Make the old scans go away -- skipping the WAPs for now
        $sql =
            "update prov_template_def set in_oubliette=1 "
          . "where name like '%]' "
          . "and in_oubliette=0 "
          . "and frozen_in_time is not null";
        &DoDBAction($sql);

        # Report our activity
        if ( $provjobclones > 0 ) {
            &Log(   "Hid "
                  . $comma{$provjobclones}
                  . " cloned Provisioning "
                  . PL( "task", $provjobclones )
                  . " from view in the console." );
        }
    }

    return 0;
}

### IsUpdate subroutine #####################################################
sub IsUpdate {

    if ( $update == 0 ) {
        &Log("Update checking disabled via command line.");
        return 0;
    }
    my $updatesemaphore = "updatesemaphore.dat";
    my $lastcheck;
    if ( -e $updatesemaphore ) {
        open( $FILE, '<', "$updatesemaphore" )
          or &LogWarn("IsUpdate: Can't read $updatesemaphore : $!");
        $lastcheck = <$FILE>;
        close($FILE);
        my $weekago = eval { time() - 86400 * $update };
        if ( $lastcheck > $weekago ) {

            # We've checked within the week, so no need to look for an update
            if ($DEBUG) {
                &LogDebug( "IsUpdate: lastcheck was "
                      . localtime($lastcheck)
                      . ", weekago was "
                      . localtime($weekago)
                      . ", skipping update check." );
            }
            return 0;
        }
    }
    else {
        $lastcheck = eval { time() - 86500 * $update };
    }

    # configure proxy if variables are set
    if ($proxy_server) {
        my $proxy_string;
        if ($proxy_user) {
            $proxy_string =
              "http://" . $proxy_user . ":" . $proxy_pass . "@" . $proxy_server;
        }
        else {
            $proxy_string = "http://" . $proxy_server;
        }
        $ua->proxy( ['http'] => $proxy_string );
    }
    my $url     = 'http://www.droppedpackets.org/scripts/ldms_core/version';
    my $content = get $url;
    my ( $onlineversion, $myversion );
    if ( defined($content) ) {
        $myversion = $VERSION;
        ## no critic  (RequireExtendedFormatting)
        # Doesn't like /x
        $content =~ m{<p>latest version is ([\d.]+)</p>};
        ## use critic
        if ($1) {
            $onlineversion = $1;
        }
        else {
            &LogWarn("didn't recognize version value at $url");
            return 1;
        }

        if ($DEBUG) { &LogDebug("IsUpdate: onlineversion is $onlineversion"); }

        # Update the semaphore
        open( $FILE, '>', "$updatesemaphore" )
          or &LogWarn("IsUpdate: Can't write $updatesemaphore : $!");
        print $FILE time();
        close($FILE);

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $onlineversion =~ s/\.?       # substitute any dot
                            (?=[0-9]) # keep any number
                            //gx;
        $myversion =~ s/\.?       # substitute any dot
                            (?=[0-9]) # keep any number
                            //gx;
        if ( &AtoI($onlineversion) > &AtoI($myversion) ) {
            $updatemessage =
"Update available at http://www.droppedpackets.org/scripts/ldms_core";
            &LogWarn($updatemessage);
            &SetSeverity( 3, "ldms_core update available." );
        }
        if ( &AtoI($onlineversion) < &AtoI($myversion) ) {
            $updatemessage = "You're running beta code. "
              . "Please keep me informed via jack\@monkeynoodle.org.";
            &LogWarn($updatemessage);
            &SetSeverity( 3, "ldms_core beta software report." );
        }
        return 0;
    }
    else {
        &Log("Couldn't get $url");
        return 1;
    }
}

### Read the BOOT.INI file and check memory optimization settings ###########
sub ReadBootIni {
    my $bootinifile;
    my ( $PAE, $TGB ) = ( 0, 0 );
    if ($WINDIR) {
        my $drive = $WINDIR;
        $drive =~ s/\\.*/\\/x;
        $bootinifile = $drive . "boot.ini";
    }
    else {
        $bootinifile = "C:\\boot.ini";
    }
    if ( !-e $bootinifile ) {
        $bootinifile = "C:\\boot.ini";
    }

    open( $FILE, '<', "$bootinifile" )
      or &LogWarn("ReadBootIni: Can't read $bootinifile : $!");
    while (<$FILE>) {
        my $defaultboot    = 0;
        my $splitdelimiter = "=\"";
        if ( $_ =~ /^default/x ) {
            my @parts = split( qr/$splitdelimiter/x, $_ );
            $defaultboot = $parts[1];
        }
        if ( $_ =~ /^multi/x ) {
            my @parts = split( qr/$splitdelimiter/x, $_ );
            if ( chomp( $parts[0] ) eq chomp($defaultboot) ) {
                if ( $parts[1] =~ /\/PAE/ix ) {
                    $PAE = 1;
                    if ($DEBUG) {
                        &LogDebug(
                            "ReadBootIni: /PAE is enabled in $bootinifile");
                    }
                }
                if ( $parts[1] =~ /\/3GB/ix ) {
                    $TGB = 1;
                    if ($DEBUG) {
                        &LogDebug(
                            "ReadBootIni: /3GB is enabled in $bootinifile");
                    }
                }
            }
        }
    }
    close($FILE);
    return ( $PAE, $TGB );
}

### Health check ############################################################
sub HealthCheck {
    &HealthCheckBootIni;
    &HealthCheckLDINV32;
    return 0;
}

### Health check, boot.ini information ######################################
sub HealthCheckBootIni {
    my ( $PAE, $TGB ) = &ReadBootIni;
    my $RAM       = &CountRAM;
    my $SQLonCore = &LocalSQL;

    # If SQL is on the core
    if ($SQLonCore) {

        # If there's more than 5000 MB of RAM
        if ( $RAM > 5000 ) {

            # PAE should be enabled
            if ( $PAE != 1 ) {
                &Log(   "/PAE should be enabled for optimal SQL server "
                      . "performance. See "
                      . "http://community.landesk.com/support/docs/DOC-2356"
                      . " and "
                      . "http://msdn.microsoft.com/en-us/library/aa366796(VS.85).aspx"
                      . " for more information." );
            }

            # TGB should be enabled
            if ( $TGB != 1 ) {
                &Log(   "/3GB should be enabled for optimal SQL server "
                      . "performance. See "
                      . "http://community.landesk.com/support/docs/DOC-2356"
                      . " and "
                      . "http://msdn.microsoft.com/en-us/library/bb613473(VS.85).aspx"
                      . " for more information." );
            }
        }
    }
    else {

        # If SQL is not on the core
        # If there's more than 5000 MB of RAM
        if ( $RAM > 5000 ) {

            # PAE should be enabled
            if ( $PAE != 1 ) {
                &Log(   "/PAE should be enabled for optimal core server "
                      . "performance. See "
                      . "http://community.landesk.com/support/docs/DOC-2681"
                      . " and "
                      . "http://msdn.microsoft.com/en-us/library/aa366796(VS.85).aspx"
                      . " for more information." );
            }
        }
    }
    return 0;
}

### Health check, LDINV32 information ######################################
sub HealthCheckLDINV32 {
    my $ldinvmsg = "To correct this, use Start > All Programs > LANDesk > "
      . "LANDesk Configure Services > Inventory > Advanced Settings.";

    my $sqlbase = "select IntValue from KeyValue "
      . "where ApplicationName='LDINV32' and KeyName=";

    # Is Delta scanning disabled?
    $sql = $sqlbase . "'Do Delta'";
    my $deltascanning = &GetSingleString($sql);
    if ( !$deltascanning ) {
        &LogWarn( "Delta Inventory Scanning is disabled. This results in"
              . "increased load and slower performance for workstations. "
              . $ldinvmsg );
        &SetSeverity( 4, "Delta Inventory Scanning is disabled." );
    }

    # Are mini scans ignored?
    $sql = $sqlbase . "'Ignore Mini Scans'";
    my $ignoreminiscans = &GetSingleString($sql);
    if ($ignoreminiscans) {
        &LogWarn( "Mini Inventory Scans are ignored. This results in"
              . "increased load and slower performance for workstations. "
              . $ldinvmsg );
        &SetSeverity( 4, "Mini Inventory Scans are ignored." );
    }

    # Is DB Error Recovery Tries too low?
    $sql = $sqlbase . "'DB Error Recovery Tries'";
    my $errorretry = &GetSingleString($sql);
    if ( $errorretry < 500 ) {
        &LogWarn( "DB Error Retry is inadvisably low. This is the number of bad"
              . "scans that it takes to force the Inventory Service offline; the "
              . "setting should be at least 500. "
              . $ldinvmsg );
        &SetSeverity( 4, "DB Error Retry is inadvisably low." );
    }

    # Is Stats Logging on?
    $sql = $sqlbase . "'Log Stats'";
    my $statslogging = &GetSingleString($sql);
    if ($statslogging) {
        &LogWarn( "The Inventory Service is logging its performance "
              . "statistics. While this is useful for troubleshooting, it "
              . "does hamper performance and should be turned off if you're "
              . "not currently diagnosing a problem. "
              . $ldinvmsg );
        &SetSeverity( 4, "Inventory Statistics Logging is on." );
    }

    # Is Scan storage on?
    $sql = $sqlbase . "'Store Scans'";
    my $storescans = &GetSingleString($sql);
    if ($storescans) {
        &LogWarn( "The Inventory Service is storing all received scans "
              . "at $ldmain\\ldscan\\storage. While this is useful for "
              . "troubleshooting, it does hamper performance and should "
              . "be turned off if you're not currently diagnosing a problem. "
              . $ldinvmsg );
        &SetSeverity( 4, "Inventory Scan Storage is on" );
    }
    return 0;
}

### ShouldEmail ############################################################
# Don't send an email if one's already been sent today, unless something
# more important has been found
sub ShouldEmail {

    # Read the semaphore
    my $emailsemaphore = "emailsemaphore.dat";
    my ( $lastemail, $lastseverity, $shouldmail ) = ( 0, 0, 0 );
    if ( -e $emailsemaphore ) {
        open( $FILE, '<', "$emailsemaphore" )
          or &LogWarn("ShouldEmail: Can't read $emailsemaphore : $!");
        my $tempstring = <$FILE>;
        close($FILE);
        ( $lastemail, $lastseverity ) = split( '[ ]-[ ]', $tempstring );
        chomp($lastseverity);

        # this isn't supposed to happen, but then, it did.
        if ( length($lastseverity) < 1 ) {
            $lastseverity = 1;
            if ($DEBUG) {
                &LogDebug("ShouldEmail: forcing lastseverity value to 1");
            }
        }

    }
    my $dayago = eval { time() - 86400 };
    my $logmsg;
    if ($DEBUG) {
        $logmsg =
            "ShouldEmail: lastemail was "
          . localtime($lastemail)
          . ", dayago was "
          . localtime($dayago)
          . ", lastseverity was $lastseverity and "
          . "sendemail is $sendemail";
    }
    if ( $lastemail > $dayago ) {

        # We've sent email within the day, let's check severity
        if ( $lastseverity < $sendemail ) {

            # severity is worse than last time, we should send
            $shouldmail = 1;
            if ($DEBUG) {
                &LogDebug( $logmsg . " -- so we're sending this email." );
            }
        }

        # Severity level 1 emails always get sent, bad things are afoot
        if ( $sendemail == 1 ) {
            $shouldmail = 1;
            if ($DEBUG) {
                &LogDebug("ShouldEmail: Severity 1 trumps email peace.");
            }
        }
    }
    else {

        # If time is past 24 hours, we should send
        $shouldmail = 1;
        if ($DEBUG) {
            &LogDebug( $logmsg
                  . " -- so we're Skipping severity check and "
                  . "just sending email." );
        }
    }

    # If we send, we should write a new semaphore
    if ($shouldmail) {
        open( $FILE, '>', "$emailsemaphore" )
          or &LogWarn("SendEmail: Can't write $emailsemaphore : $!");
        print $FILE time() . " - " . $sendemail;
        close($FILE);
    }

    # return decision
    return $shouldmail;
}

### GetSingleString ########################################################
# Database routine intended to retrieve a single string
sub GetSingleString {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        $sth = $dbh->prepare($input)
          or &LogWarn( "$input caused " . DBI->errstr );

        $sth->execute or &LogDie( "$input caused " . DBI->errstr );
        my $output = $sth->fetchrow();
        $sth->finish;
        if ($output) { $output = &Trim($output); }
        return $output;
    }
    else {
        &LogDie("GetSingleString routine called with no database handle!");
    }
    return 1;
}

### GetSingleArray ########################################################
# Database routine intended to retrieve a single array
sub GetSingleArray {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        my @output;
        $sth = $dbh->prepare($input)
          or &LogWarn( "$input caused " . DBI->errstr );

        $sth->execute or &LogDie( "$input caused " . DBI->errstr );
        while ( @row = $sth->fetchrow_array() ) {
            if ( defined( $row[0] ) ) {
                push( @output, &Trim( $row[0] ) );
            }
        }
        $sth->finish;
        return @output;
    }
    else {
        &LogDie("GetSingleArray routine called with no database handle!");
        return 1;
    }
}

### GetTwoColumnList ########################################################
# Database routine intended to retrieve a two column list ( Foo - Bar )
sub GetTwoColumnList {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        my @output;
        $sth = $dbh->prepare($input)
          or &LogWarn( "$input caused " . DBI->errstr );

        $sth->execute or &LogDie( "$input caused " . DBI->errstr );
        while ( @row = $sth->fetchrow_array() ) {
            push( @output, &Trim( $row[0] ) . " - " . &Trim( $row[1] ) );
        }
        $sth->finish;
        return @output;
    }
    else {
        &LogDie("GetTwoColumnList routine called with no database handle!");
        return 1;
    }
}

### GetThreeColumnList #######################################################
# Database routine intended to retrieve a three column list ( Foo - Bar - Baz )
sub GetThreeColumnList {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        my @output;
        $sth = $dbh->prepare($input)
          or &LogWarn( "$input caused " . DBI->errstr );

        $sth->execute or &LogDie( "$input caused " . DBI->errstr );
        while ( @row = $sth->fetchrow_array() ) {
            push( @output,
                    &Trim( $row[0] ) . " - "
                  . &Trim( $row[1] ) . " - "
                  . &Trim( $row[2] ) );
        }
        $sth->finish;
        return @output;
    }
    else {
        &LogDie("GetThreeColumnList routine called with no database handle!");
        return 1;
    }
}

### DoDBAction #############################################################
# Commit database actions that don't expect results
sub DoDBAction {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        if ($DEBUG) { &LogDebug("DoDBAction: called with $input"); }
        $dbh->{RaiseError} = 1;
        $dbh->{AutoCommit} = 0;
        eval {
                 $dbh->do($input)
              or &LogWarn( "$input caused " . DBI->errstr );
            $dbh->commit();
            1;
          }
          or do {
            my $errormessage = "$sql caused a database error.";
            if ( DBI->errstr ) { $errormessage .= DBI->errstr; }
            &LogWarn($errormessage);
            eval {
                $dbh->rollback();
                1;
              }
              or do {
                &LogWarn("Couldn't roll back transaction");
              };

            # This didn't work out, put the dbh back like it was and return 1
            $dbh->{RaiseError} = 0;
            $dbh->{AutoCommit} = 1;
            return 1;
          };

        # Eval was okay, so put the dbh back like it was and return 0
        $dbh->{RaiseError} = 0;
        $dbh->{AutoCommit} = 1;
        return 0;
    }
    else {
        &LogDie("DoDBAction routine called with no database handle!");
        return 1;
    }
}

### GetLDVersion subroutine ################################################
sub GetLDVersion {
    $sql = "SELECT mdversion from METASYSTEMS";
    my $version = &GetSingleString($sql);
    if ($version) {

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $version =~ s/\.?         # substitute any dot
                            (?=[0-9])   # or anything not a number
                            //gx;
        $version = &AtoI($version);
        if ($DEBUG) { &LogDebug("GetLDVersion: LANDesk version is $version"); }
        return $version;
    }
    else {
        &LogWarn("GetLDVersion Cannot determine LANDesk version!");
        return 1;
    }
}

### Delete a file ############################################################
# delete this file, unless DEBUG is set; then just talk about deleting it
sub DeleteFile {

    my ( $targetfile, $filetime ) = @_;
    if ($DEBUG) {
        my $deldays = floor( ( time() - $filetime ) / 86400 );
        &LogDebug(
                "DeleteFile: $targetfile is $deldays days old and no computers "
              . "need it, so it should be deleted." );
        return 1;
    }
    else {

        # stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
        my $size = ( stat($targetfile) )[7]
          or &LogWarn("DeleteFile: stat of $targetfile failed: $!");
        $totalsize += $size;
        trash($targetfile);
        $trashcount++;
        return 0;
    }
}

### Rename a file ###########################################################
# rename this file, unless DEBUG is set; then just talk about renaming it
sub RenameFile {
    my ( $base, $renamefile, $newfilename ) = @_;
    $newfilename = $base . "\\_" . $newfilename . "_" . $renamefile;
    my $oldfilename = $base . "\\" . $renamefile;
    if ($DEBUG) {
        &LogDebug(
            "RenameFile: I would be renaming $renamefile to $newfilename");
    }
    else {
        if ( move( "$oldfilename", "$newfilename" ) ) {
            $renamecount++;
            return 0;
        }
        else {
            &LogWarn(
                "RenameFile: move $oldfilename to $newfilename failed: $!");
        }
    }
    return 1;
}
### Service restart subroutine ################################################
sub RestartService {

    my $target = shift;
    &ChangeBalloon( "tip", "Restarting $target" );
    &Log("Stopping $target service.");
    Win32::Service::StopService( '', $target )
      or &LogWarn("RestartService: Having some trouble with $target");

    sleep 3;
    &Log("Starting $target service.");
    my $retval = Win32::Service::StartService( '', $target );
    if ($retval) {
        &Log("$target service restarted successfully.");
    }
    return 0;
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
    if ($DEBUG) { &LogDebug("LOG  : $msg"); }
    return 0;
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
    if ($DEBUG) { &LogDebug("WARN : $msg"); }
    return 0;
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
    if ($DEBUG) { &LogDebug("ERROR: $msg"); }
    $mailmessage .= "ERROR: $msg\n";
    &SendEmail or &Log($mailmessage);
    exit 1;
}

### Logging a Debug item subroutine ###########################################
sub LogDebug {
    my $msg = "DEBUG: " . localtime() . " ";
    $msg .= shift;

    open( $DEBUGFILE, '>>', "$logfile" )
      or &LogDie("Can't open file $logfile : $!\n");
    $DEBUGFILE->autoflush();
    print $DEBUGFILE "$msg\n";
    close($DEBUGFILE);
    return 0;
}

### Calculate Inventory percentages ###########################################
sub DoInventoryMath {

    # Check the event viewer for problems
    my ( $forcedfullscans, $pkhasherrors, $oldclienterrors ) = &ReadEventViewer;

    # Do you have machines?
    if ($allmachines) {

        # X% of your machines scanned in today
        if ($dbscans) {
            $daypercent = int( ( $dbscans / $allmachines ) * 100 );

            # Look for public key hash errors
            if ( $pkhasherrors > 0 ) {
                my $hashpercent = int( ( $pkhasherrors / $dbscans ) * 100 );
                if ( $hashpercent > 10 ) {
                    &SetSeverity( 2, "Excessive public key hash errors" );
                }
                &Log(   $comma{$pkhasherrors}
                      . " Public Key hash "
                      . PL( "error", $pkhasherrors )
                      . " found in the last day. Please see the article at "
                      . "http://community.landesk.com/support/docs/DOC-2904" );
            }

            # X% of today's scans had full rescans forced on them
            if ( $forcedfullscans > 0 ) {
                my $forcedpercent =
                  int( ( $forcedfullscans / $dbscans ) * 100 );
                if ( $forcedpercent > 10 ) {
                    &SetSeverity( 2, "Excessive forced full rescans" );
                }
                &Log(   $comma{$forcedfullscans}
                      . " of today's delta "
                      . PL( "scan", $forcedfullscans )
                      . " were out of sync; new"
                      . " full scans were forced." );
            }

            # X% of today's scans had ldappl3 errors or were old clients
            if ( $oldclienterrors > 0 ) {
                my $oldclientpercent =
                  int( ( $oldclienterrors / $dbscans ) * 100 );
                if ( $oldclientpercent > 10 ) {
                    &SetSeverity( 2, "Excessive inventory scanning problems" );
                }
                &Log(   $comma{$oldclienterrors}
                      . " of today's delta "
                      . PL( "scan", $oldclienterrors )
                      . " were out of sync; new"
                      . " full scans were forced." );
            }
        }
        else {
            if ($DEBUG) {
                &LogDebug( "DoInventoryMath: no inventory activity today. "
                      . "dbscans=$dbscans" );
            }
        }

        # X% of your machines scanned in this week
        if ($dbscansweek) {
            $weekpercent = int( ( $dbscansweek / $allmachines ) * 100 );
            if ( $weekpercent < 50 ) {
                &Log(   "Less than half of your machines have scanned in the "
                      . "last seven days; you should consider more frequent "
                      . "scanning to prevent stale data." );
                &SetSeverity( 3, "Low inventory scan frequency" );
            }
        }
    }

    &ReportDups;
    return 0;
}

### Report on stale scheduled tasks and policies ############################
sub ReportStaleTasks {
    if (@staletasks) {
        my $staletasktotal = 0;
        my $staletaskmsg   = "Stale Tasks/Policies Detected:\n";
        foreach my $staletask (@staletasks) {
            $staletaskmsg .= "$staletask\n";
            $staletasktotal++;
        }
        $staletaskmsg .=
            $comma{$staletasktotal} . " "
          . PL( "task", $staletasktotal ) . " "
          . "and/or "
          . PL( "policy", $staletasktotal ) . " "
          . "are stale, meaning that the last activity was greater than "
          . $deletiondays
          . " ago.\n";

    }
    else {
        if ($DEBUG) {
            &LogDebug("ReportStaleTasks: No stale tasks found.");
        }
    }
    return 0;
}

### Report on scheduled tasks over last 24 hours ############################
sub DoTaskMath {
    if ($tasks_good) {
        $tasks_good = &AtoI($tasks_good);
    }
    else {
        $tasks_good = 0;
    }
    if ($tasks_bad) {
        $tasks_bad = &AtoI($tasks_bad);
    }
    else {
        $tasks_bad = 0;
    }
    $tasks_all = $tasks_good + $tasks_bad;

    # X% of your completions were successful today
    if ($tasks_good) {
        $tasks_percent = int( ( $tasks_good / $tasks_all ) * 100 );
    }
    else {
        $tasks_percent = 0;
    }
    if ($DEBUG) {
        &LogDebug( "DoTaskMath done: "
              . "$tasks_good good plus $tasks_bad bad equals $tasks_all. "
              . "$tasks_all divided by $tasks_good times 100 = $tasks_percent."
        );
    }
    return 0;
}

### Report on remote control stats over last 24 hours #######################
sub DoRCMath {
    if ($rc_users) {
        $rc_users = &AtoI($rc_users);
    }
    else {
        $rc_users = 0;
    }
    if ($rc_machines) {
        $rc_machines = &AtoI($rc_machines);
    }
    else {
        $rc_machines = 0;
    }
    if ($rc_all) {
        $rc_all = &AtoI($rc_all);
    }
    else {
        $rc_all = 0;
    }
    if ($DEBUG) { &LogDebug("DoRCMath done"); }
    return 0;
}

### Report on duplicate machines and dual booters ###########################
sub ReportDups {

    my $dupcount;
    my $dupreport;

    # Do you have duplicates?
    if (@dupmachines) {
        $dupcount  = 0;
        $dupreport = "";
        foreach my $dup (@dupmachines) {

            # Count them
            my $count = &CountDups( $dup, "name" );

            # List them
            $dupreport .= "($count) $dup\n";
            $dupcount++;
        }
        if ($dupcount) {

            # Prepend some explanation
            $dupreport =
                $comma{$dupcount}
              . " duplicate computer "
              . PL( "record", $dupcount )
              . " detected. Each of these device names exists more than once"
              . " in the LANDesk database... you should probably delete the"
              . " older one(s) and review your OS Deployment procedures:\n"
              . $dupreport;
            &SetSeverity( 5, "Duplicate computer records" );
            Log($dupreport);
        }
    }

    # Do you have dual booting machines?
    if (@dualboots) {
        $dupcount  = 0;
        $dupreport = "";
        foreach my $dup (@dualboots) {

            # Count them
            my $count = &CountDups( $dup, "serial" );

            # List them
            $dupreport .= "($count) $dup\n";
            $dupcount++;
        }
        if ($dupcount) {

            # Prepend some explanation
            $dupreport =
                $comma{$dupcount}
              . " dual booting or poorly imaged "
              . PL( "machine", $dupcount )
              . " detected. Each of these serial numbers exists more than"
              . " once in the LANDesk database... that could mean duplicate"
              . " records, incorrectly configured motherboards, or dual"
              . " booting computers. You should investigate these records:\n"
              . $dupreport;
            &SetSeverity( 5, "Duplicate serial numbers" );
            &Log($dupreport);
        }
    }

    # Do you have duplicate IP Addresses?
    if (@dupaddresses) {
        $dupcount  = 0;
        $dupreport = "";
        foreach my $dup (@dupaddresses) {

            if ( &IsIPAddress($dup) ) {

                # Count them
                my $count = &CountDups( $dup, "ip" );

                # List them
                $dupreport .= "($count) $dup\n";
                $dupcount++;
            }
        }
        if ($dupcount) {

            # Prepend some explanation
            $dupreport =
                $comma{$dupcount}
              . " duplicate IP "
              . PL( "Address", $dupcount )
              . " detected. Each of these IP addresses exists more than once"
              . " in the LANDesk database... this is common in environments"
              . " that use DHCP and/or VPN:\n"
              . $dupreport;
            &SetSeverity( 5, "Duplicate IP Addresses" );
            Log($dupreport);
        }
    }

    return 0;
}
### End of ReportDups subroutine #############################################

### Get a count of a type of thing ############################################
sub CountDups {
    my ( $target, $type ) = @_;
    if ( !defined($target) ) {
        if ($DEBUG) { &LogDebug("CountDups: called without a target string"); }
        return 0;
    }
    if ( !defined($type) ) {
        if ($DEBUG) { &LogDebug("CountDups: called without a type string"); }
        return 0;
    }

    $sql =
      $type eq "name"
      ? "select count(computer_idn) from computer where devicename = '$target'"
      : $type eq "serial"
      ? "select count(computer_idn) from compsystem where serialnum = '$target'"
      : $type eq "ip"
      ? "select count(computer_idn) from tcp where address = '$target'"
      : "Unsupported";

    if ( $sql eq "Unsupported" ) {
        if ($DEBUG) { &LogDebug("CountDups: type $type is not supported"); }
        return 0;
    }

    my $count = &GetSingleString($sql);

    return $count;
}
### End of CountDups subroutine ###############################################

### Calculate Unmanaged device percentages ####################################
sub DoUDDMath {

    if ($allmachines_udd) {

        if ($dbscans_udd) {

            # X% of your unmanaged nodes were pinged today
            $daypercent_udd = int( ( $dbscans_udd / $allmachines_udd ) * 100 );
        }
        if ($dbscansweek_udd) {

            # X% of your unmanaged nodes were pinged this week
            $weekpercent_udd =
              int( ( $dbscansweek_udd / $allmachines_udd ) * 100 );
        }
    }
    return 0;
}

### Calculate Patch repair timelines ##########################################
sub DoVulnLife {

    my $vulnmessage;

    # Your vulnerabilities live this long
    if ( $vulnlife > 0 ) {
        if ($DEBUG) {
            &LogDebug("DoVulnLife: Calculating how long vulns live");
        }
        my ( $vulndays, $vulnhours, $vulnminutes, $vulnseconds ) =
          &ConvertSeconds($vulnlife);
        $vulnmessage =
"Vulnerabilities which get patched by LANDesk go unpatched an average of ";
        if ($vulndays) {
            $vulnmessage .= "$vulndays " . PL( "day", $vulndays );
        }
        if ($vulnhours) {
            if ($vulndays) { $vulnmessage .= ", "; }
            $vulnmessage .= "$vulnhours " . PL( "hour", $vulnhours );
        }
        if ($vulnminutes) {
            if (
                $vulnmessage =~ m/days   # either days
                                   |hours # or hours
                               /x
              )
            {
                $vulnmessage .= ", and ";
            }
            $vulnmessage .= "$vulnminutes " . PL( "minute", $vulnminutes );
        }
        $vulnmessage .= ". Vulnerabilities which go perennially unpatched "
          . "(by LANDesk at least) are not included in this average. ";

        if ($vulndays) {
            if ( $vulndays > 50 ) {
                &SetSeverity( 3, "Long vulnerability exposure window" );
            }
        }
    }
    else {
        $vulnmessage =
          "Vulnerabilities go unpatched (by LANDesk at least) forever.";
        &SetSeverity( 3, "LANDesk patching unused" );
    }

    # Report on repair timing
    &Log("$vulnmessage\n");
    return 0;
}

### Calculate task and policy completion timelines ###########################
sub DoTaskLife {

    my $taskmessage;

    # Your tasks go undone this long
    if ( $tasklife > 0 ) {
        if ($DEBUG) {
            &LogDebug("DoTaskLife: Calculating how long tasks take");
        }
        my ( $taskdays, $taskhours, $taskminutes, $taskseconds ) =
          &ConvertSeconds($tasklife);
        $taskmessage =
"Scheduled Tasks and Policies enforced by LANDesk go undone an average of ";
        if ($taskdays) {
            $taskmessage .= "$taskdays " . PL( "day", $taskdays );
        }
        if ($taskhours) {
            if ($taskdays) { $taskmessage .= ", "; }
            $taskmessage .= "$taskhours " . PL( "hour", $taskhours );
        }
        if ($taskminutes) {
            if (

                # matches day, days, hour, hours
                $taskmessage =~ m/days?|hours?/x
              )
            {
                $taskmessage .= ", and ";
            }
            $taskmessage .= "$taskminutes " . PL( "minute", $taskminutes );
        }
        $taskmessage .=
            ". Tasks and Policies which are not scheduled "
          . "and machines without successful completion are not included "
          . "in this average. ";

        if ($taskdays) {
            if ( $taskdays > 50 ) {
                &SetSeverity( 3, "Long task completion window" );
            }
        }
    }
    else {
        $taskmessage =
          "Scheduled Tasks and Policies are not getting completed.";
        &SetSeverity( 3, "LANDesk patching unused" );
    }

    # Report on task timing
    &Log("$taskmessage\n");
    return 0;
}

### LDSS Patch statistics subroutine #########################################
sub DoPatchStats {

    # Total up patch counts and autofix counts
    if (@patchcounts) {
        foreach my $p (@patchcounts) {
            my ( $d, $c, $e ) = split( '[ ]-[ ]', $p );
            $patchtotal += $c;
        }
    }
    if (@autofixcounts) {
        foreach my $p (@autofixcounts) {
            my ( $d, $c, $e ) = split( '[ ]-[ ]', $p );
            $autofixtotal += $c;
        }
    }
    return 0;
}

### LDMS Managed Devices statistics subroutine ###############################
sub GetManagedDevices {

    # How many machines are there?
    $sql = "select count(*) from computer where deviceid != 'Unassigned'";
    $allmachines = &GetSingleString($sql);
    if ($DEBUG) { &LogDebug("GetManagedDevices: allmachines=$allmachines"); }

    # Are any of them duplicates?
    $sql =
"select distinct computer.devicename from computer inner join computer t1 on "
      . "computer.devicename = t1.devicename where computer.computer_idn <> "
      . "t1.computer_idn order by computer.devicename asc";
    @dupmachines = nsort( &GetSingleArray($sql) );
    if ($DEBUG) { &LogDebug("GetManagedDevices: dupmachines=@dupmachines"); }

    # What about IP Address overlaps?
    $sql =
        "select distinct tcp.address from tcp inner join tcp t1 on "
      . "tcp.address = t1.address where nullif(tcp.address,'0.0.0.0') "
      . "is not null and nullif(tcp.address,'255.255.255.255') is not null "
      . "and tcp.computer_idn <> t1.computer_idn "
      . "order by tcp.address asc";
    @dupaddresses = nsort( &GetSingleArray($sql) );
    if ($DEBUG) { &LogDebug("GetManagedDevices: dupaddresses=@dupaddresses"); }

    # Detect dual-booting systems
    $sql =
"select distinct compsystem.serialnum from compsystem inner join compsystem "
      . "t1 on compsystem.serialnum = t1.serialnum where compsystem.computer_idn <> "
      . "t1.computer_idn order by compsystem.serialnum asc";
    @dualboots = nsort( &GetSingleArray($sql) );
    if ($DEBUG) { &LogDebug("GetManagedDevices: dualboots=@dualboots"); }

    # How many scans came in over the last 24 hours?
    if ( $db_type eq "SQL" ) {
        $sql =
            "select count(*) FROM computer where hwlastscandate >= GetDate()-1 "
          . "and deviceid != 'Unassigned'";
    }
    else {

        # Oracle Support
        $sql =
"select count(*) FROM computer where hwlastscandate >= current_date-1 "
          . "and deviceid != 'Unassigned'";
    }
    $dbscans = &GetSingleString($sql);
    if ($DEBUG) { &LogDebug("GetManagedDevices: dbscans=$dbscans"); }

    # How many scans came in over the last 7 days?
    if ( $db_type eq "SQL" ) {
        $sql =
            "select count(*) FROM computer where hwlastscandate >= GetDate()-7 "
          . "and deviceid != 'Unassigned'";
    }
    else {

        # Oracle Support
        $sql =
"select count(*) FROM computer where hwlastscandate >= current_date-7 "
          . "and deviceid != 'Unassigned'";
    }
    $dbscansweek = &GetSingleString($sql);
    if ($DEBUG) { &LogDebug("GetManagedDevices: dbscansweek=$dbscansweek"); }

    return 0;
}

### LDMS Unmanaged Devices statistics subroutine #############################
sub GetUnmanagedDevices {

    # How many machines are there in UNMANAGEDNODES?
    $sql             = "select count(*) from unmanagednodes";
    $allmachines_udd = &GetSingleString($sql);
    if ($DEBUG) {
        &LogDebug("GetUnmanagedDevices: allmachines_udd=$allmachines_udd");
    }

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
    $dbscans_udd = &GetSingleString($sql);
    if ($DEBUG) { &LogDebug("GetUnmanagedDevices: dbscans_udd=$dbscans_udd"); }

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
    $dbscansweek_udd = &GetSingleString($sql);
    if ($DEBUG) {
        &LogDebug("GetUnmanagedDevices: dbscansweek_udd=$dbscansweek_udd");
    }

    return 0;
}

### LDMS Stale Tasks and Policies detection subroutine ######################
sub GetStaleTasks {

    # Get Tasks with no completion data in $deletiondays
    if ( $db_type eq "SQL" ) {
        $sql =
            "SELECT CONSOLEUSER.USERNAME, LD_TASK.TASK_NAME, "
          . "MAX(LD_TASK_MACHINE.STATUS_TIME) as Last_Ran_On "
          . "FROM LD_TASK "
          . "JOIN CONSOLEUSER "
          . "ON LD_TASK.CONSOLEUSER_IDN = CONSOLEUSER.CONSOLEUSER_IDN "
          . "JOIN LD_TASK_MACHINE "
          . "ON LD_TASK_MACHINE.LD_TASK_IDN = LD_TASK.LD_TASK_IDN "
          . "WHERE RESCHEDULE_TYPE = '0' "
          . "GROUP By CONSOLEUSER.USERNAME, LD_TASK.TASK_NAME, "
          . "LD_TASK_MACHINE.LD_TASK_IDN "
          . "HAVING MAX (LD_TASK_MACHINE.STATUS_TIME) "
          . "< (getdate() - $deletiondays) "
          . "Order by LD_TASK.TASK_NAME";
    }
    else {

        # Oracle Support
        $sql =
            "SELECT CONSOLEUSER.USERNAME, LD_TASK.TASK_NAME, "
          . "MAX(LD_TASK_MACHINE.STATUS_TIME) AS Last_Ran_On "
          . "FROM LD_TASK "
          . "JOIN CONSOLEUSER "
          . "ON LD_TASK.CONSOLEUSER_IDN = CONSOLEUSER.CONSOLEUSER_IDN "
          . "JOIN LD_TASK_MACHINE "
          . "ON LD_TASK_MACHINE.LD_TASK_IDN = LD_TASK.LD_TASK_IDN "
          . "WHERE RESCHEDULE_TYPE = '0' "
          . "GROUP BY CONSOLEUSER.USERNAME, LD_TASK.TASK_NAME, "
          . "LD_TASK_MACHINE.LD_TASK_IDN "
          . "HAVING MAX (LD_TASK_MACHINE.STATUS_TIME) < "
          . "(CURRENT_DATE - $deletiondays) "
          . "ORDER BY LD_TASK.TASK_NAME";
    }
    @staletasks = &GetThreeColumnList($sql);
    return 0;
}
### LDMS Scheduled Task statistics subroutine ###############################
sub GetTaskData {

    # Get Successful Task Targets from the last 24 hours
    $sql =
        "SELECT COUNT (LD_TASK.TASK_NAME ) "
      . "FROM LD_TASK, LD_TASK_MACHINE "
      . "WHERE LD_TASK_MACHINE.LD_TASK_IDN = LD_TASK.LD_TASK_IDN "
      . "AND LD_TASK_MACHINE.MAC_RETCODE <> 1110 "
      . "AND LD_TASK_MACHINE.MAC_RETCODE <> 1101 "
      . "AND LD_TASK_MACHINE.MAC_RETCODE <> 1001 "
      . "AND((LD_TASK_MACHINE.STATUS_TIME Is Not Null ";
    if ( $db_type eq "SQL" ) {
        $sql .= "And LD_TASK_MACHINE.STATUS_TIME>= (getdate()-1)))";
    }
    else {

        # Oracle support
        $sql .= "And LD_TASK_MACHINE.STATUS_TIME>= (current_date-1)))";
    }
    $tasks_good = &GetSingleString($sql);

    # Get Unsuccessful Task Targets from the last 24 hours
    $sql =
        "SELECT COUNT (LD_TASK.TASK_NAME ) "
      . "FROM LD_TASK, LD_TASK_MACHINE "
      . "WHERE LD_TASK_MACHINE.LD_TASK_IDN = LD_TASK.LD_TASK_IDN "
      . "AND((LD_TASK_MACHINE.STATUS_TIME Is Not Null ";
    if ( $db_type eq "SQL" ) {
        $sql .= "And LD_TASK_MACHINE.STATUS_TIME>= (getdate()-1)))";
    }
    else {

        # Oracle support
        $sql .= "And LD_TASK_MACHINE.STATUS_TIME>= (current_date-1)))";
    }
    $sql .=
        "AND (LD_TASK_MACHINE.MAC_RETCODE = 1110 "
      . "OR LD_TASK_MACHINE.MAC_RETCODE = 1101 "
      . "OR LD_TASK_MACHINE.MAC_RETCODE = 1001 )";
    $tasks_bad = &GetSingleString($sql);

    # Get task start to completion average life.
    if ( $db_type eq "SQL" ) {
        $sql =
            "SELECT avg(cast(datediff(ss,LD_TASK.LAST_START, "
          . "LD_TASK_MACHINE.STATUS_TIME) as bigint)) "
          . "FROM LD_TASK, LD_TASK_MACHINE "
          . "WHERE LD_TASK.LD_TASK_IDN = LD_TASK_MACHINE.LD_TASK_IDN "
          . "AND LD_TASK_MACHINE.MAC_RETCODE NOT IN (1110, 1101, 1001) "
          . "AND LD_TASK_MACHINE.STATUS_TIME Is Not Null "
          . "AND (LD_TASK.LAST_START < LD_TASK_MACHINE.STATUS_TIME)";
    }
    else {

        # Oracle Support
        $sql =
            "SELECT AVG((m.status_time - t.last_start) * 24 * 60 * 60) AS "
          . "average_duration_in_sec FROM ld_task t, ld_task_machine m "
          . "WHERE t.ld_task_idn = m.ld_task_idn "
          . "AND m.mac_retcode NOT IN (1110, 1101, 1001) "
          . "AND m.status_time IS NOT NULL "
          . "AND (t.LAST_START < m.STATUS_TIME)";
    }
    $tasklife = &GetSingleString($sql);

    return 0;
}

### LDMS Alert statistics subroutine ########################################
sub GetAlertData {

    # Get Processed Alerts from the last 24 hours
    if ( $db_type eq "SQL" ) {
        $sql =
"select count(alertlog_idn) from alertlog where localtime > getdate()-1";
    }
    else {
        $sql = "select count(alertlog_idn) from alertlog "
          . "where localtime > current_date-1";
    }
    $alert_all = &GetSingleString($sql);

    return 0;
}
### LDMS Remote Control statistics subroutine ###############################
sub GetRCData {

    # Get Remote Control Sessions from the last 24 hours
    if ( $db_type eq "SQL" ) {
        $sql =
          "select count(rclog_idn) from rclog where eventtime > getdate()-1";
    }
    else {
        $sql = "select count(rclog_idn) from rclog "
          . "where eventtime > current_date-1";
    }
    $rc_all = &GetSingleString($sql);

    # Get Remote Control Users from the last 24 hours
    if ( $db_type eq "SQL" ) {
        $sql =
"select count (distinct username) from rclog where eventtime > getdate()-1";
    }
    else {
        $sql =
"select count (distinct username) from rclog where eventtime > current_date-1";
    }
    $rc_users = &GetSingleString($sql);

    # Get Remote Control Machines from the last 24 hours
    if ( $db_type eq "SQL" ) {
        $sql = "select count (distinct managedcomputer) from rclog "
          . "where eventtime > getdate()-1";
    }
    else {
        $sql = "select count (distinct managedcomputer) from rclog "
          . "where eventtime > current_date-1";
    }
    $rc_machines = &GetSingleString($sql);

    return 0;
}

### LDMS Database reading subroutine #########################################
sub GetLDMSData {

    #Get as much done as quickly as possible and close the connection
    # LDMS Specific Information

    &GetManagedDevices;

    # How many machines are there in Pending Unmanaged Deployments?
    $sql      = "select count(*) from computer where deviceid='Unassigned'";
    $pudcount = &GetSingleString($sql);
    if ($DEBUG) {
        &LogDebug("GetLDMSData, pudcount=$pudcount");
    }

    &GetUnmanagedDevices;
    &UnhideWAPs;

    &GetTaskData;
    &GetStaleTasks;
    &GetRCData;
    &GetAlertData;

    return 0;
}
### End of LDMS Database reading subroutine ##################################

### Unhide the hidden WAPs ###################################################
# Bug in 8.8 hides the wireless access points from view in the console #######
sub UnhideWAPs {

    # Check the LANDesk version
    if ( substr( $ldms_version, 0, 2 ) < 88 ) {
        if ($DEBUG) { &LogDebug("UnhideWAPs: nothing to do."); }
        return 1;
    }
    my $sqlbase =
        "where unmanagednodes_idn in "
      . "( select unmanagednodes_idn from wapdiscoverynodes ) "
      . "and devicegroupinfo_idn != '9'";

    # How many?
    $sql = "select count(unmanagednodes_idn) from unmanagednodes " . $sqlbase;
    my $hiddenwapcount = &GetSingleString($sql);

    # If it's more than zero, take action and report
    if ($hiddenwapcount) {
        $sql = "update unmanagednodes set devicegroupinfo_idn='9' " . $sqlbase;
        if ($DEBUG) {
            &LogDebug( "UnhideWAPs: would reveal $comma{$hiddenwapcount} "
                  . "hidden wireless access "
                  . PL( "point", $hiddenwapcount )
                  . " from the unmanaged nodes area of the "
                  . "database." );
        }
        else {
            &DoDBAction($sql);
            &Log(   "Revealed $comma{$hiddenwapcount} hidden wireless access "
                  . PL( "point", $hiddenwapcount )
                  . " from the unmanaged nodes area of the "
                  . "database." );
        }
    }
    return 0;
}

### LDSS Database reading subroutine #########################################
sub GetLDSSData {

    #Get as much done as quickly as possible and close the connection
    # LDSS Specific Information

    # Are there any manual download patch URLs I can report on?
    $sql =
        "select patch.comments from patch where comments LIKE '%http%' and "
      . "download='0' and vulnerability_idn in (select distinct "
      . "vulnerability.vulnerability_idn from vulnerability inner join "
      . "computervulnerability t1 on vulnerability.vul_id = t1.vul_id where "
      . "t1.detected='1' and vulnerability.type='0' and vulnerability.fixable='3')";
    @patchurls = &GetSingleArray($sql);

    # Is the definition data getting stale?
    if ( $db_type eq "SQL" ) {
        $sql =
          "select count(*) from vulnerability where publishdate > getdate()-7";
    }
    else {

        # Oracle Support
        $sql =
"select count(*) FROM vulnerability where publishdate > current_date-7";
    }
    $recentvulns = &GetSingleString($sql);

    # count scanned vulns
    $sql       = "SELECT count(vul_id) from vulnerability where status != '0'";
    $vulncount = &GetSingleString($sql);

    # How many vulns in unassigned?
    $sql =
      "select count(vulnerability_idn) from vulnerability where status='2'";
    $unassignedvulns = &GetSingleString($sql);

    # count missing patches, by severity:
    # http://community.landesk.com/support/message/12139
    # Note that unfixable vulnerabilities are filtered out.
    #
    my $patchquery1 =
        "SELECT VulSeverity.DisplayName, "
      . "count(distinct vulnerability.vul_id), "
      . "count(distinct computer.displayname) "
      . "FROM Scope "
      . "INNER JOIN ScopeComputer ON Scope.Scope_Idn = ScopeComputer.Scope_Idn "
      . "INNER JOIN Computer "
      . "INNER JOIN ComputerVulnerability "
      . "ON Computer.Computer_Idn = ComputerVulnerability.Computer_Idn "
      . "INNER JOIN Vulnerability "
      . "ON ComputerVulnerability.Vul_ID = Vulnerability.Vul_ID "
      . "AND Vulnerability.Fixable != 0 ";

    my $patchquery2 =
        "INNER JOIN VulSeverity "
      . "ON Vulnerability.Severity = VulSeverity.Severity_ID "
      . "ON ScopeComputer.Computer_Idn = Computer.Computer_Idn "
      . "WHERE ComputerVulnerability.Detected = 1 "
      . "GROUP BY VulSeverity.DisplayName "
      . "ORDER BY VulSeverity.DisplayName";

    $sql         = $patchquery1 . $patchquery2;
    @patchcounts = &GetThreeColumnList($sql);

    # count autofix-enabled vulnerabilities, by severity:
    # http://community.landesk.com/support/message/13664
    # Note that unfixable vulnerabilities are filtered out.
    $sql = $patchquery1 . "AND Vulnerability.Autofix = 1 " . $patchquery2;
    @autofixcounts = &GetThreeColumnList($sql);

    # What's the average lifespan of a detected vulnerability?
    if ( $db_type eq "SQL" ) {
        $sql =
"select avg(cast(datediff(ss,datedetected,patchinstalldate) as bigint)) "
          . "from computervulnerability where patchinstallstatus = 'Done' and "
          . "datedetected is not null and patchinstalldate is not null "
          . "and datedetected < patchinstalldate";
    }
    else {

        # Oracle Support
        $sql =
          "select avg((c.patchinstalldate - c.datedetected) * 24 * 60 * 60) as "
          . "average_duration_in_sec from computervulnerability c where "
          . "patchinstallstatus = 'Done' and datedetected is not null and "
          . "patchinstalldate is not null "
          . "and datedetected < patchinstalldate";
    }
    $vulnlife = &GetSingleString($sql);

    return 0;
}
### End of LDSS Database reading subroutine ##################################

### Report on LDMS Statistics ###############################################
sub ReportLDMSStats {

    my $ldmsmessage =
        $comma{$allmachines} . " "
      . PL( "computer", $allmachines )
      . " in the database.";
    if ($dbscans) {

        # knock off the period
        $ldmsmessage = substr( $ldmsmessage, 0, -1 );
        $ldmsmessage .= ", "
          . $comma{$dbscans}
          . " ($daypercent\%) reported"
          . " in the last day.";
    }
    if ($dbscansweek) {

        # knock off the period
        $ldmsmessage = substr( $ldmsmessage, 0, -1 );
        $ldmsmessage .= ", "
          . $comma{$dbscansweek}
          . " ($weekpercent\%)"
          . " reported within "
          . "the week.\n";
    }

    # Unmanaged Devices
    if ($allmachines_udd) {
        $ldmsmessage .=
          $comma{$allmachines_udd} . " unmanaged devices in the" . " database.";
        if ($dbscans_udd) {

            # knock off the period
            $ldmsmessage = substr( $ldmsmessage, 0, -1 );
            $ldmsmessage .= ", "
              . $comma{$dbscans_udd}
              . " ($daypercent_udd\%)"
              . " were seen in the last day.";
        }
        if ($dbscansweek_udd) {

            # knock off the period
            $ldmsmessage = substr( $ldmsmessage, 0, -1 );
            $ldmsmessage .= ", "
              . $comma{$dbscansweek_udd}
              . " ($weekpercent_udd\%) were seen within the week.\n";
        }
    }

    # Scheduled tasks
    if ($tasks_all) {
        $ldmsmessage .=
            $comma{$tasks_all}
          . " scheduled task "
          . PL( "event", $tasks_all )
          . " were completed in the last day. "
          . $comma{$tasks_good} . " "
          . PL( "machine", $tasks_good )
          . " reported success, "
          . $comma{$tasks_bad} . " "
          . PL( "machine", $tasks_bad )
          . " reported failure.\n";
        if ($tasks_percent) {

            # knock off the period
            $ldmsmessage = substr( $ldmsmessage, 0, -2 );
            $ldmsmessage .= ", for a success ratio of " . "$tasks_percent\%.\n";
        }
    }

    # Remote control
    if ($rc_all) {
        $ldmsmessage .=
            $comma{$rc_all}
          . " remote control "
          . PL( "event", $rc_all )
          . " occurred in the "
          . "last day. "
          . $comma{$rc_users} . " "
          . PL( "user", $rc_users )
          . " worked with "
          . $comma{$rc_machines} . " "
          . PL( "machine", $rc_machines ) . ".\n";
    }

    # Alerts
    if ($alert_all) {
        $ldmsmessage .=
            $comma{$alert_all} . " "
          . PL( "alert", $alert_all )
          . " processed in the last day.\n";
    }

    # Update RRD too
    &UpdateLDMSRRD;

    if ($pudcount) {
        $ldmsmessage .=
            "There "
          . PL_V( "is", $pudcount ) . " "
          . $pudcount . " "
          . PL( "machine", $pudcount ) . " "
          . "in Configuration > Pending Unmanaged Client Deployments. This "
          . "is a sort of purgatory between unmanaged nodes and managed "
          . "nodes; the machines in this folder have had agents pushed "
          . "to them, but they have not reported back with an inventory "
          . "scan. If you did not do agent pushing today, you're "
          . "probably not going to hear from them; you should delete "
          . "these machines and let unmanaged device discovery re-find "
          . "them. If you don't see anything in there but you're still "
          . "getting this message, it's probably PXE booting machines. "
          . "Look in your inventory for records with just a MAC address "
          . "for a name, and delete those.";
    }

    &Log($ldmsmessage);
    return 0;
}

### Update RRD With LDMS Statistics ##########################################
sub UpdateLDMSRRD {

    # Inventory Stats
    $ldmsrrd->update(
        AllDevices  => $allmachines,
        DayDevices  => $dbscans,
        WeekDevices => $dbscansweek
    ) or &LogWarn("Problem writing to ldmsstats: $!");
    %rtn = $ldmsrrd->graph(
        destination     => "$reportdir",
        title           => "LDMS Inventory Statistics",
        vertical_label  => "All / Daily / Weekly",
        extended_legend => "1",
        interlaced      => ""
      )
      or &LogWarn(
        "Problem graphing from ldmsstats: " . map { $rtn{$_}->[0] }
          keys %rtn
      );

    if ($DEBUG) {
        &LogDebug(
            "UpdateLDMSRRD: Logged LDMS RRD statistics: " .
              map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldmsstats",
        "LANDesk Management Suite Inventory Statistics" );

    # Unmanaged device stats
    $ldmsrrd_udd->update(
        AllDevices  => $allmachines_udd,
        DayDevices  => $dbscans_udd,
        WeekDevices => $dbscansweek_udd
    ) or &LogWarn("Problem writing to ldmsstats_udd: $!");
    %rtn = $ldmsrrd_udd->graph(
        destination     => "$reportdir",
        title           => "LDMS Unmanaged Devices Statistics",
        vertical_label  => "All / Daily / Weekly",
        extended_legend => "1",
        interlaced      => ""
      )
      or &LogWarn(
        "Problem graphing from ldmsstats_udd: " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "UpdateLDMSRRD: Logged LDMS UDD RRD statistics: " .
              map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldmsstats_udd",
        "LANDesk Management Suite Unmanaged Device Statistics" );

    # Scheduled tasks
    $ldmsrrd_sched->update(
        AllTasks  => $tasks_all,
        GoodTasks => $tasks_good,
        BadTasks  => $tasks_bad
    ) or &LogWarn("Problem writing to ldmsstats_sched: $!");
    %rtn = $ldmsrrd_sched->graph(
        destination     => "$reportdir",
        title           => "LDMS Scheduled Task Statistics",
        vertical_label  => "All / Succeeded / Failed",
        extended_legend => "1",
        interlaced      => ""
      )
      or &LogWarn(
        "Problem graphing from ldmsstats_sched: " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "UpdateLDMSRRD: Logged LDMS Scheduled Task RRD statistics: " .
              map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldmsstats_sched",
        "LANDesk Management Suite Scheduled Task Statistics" );

    # Task life
    $ldmsrrd_life->update( TaskLife => $tasklife )
      or &LogWarn("Problem writing to ldmsstats_life: $!");
    %rtn = $ldmsrrd_life->graph(
        destination      => "$reportdir",
        title            => "LDMS Task Duration",
        vertical_label   => "Start to Successful Finish",
        extended_legend  => "1",
        interlaced       => "",
        source_drawtypes => "AREA"
      )
      or &LogWarn(
        "Problem graphing from ldmsstats_life: " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "UpdateLDMSRRD: Logged LDMS RRD Life statistics: " .
              map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldmsstats_life", "LANDesk Management Suite Task Lifetime" );

    # Alert counts
    $ldmsrrd_alerts->update( AlertCount => $alert_all )
      or &LogWarn("Problem writing to ldmsstats_alerts $!");
    %rtn = $ldmsrrd_alerts->graph(
        destination      => "$reportdir",
        title            => "LDMS Alerts Processed",
        vertical_label   => "Alerts Processed",
        extended_legend  => "1",
        interlaced       => "",
        source_drawtypes => "AREA"
      )
      or &LogWarn(
        "Problem graphing from ldmsstats_alerts " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "UpdateLDMSRRD: Logged LDMS RRD Alert statistics: " .
              map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldmsstats_alerts", "LANDesk Management Suite Alerts" );

    # Remote control
    $ldmsrrd_rc->update(
        AllRC      => $rc_all,
        RCUsers    => $rc_users,
        RCMachines => $rc_machines
    ) or &LogWarn("Problem writing to ldmsstats_rc $!");
    %rtn = $ldmsrrd_rc->graph(
        destination     => "$reportdir",
        title           => "LDMS Remote Control Statistics",
        vertical_label  => "All / Users / Machines",
        extended_legend => "1",
        interlaced      => ""
      )
      or &LogWarn(
        "Problem graphing from ldmsstats_rc " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "UpdateLDMSRRD: Logged LDMS Remote Control RRD statistics: " .
              map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldmsstats_rc",
        "LANDesk Management Suite Remote Control Statistics" );

    return 0;
}

### Report on LDSS Statistics ###############################################
sub ReportLDSSStats {

    if ( $unassignedvulns > 0 ) {
        my $unassignedmessage =
            "There are "
          . $comma{$unassignedvulns} . " "
          . PL( 'vulnerability', $unassignedvulns )
          . " in the Unassigned folder. These are not being detected "
          . " or repaired and should be evaluated manually.";
        my $unassignedseverity = 3;
        if ( $unassignedvulns > 100 ) {
            $unassignedmessage .=
                " LANDesk Patch Management requires"
              . " some administrator attention. If your organization does not"
              . " maintain the unassigned folder, you should disable the option"
              . " to put patches into the unassigned folder. You may also want"
              . " to configure the automated patch process so that LANDesk may "
              . " scan for vulnerabilities.";
            $unassignedseverity = 2;
        }
        if ( $unassignedvulns > 250 ) {
            $unassignedseverity = 1;
        }
        &Log($unassignedmessage);
        &SetSeverity( &AtoI($unassignedseverity),
            "Unassigned vulnerabilities" );
    }

    # Warn if data is seeming stale
    if ( $recentvulns == 0 ) {
        &Log(   "No new vulnerabilities have been downloaded in the last seven "
              . "days; is your scheduled download still working?" );
        &SetSeverity( 2, "Vulnerability data old" );
    }

    # Report on patch statistics
    if (@patchcounts) {
        my $patchcountsreport = "Detected vulnerability counts by severity:\n";
        foreach my $patchtypecount (@patchcounts) {
            my ( $d, $c, $e ) = split( '[ ]-[ ]', $patchtypecount );
            $patchcountsreport .=
                "$d - $comma{$c} "
              . PL( 'vulnerability', $c )
              . " found on "
              . $comma{$e} . " "
              . PL( 'machine', $e ) . ".\n";
        }
        &Log("$patchcountsreport");
    }

    # How many of those are autofix?
    if (@autofixcounts) {
        my $autofixreport =
          "Detected vulnerabilities set to autofix by severity:\n";
        foreach my $patchtypecount (@autofixcounts) {
            my ( $d, $c, $e ) = split( '[ ]-[ ]', $patchtypecount );
            $autofixreport .=
                "$d - $comma{$c} "
              . PL( 'vulnerability', $c )
              . " found on "
              . $comma{$e} . " "
              . PL( 'machine', $e ) . ".\n";
        }
        &Log("$autofixreport");
    }

    # Update RRD too
    &UpdateLDSSRRD;

    # Report on manual patch download requirements
    if (@patchurls) {
        my $patchurlsreport = "Manual patch downloads required:\n";
        foreach my $patchurl (@patchurls) {
            $patchurlsreport .= "$patchurl\n";
        }
        &SetSeverity( 4, "Manual patch downloads required" );
        &Log("$patchurlsreport");
    }

    # Create the RRD Index page
    &GenerateIndex;
    return 0;
}

### Update RRD With LDSS Statistics ##########################################
sub UpdateLDSSRRD {

    # Vuln life
    $ldssrrd_life->update( VulnLife => $vulnlife )
      or &LogWarn("Problem writing to ldssstats_life: $!");
    %rtn = $ldssrrd_life->graph(
        destination      => "$reportdir",
        title            => "LDSS Vulnerability Duration",
        vertical_label   => "Detection to Repair",
        extended_legend  => "1",
        interlaced       => "",
        source_drawtypes => "AREA"
      )
      or &LogWarn(
        "Problem graphing from ldssstats_life: " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "UpdateLDSSRRD: Logged LDSS RRD Life statistics: " .
              map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldssstats_life",
        "LANDesk Security Suite Vulnerability Lifetime" );

    # Vuln counts
    $ldssrrd->update(
        ScannedVulns  => $vulncount,
        DetectedVulns => $patchtotal,
        AutofixVulns  => $autofixtotal
    ) or &LogWarn("Problem writing to ldssstats: $!");
    %rtn = $ldssrrd->graph(
        destination     => "$reportdir",
        title           => "LDSS Vulnerability Statistics",
        vertical_label  => "All / Detected / Autofix",
        extended_legend => "1",
        interlaced      => ""
      )
      or &LogWarn(
        "Problem graphing from ldssstats: " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "UpdateLDSSRRD: Logged LDSS RRD statistics: " .
              map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldssstats",
        "LANDesk Security Suite Vulnerability Statistics" );

    return 0;
}

### Count pending scans subroutine ############################################
sub CountPendingScans {

    # This doesn't really need to be commified since the number-producing
    # routines quit counting at 200.
    my $scanmessage;
    my $scancount = &CountPendingINV;
    if ($scancount) { $scanmessage .= "Pending scans: $scancount\n"; }
    my $xddcount = &CountPendingXDD;
    if ($xddcount) {
        $scanmessage .= "Pending discoveries: $xddcount\n";
    }
    my $sdcount = &CountPendingSCHED;
    if ($sdcount) { $scanmessage .= "Pending tasks: $sdcount\n"; }
    my $alertcount = &CountPendingAlerts;
    if ($alertcount) {
        $scanmessage .= "Pending alerts: $alertcount\n";
    }
    if ($scanmessage) { &Log($scanmessage); }
    return 0;
}
###############################################################################

### Count Pending Inventory Scans subroutine #################################
# Watches the queue for SCN and IMS scan insertions
sub CountPendingINV {

    my $ldscan = $ldmain . "ldscan";
    if ( !-e $ldscan ) {
        &LogWarn("Directory $ldscan doesn't seem to exist?");
        return 0;
    }

    opendir( $DIR, "$ldscan" )
      or &LogDie("Can't open directory $ldscan : $!\n");
    my $scancount = 0;
    while ( $file = readdir($DIR) ) {

        # Next file if we're at the top
        if (
            $file =~ /^      # from the beginning of the line
                         \.\.?$ # two dots followed by anything
                         /x
          )
        {
            next;
        }
        if (
            $file =~ /\.SCN$ # if it ends with .SCN
                         /ix
          )
        {
            $scancount++;
        }
        if (
            $file =~ /\.IMS$ # or .IMS
                         /ix
          )
        {
            $scancount++;
        }
        if ( $scancount > 200 ) {
            &Log(
"There are more than 200 inventory scans pending database insertion. You "
                  . "should investigate database performance tuning.\n"
                  . "MS-SQL 2000: http://community.landesk.com/support/docs/DOC-2528\n"
                  . "MS-SQL 2005: http://community.landesk.com/support/docs/DOC-2482\n"
                  . "Oracle 9i:   http://community.landesk.com/support/docs/DOC-1626\n"
                  . "Oracle 10g:  http://community.landesk.com/support/docs/DOC-1531\n"
            );
            &SetSeverity( 1, "Inventory queue is backed up" );
            &RestartService("LANDesk Inventory Server");
            last;
        }
    }
    closedir($DIR);
    return $scancount;
}

### Count Pending Extended Device Discoveries subroutine ######################
# Watches the queue for XDD scan insertions
sub CountPendingXDD {
    my $xddscan = $ldmain . "xddfiles";
    if ( !-e $xddscan ) {
        &LogWarn("Directory $xddscan doesn't seem to exist?");
        return 0;
    }

    opendir( $DIR, "$xddscan" )
      or &LogDie("Can't open directory $xddscan : $!\n");
    my $xddcount = 0;
    while ( $file = readdir($DIR) ) {

        # Next file if we're at the top
        if (
            $file =~ /^ 
                             \.\.?$  # if it begins with two dots
                             /x
          )
        {
            next;
        }
        if (
            $file =~ /\.XDD$  # if it ends with .XDD
                             /ix
          )
        {
            $xddcount++;
        }
        if ( $xddcount > 200 ) {
            &Log(
"There are more than 200 extended device discovery scans pending database "
                  . "insertion. You should investigate $ldmain\\XDDFiles2DB.exe.log."
            );
            &SetSeverity( 1, "Extended device discovery queue is backed up" );
            last;
        }
    }
    closedir($DIR);
    return $xddcount;
}

### Count Pending Alert insertions subroutine ################################
# Watches the queue for alerting insertions
sub CountPendingAlerts {
    my $ALERTDIR = $ldmain . "alertqueue";
    if ( !-e $ALERTDIR ) {
        &LogWarn("Directory $ALERTDIR doesn't seem to exist?");
        return 1;
    }
    opendir( $DIR, "$ALERTDIR" )
      or &LogDie("Can't open directory $ALERTDIR $!\n");
    my $pendingcount = 0;
    while ( $file = readdir($DIR) ) {

        # Next file if we're at the top
        if (
            $file =~ /^ 
                             \.\.?$  # if it begins with two dots
                             /x
          )
        {
            next;
        }
        if (
            $file =~ /\.XML$  # if it ends with .XML
                             /ix
          )
        {
            $pendingcount++;
        }
        if ( $pendingcount > 200 ) {
            &Log(
"There are more than 200 alerting system reports pending database "
                  . "insertion. You should investigate your core's performance."
            );
            &SetSeverity( 1, "Alerting queue is backed up" );
            last;
        }
    }
    closedir($DIR);
    return $pendingcount;
}

### Count Pending Scheduled Task Transfers subroutine #########################
# Watches the queue between Local Scheduler and Global Scheduler
sub CountPendingSCHED {
    my $sdscan = $ldmain . "sdstatus";
    if ( !-e $sdscan ) {
        &LogWarn("Directory $sdscan doesn't seem to exist?");
        return 0;
    }

    opendir( $DIR, "$sdscan" )
      or &LogDie("Can't open directory $sdscan : $!\n");
    my $sdcount = 0;
    while ( $file = readdir($DIR) ) {

        # Next file if we're at the top
        if (
            $file =~ /^\.\.?$     # if it begins with two dots
                             /x
          )
        {
            next;
        }
        if (
            $file =~ /\.XML$      # if it ends with .XML
                             /ix
          )
        {
            $sdcount++;
        }
        if ( $sdcount > 200 ) {
            &Log(
"There are more than 200 scheduled tasks pending transfer to global "
                  . "scheduler. You should investigate scheduler configuration."
            );
            &SetSeverity( 1, "Scheduler queue is backed up" );
            last;
        }
    }
    closedir($DIR);
    return $sdcount;
}
##############################################################################

### EventCheckSchema subroutine ##############################################
sub EventCheckSchema {
    my (%Event) = @_;
    if ( !defined( $Event{EventID} ) ) {
        if ($DEBUG) {
            &LogDebug("EventCheckSchema: saw an event with no EventID");
        }
        return 0;
    }
    if ( $Event{EventID} eq 4100 ) {
        my $text = $Event{Strings};
        if ( defined($text) ) {
            if ( $text =~ m/The size of / ) {
                &Log(   "Inventory Service Schema Extension Required:\n" 
                      . $text
                      . " for more details, see "
                      . "http://community.landesk.com/support/docs/DOC-5137" );
            }
        }
        else {
            &Log("LDINV32 connection error: $text");
        }
        &EventTieToRecord(%Event);
        return 1;
    }
    return 0;
}
### end of EventCheckSchema subroutine #######################################

### EventCheckScan subroutine ################################################
sub EventCheckScan {
    my (%Event) = @_;
    if ( !defined( $Event{EventID} ) ) {
        if ($DEBUG) {
            &LogDebug("EventCheckScan: saw an event with no EventID");
        }
        return 0;
    }

    # detect LDINV 2391, delta error, full scan forced
    if ( $Event{EventID} eq 2391 ) {
        if ($DEBUG) {
            &LogDebug(
"EventCheckScan: $Event{Source} $Event{EventID} $Event{TimeGenerated}"
            );
        }
        &EventTieToRecord(%Event);
        return 1;
    }
    return 0;
}
### end of EventCheckScan subroutine #########################################

### EventCheckOldClient subroutine ###########################################
sub EventCheckOldClient {
    my (%Event) = @_;
    if ( !defined( $Event{EventID} ) ) {
        if ($DEBUG) {
            &LogDebug("EventCheckOldClient: saw an event with no EventID");
        }
        return 0;
    }

    # detect LDINV 4114, corrupt ldappl3, older client
    if ( $Event{EventID} eq 4114 ) {
        if ($DEBUG) {
            &LogDebug(
"EventCheckOldClient: $Event{Source} $Event{EventID} $Event{TimeGenerated}"
            );
        }
        &EventTieToRecord(%Event);
        return 1;
    }
    return 0;
}
### end of EventCheckOldClient subroutine ####################################

### EventCheckHash subroutine ###########################################
sub EventCheckHash {
    my (%Event) = @_;
    if ( !defined( $Event{EventType} ) ) {

       # Commented out because it is very frequent
       #        if ($DEBUG) {
       #            &LogDebug("EventCheckHash: saw an event with no EventType");
       #        }
        return 0;
    }

    # detect LDINV public key hash errors (SLM induced)
    if ( $Event{EventType} eq 2 and $Event{EventID} eq 0 ) {
        if ($DEBUG) {
            &LogDebug(
"EventCheckHash: $Event{Source} $Event{EventID} $Event{TimeGenerated}"
            );
        }
        &EventTieToRecord(%Event);
        return 1;
    }
    return 0;
}
### end of EventCheckHash subroutine ####################################

### Look for database schema errors, Public Key hash errors, full scan forced
# in the Event Viewer ########################################################
# Need to limit this to a single day's data ##################################
sub ReadEventViewer {

    # I'll need a handle to do this with
    my $EventViewerhandle = Win32::EventLog->new( "Application", $COMPUTERNAME )
      or &LogWarn("Initialization: Can't open Application EventLog");

    my %Event = ();
    my (
        $schemaevent,     $schemaresult, $scanresult,
        $oldclientresult, $hashresult,   $result
    ) = ( 0, 0, 0, 0, 0, 0 );

    # One day ago
    my $TIME_LIMIT = time() - 86400;

    while (
        $EventViewerhandle->Read(
            EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
            0, \%Event
        )
      )
    {
        if ( $Event{TimeGenerated} >= $TIME_LIMIT ) {
            if ( $Event{Source} eq "LANDesk Inventory Server" ) {
                my %ValidEvent = (
                    Source        => $Event{Source},
                    TimeGenerated => $Event{TimeGenerated},
                    EventID       => $Event{EventID},
                    Strings       => $Event{Strings}
                );
                $schemaresult    += &EventCheckSchema(%ValidEvent);
                $scanresult      += &EventCheckScan(%ValidEvent);
                $oldclientresult += &EventCheckOldClient(%ValidEvent);
                $hashresult      += &EventCheckHash(%ValidEvent);
                $schemaevent++;

            }
        }
    }

    # Let the eventlog go
    $EventViewerhandle->Close();

    # Log what happened
    if ($DEBUG) {
        &LogDebug( "ReadEventViewer: reviewed $schemaevent "
              . " Inventory service "
              . PL( "record", $schemaevent )
              . " from the last 24 hours." );
    }

    # Log schema problems directly
    if ( $schemaresult > 0 ) {
        &SetSeverity( 2, "Schema insertion errors found" );
        &Log(   $comma{$schemaresult}
              . " Database schema "
              . PL( "error", $schemaresult )
              . " found in the last day. Please see the article at "
              . "http://community.landesk.com/support/docs/DOC-1604" );
    }
    else {
        if ($DEBUG) {
            &LogDebug("ReadEventViewer: found no schema errors.");
        }
    }

    # Pass scan, hash, and old client problems to DoInventoryMath
    if ( $scanresult > 0 ) {
        if ($DEBUG) {
            &LogDebug( "ReadEventViewer: found $scanresult forced scan "
                  . PL( "record", $scanresult )
                  . "." );
        }
    }
    else {
        if ($DEBUG) {
            &LogDebug("ReadEventViewer: found no forced full scans.");
        }
    }
    if ( $hashresult > 0 ) {
        if ($DEBUG) {
            &LogDebug( "ReadEventViewer: found $result public key hash "
                  . PL( "error", $result )
                  . "." );
        }
    }
    else {
        if ($DEBUG) {
            &LogDebug("ReadEventViewer: found no public key hash errors.");
        }
    }
    if ( $oldclientresult > 0 ) {
        if ($DEBUG) {
            &LogDebug( "ReadEventViewer: found $oldclientresult old client "
                  . "or LDAPPL3 "
                  . PL( "error", $oldclientresult )
                  . "." );
        }
    }
    else {
        if ($DEBUG) {
            &LogDebug(
                "ReadEventViewer: found no old clients or ldappl3 errors.");
        }
    }
    return ( $scanresult, $hashresult, $oldclientresult );
}
###############################################################################

### Tie an LDINV32 event to the machine that produced it ######################
sub EventTieToRecord {
    my (%Event) = @_;

    if ( !defined( $Event{Strings} ) ) {
        if ($DEBUG) {
            &LogDebug("EventTieToRecord: Saw Event with no Strings.");
        }
        return 1;
    }

    # look for UUID
    my $uuid = $Event{Strings};
    $uuid =~ m/(\{.*\})/ix;
    if ($1) {
        $uuid = $1;
    }
    else {
        $uuid = 0;
    }
    if ( $DEBUG && $uuid ) {
        &LogDebug("EventTieToRecord: found Device ID $uuid from Event.");
    }

    if ( !$uuid ) {

        # look for SCN file name
        my $SCANDIR = $ldmain . "ldscan\\errorscan";
        if ( !-e $SCANDIR ) {
            &LogWarn(
                "Can't tie event to record because $SCANDIR can't be accessed");
            return 1;
        }
        my $file = $Event{Strings};
        $file =~ m/(SCA.*\.SCN)/ix;
        if ($1) {
            $file = $1;
        }
        else {
            $file = 0;
        }
        if ($file) {
            if ($DEBUG) {
                &LogDebug("EventTieToRecord: found filename $file from Event.");
            }

            # read the scan file
            # Look for a good name
            if ( -e "$SCANDIR\\$file" ) {
                open( $FILE, '<', "$SCANDIR\\$file" )
                  or &LogWarn("Can't open file $SCANDIR\\$file : $!\n");
                while (<$FILE>) {
                    my @parts = split( /=/x, $_ );
                    if ( $parts[0] eq "Device ID " ) {
                        $uuid = &Trim( $parts[1] );
                        if ($DEBUG) {
                            &LogDebug(
"EventTieToRecord: found Device ID $uuid from SCN file."
                            );
                        }
                        last;
                    }
                }
                close($FILE);
            }
        }
    }

    # update the database
    if ($uuid) {

        # unless the device's problem has already corrected itself
        if ( $db_type eq 'SQL' ) {
            $sql =
"select top 1 lastupdinvsvr from computer where deviceid = '$uuid'";
        }
        elsif ( $db_type eq 'ORA' ) {
            $sql =
                "SELECT lastupdinvsvr FROM "
              . "(SELECT lastupdinvsvr FROM computer WHERE deviceid ='$uuid' ) "
              . "WHERE ROWNUM = 1";
        }
        my $lastupdate = &GetSingleString($sql);
        if ($lastupdate) {
            if ( str2time($lastupdate) < $Event{TimeGenerated} ) {
                if ( $db_type eq "SQL" ) {
                    $sql =
"select top 1 computer_idn from computer where deviceid = '$uuid'";
                }
                elsif ( $db_type eq 'ORA' ) {
                    $sql =
                        "SELECT computer_idn FROM "
                      . "(select computer_idn from computer where deviceid ='$uuid') "
                      . "WHERE ROWNUM = 1";
                }
                my $computer = &GetSingleString($sql);
                if ($DEBUG) {
                    &LogDebug(
                        "EventTieToRecord: Would set scantype to 'Outdated' "
                          . "for record $computer" );
                }
                else {
                    $sql = "update computer set scantype='Outdated' "
                      . "where computer_idn='$computer'";
                    &DoDBAction($sql);
                }
            }
            else {
                if ($DEBUG) {
                    &LogDebug(
                        "EventTieToRecord: Device $uuid caused an inventory "
                          . "server problem at "
                          . localtime( $Event{TimeGenerated} )
                          . ", but has since updated properly at "
                          . $lastupdate
                          . ", so ldms_core can leave its "
                          . "record alone." );
                }
            }
        }
        else {
            if ($DEBUG) {
                &LogDebug( "EventTieToRecord: Can't find a Last Updated by "
                      . "inventory server datestamp for device with UUID $uuid"
                );
            }
        }
    }
    return 0;
}

### Clean up rolling ldinv32 log files ########################################
sub CullRollingLog {
    if ( !-e $ldmain ) {
        &LogWarn("Directory $ldmain doesn't seem to exist?");
        return 1;
    }

    my ( $logcount, $logsize );
    if ($DEBUG) { &LogDebug("CullRollingLog: culling files in LDMAIN."); }
    opendir( $DIR, "$ldmain" ) or &LogDie("Cannot access $ldmain -- $!");
    while ( my $invlogfile = readdir($DIR) ) {

        # Next file if we're at the top or the file was already done
        next if $invlogfile =~ /^       # from the beginning of the line
                            \.\.?   # two dots then anything
                            $       # to the end of the line
                            /x;

        if ( $invlogfile =~ /^ldinv32\.exe(.+).log/ix ) {

            # Delete it if not from this week
            # stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
            my ( $size, $ctime ) =
              ( stat( $ldmain . "\\" . $invlogfile ) )[ 7, 10 ]
              or &LogWarn("CullRollingLog: stat($invlogfile) failed: $!");
            if ($DEBUG) {
                &LogDebug( "CullRollingLog: stat() says $invlogfile ctime is "
                      . localtime($ctime)
                      . ", size is $size" );
            }

            # seven days old
            if ( $ctime < ( time() - 804600 ) ) {

                $logcount++;
                $logsize += $size;
                &DeleteFile( $ldmain . "\\" . $invlogfile, $ctime );
            }
        }
    }
    if ($logcount) {
        my $logmsg =
            "$logcount rolling inventory service log "
          . PL( "file", $logcount )
          . " from $ldmain, recovering "
          . format_bytes($logsize)
          . " of disk space. You should turn off rolling logging if it's"
          . " no longer necessary. In the core's console, click Configure"
          . " > Services > Inventory > Advanced Settings >"
          . " Use Rolling Log.";
        if ($DEBUG) {
            &Log( "CullRollingLog: Would have deleted " . $logmsg );
        }
        else {
            &Log( "Deleted " . $logmsg );
        }
    }
    closedir($DIR);
    return 0;
}
### Clean up temp scan files #################################################
sub CullTMP {
    my $targetdir = shift;
    if ( !-e $targetdir ) {
        &LogWarn("Directory $targetdir doesn't seem to exist?");
        return 1;
    }

    my $tmpcount;
    if ($DEBUG) {
        &LogDebug("CullTMP: Culling temporary files in $targetdir.");
    }
    opendir( $DIR, "$targetdir" ) or &LogDie("Cannot access $targetdir -- $!");
    while ( my $tmpfile = readdir($DIR) ) {

        # Next file if we're at the top or the file was already done
        next if $tmpfile =~ /^       # from the beginning of the line
                            \.\.?   # two dots then anything
                            $       # to the end of the line
                            /x;

        # Ignore non-tmp files
        if (
            $tmpfile =~ /\.TMP$ # if it ends with .TMP
                            /ix
          )
        {

            # Delete it regardless of age
            $tmpcount++;
            &DeleteFile( $targetdir . "\\" . $tmpfile, localtime );
        }
    }
    if ($tmpcount) {
        my $logmsg =
          "$tmpcount temporary " . PL( "file", $tmpcount ) . " from $targetdir";
        if ($DEBUG) {
            &Log( "CullTMP: Would have deleted " . $logmsg );
        }
        else {
            &Log( "Deleted " . $logmsg );
        }
    }
    closedir($DIR);
    return 0;
}

### Broken XDDTMP cleanup subroutine ########################################
### http://community.landesk.com/support/message/18694
sub CullXDD {
    my $xddscan = $ldmain . "xddfiles";
    if ( !-e $xddscan ) {
        &LogWarn("Directory $xddscan doesn't seem to exist?");
        return 0;
    }

    opendir( $DIR, "$xddscan" )
      or &LogDie("Can't open directory $xddscan : $!\n");
    my $xddtmpcount = 0;
    while ( $file = readdir($DIR) ) {

        # Next file if we're at the top
        if (
            $file =~ /^ 
                             \.\.?$  # if it begins with two dots
                             /x
          )
        {
            next;
        }
        if (
            $file =~ /\.XDDTMP$  # if it ends with .XDDTMP
                             /ix
          )
        {
            if ($DEBUG) { &LogDebug("CullXDD: Would delete $file"); }
            else {
                eval {
                    unlink($file)
                      || &LogWarn("CullXDD: unlink $file failed: $!");
                    $xddtmpcount++;
                  }
                  or do {
                    &SetSeverity( 1,
                        "You should delete $file manually as soon as possible"
                    );
                  }
            }
        }
    }
    closedir($DIR);
    if ( $xddtmpcount > 0 ) {
        &Log(   "There "
              . PL( 'was', $xddtmpcount )
              . "$xddtmpcount corrupt "
              . "extended device discovery "
              . PL( 'scan', $xddtmpcount )
              . ". You should investigate $ldmain\\XDDFiles2DB.exe.log." );
    }
    return 0;
}

### Orphaned SLM Products cleanup subroutine ##################################
sub CullOrphanProducts {
    my $sqlbase =
"from fileinfo where fileinfo_idn in ( select distinct a.fileinfo_idn From "
      . "fileinfo a left outer join fileinfoinstance b on a.fileinfo_idn = "
      . "b.fileinfo_idn left outer join productfile c on a.fileinfo_idn = "
      . "c.fileinfo_idn where a.filesize = 0 and b.fileinfo_idn is null and "
      . "c.fileinfo_idn is null)";

    # How many?
    $sql = "select count(*) " . $sqlbase;
    my $orphancount = &GetSingleString($sql);

    # If it's more than zero, take action and report
    if ($orphancount) {
        my $logmsg =
            "$comma{$orphancount} orphaned SLM "
          . "product "
          . PL( "record", $orphancount )
          . " from the "
          . "database.";
        if ($DEBUG) {
            &Log( "CullOrphanProducts: Would have deleted " . $logmsg );
        }
        else {
            $sql = "delete " . $sqlbase;
            &DoDBAction($sql);
            &Log( "Deleted " . $logmsg );
        }
    }
    return 0;
}
### End of ComputerVulnerabilities cleanup subroutine ########################

### Orphaned ComputerVulnerabilities cleanup subroutine #######################
sub CullOrphanCompVulns {
    my $sqlbase =
        "from computervulnerability where computervulnerability_idn"
      . " in (select computervulnerability_idn from computervulnerability cv,"
      . " vulnerability v where v.vul_id = cv.vul_id and v.status = 0)";

    # How many?
    $sql = "select count(*) " . $sqlbase;
    my $orphancount = &GetSingleString($sql);

    # If it's more than zero, take action and report
    if ($orphancount) {
        my $logmsg =
            "$comma{$orphancount} orphaned computer "
          . "vulnerability "
          . PL( "record", $orphancount )
          . " from the "
          . "database.";
        if ($DEBUG) {
            &Log( "CullOrphanCompVulns: Would have deleted " . $logmsg );
        }
        else {
            $sql = "delete " . $sqlbase;
            &DoDBAction($sql);
            &Log( "Deleted " . $logmsg );
        }
    }
    return 0;
}
### End of ComputerVulnerabilities cleanup subroutine ########################

### Orphaned SCheduled Computers cleanup subroutine ##########################
sub CullOrphanTaskComps {
    my $sqlbase =
"from ld_task_machine where ld_task_machine.computer_idn not in ( select computer_idn from computer)";

    # How many?
    $sql = "select count(*) " . $sqlbase;
    my $orphancount = &GetSingleString($sql);

    # If it's more than zero, take action and report
    if ($orphancount) {
        my $logmsg =
            "$comma{$orphancount} orphaned computer " . "task "
          . PL( "record", $orphancount )
          . " from the "
          . "database.";
        if ($DEBUG) {
            &Log( "CullOrphanTaskComps: Would have deleted " . $logmsg );
        }
        else {
            $sql = "delete " . $sqlbase;
            &DoDBAction($sql);
            &Log( "Deleted " . $logmsg );
        }
    }
    return 0;
}
### End of ComputerVulnerabilities cleanup subroutine ########################

### CullUndetectedVulnCounts subroutine ######################################
sub CullUndetectedVulnCounts {
    my $sqlbase = "from computervulnerability where detected = 0 "
      . "and patchinstalldate is null";

    # How many?
    $sql = "select count(computervulnerability_idn) " . $sqlbase;
    my $undetectedcount = &GetSingleString($sql);

    # If it's more than zero, take action and report
    if ($undetectedcount) {
        my $logmsg =
            "$comma{$undetectedcount} undetected "
          . "vulnerability scan "
          . PL( "record", $undetectedcount )
          . " from the database. These are the records of vulns that "
          . "were scanned for, but not found.";
        if ($DEBUG) {
            &Log( "CullUndetectedVulnCounts: Would have deleted " . $logmsg );
        }
        else {
            $sql = "delete " . $sqlbase;
            &DoDBAction($sql);

            # If this is 8.8 SP3 or greater,  there are patch settings to
            # manage.
            if ( substr( $ldms_version, 0, 4 ) >= 8803 ) {
                &SetPatchDiscardOn;
            }
            &Log( "Deleted " . $logmsg );
        }
    }
    return 0;
}
### End of CullUndetectedVulnCounts subroutine ###############################

### SetPatchDiscardOn subroutine #############################################
sub SetPatchDiscardOn {
    my $sqlbase = "select value from patchsettings where name=";
    $sql = $sqlbase . "'DiscardUndetectedBlockedApps'";
    my $DiscardUndetectedBlockedApps = &GetSingleString($sql);
    if ($DEBUG) {
        &LogDebug( "SetPatchDiscardOn: Discard Undetected Blocked "
              . "Apps is set to $DiscardUndetectedBlockedApps" );
    }
    if ( !$DiscardUndetectedBlockedApps ) {
        $sql = "Insert into patchsettings (Name, Value) values "
          . "('DiscardUndetectedBlockedApps', '1')";
        if ($DEBUG) {
            &LogDebug( "SetPatchDiscardOn: Would force discard "
                  . "of undetected blocked apps to on" );
        }
        else {
            &DoDBAction($sql);
        }
    }
    $sql = $sqlbase . "'DiscardUndetectedSpyware'";
    my $DiscardUndetectedSpyware = &GetSingleString($sql);
    if ($DEBUG) {
        &LogDebug( "SetPatchDiscardOn: Discard Undetected Spyware "
              . "is set to $DiscardUndetectedSpyware" );
    }
    if ( !$DiscardUndetectedSpyware ) {
        $sql = "Insert into patchsettings (Name, Value) values "
          . "('DiscardUndetectedSpyware', '1')";
        if ($DEBUG) {
            &LogDebug( "SetPatchDiscardOn: Would force discard "
                  . "of undetected spyware to on" );
        }
        else {
            &DoDBAction($sql);
        }
    }
    return 0;
}
### End of SetPatchDiscardOn subroutine ######################################

### Old PatchHistory cleanup subroutine ######################################
sub CullOrphanPatchHistory {
    my $sqlbase = "from patchhistory where computer_idn not in "
      . "(select computer_idn from computer)";

    # How many?
    $sql = "select count(patchhistory_idn) " . $sqlbase;
    my $orphancount = &GetSingleString($sql);

    # If it's more than zero, take action and report
    if ($orphancount) {
        my $logmsg =
            "$comma{$orphancount} orphaned patch "
          . "history "
          . PL( "record", $orphancount )
          . " from the "
          . "database.";
        if ($DEBUG) {
            &Log( "CullOrphanPatchHistory would have deleted " . $logmsg );
        }
        else {
            $sql = "delete " . $sqlbase;
            &DoDBAction($sql);
            &Log( "Deleted " . $logmsg );
        }
    }
    else {
        if ($DEBUG) { &LogDebug("CullOrphanPatchHistory: found nothing"); }
    }
    return 0;
}
### End of PatchHistory cleanup subroutine ####################################

### Old Patch cleanup subroutine ##############################################
sub CullPatches {

    # Only culls patches that are defined in the database; if the
    # vulnerability that caused a patch to be downloaded is no longer in the
    # database, that patch will not be considered for deletion
    if ( !-e $PATCHDIR ) {
        &LogWarn("Directory $PATCHDIR doesn't seem to exist?");
        return 1;
    }

    my $possiblepatchcount = 0;
    my $patchcount         = 0;
    my $netdrive           = 0;
    if ($DEBUG) { &LogDebug("CullPatches: Analyzing patches in $PATCHDIR"); }
    if ( $PATCHDIR =~ m/^\\\\/x ) {
        $netdrive = 1;
    }
    if ($deletiondays) {

        # Get the patch count
        $sql = "select count(distinct patch) from computervulnerability where "
          . "detected=0 and patch != '*'";
        $possiblepatchcount = &GetSingleString($sql);

        # Get the patch names
        $sql = "select distinct patch from computervulnerability where "
          . "detected=0 and patch != '*'";
        my @patches = &GetSingleArray($sql);
        $trashcount = 0;
        my $time = time() - ( $deletiondays * 86400 );
        if ($DEBUG) {
            &LogDebug( "CullPatches: the deletion recommended time is "
                  . localtime($time)
                  . " -- files with older access times "
                  . "should be deleted." );
        }
        foreach my $patch (@patches) {
            my $patchfile = $PATCHDIR . "\\" . $patch;

            if ( -w $patchfile ) {

                # There really is a patch here, which is really evaluated
                $patchcount++;
                if ( $netdrive == 1 ) {

                    # Stat won't work on network drives
                    &DeleteFile( $patchfile, localtime );
                    $trashcount++;
                }
                else {

                    # stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
                    my $atime = ( stat($patchfile) )[8]
                      or &LogWarn("CullPatches: stat($patchfile) failed: $!");
                    if ( $atime < $time ) {
                        &DeleteFile( $patchfile, $atime );
                        $trashcount++;
                    }
                }
            }
        }

    }
    if ( $trashcount > 0 ) {
        my $logmsg =
            NUMWORDS($trashcount) . " "
          . PL( "patch", $trashcount )
          . ", in order to recover "
          . format_bytes($totalsize)
          . " disk space from $PATCHDIR.";
        if ($DEBUG) {
            &Log( "CullPatches: Would have deleted " . $logmsg );
        }
        else {
            &Log( "Deleted " . $logmsg );
        }
    }
    else {
        &Log(   "Evaluated "
              . NUMWORDS($patchcount) . " "
              . PL( "patch", $patchcount )
              . " out of "
              . NUMWORDS($possiblepatchcount)
              . " possible "
              . PL( "patch", $possiblepatchcount )
              . " from the vulnerability definitions, deleted none." );
    }
    return 0;
}
### End of CullPatches subroutine ###########################################

### CullPatchFiles subroutine ###############################################
sub CullPatchFiles {

    # Cull files from the patch folder that are not referenced in the database
    if ( !-e $PATCHDIR ) {
        &LogWarn("Directory $PATCHDIR doesn't seem to exist?");
        return 1;
    }

    my $possiblepatchcount = 0;
    my $patchcount         = 0;
    $trashcount = 0;
    $totalsize  = 0;
    my $netdrive = 0;
    if ( $PATCHDIR =~ m/^\\\\/x ) {
        $netdrive = 1;
    }

    if ($DEBUG) {
        &LogDebug("CullPatchFiles: Culling orphaned patch files in $PATCHDIR.");
    }
    my $time = time() - ( $deletiondays * 86400 );
    if ($DEBUG) {
        &LogDebug( "CullPatchFiles: the deletion recommended time is "
              . localtime($time)
              . "-- files with older access times should be deleted." );
    }
    opendir( $DIR, "$PATCHDIR" ) or &LogDie("Cannot access $PATCHDIR -- $!");
    if ($deletiondays) {
        while ( my $patchfile = readdir($DIR) ) {

            # Next file if we're at the top
            next if $patchfile =~ /^       # from the beginning of the line
                            \.\.?   # two dots then anything
                            $       # to the end of the line
                            /x;

            $patchcount++;

            # Ignore patch files with database references
            $sql = "select count(patch) from computervulnerability "
              . "where patch='$patchfile'";
            my $is_current_patch = &GetSingleString($sql);
            if ( !$is_current_patch ) {

                $possiblepatchcount++;
                if ( $netdrive == 1 ) {

                    # Stat won't work on network drives
                    &DeleteFile( $PATCHDIR . "\\" . $patchfile, localtime );
                    $trashcount++;
                }
                else {

                    # stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
                    my $atime = ( stat( $PATCHDIR . "\\" . $patchfile ) )[8]
                      or
                      &LogWarn("CullPatchFiles: stat($patchfile) failed: $!");
                    if ( $atime < $time ) {
                        &DeleteFile( $PATCHDIR . "\\" . $patchfile, $atime );
                        $trashcount++;
                    }
                }
            }
        }
    }
    if ( $trashcount > 0 ) {
        my $logmsg =
            NUMWORDS($trashcount) . " "
          . PL( "patch", $trashcount )
          . ", in order to recover "
          . format_bytes($totalsize)
          . " disk space from $PATCHDIR.";
        if ($DEBUG) {
            &Log( "CullPatchFiles: Would have deleted " . $logmsg );
        }
        else {
            &Log( "Deleted " . $logmsg );
        }
    }
    else {
        &Log(   "Evaluated "
              . NUMWORDS($possiblepatchcount) . " "
              . PL( "patch", $possiblepatchcount )
              . " out of "
              . NUMWORDS($patchcount)
              . " possible "
              . PL( "patch", $patchcount )
              . " in $PATCHDIR, deleted none." );
    }
    closedir($DIR);
    return 0;
}
### End of CullPatchFiles subroutine ########################################

### Force purging of alerts that alert service is choking on ################
sub PurgeAlerts {

    # Check the LANDesk version
    if ( substr( $ldms_version, 0, 2 ) < 88 ) {
        if ($DEBUG) { &LogDebug("PurgeAlerts: nothing to do."); }
        return 1;
    }

    # How many alerts are we going to do this to?
    $sql = "select count(alertlog_idn) from ALERTLOG where PURGE='1'";
    my $alertpurges = &GetSingleString($sql);

    # Got targets?
    if ( $alertpurges > 0 ) {

        # Do the work
        if ($DEBUG) {
            &LogDebug( "PurgeAlerts: would purge "
                  . $alertpurges
                  . " alert messages from the database." );
        }
        else {

            # Kill them, and their little doggies too
            $sql = "delete from alertparameters where alertlog_idn in "
              . "(select alertlog_idn from alertlog where purge='1')";
            &DoDBAction($sql);
            $sql = "delete from alertlogrules where alertlog_idn in "
              . "(select alertlog_idn from alertlog where purge='1')";
            &DoDBAction($sql);
            $sql = "delete from alertlog where purge='1'";
            &DoDBAction($sql);

            &Log(   "Purged "
                  . $comma{$alertpurges}
                  . " orphaned "
                  . PL( "alerts", $alertpurges )
                  . " from the database." );

            # Restart the service so it can take advantage of its newly
            # working state.
            &RestartService("CBA8Alert");
        }
    }
    else {
        if ($DEBUG) {
            &LogDebug("PurgeAlerts: nothing to purge.");
        }
    }

    return 0;
}

### Mark old alerts for purging #############################################
sub CullAlerts {

    # Note that Alert Service will puke if we just delete them; we need to
    # mark the alerts as purge-worthy and set a purge flag for the alert
    # service to do the dirty work on its own

    # Check the LANDesk version and deletion days
    if ( substr( $ldms_version, 0, 2 ) < 88 || !defined($deletiondays) ) {
        if ($DEBUG) { &LogDebug("CullAlerts: nothing to do."); }
        return 1;
    }

    # How many alerts are we going to do this to?
    $sql = "select count(alertlog_idn) from ALERTLOG "
      . "where PURGE='0' and ALERTTIME < ";
    if ( $db_type eq 'SQL' ) {
        $sql .= "getdate()-";
    }
    elsif ( $db_type eq 'ORA' ) {
        $sql .= "current_date-";
    }
    $sql .= $deletiondays;
    my $alertpurges = &GetSingleString($sql);

    # Do the work
    if ($DEBUG) {
        &LogDebug( "CullAlerts: would cull "
              . $alertpurges
              . " alert messages from the database." );
    }
    else {

        # Mark them for purging
        $sql = "update ALERTLOG set purge = 1 where ALERTTIME < ";
        if ( $db_type eq "SQL" ) {
            $sql .= "getdate()-";
        }
        elsif ( $db_type eq "ORA" ) {
            $sql .= "current_date-";
        }
        $sql .= $deletiondays;
        &DoDBAction($sql);

        # Do the marker file
        my $purgemarker = $ldmain . "alertqueue\\purge.sig";

        # Check the file
        if ( !-e $purgemarker ) {

            # touch the purge marker;
            open( $FILE, '>', "$purgemarker" )
              or &LogWarn("CullAlerts: Can't create $purgemarker : $!");
            print $FILE "\n";
            close($FILE);
            if ($DEBUG) { &LogDebug("CullAlerts: created $purgemarker"); }
        }

        # Report our activity
        if ( $alertpurges > 0 ) {
            &Log(   "Marked "
                  . $comma{$alertpurges}
                  . " Alert "
                  . PL( "record", $alertpurges )
                  . " for purging which were "
                  . "older than $deletiondays days." );
        }
    }

    return 0;
}

### Delete dead IP addresses ################################################
sub CullIPs {

    # If there were duplicates, we want to remove the older one
    # First scenario:
    # Machine A leaves network address 1, by shutting down or suspending.
    # Machine B claims network address 1, reports to core.
    # Core now has two machines with address 1.

# Second scenario:
# Machine A leaves network address 1 by roaming across WAPs or plugging into the wire.
# It claims address 2, but the inventory scan fails to process its update miniscan.
# Machine B takes network address 1, successfully sends in an update scan.
# Core now has two machines with address 1.

    if (@dupaddresses) {

        my $deadaddrcount = 0;

        $sql =
            "update TCP set address = '' where TCP.computer_idn = "
          . "(select computer_idn from computer where "
          . "lastupdinvsvr=(select min(lastupdinvsvr) "
          . "from COMPUTER c join tcp t "
          . "on t.computer_idn = c.computer_idn "
          . "where t.address = ?))";

        foreach my $deadaddr (@dupaddresses) {

            if ( &IsIPAddress($deadaddr) ) {
                $sth = $dbh->prepare($sql)
                  or &LogWarn( "$sql caused " . $dbh->errstr );
                if ($DEBUG) {
                    &LogDebug(
                        "CullIPs: would delete the older instance of $deadaddr"
                    );
                }
                else {
                    $sth->execute($deadaddr)
                      or &LogWarn( $dbh->errstr );
                    $deadaddrcount++;
                    $sth->finish();
                }
            }
        }

        if ( $deadaddrcount > 0 ) {
            &Log(   "Cleared "
                  . $comma{$deadaddrcount}
                  . " dead IP "
                  . PL( "address", $deadaddrcount )
                  . "." );
        }

        return 0;
    }
    else {

        if ($DEBUG) { &LogDebug("CullIPs: called with nothing to do"); }
        return 1;
    }

}

### Delete automatic products with no usage ###################################
sub CullProducts {

    # Get listing of the products we'll delete. These are autodiscovered
    # products (not custom) which have no usage data. It's possible that we'll
    # churn over recently discovered products, particularly for a newly
    # installed core... not sure how important that is or if it's worth
    # working around.
    if ( $db_type eq "SQL" ) {
        $sql =
            "SELECT DISTINCT TOP 500 Product_Idn, "
          . "( SELECT DISTINCT COUNT(DeviceName) AS Expr1 "
          . "FROM Computer where computer_idn in ( "
          . "SELECT distinct FileInfoInstance.computer_idn "
          . "FROM   FileInfoInstance "
          . "INNER JOIN ProductFile "
          . "INNER JOIN FileInfo ON "
          . "ProductFile.FileInfo_Idn = FileInfo.FileInfo_Idn "
          . "ON FileInfoInstance.FileInfo_Idn = FileInfo.FileInfo_Idn "
          . "where ProductFile.Product_Idn = Product.Product_Idn) "
          . ") as [TotalPCs] FROM Product order by TotalPCs";
    }
    else {
        $sql =
            "select product_idn, " . "cnt " . "from "
          . "(select p.product_idn, "
          . "p.title,"
          . "count(0) as cnt "
          . "from product p "
          . "join productfile pf "
          . "on pf.product_idn = p.product_idn "
          . "join fileinfo fi "
          . "on fi.fileinfo_idn = pf.fileinfo_idn "
          . "join fileinfoinstance fii "
          . "on fii.fileinfo_idn = fi.fileinfo_idn "
          . "join computer c "
          . "on c.computer_idn = fii.computer_idn "
          . "group by p.product_idn, "
          . "p.title "
          . "order by count(0) desc " . ") "
          . "where rownum <= 500";
    }

    my @productslist = &GetTwoColumnList($sql);
    my @tokill;
    my $killcount = 0;

    foreach my $p (@productslist) {
        my ( $d, $c ) = split( '[ ]-[ ]', $p );
        if ( $c == 0 ) {

            # Is this product in a compliance group? If so, we don't want to
            # delete it, so we'll avoid putting it into the list.
            if ( $db_type eq "SQL" ) {
                $sql =
                    "select top 1 count(product_idn) from product p "
                  . "inner join customgroupproduct as cgp on p.product_idn = "
                  . "cgp.member_idn where p.product_idn = '$d'";
            }
            elsif ( $db_type eq "ORA" ) {
                $sql =
                    "select count(product_idn) from "
                  . "(select count(product_idn) from product p "
                  . "inner join customgroupproduct as cgp on p.product_idn = "
                  . "cgp.member_idn where p.product_idn = '$d') "
                  . "where rownum = 1";
            }
            my $cgp = &GetSingleString($sql);
            if ( $cgp == 0 ) {

                #push $d into the to-kill list;
                push( @tokill, $d );

                #increment killcount;
                $killcount++;
            }
        }
    }

    # otherwise, foreach to-kill, execute the kill
    foreach my $product (@tokill) {
        if ($DEBUG) {
            my $prodname = &GetSingleString(
                "select title from product where product_idn = '$product'");
            &LogDebug( "CullProducts: would remove the "
                  . "automatically discovered product $prodname"
                  . " from the database." );
        }
        else {

            # This could be more efficient by using an inner join, but it
            # seems safer this way.
            $sql =
                "SELECT FileInfo_Idn FROM FILEINFO WHERE FileInfo_Idn IN "
              . "(SELECT FILEINFO_IDN FROM PRODUCTFILE WHERE "
              . "Product_idn='$product')";
            my @file_idn = &GetSingleArray($sql);

            $sql = "BEGIN TRANSACTION;"
              . "DELETE FROM PRODUCTFILE WHERE Product_idn='$product'";

            foreach my $file_idn (@file_idn) {
                $sql .=
                  "DELETE FROM FILEINFO " . "WHERE FileInfo_Idn='$file_idn';";
            }

            # Now we can do the rest of the job.
            $sql .=
                "DELETE FROM PRODUCTHASH WHERE Product_idn='$product';"
              . "DELETE FROM PRODUCTCOMPUTER WHERE Product_idn='$product';"
              . "DELETE FROM PRODUCTDOWNGRADE WHERE Product_idn='$product';";
            if ( substr( $ldms_version, 0, 2 ) == 88 ) {
                $sql .=
                    "DELETE FROM SLM_APPDENIEDBYADGROUP "
                  . "WHERE Product_idn='$product';"
                  . "DELETE FROM SLM_APPDENIEDBYLDGROUP "
                  . "WHERE Product_idn='$product';";
            }
            $sql .= "DELETE FROM PRODUCT WHERE Product_idn='$product';"
              . "COMMIT TRANSACTION";

            # If the transaction failed, we don't want to report that we
            # deleted products which didn't really get deleted.
            if ( &DoDBAction($sql) ) {
                $killcount--;
                &LogWarn( "Product deletion transaction failed "
                      . "for product id $product; this probably means it "
                      . "was in a compliance group." );
            }
        }
    }

    if ($killcount) {
        my $logmsg =
            $comma{$killcount}
          . " automatically discovered "
          . PL( "product", $killcount )
          . " from the database.";
        if ($DEBUG) {
            &Log( "CullProducts: Would have deleted " . $logmsg );
        }
        else {
            &Log( "Deleted " . $logmsg );
            &SetSeverity( 4, "Automatically gathered SLM Products deleted" );
        }
    }

    return 0;
}

### Move superceded vulns to Do Not Scan ######################################
sub CullVulns {

    # 1 == SKIP culling
    # 2 == cull completely superceded (supercededstate is 1)
    # 3 == cull partially superceded (supercededstate is not 0)
    if ( $CullVulnsAggression == 1 ) {
        if ($DEBUG) { &LogDebug("CullVulns: Skipping Vulnerability Culling"); }
        return 0;
    }

    # Get listing of the vulns we'll affect
    $sql = "select vul_id from VULNERABILITY where ";

    # Reduce aggression if necessary
    if ( $CullVulnsAggression == 3 ) {
        $sql .= "supercededstate != '0' ";
    }
    else {
        $sql .= "supercededstate = '2' ";
    }
    $sql .= "and status != '0'";
    @supercededvulns = &GetSingleArray($sql);

    # How many superceded vulns are there?
    $supercededvulncount = @supercededvulns;
    if ($DEBUG) {
        &LogDebug( "CullVulns: Found $supercededvulncount superceded "
              . PL( "vulnerability", $supercededvulncount ) );
    }

    # Move those vulns to Do Not Scan
    foreach my $vuln (@supercededvulns) {
        if ($DEBUG) {
            &LogDebug("CullVulns: I would move $vuln to Do Not Scan.");
        }
        else {
            $sql = "update VULNERABILITY set status='0', LastSerialized=";
            if ( $db_type eq "SQL" ) {
                $sql .= "getdate() ";
            }
            elsif ( $db_type eq "ORA" ) {
                $sql .= "current_date ";
            }
            $sql .= " where vul_id = '$vuln'";
            &DoDBAction($sql);
        }
    }

    $sth->finish();

    if ($supercededvulncount) {
        if ($DEBUG) {
            &Log(   "CullVulns: Would have moved $supercededvulncount "
                  . PL( "vulnerability", $supercededvulncount )
                  . " to Do Not Scan." );
        }
        else {
            &Log(   "Moved "
                  . $comma{$supercededvulncount} . " "
                  . PL( "vulnerability", $supercededvulncount )
                  . " to Do Not Scan: "
                  . "@supercededvulns\n" );
            &SetSeverity( 4, "Superceded vulnerabilities turned off" );
        }
    }

    return 0;
}

### Delete old unmanaged nodes ################################################
sub CullUDD {

    if ($deletiondays) {

        # How many unmanaged nodes are older than $deletiondays?
        $sql = "select count(lastscantime) from UNMANAGEDNODES where ";
        if ( substr( $ldms_version, 0, 2 ) == 88 ) {
            $sql .= " wapdiscovered = '0' and ";
        }
        $sql .= " lastscantime < ";
        if ( $db_type eq "SQL" ) {
            $sql .= "getdate()-";
        }
        elsif ( $db_type eq "ORA" ) {
            $sql .= "current_date-";
        }
        $sql .= $deletiondays;
        my $udddeletes = &GetSingleString($sql);

        if ( $udddeletes > 0 ) {
            my $logmsg =
                $comma{$udddeletes}
              . " Unmanaged Nodes records which hadn't been seen in"
              . " more than $deletiondays days.";
            if ($DEBUG) {
                &Log( "CullUDD: Would have deleted " . $logmsg );
            }
            else {

                # Make the old scans go away -- skipping the WAPs for now
                $sql = "delete from UNMANAGEDNODES where ";
                if ( substr( $ldms_version, 0, 2 ) == 88 ) {
                    $sql .= " wapdiscovered = '0' and ";
                }
                $sql .= " lastscantime < ";
                if ( $db_type eq "SQL" ) {
                    $sql .= "getdate()-";
                }
                elsif ( $db_type eq "ORA" ) {
                    $sql .= "current_date-";
                }
                $sql .= $deletiondays;
                &DoDBAction($sql);
                &Log( "Deleted " . $logmsg );
            }
        }
    }
    else {
        &Log("skipping UDD culling because deletion days is not set.");
    }
    return 0;
}

### Scanfile cleanup subroutine ##############################################
sub CullScanFiles {

    my $SCANDIR = $ldmain . "ldscan\\errorscan";
    if ( !-e $SCANDIR ) {
        &LogWarn("Directory $SCANDIR doesn't seem to exist?");
        return 1;
    }

    my $netdrive = $trashcount = 0;

    if ( $SCANDIR =~ m/^\\\\/x ) {
        $netdrive = 1;
    }
    opendir( $DIR, "$SCANDIR" )
      or &LogDie("Can't open directory $SCANDIR: $!\n");
    while ( $file = readdir($DIR) ) {

        # Next file if we're at the top or the file was already done
        next if $file =~ /^       # from the beginning of the line
                            \.\.?   # two dots then anything
                            $       # to the end of the line
                            /x;

        # Delete it if it's older than X days
        if ($deletiondays) {
            if ( $netdrive == 1 ) {
                $trashcount++;

                # Stat won't work on network drives
                &DeleteFile( $file, localtime );
            }
            my $cutofftime = time() - ( $deletiondays * 86400 );

            # stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
            my $mtime = ( stat( $SCANDIR . "\\" . $file ) )[8]
              or &LogWarn("Can't access file $file : $!\n");
            if ( $mtime < $cutofftime ) {
                $trashcount++;
                &DeleteFile( $SCANDIR . "\\" . $file, $mtime );
            }
        }

    }

    closedir($DIR);
    if ( $trashcount > 0 ) {
        my $logmsg = $comma{$trashcount} . " scan " . PL( "file", $trashcount );
        if ($DEBUG) {
            &Log( "CullScanFiles: Would have deleted " . $logmsg );
        }
        else {
            &Log( "Deleted " . $logmsg );
        }
    }
    return 0;
}

### Scanfile rename subroutine ###############################################
sub RenameScanFiles {

    my $SCANDIR = $ldmain . "ldscan\\errorscan";
    if ( !-e $SCANDIR ) {
        &LogWarn("Directory $SCANDIR doesn't seem to exist?");
        return 1;
    }

    my $netdrive = $renamecount = 0;

    if ( $SCANDIR =~ m/^\\\\/x ) {
        $netdrive = 1;
    }
    opendir( $DIR, "$SCANDIR" )
      or &LogDie("Can't open directory $SCANDIR: $!\n");
    while ( $file = readdir($DIR) ) {

        # Next file if we're at the top or the file was already done
        next if $file =~ /^       # from the beginning of the line
                            \.\.?   # two dots then anything
                            $       # to the end of the line
                            /x;

        # Ignore scan files that were already renamed
        next if $file =~ /^_/x;

        # Look for a good name
        if ( -e "$SCANDIR\\$file" ) {
            open( $FILE, '<', "$SCANDIR\\$file" )
              or &LogWarn("Can't open file $SCANDIR\\$file : $!\n");
            while (<$FILE>) {
                my @parts = split( /=/x, $_ );
                $newname = &GetNewName(@parts);
                if ($newname) {
                    last;
                }
            }
            close($FILE);
        }

        # if we weren't able to get something, we don't move the file.
        if ($newname) {
            &RenameFile( $SCANDIR, $file, $newname );
        }
        else {
            if ($DEBUG) {
                &LogDebug("RenameScanFiles: couldn't get anything from $file");
            }
        }
    }
    closedir($DIR);

    if ( $renamecount > 0 ) {
        &Log(   "Renamed "
              . $comma{$renamecount}
              . " scan "
              . PL( "file", $renamecount ) );
    }

    return 0;
}

### Does this line contain a new name subroutine ############################
sub GetNewName {
    my @parts = @_;

    my $marker;

    # Try each of these. The first one to match wins.
    ## no critic (RequireExtendedFormatting)
    # All three regexes break with the /x flag added
    if ( $parts[0] =~ m/^Device Name/ ) {
        $marker = &Trim( $parts[1] );
        if ($DEBUG) { &LogDebug("GetNewName: $file is from $marker"); }
        return $marker;
    }
    if ( $parts[0] =~ m/^Network - TCPIP - Host Name/ ) {
        $marker = &Trim( $parts[1] );
        if ($DEBUG) { &LogDebug("GetNewName: $file is from $marker"); }
        return $marker;
    }
    if ( $parts[0] =~ m/^Network - TCPIP - Address/ ) {
        $marker = &Trim( $parts[1] );
        if ($DEBUG) { &LogDebug("GetNewName: $file is from $marker"); }
        return $marker;
    }
    ## use critic
    # If all else fails, return 0
    return 0;
}

### Stored scanfile cleanup subroutine ####################################
sub CompressStorageFiles {

    my $STORAGEDIR = $ldmain . "ldscan\\storage";
    if ( !-e $STORAGEDIR ) {
        if ($DEBUG) {
            &LogDebug(
                "CompressStorageFileS: $STORAGEDIR doesn't seem to exist?");
        }
        return 1;
    }

    $compresscount = 0;
    my @filestokill;
    opendir( $DIR, "$STORAGEDIR" )
      or &LogDie("Can't open directory $STORAGEDIR : $!\n");
    my $zip = Archive::Zip->new();
    while ( $file = readdir($DIR) ) {

        # Next file if we're at the top or the file was already done
        next if $file =~ /^
                            \.\.?  # begins with two dots
                            $/x;
        next if $file =~ /\.zip$ # ends with .ZIP
                            /xi;

        # Compress it if it's older than X days
        if ($deletiondays) {
            my $time = time() - ( $deletiondays * 86400 );

            # stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
            my $ctime = ( stat( $STORAGEDIR . "\\" . $file ) )[10]
              or &LogWarn("Can't access file $file : $!\n");
            if ( $ctime < $time ) {

                #delete this file
                if ($DEBUG) {
                    my $days = floor( ( time() - $ctime ) / 86400 );
                    &LogDebug(
"CompressStorageFileS: $file is $days days old, should be compressed"
                    );
                }
                else {
                    my $file_member =
                      $zip->addFile( $STORAGEDIR . "\\" . $file, $file );
                    $filestokill[$compresscount] = $STORAGEDIR . "\\" . $file;
                    $compresscount++;
                    next;
                }
            }
        }
    }

    # prepare the new zip path
    #
    if ( $compresscount > 0 ) {
        my $newzipfile = &GenFileName() . ".zip";
        my $newzippath = $STORAGEDIR . "\\" . $newzipfile;

        # write the new zip file
        #
        my $status = $zip->writeToFileNamed($newzippath);
        if ( $status == AZ_OK ) {
            &Log("Created file $newzippath");
        }
        else {
            &Log("Failed to create file $newzippath");
        }
    }
    closedir($DIR);

    # Delete Storage Files
    foreach my $filetokill (@filestokill) {
        trash($filetokill);
    }

    if ( $compresscount > 0 ) {
        &Log(   "Compressed and deleted "
              . $comma{$compresscount}
              . " stored scan "
              . PL( "file", $compresscount ) );
    }
    return 0;
}
###############################################################################

### TopologyMap subroutine ####################################################
sub TopologyMap {

    # Get the gateways and node counts
    $sql =
        "select defgtwyaddr,count(address) from tcp where "
      . "nullif(address,'') is not null and "
      . "nullif(address,'0.0.0.0') is not null and "
      . "nullif(address,'255.255.255.255') is not null "
      . "and address is not null "
      . "and defgtwyaddr is not null "
      . "group by defgtwyaddr";
    my @Networks = &GetTwoColumnList($sql);

    if (@Networks) {
        my $graph = Graph::Easy->new();
        $graph->set_attribute( 'flow', 'south' );
        my $node = $graph->add_node(hostname);
        $node->set_attribute( 'fill',      'white' );
        $node->set_attribute( 'border',    'solid 2px black' );
        $node->set_attribute( 'text-wrap', 'auto' );
        $node->set_attribute( 'align',     'center' );
        foreach my $net (@Networks) {

            my $hops;

            # traceroute them
            my ( $gateway, $size ) = split( '[ ]-[ ]', $net );

            # Don't scan brazillions of tiny networks.
            if ( $size <= $mapfloor ) { next; }
            if ( &IsIPAddress($gateway) ) {
                $gateway = &ZeroUnPad($gateway);

                # If the gateway isn't pingable, it should still be drawn on
                # the map; but we'll draw it as "One hop past the maximum
                # possible"
                $hops = 31;
                my $t = new Net::Traceroute::PurePerl(
                    host            => $gateway,
                    protocol        => 'icmp',
                    concurrent_hops => 30,
                    query_timeout   => 5,
                );
                &ChangeBalloon( "tip", "Tracerouting $gateway" );
                if ($DEBUG) {
                    &LogDebug("TopologyMap: Tracerouting $gateway");
                }
                eval {
                    local $SIG{ALRM} = sub { die(alarm) };
                    alarm(10)
                      ;  # Tells the OS to issue an ALRM signal after 10 seconds
                    $t->traceroute();
                    alarm(0);    # cancel the alarm if traceroute succeeded
                };
                if ( $@ and $@ eq "alarm" ) {
                    &LogWarn("Traceroute of $gateway timed out");
                }
                if ( $t->found ) {
                    $hops = $t->hops;
                }
            }
            else {
                &LogWarn("TopologyMap: $gateway doesn't look like an IP");
            }
            my $label;
            if ($netmap_url) {
                my $url = $netmap_url;
                $url =~ s/IPADDRESS      # substitute IPADDR with gateway
                        /$gateway/x;
                $label = "<A HREF=$url>$gateway</A>";
            }
            else {
                $label = "$gateway";
            }
            $label .=
                " is $hops "
              . PL( "hop", $hops )
              . " away and has $size managed "
              . PL( "node", $size )
              . " behind it.";
            if ($DEBUG) { &LogDebug("TopologyMap: $label"); }
            my $router      = $graph->add_node($gateway);
            my $sizepercent = int( ( $size / $allmachines ) * 100 );
            my $color       = '#dbdbdb';

            # Under 10% of your nodes, the router is colored grey
            # Between 10 and 25%, it's colored pink
            # Between 25 and 50%, it's colored yellow
            # Between 50 and 75%, it's colored blue
            # Over 75%, it's colored green
            if ( $sizepercent > 10 ) { $color = '#ffaeb9'; }
            if ( $sizepercent > 25 ) { $color = '#fff68f'; }
            if ( $sizepercent > 50 ) { $color = '#aeeeee'; }
            if ( $sizepercent > 75 ) { $color = '#c1ffc1'; }
            $router->set_attribute( 'fill',      $color );
            $router->set_attribute( 'border',    'solid 2px black' );
            $router->set_attribute( 'text-wrap', 'auto' );
            $router->set_attribute( 'align',     'center' );
            $router->set_attribute( 'label',     $label );
            my $edge = $graph->add_edge( hostname, $gateway, $hops );
            $edge->undirected(1);
            $edge->set_attribute( 'minlen', $hops );
            $edge->set_attribute( 'color',  'yellow' );

            if ( $hops < 15 ) {
                $edge->set_attribute( 'color', 'white' );
            }
            if ( $hops > 30 ) {
                $edge->set_attribute( 'color', 'red' );
            }
        }

        # output the results
        &WriteGraph( $graph->as_html() );
    }
    return 0;
}
###############################################################################

### Email subroutine ##########################################################
#
# If crypto is required, I should use a different module; I need to detect
# existence of authorization and create a different object, which means
# pulling the object creation down into the subroutine. I also need to detect
# the type of crypto used in my setup routine and provide a drop-down in the
# GUI.
#
# Send email if there was an email address to send it to
sub SendEmail {
    if ( $mailto && $mailfrom && $mailserver ) {

        my $mailhostname = hostname;

        # create an object handle
        my $smtp;

        # Do I need crypto?
        if ($mail_auth_user) {

            # Use crypto to create the object
            $smtp = Net::SMTP_auth->new(
                $mailserver,
                Hello   => $mailhostname,
                Timeout => 30,
                Debug   => $DEBUG,
            ) or &LogWarn("ERROR creating SMTP object: $!");
            $smtp->auth( $mail_auth_type, $mail_auth_user, $mail_auth_pass )
              or &LogWarn("ERROR authenticating to SMTP server: $!");
        }
        else {

            # Don't use crypto to create the object
            $smtp = Net::SMTP->new(
                $mailserver,
                Hello   => $mailhostname,
                Timeout => 30,
                Debug   => $DEBUG,
            ) or &LogWarn("ERROR creating SMTP object: $!");
        }

        if ($DEBUG) {
            $mailmessage .= "Full debug log written to $logfile\n";
        }

        # We should have an email object now, so send the message
        if ($smtp) {
            $smtp->datasend("MIME-Version: 1.0\n");
            $smtp->mail("$mailfrom");
            $smtp->to("$mailto");
            $smtp->data;

    # The envelope
    #            $smtp->datasend("Content-Type: text/html; charset=us-ascii\n");
            $smtp->datasend("From: $mailfrom\n");
            $smtp->datasend("To: $mailto\n");
            $smtp->datasend("Subject: $emailsubject\n");
            $smtp->datasend("\n\n");

            # The message
            #            $smtp->datasend("<html><body>");
            $smtp->datasend($mailmessage);

            #            $smtp->datasend("</body></html>");

            # Clean up
            $smtp->dataend;
            $smtp->quit;
        }
        else {

            # Can't send email, so I need to write the output to a file.
            my $outputfile =
              $prog . "-" . $VERSION . "-" . &GenFileName . ".log";
            &Log( "Something is wrong with email -- writing output report file "
                  . "to $dir\\$outputfile" );
            open( $FILE, '>', "$outputfile" )
              or &LogDie("Can't open file $outputfile - $!");
            print $FILE $mailmessage;
            close $FILE;
            return 1;
        }
    }
    else {
        &Log(   "Can't send email from $mailfrom to $mailto via $mailserver. "
              . "Please check configuration." );
        return 1;
    }
    return 0;
}

### Open the database subroutine ##############################################
sub OpenDB {

    # if it's already open,  let's not do it again...
    if ($db_is_open) {
        if ($DEBUG) {
            &LogDebug("OpenDB: Database is already open!");
        }
        return 1;
    }

    my $dsn;

    # Open the database
    if ( $db_type eq "SQL" ) {
        $dsn =
            "dbi:ODBC:driver={SQL Server};"
          . "Server=$db_instance;"
          . "Database=$db_name;";
    }
    elsif ( $db_type eq "ORA" ) {
        $dsn = "DBI:Oracle:$db_name";
    }
    else {
        &LogDie("Cannot connect, Database type is not specified!\n");
    }
    $dbh = DBI->connect( $dsn, $db_user, $db_pass )
      or &LogDie( "Database connection failed: " . DBI->errstr );
    $dbh->{'LongReadLen'} = 1024;
    $dbh->{'LongTruncOk'} = 1;
    if ($DEBUG) {
        ### Set the trace output
        # DBI->trace( 2, undef );
        &LogDebug(
"OpenDB: Opened database with: $db_type, $db_name, $db_instance, $db_user, db_pass"
        );
    }

    # Set the semaphore
    $db_is_open = 1;
    return 0;
}

### Close the database subroutine ###########################################
sub CloseDB {

    if ($DEBUG) { &LogDebug("CloseDB: Closing database."); }
    $sth->finish();
    $dbh->disconnect;

    # Set the semaphore
    $db_is_open = 0;
    return 0;

}
#############################################################################

### Database Reindex subroutine ###############################################
# if you want to surgically do specific tables you can just run the command:
# dbcc dbreindex(tablename) -- Rob N.
sub DBReindex {

    if ($DEBUG) { &LogDebug("DBReindex: Database Reindexing started."); }

    my $indexsql;
    if ( $db_type eq "SQL" ) {

        # MS SQL Reindexing Incantation
        $indexsql = <<"EOD";
USE [$db_name]

DECLARE \@TableName varchar(255)

DECLARE TableCursor CURSOR FOR
SELECT table_name FROM information_schema.tables
WHERE table_type = 'base table'

OPEN TableCursor

FETCH NEXT FROM TableCursor INTO \@TableName
WHILE \@\@FETCH_STATUS = 0
BEGIN
DBCC DBREINDEX(\@TableName,' ',90)
FETCH NEXT FROM TableCursor INTO \@TableName
END

CLOSE TableCursor

DEALLOCATE TableCursor
EOD

    }
    elsif ( $db_type eq "ORA" ) {

        # ORACLE Reindexing Incantation
        $indexsql = <<"EOD";
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
        &LogWarn(
"Database Reindexing cannot continue, Database type is not specified!"
        );
        return 1;
    }

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ($DEBUG) {
        &LogDebug("DBReindex: Running the $db_type reindexing routine");
    }
    $sth = $dbh->prepare($indexsql)
      or &LogDie( "Database reindexing caused " . DBI::errstr );
    $sth->execute or &LogDie( "Database reindexing caused " . DBI::errstr );
    &Log("Database reindexed.");

    return 0;
}
#############################################################################

### Detect stuck LPM Listener subroutine ####################################
sub StuckLPM {

    # No need to check LPM Event Listener if they're not using it
    $sql = "select value from patchsettings where name='UseProcessManager'";
    my $UsingPatchProcess = &GetSingleString($sql);
    if ( !$UsingPatchProcess ) {
        &Log("Automatic Patch Process is not in use");
        return 0;
    }

    my $lpmlog = $lpmdir . "TaskEngine\\LANDesk.Workflow.TaskEngine.log";
    if ( !-e $lpmlog ) {
        &LogWarn("$lpmlog doesn't seem to exist?");
        return 1;
    }

    my $listenerlog = File::ReadBackwards->new("$lpmlog")
      or &LogWarn("StuckLPM: can't read $lpmlog - $!");

    # Get the most recent log entry
    my $logline;
    while ( defined( $logline = $listenerlog->readline ) ) {

        # keep looking if the line is blank
        next if $logline =~ /^$/x;

        # or begins with a non-numeric character
        next if $logline =~ /^\D/x;

        if ($DEBUG) { &LogDebug("StuckLPM: Last line in $lpmlog is $logline"); }
        my @logline = split( ' ', $logline );
        if ( !defined( $logline[0] ) ) {
            &LogWarn("Process Manager problem detected; see $lpmlog");
            return 1;
        }

        # A day ago is...
        my $dayago = eval { time() - 86400 };
        my $lastlpmtime = str2time( $logline[0] );
        if ( $lastlpmtime < $dayago ) {
            &LogWarn( "Stuck LPM Event Listener detected, "
                  . "the last log entry was at "
                  . localtime($lastlpmtime) );
            $listenerlog->close;
            &SetSeverity( 3, "LPM Event Listener is stuck" );
            return 1;
        }
        else {

            # today's date and LPM agree, quit reading the log and move on.
            return 0;
        }
    }
    return 0;

}
#############################################################################

### Configure service checking subroutine ###################################
### Also runs the individual service checks #################################
sub ServiceCheckLoop {
    if ($DEBUG) { &LogDebug("ServiceCheckLoop: Starting"); }
    my ( @ld_services, $serviceloglist, %status );

    @ld_services = (
        "LANDesk Device Monitor",
        "ALRT_SRV",
        "ALRT_PRV",
        "LANDesk(r) Activation Service",
        "LANDesk DHCP Service",
        "LANDesk DHCP Watcher Service",
        "LANDesk Handheld Manager Alarm System",
        "LANDesk Handheld Manager Control System",
        "LANDesk Handheld Manager Heartbeat System",
        "LANDesk Handheld Manager Registration System",
        "LANDesk Handheld Manager Notification System",
        "ApmTcs",
        "WorkflowScheduler",
        "Intel Scheduler",
        "Intel Local Scheduler Service",
        "LANDeskTIM",
        "LANDesk(r) Usage Service",
        "Agent_Portal",
        "LANDesk(R) Agentless Discovery Service",
        "CBA8Alert",
        "ASFProxyService",
        "IPMI_Redirection",
        "LDDashboardReportService",
        "LDGSB",
        "Softmon",
        "LSM_SNMP",
        "PSI",
        "Intel Alert Handler",
        "Intel Alert Originator",
        "Intel QIP Server Service",
        "Intel PDS",
        "LANDesk Inventory Server",
        "Avocent Management Platform ESB",
        "Avocent Management Platform Web Server"
    );

    # What LANDesk services are on this system?
    my $servicecount;
    foreach my $key (@ld_services) {
        if ( Win32::Service::GetStatus( '', $key, \%status ) ) {
            if ( &IsAutomatic($key) ) {
                &ServiceCheck($key);
                $serviceloglist .= "$key, ";
                $servicecount++;
            }
        }
    }

    if ($DEBUG) {
        $serviceloglist = substr( $serviceloglist, 0, -2 );
        &LogDebug( "ServiceCheckLoop: Checked $servicecount "
              . PL( "service", $servicecount )
              . ": $serviceloglist." );
    }

    return 0;
}
#############################################################################

### IsAutomatic subroutine ##################################################
sub IsAutomatic {

    my $servicekey = shift;
    if ( !defined($servicekey) ) {
        &LogWarn(
            "IsAutomatic called without a service to check. " . "$servicekey" );
        return 1;
    }

    # LDGSB is a special case
    if ( $servicekey eq "LDGSB" ) {
        $sql = "select count(*) from brokerconfig";
        my $ldgsb_on = &GetSingleString($sql);
        if ($ldgsb_on) {
            return 1;
        }
        else {
            return 0;
        }
    }

    # Returns 1 if the service is Automatic, 0 if it is not
    my $SvcRoot =
      $Registry->{"HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services"};
    my $SvcKey = $Registry->{
        "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/$servicekey"};
    if ( defined($SvcKey) ) {
        my $servstart = hex( $SvcKey->GetValue('Start') );
        if ($DEBUG) {
            &LogDebug("IsAutomatic: $servicekey Start mode is $servstart");
        }
        if ( $servstart == 0 ) {
            return 0;
        }
        if ( $servstart == 2 ) {
            return 1;
        }
        else {
            &Log("$servicekey not set to Automatic: $servstart");
            return 0;
        }
    }
    &LogWarn("IsAutomatic check failed to find $servicekey in the registry");
    return 0;
}

### ServiceCheck subroutine #################################################
sub ServiceCheck {

    my $servicetarget = shift;
    if ( !defined($servicetarget) ) {
        &LogWarn( "ServiceCheck called without a service to check. "
              . "$servicetarget" );
        return 1;
    }

    my %status;
    Win32::Service::GetStatus( '', $servicetarget, \%status );
    if ($DEBUG) {
        &LogDebug(
"ServiceCheck: Checked $servicetarget, current state = $status{CurrentState}."
        );
    }
    if ( $status{CurrentState} == 1 ) {
        &ChangeBalloon( "tip", "$servicetarget service down!" );
        &LogWarn( "$servicetarget service down at " . localtime() . "!" );
        &SetSeverity( 1, "A LANDesk Service is down" );
        sleep 3;
        &LogWarn("Trying to restart $servicetarget service");
        &ChangeBalloon( "tip", "Trying to restart $servicetarget service" );
        my $retval = Win32::Service::StartService( '', $servicetarget );
        sleep 8;

        if ($retval) {
            &Log("$servicetarget service restarted successfully.");
            &ChangeBalloon( "tip", "$servicetarget service restarted." );
            sleep 1;
        }
        else {

# Sometimes StartService doesn't respond truthfully; if it says there was a problem,
# we should check the status again before getting excited.
            Win32::Service::GetStatus( '', $servicetarget, \%status );
            if ($DEBUG) {
                &LogDebug(
"ServiceCheck: Startservice got $retval, rechecked $servicetarget, "
                      . "current state = $status{CurrentState}." );
            }
            if ( $status{CurrentState} == 1 ) {
                Log "Cannot restart $servicetarget at " . localtime() . "!";
            }
            else {
                if ($DEBUG) {
                    &LogDebug(
"ServiceCheck: Leaving after restart was successful, but "
                          . "retval was $retval ($servicetarget)." );
                }
                return 0;
            }
        }
        if ($DEBUG) {
            &LogDebug( "ServiceCheck: Leaving after first restart try was "
                  . "successful ($servicetarget)." );
        }
        return 0;
    }
}
#############################################################################

### NMAP Related Subroutines ################################################
#
### GetNMAP subroutine ######################################################
sub GetNMAP {

    # Check to see if NMAP is available; otherwise, we can skip its needs
    if ( !-e $nmap ) {

       # If there's no NMAP at all, do not warn, as they may not have wanted it.
        if ($DEBUG) {
            &LogDebug("GetNMAP: Cannot find NMAP at $nmap");
        }
        return 1;
    }

    # If NMAP is around, let's go ahead and use it.
    &ChangeBalloon( "tip", "Network scanning to update Unmanaged Devices" );
    my ( $nmapcount, $maxnmapcount );

    # If NMAP is around, we'll need some database information for it.
    if (
        $nmap_options =~ m/-oX     # any of these options
                                |-oN    # will cause NMAP to
                                |-oG    $ fail on fingerprinting
                                /x
      )
    {
        &LogWarn( "NMAP Options $nmap_options includes output specification "
              . "('-oX', '-oN' or '-oG'). Please remove that option in "
              . "order to use OS fingerprinting." );
    }
    else {

        # Throttle the number of nmap-able nodes in order to keep
        # execution time reasonable. If debug is on, throttle even
        # further.
        if ($DEBUG) {
            if ( $nmap_max > 10 ) {
                if ($DEBUG) {
                    &LogDebug(
                        "GetNMAP: constraining maximum nmap target count to 10 "
                          . "because debug mode is on." );
                }
                $maxnmapcount = 10;
            }
        }
        else {
            $maxnmapcount = $nmap_max;
        }

# Get all nodes with no osname or meaningless osname, unless xddexception is set
# Note that rows with no IP address are useless.
        $sql = "select DISTINCT ";
        if ($maxnmapcount) {
            if ( $db_type eq "SQL" ) {
                $sql .= "top $maxnmapcount ";
            }
        }
        $sql .= "IPADDRESS, LASTSCANTIME from "
          . "UNMANAGEDNODES where XDDEXCEPTION='0' and IPADDRESS is not NULL ";

# If it's 8.8, WAPDISCOVERED should = 0, but if it's earlier, there is no such field
        if ( substr( $ldms_version, 0, 2 ) >= 88 ) {
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
        if ( $db_type eq "ORA" ) {
            if ($maxnmapcount) {
                $sql = "SELECT IPADDRESS, LASTSCANTIME FROM (" . $sql;
                $sql .= ") where rownum <= $maxnmapcount";
            }
        }
        $nmapcount = 0;
        my @targets = &GetSingleArray($sql);
        foreach my $address (@targets) {
            if ( &IsIPAddress( &ZeroPad($address) ) ) {
                $Address[$nmapcount] = $address;
                $nmapcount++;
            }
        }

        if ($DEBUG) {
            &LogDebug( "GetNMAP: found " . $nmapcount . " NMAP targets." );
        }
    }

    # If we've got target nodes, we've got work to do.
    if ($nmapcount) {
        &DoNMAP;
    }
    else {
        if ($DEBUG) {
            &LogDebug(
"GetNMAP: NMAP binary exists, but we don't seem to have any nodes to "
                  . "scan. nmapcount is $nmapcount." );
        }
    }
    return 0;
}

### DoNMAP subroutine ########################################################
sub DoNMAP {
    $np = new Nmap::Parser;
    $np->callback( \&nmap_read_results );

    # Ping systems to see which ones are easier to get, and do them first
    # Timeout is set to 1 second
    if ($DEBUG) { &LogDebug("DoNMAP: Pinging Unmanaged devices..."); }
    &ChangeBalloon( "tip", "Pinging Unmanaged Devices" );
    my $p           = Net::Ping->new( "icmp", 1 );
    my $pingcount   = 0;
    my $nopingcount = 0;
    my @Address_np;
    foreach my $test (@Address) {

        my $pingtarget = &ZeroUnPad($test);
        my $ping = $p->ping($pingtarget);
        if ($ping) {

            # NMAP a device which responds to ping immediately
            if ($DEBUG) { &LogDebug("DoNMAP: $pingtarget responded to ping: $ping"); }
            &ChangeBalloon( "tip", "Fingerprinting " . $pingtarget );
            $np->parsescan( $nmap, $nmap_options, $test );
            $pingcount++;
        }
        else {
            if ($DEBUG) { &LogDebug("DoNMAP: $pingtarget did not respond to ping."); }
            push( @Address_np, $test );
            $nopingcount++;
        }
    }
    $p->close();
    if ( $pingcount > 0 ) {

        # report easy ones to the admin
        &Log(   "Scanned "
              . $comma{$pingcount}
              . " unmanaged "
              . PL( "node", $pingcount )
              . " without OS Names which responded to ping."
              . " There "
              . PL_V( "was", $goodcount ) . " "
              . $comma{$goodcount}
              . " successful "
              . PL( "scan", $goodcount )
              . "." );
    }

    # Then do the ones that didn't respond to ping
    if (@Address_np) {
        $goodcount = 0;
        if ($DEBUG) {
            &LogDebug( "DoNMAP: Scanning "
                  . $comma{$nopingcount}
                  . " unmanaged "
                  . PL( "node", $nopingcount )
                  . " without OS Names which don't respond to ping. This may "
                  . "take a significant amount of time to complete." );
        }
        &ChangeBalloon( "tip",
            "Scanning Unmanaged Devices which don't answer to ping" );
        foreach my $test_np (@Address_np) {

            &ChangeBalloon( "tip", "Fingerprinting " . &ZeroUnPad($test_np) );
            $np->parsescan( $nmap, $nmap_options, $test_np );
        }

        # and report to the admin
        &Log(   "Finished NMAP scanning ping-unfriendly unmanaged nodes in "
              . "the database. There "
              . PL_V( "was", $goodcount ) . " "
              . $comma{$goodcount}
              . " successful "
              . PL( "scan", $goodcount )
              . "." );
    }

    # Report on any updates I made
    if ( $osupdates || $macupdates || $vendorupdates ) {
        if ($osupdates) {
            &Log(   "Updated "
                  . $comma{$osupdates} . " OS "
                  . PL( "Name", $osupdates )
                  . " in Unmanaged Devices." );
        }
        if ($macupdates) {
            &Log(   "Updated "
                  . $comma{$macupdates} . " MAC "
                  . PL( "Address", $macupdates )
                  . " in Unmanaged Devices." );
        }
        if ($vendorupdates) {
            &Log(   "Updated "
                  . $comma{$vendorupdates} . " NIC "
                  . PL( "Manufacturer", $vendorupdates )
                  . " in Unmanaged Devices." );
        }
    }
    return 0;
}

### nmap_read_results subroutine ###########################################
# What did I get and what do I do with it?
sub nmap_read_results {

    my $host     = shift;         #Nmap::Parser::Host object, just parsed
    my $hostaddr = $host->addr;
    my ( $status, $OS );
    if ($DEBUG) {
        &LogDebug(
            "nmap_read_results: NMAP callback received for " . $hostaddr );
    }

    # Is this thing on?
    $status = $host->status;

    &ChangeBalloon( "tip", "Scanning $hostaddr" );

    if ( $status eq 'up' ) {

        # Zero-pad the IP Address so that the database can make sense of it
        $hostaddr = &ZeroPad($hostaddr);

        if ( $host->mac_addr || $host->mac_vendor || $host->os_sig ) {

            # Sometimes UNMANAGEDNODES doesn't have the MAC address,
            # so let's update that now
            if ( $host->mac_addr ) {

                &UpdateMAC( $host->mac_addr, $hostaddr );
            }

            # Get the MAC address manufacturer if available,
            # might as well update it too
            if ( $host->mac_vendor ) {

                &UpdateVendor( $host->mac_vendor, $hostaddr );
            }

            # And now let's look at the OS Name
            my $os = $host->os_sig;
            $os->name;
            $os->osfamily;

            if ( $os->name ) {

                &UpdateOS( $os->name, $os->name_accuracy, $hostaddr );
            }
            $goodcount++;

        }
        else {

            # scan didn't have anything we can use in it
            if ($DEBUG) {
                &LogDebug( "nmap_read_results: "
                      . $hostaddr
                      . " scan gave nothing useful." );
            }
            return 1;
        }
    }
    else {

        # target was down
        if ($DEBUG) {
            &LogDebug( $hostaddr . " was down." );
        }
        return 1;
    }

    # what if I got no status at all?
    if ( !$host->status ) {
        if ($DEBUG) {
            &LogDebug(
                "nmap_read_results: " . $hostaddr . " did not return status." );
        }
        return 1;
    }
    return 0;
}
###############################################################################

### Update the OS Name subroutine ###########################################
sub UpdateOS {

    my ( $OS, $accuracy, $hostaddr ) = @_;
    if ($DEBUG) {
        &LogDebug("Updating $hostaddr OS Name to $OS, $accuracy% accurate");
    }

    if ($OS) {
        if ($accuracy) {
            $OS .= " \(" . $accuracy . " percent\)";
        }
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
          or &LogWarn( "$sql caused " . $dbh->errstr );
        $sth->execute( $OS, $hostaddr )
          or &LogWarn( $dbh->errstr );
        $sth->finish();
        if ($DEBUG) {
            &LogDebug( "UpdateOS: Set OS Name of " . $hostaddr . " to " . $OS );
        }
        $osupdates++;

    }
    return 0;
}

### Update the MAC Address subroutine #######################################
sub UpdateMAC {

    my ( $newmac, $hostaddr ) = @_;

    if ($DEBUG) { &LogDebug("Updating $hostaddr MAC Address to $newmac"); }
    if ( !defined($newmac) || !defined($hostaddr) ) {
        &LogWarn( "UpdateMAC: called without sufficient information. "
              . "$newmac, $hostaddr" );
        return 1;
    }

    # Sanitize the new MAC Address
    $newmac =~ s/://gx;
    $newmac =~ s/-//gx;
    chomp($newmac);

    # Update the MAC Address if it didn't exist before
    if ( $db_type eq "SQL" ) {
        $sql = "select top 1 PHYSADDRESS from UNMANAGEDNODES WHERE IPADDRESS=?";
    }
    elsif ( $db_type eq "ORA" ) {
        $sql =
            "select PHYSADDRESS from "
          . "(select PHYSADDRESS from UNMANAGEDNODES WHERE IPADDRESS=?) "
          . "where rownum = 1";
    }
    my $oldmac = &GetSingleString($sql);

    if ( !$oldmac ) {
        $sql = "update UNMANAGEDNODES set PHYSADDRESS=? where IPADDRESS=?";
        $sth = $dbh->prepare($sql)
          or &LogWarn( "$sql caused " . $dbh->errstr );
        $sth->execute( $newmac, $hostaddr )
          or &LogWarn( $dbh->errstr );
        $sth->finish();
        if ($DEBUG) {
            &LogDebug( "UpdateMAC: Set MAC Address of "
                  . $hostaddr . " to "
                  . $newmac );
        }
        $macupdates++;
    }
    return 0;
}

### Update the Manufacturer subroutine #######################################
sub UpdateVendor {

    my ( $vendor_id, $hostaddr ) = @_;

    if ($DEBUG) { &LogDebug("Updating $hostaddr Vendor ID to $vendor_id"); }
    if ( !defined($vendor_id) || !defined($hostaddr) ) {
        &LogWarn( "UpdateVendor called without sufficient information."
              . "$vendor_id, $hostaddr" );
        return 1;
    }

    # Update the Manufacturer if it didn't exist before
    # The field only exists in 8.8 and newer
    if ( substr( $ldms_version, 0, 2 ) >= 88 ) {

        if ( $db_type eq "SQL" ) {
            $sql =
              "select top 1 MANUFACTURER from UNMANAGEDNODES WHERE IPADDRESS=?";
        }
        elsif ( $db_type eq "ORA" ) {
            $sql =
                "select manufacturer from "
              . "(select MANUFACTURER from UNMANAGEDNODES WHERE IPADDRESS=?) "
              . "where rownum = 1";

        }
        my $oldman = &GetSingleString($sql);

        if ( !$oldman ) {
            if ( length($oldman) < 2 or $oldman eq "UNKNOWN" ) {
                $sql =
                  "update UNMANAGEDNODES set MANUFACTURER=? where IPADDRESS=?";
                $sth = $dbh->prepare($sql)
                  or &LogWarn( "$sql caused " . $dbh->errstr );
                $sth->execute( $vendor_id, $hostaddr )
                  or &LogWarn( $dbh->errstr );
                $sth->finish();
                if ($DEBUG) {
                    &LogDebug( "UpdateVendor: Set Manufacturer of "
                          . $hostaddr . " to "
                          . $vendor_id );
                }
                $vendorupdates++;
            }
        }
    }
    return 0;
}

###############################################################################

### StartLogging subroutine #################################################
sub StartLogging {

    # Prepare logging system
    Win32::EventLog::Message::RegisterSource( 'Application', $prog );
    $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";

    # Get the window handle so we can hide it
    $DOS = Win32::GUI::GetPerlWindow();

    if ( !$DEBUG ) {

        # Hide console window
        Win32::GUI::Hide($DOS);
    }

    if ($DEBUG) {

        $logfile = $prog . "-" . $VERSION . "-" . &GenFileName . ".log";
        open( $DEBUGFILE, '>', "$logfile" )
          or &LogDie("Can't open file $logfile : $!\n");
        $DEBUGFILE->autoflush();
        &LogDebug(
"StartLogging: $prog $VERSION starting in debug mode. $0 $commandline"
        );

        close($DEBUGFILE);
    }

    return 0;
}
### End of StartLogging subroutine ##########################################

### SetValueFromReg subroutine ##############################################
sub SetValueFromReg {

    # Assuming RegKey handle exists, return with its contents
    if ($RegKey) {
        my $keyname = shift;
        if ( $RegKey->GetValue("$keyname") ) {
            my $output = $RegKey->GetValue("$keyname");
            return $output;
        }
        else {
            if ($DEBUG) {
                &LogDebug("SetValueFromReg: key $keyname was empty.");
            }
            return 0;
        }
    }
    else {
        if ($DEBUG) {
            &LogDebug("SetValueFromReg: called without RegKey handle");
        }
        return -1;
    }
}

### ReadRegisty subroutine #################################################
sub ReadRegistry {

    # Check the registry for ErrorDir
    $RegKey =
      $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
    if ($RegKey) {
        $ldmain = &SetValueFromReg("LDMainPath");
        $ldmain = Win32::GetShortPathName($ldmain);
        if ($DEBUG) { &LogDebug("ReadRegistry: LDMAIN is $ldmain"); }
        $reportdir = $ldmain . "reports\\ldms_core";

    }

    # Setup my homedir
    $dir =
      Win32::GetShortPathName( $PROGRAMFILES . "\\Monkeynoodle\\ldms_core" );

    # Check the registry for Database information
    $RegKey =
      $Registry->{
"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Core/Connections/Local"
      };
    if ($RegKey) {
        my $oracle = $RegKey->GetValue("IsOracle");
        if (
            $oracle =~ m/true    # case-insensitive 'true'
                          /ix
          )
        {
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
    # Allow ldms_core specific configuration to override
    # LANDesk specific configuration if present
    $RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/Monkeynoodle/ldms_core"};
    if ($RegKey) {
        $db_type     = &SetValueFromReg("db_type");
        $db_instance = &SetValueFromReg("db_instance");
        $db_name     = &SetValueFromReg("db_name");
        $db_pass     = &SetValueFromReg("db_pass");
        if ($db_pass) {

            # Decrypt what we got from the registry
            $db_pass = &Decrypt($db_pass);
        }
        $db_user        = &SetValueFromReg("db_user");
        $dbreindex_do   = &SetValueFromReg("dbreindex_do");
        $update         = &SetValueFromReg("update");
        $mailserver     = &SetValueFromReg("mailserver");
        $mailfrom       = &SetValueFromReg("mailfrom");
        $mailto         = &SetValueFromReg("mailto");
        $mailverbosity  = &AtoI( &SetValueFromReg("mailverbosity") );
        $showsystray    = &SetValueFromReg("showsystray");
        $mail_auth_user = &SetValueFromReg("mail_auth_user");
        $mail_auth_pass = &SetValueFromReg("mail_auth_pass");
        if ($mail_auth_pass) {

            # Decrypt what we got from the registry
            $mail_auth_pass = &Decrypt($mail_auth_pass);
        }
        $mail_auth_type      = &SetValueFromReg("mail_auth_type");
        $deletiondays        = &SetValueFromReg("deletiondays");
        $nmap_do             = &SetValueFromReg("nmap_do");
        $nmap_max            = &SetValueFromReg("nmap_max");
        $nmap                = &SetValueFromReg("nmap");
        $nmap_options        = &SetValueFromReg("nmap_options");
        $nmap_unidentified   = &SetValueFromReg("nmap_unidentified");
        $mapfloor            = &SetValueFromReg("mapfloor");
        $netmap_url          = &SetValueFromReg("netmap_url");
        $patch_do            = &SetValueFromReg("patch_do");
        $PATCHDIR            = &SetValueFromReg("PATCHDIR");
        $CullVulnsAggression = &SetValueFromReg("CullVulnsAggression");
        $cullundetectedvulns = &SetValueFromReg("cullundetectedvulns");

        # read proxy values
        $proxy_server = &SetValueFromReg("proxy_server");
        $proxy_user   = &SetValueFromReg("proxy_user");
        $proxy_pass   = &SetValueFromReg("proxy_pass");
        if ($proxy_pass) {

            # Decrypt what we got from the registry
            $proxy_pass = &Decrypt($proxy_pass);
        }
    }

    # Check the registry for LPM's home
    $RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/Workflow"};
    if ($RegKey) {
        $lpmdir = &SetValueFromReg("InstallPath");
        $lpmdir = Win32::GetShortPathName($lpmdir);
        if ($DEBUG) { &LogDebug("ReadRegistry: LPMDIR is $lpmdir"); }
    }

    # Check the registry for Product Activation Proxy Server
    $RegKey =
      $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite"};
    if ($RegKey) {
        my $use_proxy = &SetValueFromReg("UseProxy");
        if ( $use_proxy eq "true" ) {
            $proxy_server = &SetValueFromReg("ProxyAddress");
            my $proxy_port = &SetValueFromReg("ProxyPort");
            if ($proxy_port) { $proxy_server .= ":" . $proxy_port; }
        }
        else {
            $proxy_server = "";
        }
        my $proxy_login = &SetValueFromReg("RequiresLogin");
        if ( $proxy_login eq "true" ) {
            $proxy_user = &SetValueFromReg("ProxyUser");
            my $proxy_domain = &SetValueFromReg("ProxyDomain");
            if ($proxy_domain) {
                $proxy_user = $proxy_domain . "\\" . $proxy_user;
            }
        }
        else {
            $proxy_user = "";
            $proxy_pass = "";
        }
    }
    return 0;
}
### End of ReadRegistry subroutine #########################################

### PrepareRRD subroutine ##################################################
sub PrepareRRD {

    # these files must be written into CWD; the RRD::Simple module fails if it
    # sees Win32 pathnames.
    $ldmsrrdfile        = "ldmsstats.rrd";
    $ldmsrrdfile_udd    = "ldmsstats_udd.rrd";
    $ldmsrrdfile_sched  = "ldmsstats_sched.rrd";
    $ldmsrrdfile_life   = "ldmsstats_life.rrd";
    $ldmsrrdfile_alerts = "ldmsstats_alerts.rrd";
    $ldmsrrdfile_rc     = "ldmsstats_rc.rrd";
    $ldssrrdfile        = "ldssstats.rrd";
    $ldssrrdfile_life   = "ldssstats_life.rrd";

    # LDMS Inventory
    if ( !-e $ldmsrrdfile ) {

        # LDMS RRD file didn't exist, so create and initialize it
        $ldmsrrd = RRD::Simple->new( file => "$ldmsrrdfile" );
        $ldmsrrd->create(
            $ldmsrrdfile, "mrtg",
            AllDevices  => "GAUGE",
            DayDevices  => "GAUGE",
            WeekDevices => "GAUGE",
        );
        $ldmsrrd->heartbeat( $ldmsrrdfile, "AllDevices",  86400 );
        $ldmsrrd->heartbeat( $ldmsrrdfile, "DayDevices",  86400 );
        $ldmsrrd->heartbeat( $ldmsrrdfile, "WeekDevices", 86400 );

    }
    else {

        # LDMS RRD file did exist, so we just need to initialize it
        $ldmsrrd = RRD::Simple->new( file => $ldmsrrdfile );
    }

    # LDMS Unmanaged Nodes
    if ( !-e $ldmsrrdfile_udd ) {

        # LDMS UDD RRD file didn't exist, so create and initialize it
        $ldmsrrd_udd = RRD::Simple->new( file => "$ldmsrrdfile_udd" );
        $ldmsrrd_udd->create(
            $ldmsrrdfile_udd, "mrtg",
            AllDevices  => "GAUGE",
            DayDevices  => "GAUGE",
            WeekDevices => "GAUGE",
        );
        $ldmsrrd_udd->heartbeat( $ldmsrrdfile_udd, "AllDevices",  86400 );
        $ldmsrrd_udd->heartbeat( $ldmsrrdfile_udd, "DayDevices",  86400 );
        $ldmsrrd_udd->heartbeat( $ldmsrrdfile_udd, "WeekDevices", 86400 );

    }
    else {

        # LDMS UDD RRD file did exist, so we just need to initialize it
        $ldmsrrd_udd = RRD::Simple->new( file => $ldmsrrdfile_udd );
    }

    # LDMS Scheduled Tasks
    if ( !-e $ldmsrrdfile_sched ) {

        # LDMS Sched RRD file didn't exist, so create and initialize it
        $ldmsrrd_sched = RRD::Simple->new( file => "$ldmsrrdfile_sched" );
        $ldmsrrd_sched->create(
            $ldmsrrdfile_sched, "mrtg",
            AllTasks  => "GAUGE",
            GoodTasks => "GAUGE",
            BadTasks  => "GAUGE",
        );
        $ldmsrrd_sched->heartbeat( $ldmsrrdfile_sched, "AllTasks",  86400 );
        $ldmsrrd_sched->heartbeat( $ldmsrrdfile_sched, "GoodTasks", 86400 );
        $ldmsrrd_sched->heartbeat( $ldmsrrdfile_sched, "BadTasks",  86400 );

    }
    else {

        # LDMS Sched RRD file did exist, so we just need to initialize it
        $ldmsrrd_sched = RRD::Simple->new( file => $ldmsrrdfile_sched );
    }

    # LDMS Task Life
    if ( !-e $ldmsrrdfile_life ) {

        # LDMS RRD Life file didn't exist, so create and initialize it
        $ldmsrrd_life = RRD::Simple->new( file => "$ldmsrrdfile_life" );
        $ldmsrrd_life->create( $ldmsrrdfile_life, "mrtg", TaskLife => "GAUGE",
        );
        $ldmsrrd_life->heartbeat( $ldmsrrdfile_life, "TaskLife", 86400 );

    }
    else {

        # LDMS RRD Life file did exist, so we just need to initialize it
        $ldmsrrd_life = RRD::Simple->new( file => $ldmsrrdfile_life );
    }

    # LDMS Alert Counts
    if ( !-e $ldmsrrdfile_alerts ) {

        # LDMS RRD Alert file didn't exist, so create and initialize it
        $ldmsrrd_alerts = RRD::Simple->new( file => "$ldmsrrdfile_alerts" );
        $ldmsrrd_alerts->create( $ldmsrrdfile_alerts, "mrtg",
            AlertCount => "GAUGE", );
        $ldmsrrd_alerts->heartbeat( $ldmsrrdfile_alerts, "AlertCount", 86400 );

    }
    else {

        # LDMS RRD Alert file did exist, so we just need to initialize it
        $ldmsrrd_alerts = RRD::Simple->new( file => $ldmsrrdfile_alerts );
    }

    # LDMS Remote Control Events
    if ( !-e $ldmsrrdfile_rc ) {

        # LDMS RC RRD file didn't exist, so create and initialize it
        $ldmsrrd_rc = RRD::Simple->new( file => "$ldmsrrdfile_rc" );
        $ldmsrrd_rc->create(
            $ldmsrrdfile_rc, "mrtg",
            AllRC      => "GAUGE",
            RCUsers    => "GAUGE",
            RCMachines => "GAUGE",
        );
        $ldmsrrd_rc->heartbeat( $ldmsrrdfile_rc, "AllRC",      86400 );
        $ldmsrrd_rc->heartbeat( $ldmsrrdfile_rc, "RCUsers",    86400 );
        $ldmsrrd_rc->heartbeat( $ldmsrrdfile_rc, "RCMachines", 86400 );

    }
    else {

        # LDMS RC RRD file did exist, so we just need to initialize it
        $ldmsrrd_rc = RRD::Simple->new( file => $ldmsrrdfile_rc );
    }

    # LDSS Vulns
    if ( !-e $ldssrrdfile ) {

        # LDSS RRD file didn't exist, so create and initialize it
        $ldssrrd = RRD::Simple->new( file => "$ldssrrdfile" );
        $ldssrrd->create(
            $ldssrrdfile, "mrtg",
            ScannedVulns  => "GAUGE",
            DetectedVulns => "GAUGE",
            AutofixVulns  => "GAUGE",
        );
        $ldssrrd->heartbeat( $ldssrrdfile, "ScannedVulns",  86400 );
        $ldssrrd->heartbeat( $ldssrrdfile, "DetectedVulns", 86400 );
        $ldssrrd->heartbeat( $ldssrrdfile, "AutofixVulns",  86400 );

    }
    else {

        # LDSS RRD file did exist, so we just need to initialize it
        $ldssrrd = RRD::Simple->new( file => $ldssrrdfile );
    }

    # LDSS Vuln Life
    if ( !-e $ldssrrdfile_life ) {

        # LDSS RRD Life file didn't exist, so create and initialize it
        $ldssrrd_life = RRD::Simple->new( file => "$ldssrrdfile_life" );
        $ldssrrd_life->create( $ldssrrdfile_life, "mrtg", VulnLife => "GAUGE",
        );
        $ldssrrd_life->heartbeat( $ldssrrdfile_life, "VulnLife", 86400 );

    }
    else {

        # LDSS RRD Life file did exist, so we just need to initialize it
        $ldssrrd_life = RRD::Simple->new( file => $ldssrrdfile_life );
    }

    # Make sure my report directory is ready
    if ( !-e $reportdir ) { &MakeDir($reportdir); }
    return 0;
}
### End of PrepareRRD subroutine ##############################################

### GenerateIndex subroutine ###################################################
# Writes index HTML page to display RRD counters from
sub GenerateIndex {

    # Make sure the favicon is there
    if ( !-e "$reportdir/ldms_core.ico" ) {
        copy( "$dir/ldms_core.ico", "$reportdir/ldms_core.ico" )
          or &LogWarn("Cannot copy $dir/ldms_core.ico to $reportdir - $!");
    }
    if ( !-e "$reportdir/ldms_core.css" ) {
        copy( "$dir/ldms_core.css", "$reportdir/ldms_core.css" )
          or &LogWarn("Cannot copy $dir/ldms_core.css to $reportdir - $!");
    }
    if ( !-e "$reportdir/ldms_core_icon.png" ) {
        copy( "$dir/ldms_core_icon.png", "$reportdir/ldms_core_icon.png" )
          or &LogWarn("Cannot copy $dir/ldms_core_icon.png to $reportdir - $!");
    }
    my $rrdtime    = localtime;
    my $targetfile = $reportdir . "/index.htm";
    my $output     = <<"EOHTML";
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/dtd/xhtml11.dtd">
<!-- Begin Head -->
<html>
	<head>
		<title>ldms_core LANDesk Statistics Report</title>
		<meta http-equiv="refresh" content="3600" />
		<meta http-equiv="pragma" content="no-cache" />
		<meta http-equiv="cache-control" content="no-cache" />
		<meta http-equiv="expires" content="$rrdtime" />
		<meta http-equiv="generator" content="$prog $VERSION" />
		<meta http-equiv="date" content="$rrdtime" />
		<meta http-equiv="content-type" content="text/html; charset=iso-8859-1" />
        <link HREF="ldms_core.css" rel="stylesheet" type="text/css"> 
        <link REL="SHORTCUT ICON" HREF="ldms_core.ico">
	</head>
<body>
<img src="ldms_core_icon.png">
<H1>ldms_core LANDesk Statistics Report last updated at <A HREF="ldms_core-latest.htm">$rrdtime</A>.</H1><br />
EOHTML
    if ( -e "$reportdir/ldms_core-netmap.htm" ) {
        $output .= "<H2><A HREF=\"ldms_core-netmap.htm\">ldms_core Network "
          . "Map Report</A></H2><br />";
    }
    $output .= <<"EOHTML";
<hr>
<!-- End Head -->
<table>
<tr>
<!-- Begin `Inventory' Graph -->
<td>
    <a href="ldmsstats.htm"><H2>LANDesk Management Suite Inventory</H2>
    <img src="ldmsstats-daily.png"></a>
</td>
<!-- End `Inventory' Graph -->
<!-- Begin `Unmanaged' Graph -->
<td>
    <a href="ldmsstats_udd.htm"><H2>LANDesk Management Suite Unmanaged Devices</H2>
    <img src="ldmsstats_udd-daily.png"></a>
</td>
<!-- End `Unmanaged' Graph -->
</tr>
<tr>
<!-- Begin `Scheduled Tasks' Graph -->
<td>
    <a href="ldmsstats_sched.htm"><H2>LANDesk Management Suite Scheduled Tasks</H2>
    <img src="ldmsstats_sched-daily.png"></a>
</td>
<!-- End `Scheduled Tasks' Graph -->
<!-- Begin `Task Life' Graph -->
<td>
    <a href="ldmsstats_life.htm"><H2>LANDesk Management Suite Task Lifetime</H2>
    <img src="ldmsstats_life-daily.png"></a>
</td>
<!-- End `Task Life' Graph -->
</tr>
<tr>
<!-- Begin `Remote Control' Graph -->
<td>
    <a href="ldmsstats_rc.htm"><H2>LANDesk Management Suite Remote Control Events</H2>
    <img src="ldmsstats_rc-daily.png"></a>
</td>
<!-- End `Remote Control' Graph -->
<!-- Begin `Alerts' Graph -->
<td>
    <a href="ldmsstats_alerts.htm"><H2>LANDesk Management Suite Alerts Processed</H2>
    <img src="ldmsstats_alerts-daily.png"></a>
</td>
<!-- End `Alerts' Graph -->
</tr>
<tr>
<!-- Begin `Patch' Graph -->
<td>
    <a href="ldssstats.htm"><H2>LANDesk Security Suite Vulnerabilities</H2>
    <img src="ldssstats-daily.png"></a>
</td>
<!-- End `Patch' Graph -->
<!-- Begin `Vuln Life' Graph -->
<td>
    <a href="ldssstats_life.htm"><H2>LANDesk Security Suite Vulnerability Lifetime</H2>
    <img src="ldssstats_life-daily.png"></a>
</td>
<!-- End `Vuln Life' Graph -->
</tr>
</table>
<!-- Begin Footer Block -->
        <hr>
        Report page generated by <a
href="http://www.droppedpackets.org/scripts/ldms_core">$prog $VERSION</a> using <A HREF="http://oss.oetiker.ch/rrdtool/">RRDtool</A>.
<!-- End Footer Block -->
	</body>
</html>


EOHTML
    open( $FILE, '>', "$targetfile" )
      or &LogDie("Can't open file $targetfile - $!");
    print $FILE $output;
    close($FILE);
    if ($DEBUG) { &LogDebug("GeneratePage: Recreated $targetfile"); }
    return 0;
}
### End of GenerateIndex subroutine ############################################

### GenerateWebHeader subroutine ###############################################
# Writes generic HTML page header
sub GenerateWebHeader {
    my ( $title, $gentime ) = @_;
    my $output = <<"EOHTML";
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/dtd/xhtml11.dtd">
<!-- Begin Head -->
<html>
	<head>
		<title>$title</title>
		<meta http-equiv="refresh" content="86400" />
		<meta http-equiv="pragma" content="no-cache" />
		<meta http-equiv="cache-control" content="no-cache" />
		<meta http-equiv="expires" content="$gentime" />
		<meta http-equiv="generator" content="$prog $VERSION" />
		<meta http-equiv="date" content="$gentime" />
		<meta http-equiv="content-type" content="text/html; charset=iso-8859-1" />
        <link HREF="ldms_core.css" rel="stylesheet" type="text/css"> 
        <link REL="SHORTCUT ICON" HREF="ldms_core.ico">
	</head>
EOHTML
    if ($DEBUG) { &LogDebug("GenerateWebHeader: created $title header"); }
    return $output;
}

### GenerateWebFooter subroutine ###############################################
# Writes generic HTML page footer
sub GenerateWebFooter {
    my $output = <<"EOHTML";
<!-- Begin Footer Block -->
<hr>
<p>Report page generated by <a href="http://www.droppedpackets.org/scripts/ldms_core">
$prog $VERSION</a> using <A HREF="http://oss.oetiker.ch/rrdtool/">RRDtool</A> and 
<A HREF="http://bloodgate.com/perl/graph/manual/index.html">Graph::Easy</A>.
<BR/>CSS for this page provided by <A
HREF="http://www.freecsstemplates.org/preview/boxybox">FreeCSSTemplates.Org</A>
<!-- End Footer Block -->
	</body>
</html>

EOHTML
    if ($DEBUG) { &LogDebug("GenerateWebFooter: created footer"); }
    return $output;
}

### GeneratePage subroutine ###################################################
# Writes counter-specific HTML pages to display RRD traffic
sub GeneratePage {
    my ( $targetrrd, $description ) = @_;
    my $dayfile    = $targetrrd . "-daily.png";
    my $weekfile   = $targetrrd . "-weekly.png";
    my $monthfile  = $targetrrd . "-monthly.png";
    my $yearfile   = $targetrrd . "-annual.png";
    my $rrdtime    = localtime;
    my $targetfile = $reportdir . "/" . $targetrrd . ".htm";
    my $output     = &GenerateWebHeader( $description, $rrdtime );
    $output .= <<"EOHTML";
<body>
<img src="ldms_core_icon.png">
<H1>$description last updated at <A HREF="ldms_core-latest.htm">$rrdtime</A>.</H1><br />
<hr>
<!-- End Head -->
<!-- Begin `Daily' Graph -->
			<h2>`Daily' Graph</h2>
			<img src="$dayfile" title="day" alt="day" />
<!-- End `Daily' Graph -->
<!-- Begin `Weekly' Graph -->
			<h2>`Weekly' Graph</h2>
			<img src="$weekfile" title="week" alt="week" />
<!-- End `Weekly' Graph -->
<!-- Begin `Monthly' Graph -->
			<h2>`Monthly' Graph</h2>
			<img src="$monthfile" title="month" alt="month" />
<!-- End `Monthly' Graph -->
<!-- Begin `Yearly' Graph -->
			<h2>`Yearly' Graph</h2>
			<img src="$yearfile" title="year" alt="year" />
<!-- End `Yearly' Graph -->
EOHTML
    $output .= &GenerateWebFooter;
    open( $FILE, '>', "$targetfile" )
      or &LogDie("Can't open file $targetfile - $!");
    print $FILE $output;
    close($FILE);
    if ($DEBUG) { &LogDebug("GeneratePage: Recreated $targetfile"); }
    return 0;
}
### End of GeneratePage subroutine ############################################

### WriteReport subroutine ####################################################
sub WriteReport {
    $mailmessage =~ s/\n/<br \/>\n/gx;
    my $rrdtime    = localtime;
    my $reportfile = $reportdir . "/ldms_core-latest.htm";
    my $output =
      &GenerateWebHeader( "ldms_core Latest Output Report", $rrdtime );
    $output .= <<"EOHTML";
<body>
<img src="ldms_core_icon.png">
<H1>ldms_core LANDesk Statistics Report last updated at $rrdtime.</H1>
<H2>$emailsubject.</H2>
<br />
<hr>
<!-- End Head -->
<P>$mailmessage</P>
EOHTML
    $output .= &GenerateWebFooter;
    open( $FILE, '>', "$reportfile" )
      or &LogDie("Can't open file $reportfile - $!");
    print $FILE $output;
    close($FILE);
    if ($DEBUG) { &LogDebug("WriteReport: Recreated report page"); }
    return 0;
}
### End of WriteReport subroutine ############################################

### WriteGraph subroutine ####################################################
sub WriteGraph {
    my $input     = shift;
    my $graphtime = localtime;
    my $graphfile = $reportdir . "/ldms_core-netmap.htm";
    my $output =
      &GenerateWebHeader( "ldms_core Latest Network Map", $graphtime );
    $output .= <<"EOHTML";
<body>
<img src="ldms_core_icon.png">
<H1>ldms_core LANDesk Network Map last updated at $graphtime.</H1>
<br />
<hr>
<!-- End Head -->
<P>$input</P>
EOHTML

    if ($mapfloor) {
        $output .=
            "<p>Routers with fewer than $mapfloor "
          . PL( "node", $mapfloor )
          . " behind them were not included in this "
          . "topology map.</p>";
    }
    $output .= &GenerateWebFooter;
    open( $FILE, '>', "$graphfile" )
      or &LogDie("Can't open file $graphfile - $!");
    binmode( $FILE, ":utf8" );
    print $FILE $output;
    close($FILE);
    &Log("Created network map at $graphfile");
    return 0;
}
### End of WriteReport subroutine ############################################

### Setup subroutine ##########################################################
sub Setup {

    $ldms_core_icon = new Win32::GUI::Icon("ldms_core.ico")
      ;    # replace default camel icon with my own

    $ldms_core_class = new
      Win32::GUI::Class(  # set up a class to use my icon throughout the program
        -name => "ldms_core Class",
        -icon => $ldms_core_icon,
      );

    Win32::GUI::SetCursor($oldCursor);    #show previous arrow cursor again

    # Get database info
    &DBWindow_Show;
    Win32::GUI::Dialog();
    if ($DEBUG) { &LogDebug("Setup: Returned to Setup from DBWindow_Show"); }

    # Get mail server info
    &ConfigWindow_Show;
    &ConfigWindow_InsertTabs;
    &ConfigWindow_Hide;
    &ConfigWindowTab_Email;
    Win32::GUI::Dialog();
    if ($DEBUG) {
        &LogDebug("Setup: Returned to Setup from Show_ConfigWindow");
    }

    # Encrypt passwords
    my $db_pass_storage        = &Encrypt($db_pass);
    my $mail_auth_pass_storage = &Encrypt($mail_auth_pass);
    my $proxy_pass_storage     = &Encrypt($proxy_pass);

    # Write discovered data
    $Registry->{"LMachine/Software/Monkeynoodle/"} = {
        "ldms_core/" => {
            "/db_type"             => $db_type,
            "/db_instance"         => $db_instance,
            "/db_name"             => $db_name,
            "/db_user"             => $db_user,
            "/db_pass"             => $db_pass_storage,
            "/dbreindex_do"        => $dbreindex_do,
            "/update"              => $update,
            "/patch_do"            => $patch_do,
            "/patchdir"            => $PATCHDIR,
            "/mailserver"          => $mailserver,
            "/mailfrom"            => $mailfrom,
            "/mailto"              => $mailto,
            "/mail_auth_user"      => $mail_auth_user,
            "/mail_auth_pass"      => $mail_auth_pass_storage,
            "/mail_auth_type"      => $mail_auth_type,
            "/mailverbosity"       => $mailverbosity,
            "/deletiondays"        => $deletiondays,
            "/nmap_do"             => $nmap_do,
            "/nmap"                => $nmap,
            "/nmap_max"            => $nmap_max,
            "/nmap_options"        => $nmap_options,
            "/nmap_unidentified"   => $nmap_unidentified,
            "/netmap_url"          => $netmap_url,
            "/mapfloor"            => $mapfloor,
            "/showsystray"         => $showsystray,
            "/cullvulnsaggression" => $CullVulnsAggression,
            "/cullundetectedvulns" => $cullundetectedvulns,
            "/proxy_server"        => $proxy_server,
            "/proxy_user"          => $proxy_user,
            "/proxy_pass"          => $proxy_pass_storage,
        },
    };

    # Create a LANDesk Scheduled Task
    if ( -e "$ldmain\\ldinv32.exe" ) {

        # This is a core, we should do the LANDesk managed script
        &SetupTask;
    }
    else {
        Win32::GUI::MessageBox(
            0,
            "Please schedule a Windows task to run this program.",
            "Setup complete!", 64
        );
    }

    # Restore console window
    Win32::GUI::Show($DOS);
    return 0;
}

### Create a SCheduled Task ###################################################
sub SetupTask {

    # Script file
    my $cli = Win32::GetShortPathName( Cwd::abs_path($0) );
    $cli =~ s/ldms_c~1\.exe/ldms_core.exe/ix;    # replace mangled .exe name
    $cli =~ s/\//\\/gx;    # substitute forward slashes with backslashes
    my $script = $ldmain . "scripts\\ldms_core.ini";
    if ( -e $script ) {

        # We have a script file
        if ($DEBUG) { &LogDebug("SetupTask: $script exists."); }
    }
    else {

        # We need a script file
        if ($DEBUG) {
            &LogDebug("SetupTask: $script does not exist, creating it.");
        }
        open( $FILE, '>', "$script" )
          or &LogDie("Can't open file $script - $!");
        print $FILE "[MACHINES]\n";
        print $FILE "LOCEXEC=$cli /map, SYNC\n";
        close $FILE;
    }

    # Script definition
    &OpenDB;
    $sql = "select count(*) from LD_TASK_CONFIG where CFG_NAME='ldms_core'";
    my $count = &GetSingleString($sql);
    &CloseDB;
    if ($count) {

        # We have a definition
        if ($DEBUG) {
            &LogDebug("SetupTask: ldms_core exists in LD_TASK_CONFIG.");
        }
    }
    else {

        # Tell them what to do next
        Win32::GUI::MessageBox(
            0,
            "Managed Script created; Please schedule a LANDesk task to run "
              . "it. If you previously used a Windows Scheduled Task, that may "
              . "now be deleted.",
            "Setup complete!",
            64
        );

    }

    return 0;
}
###############################################################################

### Windowing Subroutines  ###################################################
sub DBWindow_Show {

    my $leftmargin   = 120;
    my $rightmargin  = 25;
    my $bottommargin = 50;
    my $nexthoriz    = 5;

    if ($DEBUG) { &LogDebug("DBWindow_Show: Showing database setup window"); }

    # build window
    $DBWindow = Win32::GUI::Window->new(
        -name        => 'DBWindow',
        -text        => 'ldms_core database setup',
        -class       => $ldms_core_class,
        -dialogui    => 1,
        -onResize    => \&DBWindow_Resize,
        -onTerminate => \&Window_Terminate,
    );

    # Add some stuff
    $lbl_Instructions = $DBWindow->AddLabel(
        -name => "lblInstructions",
        -text => "Please enter the required database information.",
        -pos  => [ 5, $nexthoriz ],
        -size => [ 300, 20 ],
    );

    # Begin db_instance row
    $form_db_instance = $DBWindow->AddTextfield(
        -name    => "db_instance_field",
        -prompt  => "Database Server:",
        -text    => $db_instance,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    # Begin db_name row
    $form_db_name = $DBWindow->AddTextfield(
        -name    => "db_name_field",
        -prompt  => "LANDesk Database:",
        -text    => $db_name,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    # Begin db_user row
    $form_db_user = $DBWindow->AddTextfield(
        -name    => "db_user_field",
        -prompt  => "Database Username:",
        -text    => $db_user,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    # Begin db_pass row
    $form_db_pass = $DBWindow->AddTextfield(
        -name     => "db_pass_field",
        -prompt   => "Database Password:",
        -text     => $db_pass,
        -tabstop  => 1,
        -password => 1,
        -pos      => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    # Begin db_type row
    $lbl_db_type = $DBWindow->AddLabel(
        -name => "lbldb_type",
        -text => "Is this an Oracle database?",
        -pos  => [ $leftmargin - 105, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    $form_db_type = $DBWindow->AddCheckbox(
        -name    => "form_db_type",
        -tabstop => 1,
        -pos     => [ $leftmargin + 35, $nexthoriz - 3 ],
        -size    => [ 20, 20 ],
    );

    # Convert Oracle/SQL decision to binary
    if ( $db_type eq "ORA" ) {
        $db_type_binary = 1;
    }
    else {
        $db_type_binary = 0;
    }
    $form_db_type->Checked($db_type_binary);

    # End db_type row

    # Begin button row
    $btn_DBWindowDefault = $DBWindow->AddButton(
        -name    => 'DBWindowDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,                   # Give button darker border
        -ok      => 1,                   # press 'Return' to click this button
        -pos => [ 25, $nexthoriz += 25 ],
        -size    => [ 60, 20 ],
        -onClick => \&DBWindowDefault_Click,
    );

    $btn_DBWindowCancel = $DBWindow->AddButton(
        -name    => 'DBWindowCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                        # press 'Esc' to click this button
        -pos     => [ 100, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&DBWindowCancel_Click,
    );

    $btn_DBWindowDBInfo = $DBWindow->AddButton(
        -name    => 'DBWindowDBInfo',
        -text    => 'Database',
        -tabstop => 1,
        -pos     => [ 175, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&DBWindowDBInfo_Click,
    );

    $btn_DBWindowHelp = $DBWindow->AddButton(
        -name    => 'DBWindowHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&Help_Click,
    );

    # End button row

    $DBWindowsb = $DBWindow->AddStatusBar( -name => 'DBWindowStatus', );
    if ($updatemessage) {
        $DBWindowsb->Text($updatemessage);
    }

    # calculate its size
    $ncw = $DBWindow->Width() - $DBWindow->ScaleWidth();
    $nch = $DBWindow->Height() - $DBWindow->ScaleHeight();
    $w   = $leftmargin + $form_db_instance->Width() + $rightmargin + $ncw;
    $h   = $nexthoriz + $bottommargin + $nch;

    # Don't let it get smaller than it should be
    $DBWindow->Change( -minsize => [ $w, $h ] );

    # calculate its centered position
    # Assume we have the main window size in ($w, $h) as before
    $desk = Win32::GUI::GetDesktopWindow();
    $dw   = Win32::GUI::Width($desk);
    $dh   = Win32::GUI::Height($desk);
    $wx   = ( $dw - $w ) / 2;
    $wy   = ( $dh - $h ) / 2;

    # Resize, position and display
    $DBWindow->Resize( $w, $h );
    $DBWindow->Move( $wx, $wy );

    $DBWindow->Show();
    return 0;
}
###############################################################################

sub Window_Terminate {
    return -1;
}

sub DBWindow_Resize {
    $DBWindowsb->Move( 0, $DBWindow->ScaleHeight - $DBWindowsb->Height );
    $DBWindowsb->Resize( $DBWindow->ScaleWidth, $DBWindowsb->Height );
    return 0;
}

# What to do when the button is clicked #######################################
sub DBWindowDefault_Click {

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
        $dbh = DBI->connect(
"dbi:ODBC:driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass"
          )
          or
          Win32::GUI::MessageBox( 0, DBI->errstr, "Database connection failed",
            48 );
        if ($DEBUG) {
            &LogDebug(
"DBWindowDefault_Click: Okay clicked in DBWindow: Opening database with "
                  . "$db_type, $db_instance, $db_name, $db_user, db_pass" );
        }
    }
    else {
        $dbh = DBI->connect( "DBI:Oracle:$db_name", $db_user, $db_pass )
          or
          Win32::GUI::MessageBox( 0, DBI->errstr, "Database connection failed",
            48 );
        if ($DEBUG) {
            &LogDebug(
"DBWindowDefault_Click: Okay clicked in DBWindow: Opening database with "
                  . "$db_type, $db_name, $db_user, db_pass" );
        }
    }
    if ( !$dbh ) {
        if ($DEBUG) {
            &LogDebug("DBWindowDefault_Click: Failed database connection");
        }
        $DBWindowsb->SetText( 0, "Connection failed, please try again." );
        return 0;
    }

    # Get the mail server info & store in $mailserver and $mailfrom
    if ( $db_type eq "SQL" ) {
        $sql = "select top 1 host,replyemail from ld_task_smtp "
          . "where sendusing='2' and port='25'";
    }
    else {
        $sql =
            "select * from "
          . "(select host,replyemail from ld_task_smtp "
          . "where sendusing='2' and port='25') "
          . "where rownum = 1";
    }
    $sth = $dbh->prepare($sql)
      or &LogWarn("Database connection failure.\n");
    $sth->execute
      or &LogWarn("Database connection failure.\n");
    while ( @row = $sth->fetchrow_array() ) {
        $mailserver = $row[0];
        $mailfrom   = $row[1];
    }

    # What's the LANDesk version we're working with?
    $ldms_version = &GetLDVersion;

    # Close the database
    $dbh->disconnect;
    if ($DEBUG) {
        &LogDebug(
"DBWindowDefault_Click: Read $mailserver, $mailfrom from database connection"
        );
    }

    # If it succeeded, we're ready to close the window and move on.
    $DBWindow->Hide();
    return -1;
}
###############################################################################

sub DBWindowCancel_Click {
    if ($DEBUG) {
        &LogDebug("DBWindowCancel_Click: Cancel clicked in DBWindow");
    }
    $DBWindow->Hide();

    &Log("$prog $VERSION exiting");

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

sub Help_Click {
    if ($DEBUG) { &LogDebug("DBWindowCancel_Click: Help clicked"); }
    open_browser(
        'http://www.droppedpackets.org/scripts/ldms_core/ldms_core-manual');

    return 0;
}

sub DBWindowDBInfo_Click {
    if ($DEBUG) {
        &LogDebug("DBWindowCancel_Click: DBInfo clicked in DBWindow");
    }
    open_browser(
'https://localhost/landesk/ManagementSuite/Core/ssl/information/DatabaseInformation.asmx?op=GetConnectionString'
    );
    return 0;
}

sub ConfigWindowBrowsePatchDir_Click {
    if ($DEBUG) {
        &LogDebug("DBWindowCancel_Click: ConfigWindowBrowsePatchDir clicked");
    }

    my $target = Win32::GUI::BrowseForFolder(
        -title => "Find LANDesk Patch Directory",
        -owner => $ConfigWindow,
    );

    $target = Win32::GetShortPathName($target);
    if ($target) {
        $form_patchdir_override->Text("$target");
    }
    return 0;
}

# This subroutine gets configuration information ##############################
sub ConfigWindow_Show {

    my $leftmargin   = 130;
    my $rightmargin  = 50;
    my $bottommargin = 50;
    my $nexthoriz    = 15;

    # build window
    $ConfigWindow = Win32::GUI::Window->new(
        -name        => 'ConfigWindow',
        -text        => 'ldms_core setup',
        -class       => $ldms_core_class,
        -dialogui    => 1,
        -onTerminate => \&Window_Terminate,
        -onResize    => \&ConfigWindow_Resize,
    );

    # Email tab
    # Begin Email information
    $lbl_email = $ConfigWindow->AddLabel(
        -name    => "lbl_email",
        -text    => "Please enter the required email sending information.",
        -tabstop => 0,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    # Begin mailserver row
    $form_mailserver = $ConfigWindow->AddTextfield(
        -name    => "mailserver_field",
        -prompt  => "Email Server:",
        -text    => $mailserver,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );
    $btn_mailauth = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowMailAuth',
        -text    => 'Authorization',
        -tabstop => 1,
        -pos     => [ $form_mailserver->Width() + $leftmargin, $nexthoriz ],
        -size    => [ 75, 20 ],
        -onClick => \&ConfigWindowMailAuth_Click,
    );

    # Begin mailfrom row
    $form_mailfrom = $ConfigWindow->AddTextfield(
        -name    => "mailfrom_field",
        -prompt  => "Email From Address:",
        -tabstop => 1,
        -text    => $mailfrom,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );
    $btn_mailtest = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowMailTest',
        -text    => 'Test Email',
        -tabstop => 1,
        -pos     => [ $form_mailfrom->Width() + $leftmargin, $nexthoriz ],
        -size    => [ 75, 20 ],
        -onClick => \&ConfigWindowMailTest_Click,
    );

    # Begin mailto row
    $form_mailto = $ConfigWindow->AddTextfield(
        -name    => "mailto_field",
        -prompt  => "Email To Address:",
        -tabstop => 1,
        -text    => $mailto,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    # Begin mail verbosity slider rows
    $lbl_mailverbosity = $ConfigWindow->AddLabel(
        -name    => "lbl_mailverbosity",
        -text    => "How much email do you want to get?",
        -tabstop => 0,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    $form_mailverbosity = $ConfigWindow->AddSlider(
        -name    => "mailverbosity_field",
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size     => [ 200, 20 ],
        -selrange => 0,
    );
    $form_mailverbosity->SetRange( 1, 6 );
    $form_mailverbosity->SetPos($mailverbosity);
    $form_mailverbosity->SetBuddy(
        0,
        $ConfigWindow->AddLabel(
            -name => "lbl_mailverbosity_left",
            -text => "More"
        )
    );
    $form_mailverbosity->SetBuddy(
        1,
        $ConfigWindow->AddLabel(
            -name => "lbl_mailverbosity_right",
            -text => "Less"
        )
    );

    # End mail verbosity slider rows

    # Network tab
    $nexthoriz = 15;

    # Begin nmap-skip row (label and checkbox)
    $form_nmap_do = $ConfigWindow->AddCheckbox(
        -name    => "form_nmap_do",
        -tabstop => 1,
        -checked => $nmap_do,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size    => [ 20, 20 ],
        -onClick => \&ConfigWindowNMAPDo_Click,
    );

    $form_nmap_dolabel = $ConfigWindow->AddLabel(
        -name => "nmap_dolabel",
        -text => "Use NMAP to fill in missing unmanaged nodes info?",
        -pos  => [ $leftmargin - 80, $nexthoriz + 3 ],
        -size => [ 250, 20 ],
    );

    # End nmap-skip row

    # Begin nmap binary row
    $form_nmap = $ConfigWindow->AddTextfield(
        -name    => "nmap_field",
        -prompt  => "Path to nmap binary:",
        -tabstop => 1,
        -text    => $nmap,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    $btn_browsenmap = $ConfigWindow->AddButton(
        -name    => "ConfigWindowBrowseNMAP",
        -text    => "Browse",
        -tabstop => 1,
        -pos     => [ $form_nmap->Width() + $leftmargin + 5, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&ConfigWindowBrowseNMAP_Click,
    );

    # Begin nmap commandline row
    $form_nmap_options = $ConfigWindow->AddTextfield(
        -name    => "nmap_options_field",
        -prompt  => "nmap options:",
        -tabstop => 1,
        -text    => $nmap_options,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    # Begin nmap max row
    $form_nmap_max = $ConfigWindow->AddTextfield(
        -name    => "nmap_max_field",
        -prompt  => "maximum nmap targets:",
        -tabstop => 1,
        -text    => $nmap_max,
        -pos     => [ $leftmargin + 25, $nexthoriz += 25 ],
        -size => [ 50, 20 ],
    );

    # Begin nmap unidentified row (label and checkbox)
    $form_nmap_u = $ConfigWindow->AddCheckbox(
        -name    => "form_nmap_u",
        -tabstop => 1,
        -checked => $nmap_unidentified,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size => [ 20, 20 ],
    );

    $form_nmap_ulabel = $ConfigWindow->AddLabel(
        -name => "nmap_ulabel",
        -text => "Should nmap skip previously unidentified nodes?",
        -pos  => [ $leftmargin - 80, $nexthoriz + 3 ],
        -size => [ 250, 20 ],
    );

    # End nmap unidentified row

    # Grey all those out if nmap_do isn't on
    if ( !$nmap_do ) {
        $form_nmap->Disable();
        $btn_browsenmap->Disable();
        $form_nmap_options->Disable();
        $form_nmap_u->Disable();
    }

    # Begin network map url row
    $form_netmap_url = $ConfigWindow->AddTextfield(
        -name    => "netmap_url_field",
        -prompt  => "Network map router URL:",
        -tabstop => 1,
        -text    => $netmap_url,
        -pos     => [ $leftmargin + 25, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    # Begin network map floor row
    $form_mapfloor = $ConfigWindow->AddTextfield(
        -name    => "mapfloor_field",
        -prompt  => "Network map floor",
        -tabstop => 1,
        -text    => $mapfloor,
        -pos     => [ $leftmargin + 25, $nexthoriz += 25 ],
        -size => [ 20, 20 ],
    );

    # Patch tab
    $nexthoriz = 15;

    # Begin patch-skip row (label and checkbox)
    $form_patch_do = $ConfigWindow->AddCheckbox(
        -name    => "form_patch_do",
        -tabstop => 1,
        -checked => $patch_do,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size    => [ 20, 20 ],
        -onClick => \&ConfigWindowPatchDo_Click,
    );

    $form_patch_dolabel = $ConfigWindow->AddLabel(
        -name => "patch_dolabel",
        -text =>
          "Should ldms_core purge vulns and patches that are no longer needed?",
        -pos  => [ $leftmargin - 80, $nexthoriz + 3 ],
        -size => [ 340,              20 ],
    );

    # End patch-skip row

    # Begin patchdir_override row
    $lbl_patch = $ConfigWindow->AddLabel(
        -name    => "lbl_patch",
        -text    => "Please enter the actual location of your patch directory.",
        -tabstop => 0,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    $form_patchdir_override = $ConfigWindow->AddTextfield(
        -name    => "patchdir_override_field",
        -prompt  => "Patch Directory: ",
        -text    => $PATCHDIR,
        -tabstop => 1,
        -pos     => [ $leftmargin - 30, $nexthoriz += 25 ],
        -size => [ 280, 20 ],
    );

    $btn_browsepatchdir = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowBrowsePatchDir',
        -text    => 'Browse',
        -tabstop => 1,
        -pos     => [ $form_patchdir_override->Width() + 105, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&ConfigWindowBrowsePatchDir_Click,
    );

    # End patchdir_override row

    # Begin cullundetectedvulns row (label and checkbox)
    $form_cullundetectedvulns = $ConfigWindow->AddCheckbox(
        -name    => "form_cullundetectedvulns",
        -tabstop => 1,
        -checked => $cullundetectedvulns,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size => [ 20, 20 ],
    );

    $lbl_cullundetectedvulns = $ConfigWindow->AddLabel(
        -name => "cullundetectedvulnslabel",
        -text =>
"Should ldms_core clear the scan state of vulns that aren't detected?",
        -pos  => [ $leftmargin - 80, $nexthoriz + 3 ],
        -size => [ 340,              20 ],
    );

    # End cullundetectedvulns row

    # Grey all those out if patch_do isn't on
    if ( !$patch_do ) {
        $form_patchdir_override->Disable();
        $btn_browsepatchdir->Disable();

        # cullundetectedvulns is a special case; it defaults to on if the LDMS
        # level is 8.8.sp3 or greater, but it should still be forced off if
        # they don't check patch_do.
        $cullundetectedvulns = 0;
        $form_cullundetectedvulns->Disable();
    }

    # Begin CullVulnsAggression slider rows
    $lbl_cullvulnsaggression = $ConfigWindow->AddLabel(
        -name => "lbl_cullvulnsaggression",
        -text => "How should superceded vulnerabilities be moved to "
          . "Do Not Scan?",
        -tabstop => 0,
        -pos     => [ 15, $nexthoriz += 25 ],
        -size => [ 320, 20 ],
    );

    $form_cullvulnsaggression = $ConfigWindow->AddSlider(
        -name    => "cullvulnsaggression_field",
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size     => [ 200, 20 ],
        -selrange => 0,
    );
    $form_cullvulnsaggression->SetRange( 1, 3 );
    $form_cullvulnsaggression->SetPos($CullVulnsAggression);
    $form_cullvulnsaggression->SetBuddy(
        0,
        $ConfigWindow->AddLabel(
            -name => "lbl_cullVulnsaggression_left",
            -text => "Move partially superceded"
        )
    );
    $form_cullvulnsaggression->SetBuddy(
        1,
        $ConfigWindow->AddLabel(
            -name => "lbl_cullVulnsaggression_right",
            -text => "Don't move any vulns"
        )
    );

    $lbl_cullvulnsaggression2 = $ConfigWindow->AddLabel(
        -name    => "lbl_cullvulnsaggression2",
        -text    => "Move completely superceded",
        -tabstop => 0,
        -pos     => [ $leftmargin + 25, $nexthoriz += 25 ],
        -size => [ 250, 20 ],
    );

    # End cullvulnsaggresion slider rows

    # Maintenance tab
    $nexthoriz = 15;

    # Begin days to deletion row
    $form_deletiondays = $ConfigWindow->AddTextfield(
        -name    => "deletiondays_field",
        -prompt  => "Purge old files after X Days (0 to disable):",
        -tabstop => 1,
        -text    => $deletiondays,
        -pos     => [ $leftmargin + 100, $nexthoriz += 25 ],
        -size => [ 40, 20 ],
    );

    # Begin showsystray row (label and checkbox)
    $form_showsystray = $ConfigWindow->AddCheckbox(
        -name    => "form_showsystray",
        -tabstop => 1,
        -checked => $showsystray,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size => [ 20, 20 ],
    );

    $lbl_showsystray = $ConfigWindow->AddLabel(
        -name => "showsystraylabel",
        -text =>
          "Should ldms_core display its activity with a system tray icon?",
        -pos  => [ $leftmargin - 80, $nexthoriz + 3 ],
        -size => [ 290,              20 ],
    );

    # End showsystray row

    # Begin dbreindex_do row (label and checkbox)
    $form_dbreindex_do = $ConfigWindow->AddCheckbox(
        -name    => "form_dbreindex_do",
        -tabstop => 1,
        -checked => $dbreindex_do,
        -pos     => [ $leftmargin - 100, $nexthoriz += 25 ],
        -size => [ 20, 20 ],
    );

    $lbl_dbreindex_do = $ConfigWindow->AddLabel(
        -name => "dbreindex_dolabel",
        -text => "Should ldms_core reindex your database?",
        -pos  => [ $leftmargin - 80, $nexthoriz + 3 ],
        -size => [ 290, 20 ],
    );

    # End dbreindex_do row

    # Begin update frequency slider rows
    $lbl_update = $ConfigWindow->AddLabel(
        -name    => "lbl_update",
        -text    => "How often should ldms_core check for updates?",
        -tabstop => 0,
        -pos     => [ 15, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    $form_update = $ConfigWindow->AddSlider(
        -name    => "update_field",
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size     => [ 200, 20 ],
        -selrange => 0,
    );
    $form_update->SetRange( 0, 7 );
    $form_update->SetPos($update);
    $form_update->SetBuddy(
        0,
        $ConfigWindow->AddLabel(
            -name => "lbl_update_left",
            -text => "Weekly"
        )
    );
    $form_update->SetBuddy(
        1,
        $ConfigWindow->AddLabel(
            -name => "lbl_update_right",
            -text => "Never"
        )
    );

    # End update frequency slider rows

    # Begin proxy server row
    $form_proxy_server = $ConfigWindow->AddTextfield(
        -name    => "proxy_server_field",
        -prompt  => "Proxy server:",
        -tabstop => 1,
        -text    => $proxy_server,
        -pos     => [ $leftmargin - 30, $nexthoriz += 25 ],
        -size => [ 350, 20 ],
    );

    # End proxy server row

    # Begin proxy user row
    $form_proxy_user = $ConfigWindow->AddTextfield(
        -name    => "proxy_user_field",
        -prompt  => "Proxy user",
        -tabstop => 1,
        -text    => $proxy_user,
        -pos     => [ $leftmargin - 30, $nexthoriz += 25 ],
        -size => [ 350, 20 ],
    );

    # End proxy user row

    # Begin proxy pass row
    $form_proxy_pass = $ConfigWindow->AddTextfield(
        -name     => "proxy_pass_field",
        -prompt   => "Proxy password",
        -password => 1,
        -tabstop  => 1,
        -text     => $proxy_pass,
        -pos      => [ $leftmargin - 30, $nexthoriz += 25 ],
        -size => [ 350, 20 ],
    );

    # End proxy pass row

    # Begin button row
    $btn_ConfigWindowdefault = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,                     # Give button darker border
        -ok      => 1,                     # press 'Return' to click this button
        -pos => [ 75, $nexthoriz += 80 ],
        -size    => [ 60, 20 ],
        -onClick => \&ConfigWindowDefault_Click,
    );

    $btn_ConfigWindowcancel = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                      # press 'Esc' to click this button
        -pos     => [ 150, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&ConfigWindowCancel_Click,
    );

    $btn_ConfigWindowHelp = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 225, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&Help_Click,
    );

    # End button row

    my $lbl_ConfigWindowSpacer = $ConfigWindow->AddLabel(
        -name => 'ConfigWindowSpacer',
        -text => '',
        -pos  => [ 200, $nexthoriz += 25 ],
        -size => [ 1, 1 ],
    );

    $ConfigWindowsb = $ConfigWindow->AddStatusBar();
    if ($updatemessage) {
        $ConfigWindowsb->Text($updatemessage);
    }

    # calculate its size
    $ConfigWindowncw = $ConfigWindow->Width() - $ConfigWindow->ScaleWidth();
    $ConfigWindownch = $ConfigWindow->Height() - $ConfigWindow->ScaleHeight();
    $ConfigWindoww   = $leftmargin + 300 + $rightmargin + $ConfigWindowncw;
    $ConfigWindowh   = $nexthoriz + $bottommargin + $ConfigWindownch;

    # Don't let it get smaller than it should be
    $ConfigWindow->Change( -minsize => [ $ConfigWindoww, $ConfigWindowh ] );

    # calculate its centered position
    $desk           = Win32::GUI::GetDesktopWindow();
    $dw             = Win32::GUI::Width($desk);
    $dh             = Win32::GUI::Height($desk);
    $ConfigWindowwx = ( $dw - $ConfigWindoww ) / 2;
    $ConfigWindowwy = ( $dh - $ConfigWindowh ) / 2;

    # Resize, position and display
    $ConfigWindow->Resize( $w, $h );
    $ConfigWindow->Move( $ConfigWindowwx, $ConfigWindowwy );

    $ConfigWindow->Show();
    return 0;
}
###############################################################################

## Create the tab bar #########################################################
sub ConfigWindow_InsertTabs {
    $ConfigWindowTab = $ConfigWindow->AddTabStrip(
        -left     => 10,
        -top      => 10,
        -width    => $ConfigWindow->ScaleWidth - 20,
        -height   => $ConfigWindow->ScaleHeight - 50,
        -name     => "ConfigWindow_Tab",
        -onChange => \&ConfigWindow_TabChanged,
    );

    # tab 0
    $ConfigWindowTab->InsertItem( -text => "Email" );

    # tab 1
    $ConfigWindowTab->InsertItem( -text => "Network" );

    # tab 2
    $ConfigWindowTab->InsertItem( -text => "Patches" );

    # tab 3
    $ConfigWindowTab->InsertItem( -text => "Maintenance" );
    return 0;
}
###############################################################################

### Handle changes in the tab bar #############################################
sub ConfigWindow_TabChanged {
    &ConfigWindow_Hide;

    #what tab is it now?
    my $newtab = $ConfigWindowTab->SelectedItem();

    # Email tab
    if ( $newtab == 0 ) {
        &ConfigWindowTab_Email;
    }

    # Network tab
    if ( $newtab == 1 ) {
        &ConfigWindowTab_Network;
    }

    # Patches tab
    if ( $newtab == 2 ) {
        &ConfigWindowTab_Patch;
    }

    # Maintenance tab
    if ( $newtab == 3 ) {
        &ConfigWindowTab_Maint;
    }
    return 0;
}
###############################################################################

###############################################################################
sub ConfigWindowTab_Email {

   # Some of the visible items on the window are automagically created and don't
   # have associated objects... so they have to be called directly via name
    $lbl_email->Show();
    $form_mailserver->Show();
    Win32::GUI::Show( $ConfigWindow->mailserver_field_Prompt()->{-handle} );
    $btn_mailauth->Show();
    $form_mailfrom->Show();
    Win32::GUI::Show( $ConfigWindow->mailfrom_field_Prompt()->{-handle} );
    $btn_mailtest->Show();
    $form_mailto->Show();
    Win32::GUI::Show( $ConfigWindow->mailto_field_Prompt()->{-handle} );
    $lbl_mailverbosity->Show();
    $form_mailverbosity->Show();
    Win32::GUI::Show( $ConfigWindow->lbl_mailverbosity_left()->{-handle} );
    Win32::GUI::Show( $ConfigWindow->lbl_mailverbosity_right()->{-handle} );
    return 0;
}
###############################################################################

###############################################################################
sub ConfigWindowTab_Network {
    $form_nmap_dolabel->Show();
    $form_nmap_do->Show();
    $form_nmap->Show();
    Win32::GUI::Show( $ConfigWindow->nmap_field_Prompt()->{-handle} );
    $btn_browsenmap->Show();
    $form_nmap_options->Show();
    Win32::GUI::Show( $ConfigWindow->nmap_options_field_Prompt()->{-handle} );
    $form_nmap_ulabel->Show();
    $form_nmap_u->Show();
    $form_nmap_max->Show();
    Win32::GUI::Show( $ConfigWindow->nmap_max_field_Prompt()->{-handle} );
    $form_netmap_url->Show();
    Win32::GUI::Show( $ConfigWindow->netmap_url_field_Prompt()->{-handle} );
    $form_mapfloor->Show();
    Win32::GUI::Show( $ConfigWindow->mapfloor_field_Prompt()->{-handle} );
    return 0;
}
###############################################################################

###############################################################################
sub ConfigWindowTab_Patch {
    $form_patch_dolabel->Show();
    $form_patch_do->Show();
    $lbl_patch->Show();
    $form_patchdir_override->Show();
    Win32::GUI::Show(
        $ConfigWindow->patchdir_override_field_Prompt()->{-handle} );
    $btn_browsepatchdir->Show();
    $lbl_cullvulnsaggression->Show();
    $form_cullvulnsaggression->Show();
    Win32::GUI::Show(
        $ConfigWindow->lbl_cullVulnsaggression_left()->{-handle} );
    Win32::GUI::Show(
        $ConfigWindow->lbl_cullVulnsaggression_right()->{-handle} );
    $lbl_cullvulnsaggression2->Show();
    $form_cullundetectedvulns->Show();
    $lbl_cullundetectedvulns->Show();
    return 0;
}
###############################################################################

###############################################################################
sub ConfigWindowTab_Maint {
    $form_deletiondays->Show();
    Win32::GUI::Show( $ConfigWindow->deletiondays_field_Prompt()->{-handle} );
    $lbl_update->Show();
    $form_update->Show();
    Win32::GUI::Show( $ConfigWindow->lbl_update_left()->{-handle} );
    Win32::GUI::Show( $ConfigWindow->lbl_update_right()->{-handle} );
    $lbl_showsystray->Show();
    $form_showsystray->Show();
    $lbl_dbreindex_do->Show();
    $form_dbreindex_do->Show();
    $form_proxy_server->Show();
    Win32::GUI::Show( $ConfigWindow->proxy_server_field_Prompt()->{-handle} );
    $form_proxy_user->Show();
    Win32::GUI::Show( $ConfigWindow->proxy_user_field_Prompt()->{-handle} );
    $form_proxy_pass->Show();
    Win32::GUI::Show( $ConfigWindow->proxy_pass_field_Prompt()->{-handle} );
    return 0;
}
###############################################################################

## Hide everything except the tab bar #########################################
sub ConfigWindow_Hide {

   # Some of the visible items on the window are automagically created and don't
   # have associated objects... so they have to be called directly via name
   # Email
    $lbl_email->Hide();
    $form_mailserver->Hide();
    Win32::GUI::Hide( $ConfigWindow->mailserver_field_Prompt()->{-handle} );
    $btn_mailauth->Hide();
    $form_mailfrom->Hide();
    Win32::GUI::Hide( $ConfigWindow->mailfrom_field_Prompt()->{-handle} );
    $btn_mailtest->Hide();
    $form_mailto->Hide();
    Win32::GUI::Hide( $ConfigWindow->mailto_field_Prompt()->{-handle} );
    $lbl_mailverbosity->Hide();
    $form_mailverbosity->Hide();
    Win32::GUI::Hide( $ConfigWindow->lbl_mailverbosity_left()->{-handle} );
    Win32::GUI::Hide( $ConfigWindow->lbl_mailverbosity_right()->{-handle} );

    # Network
    $form_nmap_dolabel->Hide();
    $form_nmap_do->Hide();
    $form_nmap->Hide();
    $form_nmap_max->Hide();
    Win32::GUI::Hide( $ConfigWindow->nmap_max_field_Prompt()->{-handle} );
    Win32::GUI::Hide( $ConfigWindow->nmap_field_Prompt()->{-handle} );
    $btn_browsenmap->Hide();
    $form_nmap_options->Hide();
    Win32::GUI::Hide( $ConfigWindow->nmap_options_field_Prompt()->{-handle} );
    $form_nmap_ulabel->Hide();
    $form_nmap_u->Hide();
    $form_netmap_url->Hide();
    Win32::GUI::Hide( $ConfigWindow->netmap_url_field_Prompt()->{-handle} );
    $form_mapfloor->Hide();
    Win32::GUI::Hide( $ConfigWindow->mapfloor_field_Prompt()->{-handle} );

    # Patch
    $form_patch_dolabel->Hide();
    $form_patch_do->Hide();
    $lbl_patch->Hide();
    $form_patchdir_override->Hide();
    Win32::GUI::Hide(
        $ConfigWindow->patchdir_override_field_Prompt()->{-handle} );
    $btn_browsepatchdir->Hide();
    $lbl_cullvulnsaggression->Hide();
    $form_cullvulnsaggression->Hide();
    Win32::GUI::Hide(
        $ConfigWindow->lbl_cullVulnsaggression_left()->{-handle} );
    Win32::GUI::Hide(
        $ConfigWindow->lbl_cullVulnsaggression_right()->{-handle} );
    $lbl_cullvulnsaggression2->Hide();
    $form_cullundetectedvulns->Hide();
    $lbl_cullundetectedvulns->Hide();

    # Maint
    $form_deletiondays->Hide();
    Win32::GUI::Hide( $ConfigWindow->deletiondays_field_Prompt()->{-handle} );
    $lbl_update->Hide();
    $form_update->Hide();
    Win32::GUI::Hide( $ConfigWindow->lbl_update_left()->{-handle} );
    Win32::GUI::Hide( $ConfigWindow->lbl_update_right()->{-handle} );
    $lbl_showsystray->Hide();
    $form_showsystray->Hide();
    $lbl_dbreindex_do->Hide();
    $form_dbreindex_do->Hide();
    $form_proxy_server->Hide();
    Win32::GUI::Hide( $ConfigWindow->proxy_server_field_Prompt()->{-handle} );
    $form_proxy_user->Hide();
    Win32::GUI::Hide( $ConfigWindow->proxy_user_field_Prompt()->{-handle} );
    $form_proxy_pass->Hide();
    Win32::GUI::Hide( $ConfigWindow->proxy_pass_field_Prompt()->{-handle} );
    return 0;
}
###############################################################################

## Handle click of the Okay button ############################################
sub ConfigWindowDefault_Click {

    # Read my variables
    $PATCHDIR            = $form_patchdir_override->GetLine(0);
    $mailserver          = $form_mailserver->GetLine(0);
    $mailfrom            = $form_mailfrom->GetLine(0);
    $mailto              = $form_mailto->GetLine(0);
    $deletiondays        = $form_deletiondays->GetLine(0);
    $nmap_do             = $form_nmap_do->Checked();
    $dbreindex_do        = $form_dbreindex_do->Checked();
    $patch_do            = $form_patch_do->Checked();
    $nmap                = Win32::GetShortPathName( $form_nmap->GetLine(0) );
    $nmap_options        = $form_nmap_options->GetLine(0);
    $nmap_unidentified   = $form_nmap_u->Checked();
    $netmap_url          = $form_netmap_url->GetLine(0);
    $nmap_max            = $form_nmap_max->GetLine(0);
    $mapfloor            = $form_mapfloor->GetLine(0);
    $showsystray         = $form_showsystray->Checked();
    $mailverbosity       = $form_mailverbosity->GetPos();
    $update              = $form_update->GetPos();
    $CullVulnsAggression = $form_cullvulnsaggression->GetPos();

    # read proxy values
    $proxy_server = $form_proxy_server->GetLine(0);
    $proxy_user   = $form_proxy_user->GetLine(0);
    $proxy_pass   = $form_proxy_pass->GetLine(0);

    if ($DEBUG) {
        &LogDebug(
                "ConfigWindowDefault_Click: Okay clicked in ConfigWindow, read "
              . "mailserver $mailserver, "
              . "mailfrom $mailfrom, "
              . "mailto $mailto, "
              . "deletiondays $deletiondays, "
              . "mailverbosity $mailverbosity" );
    }
    $ConfigWindow->Hide();
    return -1;
}

sub ConfigWindowCancel_Click {
    if ($DEBUG) {
        &LogDebug("ConfigWindowDefault_Click: Cancel clicked in ConfigWindow");
    }

    &Log("$prog $VERSION exiting");

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

sub ConfigWindowBrowseNMAP_Click {
    if ($DEBUG) { &LogDebug("ConfigWindowDefault_Click: BrowseNMAP clicked"); }

    my $target = Win32::GUI::GetOpenFileName(
        -title  => "Browse filesystem",
        -file   => "\0" . " " x 256,
        -owner  => $ConfigWindow,
        -filter => [
            "Programs (*.exe)" => "*.exe",
            "All files", "*.*",
        ],

    );

    $target = Win32::GetShortPathName($target);
    if ($target) {
        $form_nmap->Text("$target");
    }
    return 0;
}

sub ConfigWindowNMAPDo_Click {
    if ( $form_nmap_do->GetCheck() ) {
        $form_nmap->Enable();
        $form_nmap_u->Enable();
        $form_nmap_options->Enable();
    }
    else {
        $form_nmap->Disable();
        $form_nmap_u->Disable();
        $form_nmap_options->Disable();
    }
    return 0;
}

sub ConfigWindowPatchDo_Click {
    if ( $form_patch_do->GetCheck() ) {
        $form_patchdir_override->Enable();
        $btn_browsepatchdir->Enable();
    }
    else {
        $form_patchdir_override->Disable();
        $btn_browsepatchdir->Disable();
    }
    return 0;
}

sub ConfigWindow_Resize {
    $ConfigWindowsb->Move( 0,
        $ConfigWindow->ScaleHeight - $ConfigWindowsb->Height );
    $ConfigWindowsb->Resize( $ConfigWindow->ScaleWidth,
        $ConfigWindowsb->Height );
    return 0;
}

sub ConfigWindowMailAuth_Click {
    $oldCursor = Win32::GUI::SetCursor($waitCursor);    #show hourglass ...
    &MailAuth_Show;
    return 0;
}

sub ConfigWindowMailTest_Click {

    # Read my variables
    $mailserver = $form_mailserver->GetLine(0);
    $mailfrom   = $form_mailfrom->GetLine(0);
    $mailto     = $form_mailto->GetLine(0);

    if ( $mailserver && $mailfrom && $mailto ) {
        $oldCursor = Win32::GUI::SetCursor($waitCursor);    #show hourglass ...
        $mailmessage = "This is a test message from $prog $VERSION.";
        &SendEmail;
        $mailmessage = "";
        Win32::GUI::MessageBox(
            0,
            "Sent an email to $mailto from $mailfrom via $mailserver.",
            "Test message sent", 32
        );
        Win32::GUI::SetCursor($oldCursor);    #show previous arrow cursor again
    }
    else {
        Win32::GUI::MessageBox(
            0,
            "Send an email to $mailto from $mailfrom via $mailserver?",
            "Not so ready yet", 32
        );
    }
    return 0;
}
###############################################################################

## Get Mail authorization Window ##############################################

sub MailAuth_Show {

    my $leftmargin   = 120;
    my $rightmargin  = 25;
    my $bottommargin = 50;
    my $nexthoriz    = 5;

    # Should have a server name by now.
    $mailserver = $form_mailserver->GetLine(0);
    if ( !$mailserver ) {
        Win32::GUI::MessageBox(
            0,
            "Exactly which server were you thinking of authenticating to?",
            "Not so ready yet", 32
        );
        return 0;
    }

    # Find what auth_types are supported
    my $smtp_auth_test = Net::SMTP_auth->new($mailserver);
    if ( !$smtp_auth_test ) {
        Win32::GUI::MessageBox(
            0,
            "Can't connect to $mailserver",
            "Not so ready yet", 32
        );
        return 0;
    }
    my $auth_types = $smtp_auth_test->auth_types;
    if ($DEBUG) {
        &LogDebug("MailAuthShow: $mailserver supports auth types: $auth_types");
    }
    my @mail_auth_options;
    if ($auth_types) {
        @mail_auth_options = split( ' ', $auth_types );
    }
    else {
        Win32::GUI::MessageBox(
            0,
            "Can't get a list of authentication types from $mailserver",
            "Not so ready yet", 32
        );
        return 0;
    }

    # Build the window
    $MailAuth = Win32::GUI::Window->new(
        -name        => 'MailAuth',
        -text        => 'ldms_core mail configuration',
        -width       => 450,
        -height      => 400,
        -class       => $ldms_core_class,
        -dialogui    => 1,
        -onTerminate => \&MailAuth_Terminate,
        -onResize    => \&MailAuth_Resize,
    );

    # Add some stuff
    $lbl_mailinstructions = $MailAuth->AddLabel(
        -name => "lbl_MailAuth",
        -text => "Please enter the authorization for your email server.",
        -pos  => [ 5, $nexthoriz ],
        -size => [ 300, 20 ],
    );

    # Begin mail_auth_user field
    $form_mail_auth_user = $MailAuth->AddTextfield(
        -name    => "mail_auth_user_field",
        -prompt  => "User name: ",
        -tabstop => 1,
        -text    => $mail_auth_user,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    # End mail_auth_user field

    # Begin mail_auth_pass field
    $form_mail_auth_pass = $MailAuth->AddTextfield(
        -name     => "mail_auth_pass_field",
        -prompt   => "Password: ",
        -tabstop  => 1,
        -password => 1,
        -text     => $mail_auth_user,
        -pos      => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 200, 20 ],
    );

    # End mail_auth_user field

    # Begin mail_auth_type field
    $lbl_mail_auth_type = $MailAuth->AddLabel(
        -name => "lbl_MailAuthType",
        -text => "Type: ",
        -pos  => [ $leftmargin - 50, $nexthoriz += 25 ],
        -size => [ 70, 20 ],
    );

    $form_mail_auth_type = $MailAuth->AddCombobox(
        -name         => "mail_auth_type_field",
        -tabstop      => 1,
        -dropdownlist => 1,
        -vscroll      => 1,
        -pos          => [ $leftmargin + 50, $nexthoriz ],
        -size         => [ 75, 120 ],
    );
    foreach my $auth_type (@mail_auth_options) {

        # skip it if it's GSSAPI -- support for that protocol won't build on
        # Win32 at this time. http://matrix.cpantesters.org/?dist=GSSAPI+0.13
        if ( $auth_type =~ m/(?!gssapi)/i ) {
            $form_mail_auth_type->AddString($auth_type);
            if ($DEBUG) {
                &LogDebug(
                    "MailAuthShow: MailAuth window added auth type: $auth_type"
                );
            }
        }
    }

    # End mail_auth_type field

    # Begin button row
    $btn_MailAuthDefault = $MailAuth->AddButton(
        -name    => 'MailAuthDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,                   # Give button darker border
        -ok      => 1,                   # press 'Return' to click this button
        -pos => [ 75, $nexthoriz += 25 ],
        -size    => [ 60, 20 ],
        -onClick => \&MailAuthDefault_Click,
    );

    $btn_MailAuthCancel = $MailAuth->AddButton(
        -name    => 'MailAuthCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                        # press 'Esc' to click this button
        -pos     => [ 150, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&MailAuthCancel_Click,
    );

    $btn_MailAuthHelp = $MailAuth->AddButton(
        -name    => 'MailAuthHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 225, $nexthoriz ],
        -size    => [ 60, 20 ],
        -onClick => \&MailAuthHelp_Click,
    );

    # End button row

    $MailAuthsb = $MailAuth->AddStatusBar();
    if ($updatemessage) {
        $MailAuthsb->Text($updatemessage);
    }

    # calculate its size
    $MailAuthncw = $MailAuth->Width() - $MailAuth->ScaleWidth();
    $MailAuthnch = $MailAuth->Height() - $MailAuth->ScaleHeight();
    $MailAuthw =
      $leftmargin +
      $lbl_mailinstructions->Width() +
      $rightmargin +
      $MailAuthncw;
    $MailAuthh = $nexthoriz + $bottommargin + $MailAuthnch;

    # Don't let it get smaller than it should be
    $MailAuth->Change( -minsize => [ $MailAuthw, $MailAuthh ] );

    # calculate its centered position
    # Assume we have the main window size in ($macw, $mach) as before
    $MailAuthwx = ( $dw - $MailAuthw ) / 2;
    $MailAuthwy = ( $dh - $MailAuthh ) / 2;

    # Resize, position and display
    $MailAuth->Resize( $MailAuthw, $MailAuthh );
    $MailAuth->Move( $MailAuthwx, $MailAuthwy );

    Win32::GUI::SetCursor($oldCursor);    #show previous arrow cursor again

    $MailAuth->Show();
    return 0;
}

sub MailAuth_Terminate {
    return -1;
}

sub MailAuth_Resize {
    $MailAuthsb->Move( 0, $MailAuth->ScaleHeight - $MailAuthsb->Height );
    $MailAuthsb->Resize( $MailAuth->ScaleWidth, $MailAuthsb->Height );
    return 0;
}

sub form_mail_auth_type_GotFocus {
    $form_mail_auth_type->ShowDropDown(1);
    return 0;
}

sub MailAuthDefault_Click {

    if ($DEBUG) {
        &LogDebug("MailAuthDefault_Click: Okay clicked in MailAuthWindow");
    }

    # Read my variables
    $mail_auth_user = $form_mail_auth_user->GetLine(0);
    $mail_auth_pass = $form_mail_auth_pass->GetLine(0);
    $mail_auth_type =
      $form_mail_auth_type->Text(
        $form_mail_auth_type->GetString( $form_mail_auth_type->SelectedItem ) );
    if ($DEBUG) {
        &LogDebug(
"MailAuthDefault_Click: read $mail_auth_user, mail_auth_pass, $mail_auth_type from user input"
        );
    }
    $MailAuth->Hide();
    return 0;
}

sub MailAuthCancel_Click {
    if ($DEBUG) {
        &LogDebug("MailAuthDefault_Click: Cancel clicked in MailAuthWindow");
    }
    $MailAuth->Hide();
    return 0;
}

sub MailAuthHelp_Click {
    if ($DEBUG) {
        &LogDebug("MailAuthDefault_Click: Help clicked in MailAuthWindow");
    }
    open_browser(
        'http://www.droppedpackets.org/scripts/ldms_core/ldms_core-manual');

    return 0;
}
###############################################################################

## System tray icon subroutines ###############################################
sub EnableSystray {
    $systrayicon = new Win32::GUI::Icon('ldms_core.ico');
    $systraymain = Win32::GUI::Window->new(
        -name    => 'ldms_core_systray',
        -text    => 'ldms_core_systray',
        -width   => 20,
        -height  => 20,
        -visible => 0,
    );
    $systraymain->Enable();
    $popupMenu = Win32::GUI::Menu->new(
        "Options" => "Options",
        ">Manual" => {
            -name    => "Manual",
            -onClick => sub {
                open_browser(
'http://www.droppedpackets.org/scripts/ldms_core/ldms_core-manual'
                );
              }
        },
        ">Exit" => {
            -name    => "Exit",
            -onClick => \&systrayexit
        }
    );
    $systraynotify = $systraymain->AddNotifyIcon(
        -name         => "ldms_core_systray",
        -icon         => $systrayicon,
        -tip          => "$prog $VERSION running\n",
        -balloon_icon => "info",
        -onClick      => \&systraymenu,
        -onRightClick => \&systraymenu,

    );
    return 0;
}

sub ChangeBalloon {

    # Is the user trying to kill us?
    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

    # If systray support is off, just leave now
    if ( $showsystray == 0 ) { return 0; }

    # item can be title or tip
    # icon is fixed as "info"
    my $item  = shift;
    my $value = shift;
    $systraynotify->Change( "-balloon_$item" => $value );

    # this is to change the hovering tooltip
    $systraynotify->Change( -tip => $value, );
    $systraynotify->ShowBalloon(0);
    $systraynotify->ShowBalloon(1);
    return 0;
}

sub systraymain_Terminate {
    &LogDie("Killed by user");
    return 0;
}

sub systraymenu {
    $systraymain->TrackPopupMenu( $popupMenu->{Options} );
    return 1;
}

sub systrayexit {
    &LogDie("Killed by user");
    return 0;
}
## End of Windowing Subroutines  ############################################

1;
__END__
