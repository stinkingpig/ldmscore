#############################################################################
# ldms_core.pl                                                              #
# (c) 2005-2008 Jack Coates, jack@monkeynoodle.org                          #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/                                            #
#############################################################################

# TODO -- List uninstallable patches?
# TODO -- group patches by vendor?
# TODO -- Topology map. Gateways become nodes, devices sharing gateways are
# grouped in clouds around them, subnet masks decide size of circle.
# Core's gateway is in the center and traceroute hops to the other gateways
# are used to define the map. Use Perl::Graph to generate HTML?
# select defgtwyaddr,count(address) from tcp where nullif(address,'') is not null group by defgtwyaddr
# TODO -- Check scheduled tasks and policies
# TODO -- switch to MIME email so I can send multipart messages with attachments. Text::Table?
# TODO -- plot non-RFC1918 addresses on a map
# TODO -- purty Charts, http://search.cpan.org/src/CHARTGRP/Chart-2.4.1/README
# TODO -- Find a way to detect stuck LPM Event Listeners
# TODO -- convert into a long-running service?
# TODO -- Cull software definitions with no installations
# TODO -- import ldms_deleteusers, auto-reassign to single user

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use Env;
use Cwd 'abs_path';
use DBI;
use Crypt::Blowfish;
use Win32;
use Win32::File::VersionInfo;
use Win32::FileOp;
use Win32::GUI();
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1 );
use Win32::API;
use Win32::API::Prototype;
use Win32::EventLog;
use Win32::EventLog::Message;
use Win32::Security::SID;
use Win32::WebBrowser;
use Win32::Service;
use POSIX qw(floor);
use File::Copy;
use File::Remove qw(trash);
use Archive::Zip qw( :ERROR_CODES );
use Net::SMTP;
use Net::SMTP_auth;
use Net::Ping;
use Sys::Hostname;
use Nmap::Parser;
use RRD::Simple;
use LWP::Simple qw(!head !getprint !getstore !mirror);
use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;

#############################################################################
# Variables                                                                 #
#############################################################################
our %A;    # get commandline switches into %A
for ( my $ii = 0 ; $ii < @ARGV ; ) {
    last if $ARGV[$ii] =~ /^   # beginning of the line
                           --  # two dashes
                          $    # end of the line
                          /x;
    if (
        $ARGV[$ii] !~ /^      # beginning of the line
                        -{1,2} # one or two dashes
                        (.*)   # anything else goes in $1
                        $      # end of the line
                        /x
      )
    {
        $ii++;
        next;
    }
    my $arg = $1;
    splice @ARGV, $ii, 1;
    if (
        $arg =~ /^            # beginning of the line
                  ([\w]+)      # any word goes in $1
                  =(.*)        # = anything goes in $2
                  $            # end of the line
                  /x
      )
    {
        $A{$1} = $2;
    }
    else {
        $A{$1}++;
    }
}

# It takes a long time to do all this preprocessing stuff before setup starts,
# so I want to show an hourglass cursor.
my ( $loadImage, $waitCursor, $oldCursor );
if ( $A{setup} ) {
    $loadImage =
      new Win32::API( 'user32', 'LoadImage', [ 'N', 'N', 'I', 'I', 'I', 'I' ],
        'N' )
      or die 'cannot find LoadImage function';
    $waitCursor = $loadImage->Call( 0, 32514, 2, 0, 0, 0x8040 );
    $oldCursor = Win32::GUI::SetCursor($waitCursor);    #show hourglass ...
}

( my $prog = $0 ) =~ s/^         # command line from the beginning
                       .*[\\\/]  # without any slashes
                       //x;
my $ver = "3.1.7";

my $skipupdate = $A{skipupdate};

# Now we're running for real, so let's show off
&EnableSystray;

# Prepare logging system
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";

# Get the window handle so we can hide it
my ($DOS) = Win32::GUI::GetPerlWindow();

my $DEBUG = $A{d} || $A{debug} || 0;
my $DEBUGFILE;

if ( !$DEBUG ) {

    # Hide console window
    Win32::GUI::Hide($DOS);
}

if ($DEBUG) {

    my $logfile = $prog . "-" . $ver . "-" . &genfilename . ".log";
    open( $DEBUGFILE, '>', "$logfile" )
      or &LogDie("Can't open file $logfile : $!\n");
    my @cli = %A;
    &LogDebug("$prog $ver starting in debug mode. $0 @cli");
}

# I like to read the event viewer
my $EventViewerhandle = Win32::EventLog->new( "Application", $COMPUTERNAME )
  or &LogWarn("Initialization: Can't open Application EventLog");

# Configuration variables
my ( $ldmain, $SCANDIR, $STORAGEDIR, $PATCHDIR, $ldscan, $xddscan, $sdscan );
my ( $db_type, $db_user, $db_pass, $db_name,   $db_instance, $reportdir );
my ( $sql,     $dbh,     $sth );
my ( @rows,    %nodes,   @files,   @patchurls, @patchcounts, @autofixcounts );
my ( $mailserver, $mailfrom, $mailto, $mailmessage, $sendemail );
my ( $mail_auth_user, $mail_auth_pass, $mail_auth_type );
my ( $deletiondays, $deldays ) = 0;
my ( $url, $content, $onlineversion, $myversion );
my $mailhostname = hostname;
my ( $DIR, $FILE );

# GUI variables
my ( $ldms_core_icon, $ldms_core_class );
my ( $systrayicon, $systraymain, $popupMenu, $systraynotify );

# Setup variables
my (
    $main,                   $lbl_Instructions, $form_db_instance,
    $form_db_name,           $form_db_user,     $form_db_pass,
    $lbl_db_type,            $form_db_type,     $db_type_binary,
    $form_patchdir_override, $count,            $cfg_params,
    $btn_Default,            $btn_Cancel,       $btn_Help,
    $btn_DBInfo,             $sb
);
my (
    $second,            $lbl_email,        $form_mailserver,
    $form_mailfrom,     $form_mailto,      $form_deletiondays,
    $btn_seconddefault, $btn_secondcancel, $sb2,
    $form_nmap,         $form_nmap_u,      $form_nmap_options,
    $form_nmap_ulabel,  $btn_mailauth,     $btn_secondHelp
);
my (
    $mailauth,            $lbl_mailinstructions, $form_mail_auth_user,
    $form_mail_auth_pass, $btn_mailauthDefault,  $btn_mailauthCancel,
    $btn_mailauthHelp,    $mailauthsb,           $form_mail_auth_type,
    $lbl_mail_auth_type,  $btn_mailtest
);
my ( $w, $h, $ncw, $nch, $dw, $dh, $desk, $wx, $wy );
my (
    $mailauthw,   $mailauthh,  $mailauthncw,
    $mailauthnch, $mailauthwx, $mailauthwy
);

#Stats gathering variables
my (
    $deviceid,            $devicename,      $allmachines,
    @dupmachines,         $dbscans,         $dbscansweek,
    $allmachines_udd,     $dbscans_udd,     $source,
    $vulnlife,            $dbscansweek_udd, @dupaddresses,
    $daypercent,          $weekpercent,     $forcedpercent,
    $forcedfullscans,     $pkhasherrors,    $vulndays,
    $daypercent_udd,      $weekpercent_udd, $vulnhours,
    $vulnminutes,         $vulnseconds,     $vulnmessage,
    $supercededvulncount, @supercededvulns, $hashpercent,
    @dualboots,           %rtn
);
my (
    $osupdates, $macupdates,  $vendorupdates, $udddeletes,
    $goodcount, $recentvulns, $tmpcount,      $dupcount,
    $vulncount, $patchtotal,  $autofixtotal
) = 0;
my (
    $patchcountsreport, $autofixreport, $patchurlsreport, $dupreport,
    $dualbootreport,    $ALERTDIR,      $purgemarker,     $updatemessage
);
my ( $scancount, $xddcount, $sdcount, $alertcount ) = "UNKNOWN";

# service checking variables
my ( @ld_services, $serviceloglist, %status, $service, $restart );
my ( $downcount, $servicecount ) = 0;

# NMAP Variables and defaults
my ( $np,      @row,        $nmap_unidentified, $maxnmapcount );
my ( @Address, @Address_np, $oldmac,            $oldman );
my $nmap         = Win32::GetShortPathName("C:/Program Files/nmap/nmap.exe");
my $nmap_options = "-A -T4 -P0 -n";

# Prepare encryption system
my ( @SIDTYPE, $system, $account, $Blowfish_Key, $Blowfish_Cipher );
&PrepareCrypto;

# Read the registry
&ReadRegistry;

# Prepare the RRD files
my ( $ldmsrrd, $ldmsrrdfile, $ldmsrrd_udd, $ldmsrrdfile_udd, $ldssrrd,
    $ldssrrdfile, $ldssrrd_life, $ldssrrdfile_life );
$ldmsrrdfile      = "ldmsstats.rrd";
$ldmsrrdfile_udd  = "ldmsstats_udd.rrd";
$ldssrrdfile      = "ldssstats.rrd";
$ldssrrdfile_life = "ldssstats_life.rrd";
&PrepareRRD;

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
if ( $A{m_user} )       { $mail_auth_user    = $A{m_user}; }
if ( $A{m_pass} )       { $mail_auth_pass    = $A{m_pass}; }
if ( $A{m_type} )       { $mail_auth_type    = $A{m_type}; }
if ( $A{x} )            { $deletiondays      = $A{x}; }
if ( $A{nmap} )         { $nmap              = $A{nmap}; }
if ( $A{nmap_options} ) { $nmap_options      = $A{nmap_options}; }
if ( $A{u} )            { $nmap_unidentified = $A{nmap_unidentified}; }

my (
    $patchcount,    $nmapcount, $trashcount, $renamecount,
    $compresscount, $totalsize, $alertpurges
);
my $UNDO = $A{u};
my ( $newname, $file, $marker );
my $time = eval {
    time() - eval { $deletiondays * 86400 };
};
my $usage = <<"EOD";

Usage: $prog [-d] [-u] [-h] [-x=10] -db_type=[SQL|ORA] 
			 -db_user=USER -db_pass=PASS -db_name=DB [-db_instance=SERVER] 
			 -m=ADDRESS -f=ADDRESS -s=SERVER -m_user=USER -m_pass=PASS
             -m_type=TYPE
             [-nmap="x:\\foo"] [-nmap_options="-bar -baz"]
			 
	-d(ebug)	 debug
	-x=[number]	 delete scans and patches more than [number] days old. Files go
                  to the Recycle Bin. Default is off. This option also controls
                  removal of unmanaged device records which are no longer on
                  the network.
	-m=me\@here	 email address to send output report to.
	-f=ld\@here	 email address to send output report from.
	-s=host		 email server to send output report through.
    -m_user=user email server username for TLS authentication.
    -m_pass=pass email server password for TLS authentication.
    -m_type=type email server authentication type for TLS authentication.
	-setup		 setup the product.
	-h(elp)		 this display
	db_instance  is only necessary for SQL Servers, Oracle environments will
                  pick it up from a properly configured client.
	nmap         By default, "C:/Program Files/nmap/nmap.exe"
	nmap_options By default, "-A T4 -P0 -n
	-u			 Should NMAP rescan devices it couldn't identify earlier?
	-skipupdate  Disable online checking for an updated version

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program will rename the scan files in ErrorScan to the computer name, for
easier troubleshooting, compress old scans in the Storage directory, and 
delete patches that are no longer needed. It also checks a few important 
thresholds, and uses NMAP fingerprinting to properly identify the OS of the 
machines in Unmanaged Devices. It will email if there's something important.
The latest version lives at http://www.droppedpackets.org/scripts/ldms_core.

EOD

#############################################################################
# Main Loop                                                                 #
#############################################################################
croak $usage if $A{h} or $A{help};

# Check to see if there's an update available
&IsUpdate;

# Should we do setup?
if ( $A{setup} ) {
    &Log("$prog $ver starting in setup mode");
    &Setup;
    &Log("$prog $ver exiting");
    exit 0;
}

# Set the process priority so we don't murderize the CPU.
&DropCPU;

# What's the LANDesk version we're working with?
my $ldms_version = &GetLDVersion;

# Check to see if NMAP is available; otherwise, we can skip its needs
my $nmap_present = 1;
if ( !-e $nmap ) {

    # If there's no NMAP at all, do not warn, as they may not have wanted it.
    if ($DEBUG) {
        &LogDebug("Cannot find NMAP at $nmap\n");
    }
    $nmap_present = 0;
}

# Things are okay so far...
$sendemail = 0;

# Work on the unmanaged nodes
&change_balloon( "tip", "Culling unmanaged nodes" );
&CullUDD;

# If NMAP is around, let's go ahead and use it.
if ($nmap_present) {
    &change_balloon( "tip", "Network scanning to update Unmanaged Devices" );
    &GetNMAP;
}

# Read all our database information now
&change_balloon( "tip", "Gathering management information from the database" );
&GetLDMSData;
&change_balloon( "tip", "Gathering security information from the database" );
&GetLDSSData;

# Do all that fancy calculation stuff
&change_balloon( "tip", "Calculating statistics" );
&DoInventoryMath;
&DoUDDMath;
&DoPatchMath;

# Clear out duplicate network addresses
if (@dupaddresses) {

    # Something goofy going on with undefined values
    if ( &IsIPAddress( $dupaddresses[0] ) ) {
        &change_balloon( "tip", "Culling dead IP addresses" );
        &CullIPs;
    }
}

# Clear out old alerts
&change_balloon( "tip", "Culling old alert messages" );
&CullAlerts;

# Report all those stats
&change_balloon( "tip", "Reporting LDMS statistics" );
&ReportLDMSStats;

# Check for exceeded thresholds
&change_balloon( "tip", "Checking for exceeded thresholds" );
&CountPendingScans();

# Report on LDSS Statistics
&change_balloon( "tip", "Reporting LDSS statistics" );
&ReportLDSSStats;

# Work on superceded vulnerabilities
&change_balloon( "tip", "Culling superceded vulnerabilities" );
&CullVulns;

# Work on the patch files
&change_balloon( "tip", "Culling patches" );
&CullPatches;

# Work on the scan files
&change_balloon( "tip", "Culling stale temporary scan files" );
&CullTMP;
&change_balloon( "tip", "Renaming and culling scan files" );
&CullScanFiles;
&change_balloon( "tip", "Compressing stored scan files" );
&CompressStorageFiles;

# Check that all the services are running
&change_balloon( "tip", "Checking service status" );
&ServiceCheckLoop;

# Do we need to send a message?
if ( $sendemail == 1 || $DEBUG ) {
    &change_balloon( "tip", "Sending email" );
    &Log("Sending email report to $mailto.");
    &SendEmail;
}

&Log("$prog $ver exiting.");

# Write the output into the report directory.
&WriteReport;

# Restore console window
Win32::GUI::Show($DOS);

# clean up the tray icon
$systraymain->systraynotify->Remove();

exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################

# Utility Subroutines #######################################################
#
### PrepareCrypto subroutine ################################################
# Set up the cryptographic subsystem and ensure that we have a good key
sub PrepareCrypto {
    @SIDTYPE = qw(
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
    $system       = Win32::NodeName;
    $account      = Win32::LoginName;
    $Blowfish_Key = &GetSID( $system, $system );
    if ($DEBUG) { &LogDebug("Machine SID is $Blowfish_Key\n"); }
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

### Directory maker #########################################################
sub makeDir {
    my $target = shift;
    if ( -e $target ) {

        # It already exists, my work here is through. I'm still warning and
        # returning 1 because I shouldn't have been called
        &LogWarn("makeDir called uselessly for $target");
        return 1;
    }
    else {
        mkdir( $target, "755" )
          or &LogDie("makeDir failed to make $target - $!");
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
sub zeropad {

    my $ip = shift;

    # Pad IP Addresses with zeroes for use in LANDesk database
    my $return = sprintf( "%03d.%03d.%03d.%03d", split /\./, $ip );
    return $return;
}

### IsIPAddress subroutine ##################################################
# Shamelessly lifted from http://www.perlmonks.org/?node_id=396001
sub IsIPAddress {
    my $target = shift;
    my $range  = qr/^
    (
     (?:                               # first 3 octets:
      (?: 2(?:5[0-5]|[0-4][0-9])\. )   # 200 - 255
      |                                # or
      (?: 1[0-9][0-9]\. )              # 100 - 199
      |                                # or
      (?: (?:[1-9][0-9]?|[0-9])\. )    # 0 - 99
     )
     {3}                               # above: three times
 
    (?:                                # 4th octet:
     (?: 2(?:5[0-5]|[0-4][0-9]) )      # 200 - 255
      |                                # or
     (?: 1[0-9][0-9] )                 # 100 - 199
      |                                # or
     (?: [1-9][0-9]?|[0-9] )           # 0 - 99
    )
 
    $)
    /x;
    if ( $target =~ /$range/ ) {

        # This is an IP
        return 1;
    }
    else {

        # This is not an IP
        return 0;
    }
}

### DropCPU subroutine ######################################################
sub DropCPU {
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
        &Log("Unable to set master PID scheduling priority to low.");
    }
    else {
        &Log("$prog $ver starting, scheduling priority set to low.");
    }
    CloseHandle($hProcess);
    return 0;
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

### Generate file names based on the date ####################################
sub genfilename {
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
      localtime(time);
    my $return = sprintf "%04d%02d%02d-%02d%02d%02d", $year + 1900, $mon + 1,
      $mday, $hour, $min, $sec;
    return $return;
}

### Format numbers with commas ################################################
sub commify {

    #          s/^         # from the beginning of the line
    #          (-?\d+)     # numbers, even if negative
    #          (\d{3})     # group every three digits
    #          /$1,$2      # put a comma between the groups of three
    local ($_) = shift;
    1 while s/^(-?\d+)(\d{3})/$1,$2/x;
    return $_;
}

### ASCII to Integer subroutine ###############################################
sub atoi {
    my $t = 0;
    foreach my $d ( split( //, shift() ) ) {
        $t = $t * 10 + $d;
    }
    return $t;
}

### ConvertSeconds subroutine ##############################################
sub ConvertSeconds {
    my $secs = shift;
    my ( $days, $hours, $minutes, $seconds ) = 0;
    if ($DEBUG) { &LogDebug("ConvertSeconds received $secs"); }
    if ($secs) {
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
    }
    if ($DEBUG) {
        &LogDebug("ConvertSeconds returned $days, $hours, $minutes, $seconds");
    }
    return $days, $hours, $minutes, $seconds;
}

### IsUpdate subroutine #####################################################
sub IsUpdate {

    if ($skipupdate) {
        &Log("Update checking disabled via command line.");
        return 0;
    }
    $url     = 'http://www.droppedpackets.org/scripts/ldms_core/version';
    $content = get $url;
    if ( defined($content) ) {
        $myversion = $ver;
        $content =~ m{<p>latest version is ([\d.]+)<br /></p>};
        my $onlineversion = $1;

        if ($DEBUG) { &LogDebug("onlineversion is $onlineversion"); }

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $onlineversion =~ s/\.?       # substitute any dot
                            (?=[0-9]) # keep any number
                            //gx;
        $myversion =~ s/\.?       # substitute any dot
                            (?=[0-9]) # keep any number
                            //gx;
        if ( &atoi($onlineversion) > &atoi($myversion) ) {
            $updatemessage =
"Update available at http://www.droppedpackets.org/scripts/ldms_core";
            &LogWarn($updatemessage);
        }
        if ( &atoi($onlineversion) < &atoi($myversion) ) {
            $updatemessage = "You're running beta code. "
              . "Please keep me informed via jack\@monkeynoodle.org.";
            &LogWarn($updatemessage);
        }
        return 0;
    }
    else {
        &Log("Couldn't get $url");
        return 1;
    }
}

### GetSingleString ########################################################
# Database routine intended to retrieve a single string
sub GetSingleString {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        $sth = $dbh->prepare($sql) or &LogWarn("$sql caused $DBI::errstr\n");

        # Is the user trying to kill us?
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        $sth->execute               or &LogDie("$sql caused $DBI::errstr\n");
        my $output = &Trim( $sth->fetchrow() );
        $sth->finish;
        return $output;
    }
    else {
        &LogDie("GetSingleString routine called with no database handle!");
    }
}

### GetSingleArray ########################################################
# Database routine intended to retrieve a single array
sub GetSingleArray {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        my @output;
        $sth = $dbh->prepare($sql) or &LogWarn("$sql caused $DBI::errstr\n");

        # Is the user trying to kill us?
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        $sth->execute               or &LogDie("$sql caused $DBI::errstr\n");
        while ( @rows = $sth->fetchrow_array() ) {
            if ( defined( $rows[0] ) ) {
                push( @output, &Trim( $rows[0] ) );
            }
        }
        $sth->finish;
        return @output;
    }
    else {
        &LogDie("GetSingleArray routine called with no database handle!");
    }
}

### GetTwoColumnList ########################################################
# Database routine intended to retrieve a two column list ( Foo - Bar )
sub GetTwoColumnList {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        my @output;
        $sth = $dbh->prepare($sql) or &LogWarn("$sql caused $DBI::errstr\n");

        # Is the user trying to kill us?
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        $sth->execute               or &LogDie("$sql caused $DBI::errstr\n");
        while ( @rows = $sth->fetchrow_array() ) {
            push( @output, &Trim( $rows[0] ) . " - " . &Trim( $rows[1] ) );
            Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        }
        $sth->finish;
        return @output;
    }
    else {
        &LogDie("GetTwoColumnList routine called with no database handle!");
    }
}

### DoDBAction #############################################################
# Commit database actions that don't expect results
sub DoDBAction {
    if ($dbh) {

        # Go ahead
        my $input = shift;
        $sth = $dbh->prepare($sql) or &LogWarn("$sql caused $DBI::errstr\n");
        # Is the user trying to kill us?
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        $sth->execute               or &LogDie("$sql caused $DBI::errstr\n");
        $sth->finish;
        return 0;
    }
    else {
        &LogDie("DoDBAction routine called with no database handle!");
    }
}

### GetLDVersion subroutine ################################################
sub GetLDVersion {
    my $version =
      GetFileVersionInfo(
        Win32::GetShortPathName( $ldmain . "//ldinv32.exe" ) );
    if ($version) {
        my $ldinv_version = $version->{FileVersion};

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $ldinv_version =~ s/\.?         # substitute any dot
                            (?=[0-9])   # or anything not a number
                            //gx;

        # LANDesk buildmasters keep screwing with the number of ordinals in the
        # version number, so this has grown unreliable with certain patches.
        # If I just use the first two numbers, that should work well enough.
        $ldinv_version = substr( $ldinv_version, 0, 2 );
        $ldinv_version = &atoi($ldinv_version);
        if ($DEBUG) { &LogDebug("LANDesk version is $ldinv_version"); }
        return $ldinv_version;
    }
    else {
        &LogWarn("GetLDVersion Cannot determine LANDesk version!");
        return 1;
    }
}

### Delete a file ############################################################
sub DeleteFile {

    #delete this file, unless DEBUG is set; then just talk
    #about deleting it
    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    my ( $targetfile, $filetime ) = @_;
    if ($DEBUG) {
        $deldays = floor(
            eval {
                eval { time() - $filetime } / 86400;
            }
        );
        &LogDebug( "$targetfile is $deldays days old and no computers "
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

### Service restart subroutine ################################################
sub RestartService {

    my $target = shift;
    &change_balloon( "tip", "Restarting $target" );
    &Log("Stopping $target service.");
    Win32::Service::StopService( '', $target )
      or &LogWarn("RestartService: Having some trouble with $target");

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
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
    if ($DEBUG) { print $DEBUGFILE "LOG  : $msg\n"; }
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
    if ($DEBUG) { print $DEBUGFILE "WARN : $msg\n"; }
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
    if ($DEBUG) { print $DEBUGFILE "ERROR: $msg\n"; }
    $mailmessage .= "ERROR: $msg\n";
    &SendEmail or &Log($mailmessage);
    exit 1;
}

### Logging a Debug item subroutine ###########################################
sub LogDebug {
    my $msg = "DEBUG: " . localtime() . " ";
    $msg .= shift;

    # flush so the logfile won't be buffered
    select $DEBUGFILE;
    $| = 1;
    print $DEBUGFILE "$msg\n";
    $mailmessage .= "$msg\n";
    return 0;
}

### Calculate Inventory percentages ###########################################
sub DoInventoryMath {

    # Do you have machines?
    if ($allmachines) {

        # X% of your machines scanned in today
        if ($dbscans) {
            $daypercent = int( ( $dbscans / $allmachines ) * 100 );

            # Look for public key hash errors
            $pkhasherrors = &CountHashErrors();
            if ($pkhasherrors) {
                $hashpercent = int( ( $pkhasherrors / $dbscans ) * 100 );
                if ( $hashpercent > 10 ) { $sendemail = 1; }
                &Log("$pkhasherrors Public Key hash errors in the last day.");
            }

            # Rescan forced?
            $forcedfullscans = &CountForcedScans();

            # X% of today's scans had full rescans forced on them
            if ($forcedfullscans) {
                $forcedpercent = int( ( $forcedfullscans / $dbscans ) * 100 );
                if ( $forcedpercent > 10 ) { $sendemail = 1; }
                &Log(
                    "$forcedfullscans of today's delta scans were out of sync; "
                      . "new full scans were forced." );
            }
            else {
                $forcedpercent = 0;
            }
        }
        else {
            if ($DEBUG) {
                &LogDebug( "DoInventoryMath doesn't see anything today."
                      . "dbscans=$dbscans" );
            }
        }

        # X% of your machines scanned in this week
        if ($dbscansweek) {
            $weekpercent = int( ( $dbscansweek / $allmachines ) * 100 );
            if ( $weekpercent < 50 ) {
                &Log("Less than half of your machines have scanned in the "
                    . "last seven days; you should consider more frequent "
                    . "scanning to prevent stale data.");
                $sendemail = 1;
            }
        }
    }

    # Do you have duplicates?
    if (@dupmachines) {
        $dupcount  = 0;
        $dupreport = "Duplicate computer records detected:\n";
        foreach my $dup (@dupmachines) {
            $dupreport .= "$dup\n";
            $dupcount++;
        }
        if ($dupcount) {
            $sendemail = 1;
            Log("$dupcount $dupreport");
        }
    }
    if (@dupaddresses) {
        $dupcount  = 0;
        $dupreport = "Duplicate IP Addresses detected:\n";
        foreach my $dup (@dupaddresses) {
            if ( &IsIPAddress($dup) ) {
                $dupreport .= "$dup\n";
                $dupcount++;
            }
        }
        if ($dupcount) {
            $sendemail = 1;
            Log("$dupcount $dupreport");
        }
    }

    # Do you have dual booting machines?
    if (@dualboots) {
        $dupcount       = 0;
        $dualbootreport = "Dual booting machines detected:\n";
        foreach my $dual (@dualboots) {
            $dualbootreport .= "$dual\n";
            $dupcount++;
        }
        if ($dupcount) {
            $sendemail = 1;
            &Log("$dupcount $dualbootreport");
        }
    }
    return 0;
}

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
sub DoPatchMath {

    # Your vulnerabilities live this long
    if ($vulnlife) {
        if ($DEBUG) { &LogDebug("Calculating how long vulns live"); }
        ( $vulndays, $vulnhours, $vulnminutes, $vulnseconds ) =
          &ConvertSeconds($vulnlife);
        $vulnmessage =
          "Vulnerabilities which get patched go unpatched an average of ";
        if ($vulndays) { $vulnmessage .= "$vulndays days"; }
        if ($vulnhours) {
            if ($vulndays) { $vulnmessage .= ", "; }
            $vulnmessage .= "$vulnhours hours";
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
            $vulnmessage .= "$vulnminutes minutes";
        }
        $vulnmessage .= ". Vulnerabilities which go perennially unpatched "
          . "(by LANDesk at least) are not included in this average.";

        if ($vulndays) {
            if ( $vulndays > 50 ) {
                $sendemail = 1;
            }
        }
    }
    else {
        $vulnmessage =
          "Vulnerabilities go unpatched (by LANDesk at least) forever.";
        $sendemail = 1;
    }

    # Total up patch counts and autofix counts
    if (@patchcounts) {
        foreach my $p (@patchcounts) {
            my ($d,$c) = split(/ - /, $p);
            $patchtotal += $c;
        }
    }
    if (@autofixcounts) {
        foreach my $p (@autofixcounts) {
            my ($d,$c) = split(/ - /, $p);
            $autofixtotal += $c;
        }
    }

    return 0;
}

### LDMS Database reading subroutine #########################################
sub GetLDMSData {

    #Get as much done as quickly as possible and close the connection
    # LDMS Specific Information

    # Open the database
    &OpenDB;

    # How many machines are there?
    $sql = "select count(*) from computer where deviceid != 'Unassigned'";
    $allmachines = &GetSingleString($sql);
    if ($DEBUG) { &LogDebug("GetLDMSData, allmachines=$allmachines"); }

    # Are any of them duplicates?
    $sql =
"select distinct computer.devicename from computer inner join computer t1 on "
      . "computer.devicename = t1.devicename where computer.computer_idn <> "
      . "t1.computer_idn order by computer.devicename asc";
    @dupmachines = &GetSingleArray($sql);
    if ($DEBUG) { &LogDebug("GetLDMSData, dupmachines=@dupmachines"); }

    # What about IP Address overlaps?
    $sql =
        "select distinct tcp.address from tcp inner join tcp t1 on "
      . "tcp.address = t1.address where tcp.computer_idn <> t1.computer_idn "
      . "order by tcp.address asc";
    @dupaddresses = &GetSingleArray($sql);
    if ($DEBUG) { &LogDebug("GetLDMSData, dupaddresses=@dupaddresses"); }

    # Detect dual-booting systems
    $sql =
"select distinct compsystem.serialnum from compsystem inner join compsystem "
      . "t1 on compsystem.serialnum = t1.serialnum where compsystem.computer_idn <> "
      . "t1.computer_idn order by compsystem.serialnum asc";
    @dualboots = &GetSingleArray($sql);
    if ($DEBUG) { &LogDebug("GetLDMSData, dualboots=@dualboots"); }

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
    if ($DEBUG) { &LogDebug("GetLDMSData, dbscans=$dbscans"); }

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
    if ($DEBUG) { &LogDebug("GetLDMSData, dbscansweek=$dbscansweek"); }

    # How many machines are there in UNMANAGEDNODES?
    $sql             = "select count(*) from unmanagednodes";
    $allmachines_udd = &GetSingleString($sql);
    if ($DEBUG) { &LogDebug("GetLDMSData, allmachines_udd=$allmachines_udd"); }

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
    if ($DEBUG) { &LogDebug("GetLDMSData, dbscans_udd=$dbscans_udd"); }

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
    if ($DEBUG) { &LogDebug("GetLDMSData, dbscansweek_udd=$dbscansweek_udd"); }

    # Close the database
    &CloseDB;

    return 0;
}
### End of LDMS Database reading subroutine ##################################

### LDSS Database reading subroutine #########################################
sub GetLDSSData {

    #Get as much done as quickly as possible and close the connection
    # LDSS Specific Information

    # Open the database
    &OpenDB;

    # Get the patch names & store them in @files
    $sql = "select patch from computervulnerability where "
      . "detected=0 and patch != '*'";
    @files = &GetSingleArray($sql);

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
    $sql = "SELECT count(vul_id) from vulnerability where status != '0'";
    $vulncount = &GetSingleString($sql);
    
    # count missing patches, by severity:
    # http://community.landesk.com/support/message/12139
    # Note that unfixable vulnerabilities are filtered out.
    $sql =
        "SELECT VulSeverity.DisplayName, count(computer.displayname)"
      . "FROM Scope "
      . "INNER JOIN ScopeComputer ON Scope.Scope_Idn = ScopeComputer.Scope_Idn "
      . "INNER JOIN Computer "
      . "INNER JOIN ComputerVulnerability "
      . "ON Computer.Computer_Idn = ComputerVulnerability.Computer_Idn "
      . "INNER JOIN Vulnerability "
      . "ON ComputerVulnerability.Vul_ID = Vulnerability.Vul_ID "
      . "AND Vulnerability.Fixable != 0 "
      . "INNER JOIN VulSeverity "
      . "ON Vulnerability.Severity = VulSeverity.Severity_ID "
      . "ON ScopeComputer.Computer_Idn = Computer.Computer_Idn "
      . "WHERE ComputerVulnerability.Detected = 1"
      . "GROUP BY VulSeverity.DisplayName "
      . "ORDER BY VulSeverity.DisplayName";
    @patchcounts = &GetTwoColumnList($sql);

    # count autofix-enabled vulnerabilities, by severity:
    # http://community.landesk.com/support/message/13664
    # Note that unfixable vulnerabilities are filtered out.
    $sql =
        "SELECT VulSeverity.DisplayName, count(computer.displayname) "
      . "FROM Scope "
      . "INNER JOIN ScopeComputer ON Scope.Scope_Idn = ScopeComputer.Scope_Idn "
      . "INNER JOIN Computer "
      . "INNER JOIN ComputerVulnerability "
      . "ON Computer.Computer_Idn = ComputerVulnerability.Computer_Idn "
      . "INNER JOIN Vulnerability "
      . "ON ComputerVulnerability.Vul_ID = Vulnerability.Vul_ID "
      . "AND Vulnerability.Fixable != 0 AND Vulnerability.Autofix = 1 "
      . "INNER JOIN VulSeverity "
      . "ON Vulnerability.Severity = VulSeverity.Severity_ID "
      . "ON ScopeComputer.Computer_Idn = Computer.Computer_Idn "
      . "WHERE ComputerVulnerability.Detected = 1 "
      . "GROUP BY VulSeverity.DisplayName "
      . "ORDER BY VulSeverity.DisplayName";
    @autofixcounts = &GetTwoColumnList($sql);

    # What's the average lifespan of a detected vulnerability?
    if ( $db_type eq "SQL" ) {
        $sql =
"select avg(cast(datediff(ss,datedetected,patchinstalldate) as bigint)) "
          . "from computervulnerability where patchinstallstatus = 'Done' and "
          . "datedetected is not null and patchinstalldate is not null";
    }
    else {

        # Oracle Support
        $sql =
          "select avg((c.patchinstalldate - c.datedetected) * 24 * 60 * 60) as "
          . "average_duration_in_sec from computervulnerability c where "
          . "patchinstallstatus = 'Done' and datedetected is not null and "
          . "patchinstalldate is not null";
    }
    $vulnlife = &GetSingleString($sql);

    # Close the database
    &CloseDB;

    return 0;
}
### End of LDSS Database reading subroutine ##################################

### Report on LDMS Statistics ###############################################
sub ReportLDMSStats {

    my $ldmsmessage = "$allmachines computers in the database.";
    if ($dbscans) {

        # knock off the period
        $ldmsmessage = substr( $ldmsmessage, 0, -1 );
        $ldmsmessage .= ", $dbscans ($daypercent\%) reported in the last day.";
    }
    if ($dbscansweek) {

        # knock off the period
        $ldmsmessage = substr( $ldmsmessage, 0, -1 );
        $ldmsmessage .=
          ", $dbscansweek ($weekpercent\%) reported within " . "the week.\n";
    }

    # Update RRD too
    $ldmsrrd->update(
        AllDevices  => $allmachines,
        DayDevices  => $dbscans,
        WeekDevices => $dbscansweek
    ) or &LogWarn("Problem writing to ldmsstats: $!");
    %rtn = $ldmsrrd->graph(
        destination    => "$reportdir",
        title          => "LDMS Inventory Statistics",
        vertical_label => "All / Daily / Weekly",
        interlaced     => ""
    ) or &LogWarn("Problem graphing from ldmsstats: " . map { $rtn{$_}->[0] }
              keys %rtn
          );

    if ($DEBUG) {
        &LogDebug( "Logged LDMS RRD statistics: " . map { $rtn{$_}->[0] }
              keys %rtn );
    }
    &GeneratePage("ldmsstats","LANDesk Management Suite Inventory Statistics");

    if ($allmachines_udd) {
        $ldmsmessage .= "$allmachines_udd unmanaged devices in the database.";
        if ($dbscans_udd) {

            # knock off the period
            $ldmsmessage = substr( $ldmsmessage, 0, -1 );
            $ldmsmessage .= ", $dbscans_udd ($daypercent_udd\%) were seen in "
              . "the last day.";
        }
        if ($dbscansweek_udd) {

            # knock off the period
            $ldmsmessage = substr( $ldmsmessage, 0, -1 );
            $ldmsmessage .= ", $dbscansweek_udd ($weekpercent_udd\%) were seen "
              . "within the week.\n";
        }
    }

    # Update RRD too
    $ldmsrrd_udd->update(
        AllDevices  => $allmachines_udd,
        DayDevices  => $dbscans_udd,
        WeekDevices => $dbscansweek_udd
    ) or &LogWarn("Problem writing to ldmsstats_udd: $!");
    %rtn = $ldmsrrd_udd->graph(
        destination    => "$reportdir",
        title          => "LDMS Unmanaged Devices Statistics",
        vertical_label => "All / Daily / Weekly",
        interlaced     => ""
    ) or &LogWarn("Problem graphing from ldmsstats_udd: " . map { $rtn{$_}->[0] }
              keys %rtn
          );
    if ($DEBUG) {
        &LogDebug( "Logged LDMS UDD RRD statistics: " . map { $rtn{$_}->[0] }
              keys %rtn );
    }
    &GeneratePage("ldmsstats_udd","LANDesk Management Suite Unmanaged Device Statistics");

    &Log($ldmsmessage);
    return 0;
}

### Report on LDSS Statistics ###############################################
sub ReportLDSSStats {

    # Report on repair timing
    &Log("$vulnmessage\n");

    # Update RRD too
    $ldssrrd_life->update(
        VulnLife  => $vulnlife
    ) or &LogWarn("Problem writing to ldssstats_life: $!");
    %rtn = $ldssrrd_life->graph(
        destination    => "$reportdir",
        title          => "LDSS Vulnerability Duration",
        vertical_label => "Detection to Repair",
        interlaced     => "",
        source_drawtypes => "AREA"
    ) or &LogWarn("Problem graphing from ldssstats_life: " . map { $rtn{$_}->[0] }
              keys %rtn
          );
    if ($DEBUG) {
        &LogDebug( "Logged LDSS RRD Life statistics: " . map { $rtn{$_}->[0] }
              keys %rtn );
    }
    &GeneratePage("ldssstats_life",
        "LANDesk Security Suite Vulnerability Lifetime"
    );

    # Warn if data is seeming stale
    if ( $recentvulns == 0 ) {
        &Log(   "No new vulnerabilities have been downloaded in the last seven "
              . "days; is your scheduled download still working?" );
    }

    # Report on patch statistics
    if (@patchcounts) {
        $patchcountsreport = "Detected vulnerability counts by severity:\n";
        foreach my $patchtypecount (@patchcounts) {
            $patchcountsreport .= "$patchtypecount\n";
        }
        &Log("$patchcountsreport");
    }

    # How many of those are autofix?
    if (@autofixcounts) {
        $autofixreport =
          "Detected vulnerabilities set to autofix by severity:\n";
        foreach my $patchtypecount (@autofixcounts) {
            $autofixreport .= "$patchtypecount\n";
        }
        &Log("$autofixreport");
    }

    # Update RRD too
    $ldssrrd->update(
        ScannedVulns  => $vulncount,
        DetectedVulns  => $patchtotal,
        AutofixVulns => $autofixtotal
    ) or &LogWarn("Problem writing to ldssstats: $!");
    %rtn = $ldssrrd->graph(
        destination    => "$reportdir",
        title          => "LDSS Vulnerability Statistics",
        vertical_label => "All / Detected / Autofix",
        interlaced     => ""
    ) or &LogWarn("Problem graphing from ldssstats: " . map { $rtn{$_}->[0] }
              keys %rtn
          );
    if ($DEBUG) {
        &LogDebug( "Logged LDSS RRD statistics: " . map { $rtn{$_}->[0] }
              keys %rtn );
    }
    &GeneratePage("ldssstats","LANDesk Security Suite Vulnerability Statistics");

    # Report on manual patch download requirements
    if (@patchurls) {
        $patchurlsreport = "Manual patch downloads required:\n";
        foreach my $patchurl (@patchurls) {
            $patchurlsreport .= "$patchurl\n";
        }
        $sendemail = 1;
        &Log("$patchurlsreport");
    }

    # Create the RRD Index page
    &GenerateIndex;
    return 0;
}

### Count pending scans subroutine ############################################
sub CountPendingScans {
    &CountPendingINV;
    &CountPendingXDD;
    &CountPendingSCHED;
    &CountPendingAlerts;
    my $scanmessage;
    if ($scancount)  { $scanmessage .= "Pending scans: $scancount\n"; }
    if ($xddcount)   { $scanmessage .= "Pending discoveries: $xddcount\n"; }
    if ($sdcount)    { $scanmessage .= "Pending tasks: $sdcount\n"; }
    if ($alertcount) { $scanmessage .= "Pending alerts: $alertcount\n"; }
    if ($scanmessage) { &Log($scanmessage); }
    return 0;
}
###############################################################################

### Count Pending Inventory Scans subroutine #################################
# Watches the queue for SCN and IMS scan insertions
sub CountPendingINV {
    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ( -e $ldscan ) {
        opendir( $DIR, "$ldscan" )
          or &LogDie("Can't open directory $ldscan : $!\n");
        $scancount = 0;
        while ( $source = readdir($DIR) ) {

            # Next file if we're at the top
            if (
                $source =~ /^      # from the beginning of the line
                             \.\.?$ # two dots followed by anything
                             /x
              )
            {
                next;
            }
            if (
                $source =~ /\.SCN$ # if it ends with .SCN
                             /ix
              )
            {
                $scancount++;
            }
            if (
                $source =~ /\.IMS$ # or .IMS
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
                $sendemail = 1;
                &RestartService("LANDesk Inventory Server");
                last;
            }
        }
        closedir($DIR);
        return 0;
    }
    else {
        &LogWarn("Can't count pending inventory scans from $ldscan");
        return 1;
    }
}

### Count Pending Extended Device Discoveries subroutine ######################
# Watches the queue for XDD scan insertions
sub CountPendingXDD {
    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ( -e $xddscan ) {
        opendir( $DIR, "$xddscan" )
          or &LogDie("Can't open directory $xddscan : $!\n");
        $xddcount = 0;
        while ( $source = readdir($DIR) ) {

            # Next file if we're at the top
            if (
                $source =~ /^ 
                             \.\.?$  # if it begins with two dots
                             /x
              )
            {
                next;
            }
            if (
                $source =~ /\.XDD$  # if it ends with .XDD
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
                $sendemail = 1;
                last;
            }
        }
        closedir($DIR);
        return 0;
    }
    else {
        &LogWarn("Can't count pending device discoveries from $xddscan");
        return 1;
    }
}

### Count Pending Alert insertions subroutine ################################
# Watches the queue for alerting insertions
sub CountPendingAlerts {
    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ( -e $ALERTDIR ) {
        opendir( $DIR, "$ALERTDIR" )
          or &LogDie("Can't open directory $ALERTDIR $!\n");
        $alertcount = 0;
        while ( $source = readdir($DIR) ) {

            # Next file if we're at the top
            if (
                $source =~ /^ 
                             \.\.?$  # if it begins with two dots
                             /x
              )
            {
                next;
            }
            if (
                $source =~ /\.XML$  # if it ends with .XML
                             /ix
              )
            {
                $alertcount++;
            }
            if ( $alertcount > 200 ) {
                &Log(
"There are more than 200 alerting system reports pending database "
                      . "insertion. You should investigate your core's performance."
                );
                $sendemail = 1;
                last;
            }
        }
        closedir($DIR);
        return 0;
    }
    else {
        &LogWarn("Can't count pending alert insertions from $ALERTDIR");
        return 1;
    }
}

### Count Pending Scheduled Task Transfers subroutine #########################
# Watches the queue between Local Scheduler and Global Scheduler
sub CountPendingSCHED {
    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ( -e $sdscan ) {
        opendir( $DIR, "$sdscan" )
          or &LogDie("Can't open directory $sdscan : $!\n");
        $sdcount = 0;
        while ( $source = readdir($DIR) ) {

            # Next file if we're at the top
            if (
                $source =~ /^\.\.?$     # if it begins with two dots
                             /x
              )
            {
                next;
            }
            if (
                $source =~ /\.XML$      # if it ends with .XML
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
                $sendemail = 1;
                last;
            }
        }
        closedir($DIR);
        return 0;
    }
    else {
        &LogWarn("Can't count pending task insertions from $sdscan");
        return 1;
    }
}

### Look for Full scan forced in the Event Viewer #############################
# Need to limit this to a single day's data
sub CountForcedScans {
    my ( $handle, $base, $recs, %Event, $record, $result );

    # One day ago
    my $TIME_LIMIT = time() - 86400;

    while (
        (
            $EventViewerhandle->Read(
                EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ, 0,
                \%Event
            )
        )
        && ( $Event{TimeGenerated} > $TIME_LIMIT )
      )
    {
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        if ( $Event{Source} eq "LANDesk Inventory Server" ) {
            if ( $Event{EventType} == 2 and $Event{EventID} == 2391 ) {
                $result++;
            }
        }
        $record++;
    }
    if ($result) {
        if ($DEBUG) {
            &LogDebug(
                "CountForcedScans found result of $result, record of $record."
            );
        }
        return $result;
    }
    else {
        if ($DEBUG) {
            &LogDebug("CountForcedScans found nothing.");
        }
        return 0;
    }
}
###############################################################################

### Look for Public Key hash errors in the Event Viewer #######################
# Need to limit this to a single day's data
sub CountHashErrors {
    my ( $handle, $base, $recs, %Event, $record, $result );

    # One day ago
    my $TIME_LIMIT = time() - 86400;

    # if this is set, we also retrieve the full text of every
    # message on each Read( )
    local $Win32::EventLog::GetMessageText = 0;

    $handle = Win32::EventLog->new( "Application", $COMPUTERNAME )
      or &LogWarn("CountHashErrors Can't open Application EventLog");

    while (
        (
            $EventViewerhandle->Read(
                EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ, 0,
                \%Event
            )
        )
        && ( $Event{TimeGenerated} > $TIME_LIMIT )
      )
    {
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        if ( $Event{Source} eq "LANDesk Inventory Server" ) {
            if ( $Event{EventType} == 2 and $Event{EventID} == 0 ) {
                $result++;
            }
        }
        $record++;
    }
    if ($result) {
        if ($DEBUG) {
            &LogDebug(
                "CountHashErrors found result of $result, record of $record.");
        }
        return $result;
    }
    else {
        if ($DEBUG) {
            &LogDebug("CountHashErrors found nothing.");
        }
        return 0;
    }
}
###############################################################################

### Clean up temp scan files #################################################
sub CullTMP {
    if ( -e $ldscan ) {
        if ($DEBUG) { &LogDebug("Culling temporary files in LDSCAN."); }
        opendir( $DIR, "$ldscan" ) or &LogDie("Cannot access $ldscan -- $!");
        while ( my $tmpfile = readdir($DIR) ) {

            # Next file if we're at the top or the file was already done
            next if $tmpfile =~ /^       # from the beginning of the line
                            \.\.?   # two dots then anything
                            $       # to the end of the line
                            /x;

            Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

            # Ignore non-tmp files
            if (
                $tmpfile =~ /\.TMP$ # if it ends with .TMP
                            /ix
              )
            {

                # Delete it regardless of age
                $tmpcount++;
                &DeleteFile( $ldscan . "\\" . $tmpfile, localtime );
            }
        }
        if ($tmpcount) {
            &Log("Deleted $tmpcount temporary scan files from $ldscan");
        }
        closedir($DIR);
        return 0;
    }
    else {
        &LogWarn("Can't cull temp files from $ldscan");
        return 1;
    }
}
### Old Patch cleanup subroutine ##############################################
sub CullPatches {
    if ( -e $PATCHDIR ) {
        my $netdrive = 0;
        if ($DEBUG) { &LogDebug("Analyzing patches in $PATCHDIR"); }
        if ( $PATCHDIR =~ m/^\\\\/ ) {
            $netdrive = 1;
        }
        if ($deletiondays) {
            $trashcount = 0;
            foreach my $patch (@files) {
                my $file = $PATCHDIR . "\\" . $patch;

                Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

                if ( -w $file ) {
                    $patchcount++;
                    if ( $netdrive == 1 ) {

                        # Stat won't work on network drives
                        &DeleteFile( $file, localtime );
                    }
                    else {

                        # stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
                        my $atime = ( stat($file) )[8]
                          or &LogWarn("CullPatches: stat($file) failed: $!");
                        if ( $atime < $time ) {

                            &DeleteFile( $file, $atime );
                        }
                    }
                }
            }
        }
        if ( $trashcount > 0 ) {
            if ($DEBUG) {
                &LogDebug(
"CullPatches: trashcount is $trashcount, totalsize is $totalsize"
                );
            }
            $totalsize  = &commify($totalsize);
            $trashcount = &commify($trashcount);
            &Log("Deleted $trashcount patches, recovered $totalsize bytes.");
        }
        else {
            $patchcount = &commify($patchcount);
            &Log("Evaluated $patchcount patches, deleted none.");
        }
        return 0;
    }
    else {
        &LogWarn("can't cull old patches from $PATCHDIR");
        return 1;
    }
}

### Mark old alerts for purging #############################################
sub CullAlerts {

    # Note that Alert Service will puke if we just delete them; we need to
    # mark the alerts as purge-worthy and set a purge flag for the alert
    # service to do the dirty work on its own

    # Check the LANDesk version and deletion days
    if ( $ldms_version < 88 || !defined($deletiondays) ) {
        if ($DEBUG) { &LogDebug("CullAlerts has nothing to do."); }
        return 1;
    }

    # Check the file
    if ( !-e $purgemarker ) {

        # touch the purge marker;
        my $PM;
        open( $PM, '>', "$purgemarker" )
          or &LogWarn("CullAlerts: Can't create $purgemarker: $!");
        print $PM "\n";
        close($PM);
        if ($DEBUG) { &LogDebug("created $purgemarker"); }
    }

    # Open Database
    &OpenDB;

    # How many alerts are we going to do this to?
    $sql = "select count(alertlog_idn) from ALERTLOG where ALERTTIME < ";
    if ( $db_type eq 'SQL' ) {
        $sql .= "getdate()-";
    }
    elsif ( $db_type eq 'ORA' ) {
        $sql .= "current_date-";
    }
    $sql .= $deletiondays;
    $alertpurges = &GetSingleString($sql);

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

    # Do the work
    if ($DEBUG) {
        &LogDebug( "I would purge "
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
        $sth = $dbh->prepare($sql)
          or &LogWarn("$sql caused $DBI::errstr");
        $sth->execute()
          or &LogWarn("$sql caused $DBI::errstr");
        $sth->finish();

        # Report our activity
        if ( $alertpurges > 0 ) {
            &Log(   "Marked $alertpurges Alert records for purging which were "
                  . "older than $deletiondays days." );
        }
    }

    # Close database
    &CloseDB;
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

        # Open the database
        &OpenDB;
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
                  or &LogWarn("$sql caused $DBI::errstr");
                if ($DEBUG) {
                    &LogDebug("I would delete the older instance of $deadaddr");
                }
                else {
                    $sth->execute($deadaddr)
                      or &LogWarn("$DBI::errstr");
                    $deadaddrcount++;
                    $sth->finish();
                }
            }
        }

        # Close the database
        &CloseDB;

        if ( $deadaddrcount == 1 ) {
            &Log("Cleared $deadaddrcount dead IP address.");
        }
        else {
            &Log("Cleared $deadaddrcount dead IP addresses.");
        }

        return 0;
    }
    else {

        if ($DEBUG) { &LogDebug("CullIPs called with nothing to do"); }
        return 1;
    }

}

### Move superceded vulns to Do Not Scan ######################################
sub CullVulns {

    # Open the database
    &OpenDB;

    # Get listing of the vulns we'll affect
    $sql = "select vul_id from VULNERABILITY where supercededstate != '0' "
      . "and status != '0'";
    @supercededvulns = &GetSingleArray($sql);

    # How many superceded vulns are there?
    $supercededvulncount = @supercededvulns;

    # Move those vulns to Do Not Scan
    foreach my $vuln (@supercededvulns) {
        if ($DEBUG) {
            &LogDebug("I would move $vuln to Do Not Scan.");
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
            $sth = $dbh->prepare($sql)
              or &LogWarn("$sql caused $DBI::errstr");
            $sth->execute()
              or &LogWarn("$DBI::errstr");
        }
    }

    $sth->finish();

    # Close the database
    &CloseDB;

    if ($supercededvulncount) {
        if ($DEBUG) {
            &Log(   "Would have moved $supercededvulncount vulnerabilities to "
                  . "Do Not Scan." );
        }
        else {
            &Log( "Moved $supercededvulncount vulnerabilities to Do Not Scan: "
                  . "@supercededvulns\n" );
        }
    }

    return 0;
}

### Delete old unmanaged nodes ################################################
sub CullUDD {

    if ($deletiondays) {

        # Open the database
        &OpenDB;

        # How many unmanaged nodes are older than $deletiondays?
        $sql = "select count(lastscantime) from UNMANAGEDNODES where ";
        if ($ldms_version == "88") {
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
        $udddeletes = &GetSingleString($sql);

        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

        if ($DEBUG) {
            &LogDebug( "I would delete "
                  . $udddeletes
                  . " machines from unmanaged nodes "
                  . "because they haven't been seen in more than "
                  . $deletiondays
                  . " days." );
        }
        else {

            # Make the old scans go away -- skipping the WAPs for now
            $sql = "delete from UNMANAGEDNODES where ";
            if ($ldms_version == "88") {
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

            # Report our activity
            if ( $udddeletes > 0 ) {
                &Log(   "Deleted $udddeletes Unmanaged Nodes records which "
                      . "hadn't been seen in more than $deletiondays days." );
            }
        }

        # Close the database
        &CloseDB;
    }
    return 0;
}

### Scanfile rename and cleanup subroutine ####################################
sub CullScanFiles {

    # Open the database
    &OpenDB;

    $trashcount  = 0;
    $renamecount = 0;
    if ( !-e $SCANDIR ) {
        &LogWarn("Directory $SCANDIR doesn't seem to exist?");
        return 1;
    }
    opendir( $DIR, "$SCANDIR" )
      or &LogDie("Can't open directory $SCANDIR: $!\n");
    while ( $source = readdir($DIR) ) {

        # Next file if we're at the top or the file was already done
        next if $source =~ /^       # from the beginning of the line
                            \.\.?   # two dots then anything
                            $       # to the end of the line
                            /x;

        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

        # Delete it if it's older than X days
        if ($deletiondays) {
            my $time = eval {
                time() - eval { $deletiondays * 86400 };
            };

            # stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
            my $mtime = ( stat( $SCANDIR . "\\" . $source ) )[8]
              or &LogWarn("Can't access file $source : $!\n");
            if ( $mtime < $time ) {

                &DeleteFile( $SCANDIR . "\\" . $source, $mtime );
            }
        }

        # Ignore scan files that were already renamed
        next if $source =~ /^_/x;
        $file = $SCANDIR . "\\" . $source;
        open( $FILE, '<', "$file" ) or &LogWarn("Can't open file $file : $!\n");
        while ( my $line = <$FILE> ) {
            my @parts = split( /=/, $line );

            # If the UUID is in the database, get the device name
            if ( $parts[0] =~ m/^Device ID/ ) {
                my $uuid = &Trim( $parts[1] );
                if ($DEBUG) { &LogDebug("$source is from $uuid"); }

                $sql = "select devicename from computer where deviceid='$uuid'";
                my $devicename = &GetSingleString($sql);
                $marker = $devicename;
                if ($devicename) {
                    $newname = $SCANDIR . "\\_" . $devicename . "_" . $source;
                    last;
                }
            }

            # If the scan didn't have Device ID in it, we'll try each of these.
            # The first one to match wins.
            if ( $parts[0] =~ m/^Device Name/ ) {
                $marker = &Trim( $parts[1] );
                if ($DEBUG) { &LogDebug("$source is from $marker"); }
                $newname = $SCANDIR . "\\_" . $marker . "_" . $source;
                last;
            }
            if ( $parts[0] =~ m/^Network - TCPIP - Host Name/ ) {
                $marker = &Trim( $parts[1] );
                if ($DEBUG) { &LogDebug("$source is from $marker"); }
                $newname = $SCANDIR . "\\_" . $marker . "_" . $source;
                last;
            }
            if ( $parts[0] =~ m/^Network - TCPIP - Address/ ) {
                $marker = &Trim( $parts[1] );
                if ($DEBUG) { &LogDebug("$source is from $marker"); }
                $newname = $SCANDIR . "\\_" . $marker . "_" . $source;
                last;
            }

            # If all else fails, undef $newname
            if ( !defined($marker) ) {
                if ($DEBUG) {
                    &LogDebug("couldn't get anything from $source");
                }
                $newname = undef;
            }
        }
        close($FILE);

        # if we weren't able to get something, we don't move the file.
        # if debug is off, try to move the file and fail safely if we can't.
        # if debug is on, just print what would have been done.
        if ($newname) {
            if ($DEBUG) {
                &LogDebug("I would be renaming $file to $newname");
            }
            else {
                if ( copy( "$file", "$newname" ) ) {
                    unlink($file)
                      || &LogWarn("CullScanFiles: unlink $file: $!");
                }
                else {
                    &LogWarn("CullScanFiles: copy $file, $newname: $!");
                }
            }
        }
    }
    closedir($DIR);
    if ( $trashcount > 0 ) {
        &Log("Deleted $trashcount scan files");
    }
    if ( $renamecount > 0 ) {
        &Log("Renamed $renamecount scan files");
    }

    # Close the database
    &CloseDB;

    return 0;
}

### Stored scanfile cleanup subroutine ####################################
sub CompressStorageFiles {

    # Compress Storage Files
    if ( -e $STORAGEDIR ) {
        $compresscount = 0;
        my @filestokill;
        opendir( $DIR, "$STORAGEDIR" )
          or &LogDie("Can't open directory $STORAGEDIR : $!\n");
        my $zip = Archive::Zip->new();
        while ( $source = readdir($DIR) ) {

            # Next file if we're at the top or the file was already done
            next if $source =~ /^
                                \.\.?  # begins with two dots
                                $/x;
            next if $source =~ /\.zip$ # ends with .ZIP
                                /xi;

            Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

            # Compress it if it's older than X days
            if ($deletiondays) {

                # stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
                my $ctime = ( stat( $STORAGEDIR . "\\" . $source ) )[10]
                  or &LogWarn("Can't access file $source : $!\n");
                if ( $ctime < $time ) {

                    #delete this file
                    if ($DEBUG) {
                        my $days = floor(
                            eval {
                                eval { time() - $ctime } / 86400;
                            }
                        );
                        &LogDebug(
                            "$source is $days days old, should be compressed\n"
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
            my $newzipfile = genfilename() . ".zip";
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
            &Log("Compressed and deleted $compresscount stored scan files");
        }
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

        # We should have an email object now, so send the message
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

            # Can't send email, so I need to write the output to a file.
            my $OUTPUTFILE;
            my $outputfile = $prog . "-" . $ver . "-" . &genfilename . ".log";
            &Log(
                "Something is wrong with email -- writing output report file
                to $outputfile"
            );
            open( $OUTPUTFILE, '>', "$outputfile" )
              or &LogDie("Can't open file $outputfile - $!");
            print $OUTPUTFILE $mailmessage;
            close $OUTPUTFILE;
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

    # Open the database
    if ( $db_type eq "SQL" ) {
        $dbh =
          DBI->connect(
"dbi:ODBC:driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass"
          ) or &LogDie("Database connection failed: $DBI::errstr\n");
        if ($DEBUG) {
            ### Set the trace output
            # DBI->trace( 2, undef );
            &LogDebug(
"Opening database with: $db_type, $db_name, $db_instance, $db_user, db_pass"
            );
        }
    }
    elsif ( $db_type eq "ORA" ) {
        $dbh = DBI->connect( "DBI:Oracle:$db_name", $db_user, $db_pass )
          or &LogDie("Database connection failed: $DBI::errstr\n");
        if ($DEBUG) {
            ### Set the trace output
            # DBI->trace( 2, undef );
            &LogDebug(
                "Opening database with: $db_type, $db_name, $db_user, db_pass"
            );
        }
    }
    else {
        &LogDie("Cannot connect, Database type is not specified!\n");
    }
    $dbh->{'LongReadLen'} = 1024;
    $dbh->{'LongTruncOk'} = 1;
    return 0;
}

### Close the database subroutine ##############################################
sub CloseDB {

    if ($DEBUG) { &LogDebug("Closing database."); }
    $sth->finish();
    $dbh->disconnect;
    return 0;

}
#############################################################################

### Configure service checking subroutine ###################################
### Also runs the individual service checks #################################
sub ServiceCheckLoop {
    if ($DEBUG) { &LogDebug("Starting ServiceCheckLoop"); }
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
        "CBA8",
        "Intel Alert Handler",
        "Intel Alert Originator",
        "Intel QIP Server Service",
        "Intel PDS",
        "LANDesk Inventory Server"
    );

    # What LANDesk services are on this system?
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
        &LogDebug(
"ServiceCheckLoop - Checked $servicecount services: $serviceloglist."
        );
    }

    return 0;
}
#############################################################################

### IsAutomatic subroutine ##################################################
sub IsAutomatic {

    my $servicekey = shift;
    if ( !defined($servicekey) ) {
        &LogWarn(
            "ServiceCheck called without a service to check. " . "$_[0]" );
        return 1;
    }

    # LDGSB is a special case
    if ( $servicekey eq "LDGSB" ) {
        &OpenDB;
        $sql = "select count(*) from brokerconfig";
        my $ldgsb_on = &GetSingleString($sql);
        &CloseDB;
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
        if ($DEBUG) { Log("$servicekey Start mode is $servstart"); }
        if ( $servstart == "0" ) {
            return 0;
        }
        if ( $servstart == "2" ) {
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
        &LogWarn(
            "ServiceCheck called without a service to check. " . "$_[0]" );
        return 1;
    }

    Win32::Service::GetStatus( '', $servicetarget, \%status );
    if ($DEBUG) {
        &LogDebug(
            "Checked $servicetarget, current state = $status{CurrentState}.");
    }
    if ( $status{CurrentState} == 1 ) {
        $downcount++;
        my $time = localtime();
        &change_balloon( "tip", "$servicetarget service down!" );
        &LogWarn("$servicetarget service down at $time!");
        $sendemail = 1;
        sleep 3;
        &LogWarn("Trying to restart $servicetarget service");
        &change_balloon( "tip", "Trying to restart $servicetarget service" );
        my $retval = Win32::Service::StartService( '', $servicetarget );
        sleep 8;

        if ($retval) {
            &Log("$servicetarget service restarted successfully.");
            &change_balloon( "tip", "$servicetarget service restarted." );
            sleep 1;
        }
        else {

# Sometimes StartService doesn't respond truthfully; if it says there was a problem,
# we should check the status again before getting excited.
            Win32::Service::GetStatus( '', $servicetarget, \%status );
            if ($DEBUG) {
                &LogDebug(
                        "Startservice got $retval, rechecked $servicetarget, "
                      . "current state = $status{CurrentState}." );
            }
            if ( $status{CurrentState} == 1 ) {
                Log "Cannot restart $servicetarget at $time!";
            }
            else {
                if ($DEBUG) {
                    &LogDebug(
                            "Leaving ServiceCheck restart was successful, but "
                          . "retval was $retval ($servicetarget)." );
                }
                return 0;
            }
        }
        if ($DEBUG) {
            &LogDebug( "Leaving ServiceCheck after first restart try was "
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

    # If NMAP is around, we'll need some database information for it.
    if ($nmap_present) {
        if (
            $nmap_options =~ m/-oX     # any of these options
                                |-oN    # will cause NMAP to
                                |-oG    $ fail on fingerprinting
                                /x
          )
        {
            &LogWarn(
                    "NMAP Options $nmap_options includes output specification "
                  . "('-oX', '-oN' or '-oG'). Please remove that option in "
                  . "order to use OS fingerprinting." );
            $nmap_present = 0;
        }
        else {

            &OpenDB;

            # Throttle the number of nmap-able nodes in order to keep
            # execution time reasonable. If debug is on, throttle even
            # further.
            if ($DEBUG) {
                $maxnmapcount = 10;
            }
            else {
                $maxnmapcount = 30;
            }

# Get all nodes with no osname or meaningless osname, unless xddexception is set
# Note that rows with no IP address are useless.
            $sql =
              "select DISTINCT top $maxnmapcount IPADDRESS, LASTSCANTIME from "
              . "UNMANAGEDNODES where XDDEXCEPTION='0' and IPADDRESS is not NULL ";

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
              or &LogWarn("$sql caused $DBI::errstr\n");
            $sth->execute()
              or &LogWarn("$sql caused $DBI::errstr\n");
            while ( @row = $sth->fetchrow ) {
                if ( &IsIPAddress( &Trim( $row[0] ) ) ) {
                    if ($DEBUG) { &LogDebug("NMAP will test $row[0]."); }
                    $Address[$nmapcount] = &Trim( $row[0] );
                    $nmapcount++;
                    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
                }
            }

            # Close the database
            &CloseDB;

            if ($DEBUG) {
                &LogDebug( "found "
                      . $nmapcount
                      . " NMAP targets, SQL string was $sql" );
            }
        }
    }

    # If we've got target nodes, we've got work to do.
    if ($nmapcount) {
        &DoNMAP;
    }
    else {
        if ($DEBUG) {
            &LogDebug(
                "NMAP binary exists, but we don't seem to have any nodes to "
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
    if ($DEBUG) { &LogDebug("Pinging Unmanaged devices..."); }
    &change_balloon( "tip", "Pinging Unmanaged Devices" );
    my $p           = Net::Ping->new( "icmp", 1 );
    my $pingcount   = 0;
    my $nopingcount = 0;
    foreach my $test (@Address) {

        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        my $ping = $p->ping($test);
        if ($ping) {

            # NMAP a device which responds to ping immediately
            if ($DEBUG) { &LogDebug("$test responded to ping: $ping"); }
            $np->parsescan( $nmap, $nmap_options, $test );
            $pingcount++;
        }
        else {
            push( @Address_np, $test );
            $nopingcount++;
        }
    }
    $p->close();
    if ( $pingcount > 0 ) {

        # report easy ones to the admin
        &Log(   "Scanned "
              . $pingcount
              . " unmanaged nodes without OS Names which responded to ping."
              . "database. There were $goodcount successful scans." );
    }

    # Then do the ones that didn't respond to ping
    if (@Address_np) {
        $goodcount = 0;
        if ($DEBUG) {
            &LogDebug( "Scanning "
                  . $nopingcount
                  . " unmanaged nodes without OS "
                  . "Names which don't respond to ping. This may take a "
                  . "significant amount of time to complete." );
        }
        &change_balloon( "tip",
            "Scanning Unmanaged Devices which don't answer to ping" );
        foreach my $test_np (@Address_np) {

            Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
            $np->parsescan( $nmap, $nmap_options, $test_np );
        }

        # and report to the admin
        &Log(   "Finished NMAP scanning ping-unfriendly unmanaged nodes in "
              . "the database. There were $goodcount successful scans." );
    }

    # Report on any updates I made
    if ( $osupdates || $macupdates || $vendorupdates ) {
        if ($osupdates) {
            &Log("Updated $osupdates OS Names in Unmanaged Devices.");
        }
        if ($macupdates) {
            &Log("Updated $macupdates MAC Addresses in Unmanaged Devices.");
        }
        if ($vendorupdates) {
            &Log(   "Updated $vendorupdates NIC Manufacturers "
                  . "in Unmanaged Devices." );
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
        &LogDebug( "NMAP callback received for " . $hostaddr );
    }

    # Is this thing on?
    $status = $host->status;

    &change_balloon( "tip", "Processing $hostaddr" );

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ( $status eq 'up' ) {

        # Zero-pad the IP Address so that the database can make sense of it
        $hostaddr = &zeropad($hostaddr);

        if ( $host->mac_addr || $host->mac_vendor || $host->os_sig ) {

            # Open the database
            &OpenDB;

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

            # Close the database
            &CloseDB;
        }
        else {

            # scan didn't have anything we can use in it
            if ($DEBUG) {
                &LogDebug( $hostaddr . " scan gave nothing useful." );
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
    if ( !$host->status ) { return 1; }
    return 0;
}
###############################################################################

### Update the OS Name subroutine ###########################################
sub UpdateOS {

    my ( $OS, $accuracy, $hostaddr ) = @_;

    if ($OS) {
        if ($accuracy) {
            $OS .= " \(" . $accuracy . " percent\)";
        }
    }
    else {
        $OS = "Unidentified";
    }

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

    # Make sure it fits into the database field
    if ($OS) {
        if ( length($OS) > 254 ) {
            $OS = substr( $OS, 0, 255 );
        }
        chomp($OS);
        &Trim($OS);
        $sql = "update UNMANAGEDNODES set OSNAME=? where IPADDRESS=?";
        $sth = $dbh->prepare($sql)
          or &LogWarn("$sql caused $DBI::errstr");
        $sth->execute( $OS, $hostaddr )
          or &LogWarn("$DBI::errstr");
        $sth->finish();
        if ($DEBUG) {
            &LogDebug( "Set OS Name of " . $hostaddr . " to " . $OS );
        }
        $osupdates++;

    }
    return 0;
}

### Update the MAC Address subroutine #######################################
sub UpdateMAC {

    my ( $newmac, $hostaddr ) = @_;

    if ( !defined($newmac) || !defined($hostaddr) ) {
        &LogWarn( "UpdateMAC called without sufficient information. "
              . "$_[0], $_[1]" );
        return 1;
    }

    # Sanitize the new MAC Address
    $newmac =~ s/://gx;
    $newmac =~ s/-//gx;
    chomp($newmac);

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

    # Update the MAC Address if it didn't exist before
    $sql    = "select top 1 PHYSADDRESS from UNMANAGEDNODES WHERE IPADDRESS=?";
    $oldmac = &GetSingleString($sql);

    if ($oldmac) {
        $sql = "update UNMANAGEDNODES set PHYSADDRESS=? where IPADDRESS=?";
        $sth = $dbh->prepare($sql)
          or &LogWarn("$sql caused $DBI::errstr");
        $sth->execute( $newmac, $hostaddr )
          or &LogWarn("$DBI::errstr\n");
        $sth->finish();
        if ($DEBUG) {
            &LogDebug( "Set MAC Address of " . $hostaddr . " to " . $newmac );
        }
        $macupdates++;
    }
    return 0;
}

### Update the Manufacturer subroutine #######################################
sub UpdateVendor {

    my ( $vendor_id, $hostaddr ) = @_;

    if ( !defined($vendor_id) || !defined($hostaddr) ) {
        &LogWarn( "UpdateVendor called without sufficient information."
              . "$_[0], $_[1]" );
        return 1;
    }

    # Update the Manufacturer if it didn't exist before
    # The field only exists in 8.8 and newer
    if ( $ldms_version >= 88 ) {

        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        $sql =
          "select top 1 MANUFACTURER from UNMANAGEDNODES WHERE IPADDRESS=?";
        $oldman = &GetSingleString($sql);

        if ($oldman) {
            if ( length($oldman) < 2 or $oldman eq "UNKNOWN" ) {
                $sql =
                  "update UNMANAGEDNODES set MANUFACTURER=? where IPADDRESS=?";
                $sth = $dbh->prepare($sql)
                  or &LogWarn("$sql caused $DBI::errstr");
                $sth->execute( $vendor_id, $hostaddr )
                  or &LogWarn("$DBI::errstr");
                $sth->finish();
                if ($DEBUG) {
                    &LogDebug( "Set Manufacturer of "
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

### ReadRegisty subroutine #################################################
sub ReadRegistry {

    # Check the registry for ErrorDir
    my $RegKey =
      $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
    if ($RegKey) {
        $ldmain = $RegKey->GetValue("LDMainPath");
        $ldmain = Win32::GetShortPathName($ldmain);
        if ($DEBUG) { &LogDebug("LDMAIN is $ldmain"); }
        $SCANDIR     = $ldmain . "ldscan\\errorscan";
        $STORAGEDIR  = $ldmain . "ldscan\\storage";
        $PATCHDIR    = $ldmain . "ldlogon\\patch";
        $ldscan      = $ldmain . "ldscan";
        $xddscan     = $ldmain . "xddfiles";
        $sdscan      = $ldmain . "sdstatus";
        $ALERTDIR    = $ldmain . "alertqueue";
        $purgemarker = $ldmain . "alertqueue\\purge.sig";
        $reportdir   = $ldmain . "reports\\ldms_core";

    }

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
        $db_pass        = &Decrypt($db_pass);
        $db_user        = $RegKey->GetValue("db_user");
        $mailserver     = $RegKey->GetValue("mailserver");
        $mailfrom       = $RegKey->GetValue("mailfrom");
        $mailto         = $RegKey->GetValue("mailto");
        $mail_auth_user = $RegKey->GetValue("mail_auth_user");
        $mail_auth_pass = $RegKey->GetValue("mail_auth_pass");
        if ($mail_auth_pass) {

            # Decrypt what we got from the registry
            $mail_auth_pass = &Decrypt($mail_auth_pass);
        }
        $mail_auth_type = $RegKey->GetValue("mail_auth_type");
        $deletiondays   = $RegKey->GetValue("deletiondays");

        # In upgrades, we'll wipe out the useful defaults by reading
        # empty registry keys.
        if ( $RegKey->GetValue("nmap") ) {
            $nmap = $RegKey->GetValue("nmap");
        }
        if ( $RegKey->GetValue("nmap_options") ) {
            $nmap_options = $RegKey->GetValue("nmap_options");
        }
        $nmap_unidentified = $RegKey->GetValue("nmap_unidentified");
        if ( $RegKey->GetValue("patchdir") ) {
            $PATCHDIR = $RegKey->GetValue("patchdir");
        }
    }
    return 0;
}
### End of ReadRegisty subroutine ##########################################

### PrepareRRD subroutine ##################################################
sub PrepareRRD {

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

    # LDSS Vulns
    if ( !-e $ldssrrdfile ) {

        # LDSS RRD file didn't exist, so create and initialize it
        $ldssrrd = RRD::Simple->new( file => "$ldssrrdfile" );
        $ldssrrd->create(
            $ldssrrdfile, "mrtg",
            ScannedVulns  => "GAUGE",
            DetectedVulns  => "GAUGE",
            AutofixVulns => "GAUGE",
        );
        $ldssrrd->heartbeat( $ldssrrdfile, "ScannedVulns",  86400 );
        $ldssrrd->heartbeat( $ldssrrdfile, "DetectedVulns",  86400 );
        $ldssrrd->heartbeat( $ldssrrdfile, "AutofixVulns", 86400 );

    }
    else {

        # LDSS RRD file did exist, so we just need to initialize it
        $ldssrrd = RRD::Simple->new( file => $ldssrrdfile );
    }

    # LDSS Vuln Life
    if ( !-e $ldssrrdfile_life ) {

        # LDSS RRD Life file didn't exist, so create and initialize it
        $ldssrrd_life = RRD::Simple->new( file => "$ldssrrdfile_life" );
        $ldssrrd_life->create(
            $ldssrrdfile_life, "mrtg",
            VulnLife  => "GAUGE",
        );
        $ldssrrd_life->heartbeat( $ldssrrdfile_life, "VulnLife",  86400 );

    }
    else {

        # LDSS RRD Life file did exist, so we just need to initialize it
        $ldssrrd_life = RRD::Simple->new( file => $ldssrrdfile_life );
    }

    # Make sure my report directory is ready
    if ( !-e $reportdir ) { &makeDir($reportdir); }
}
### End of PrepareRRD subroutine ##############################################

### GenerateIndex subroutine ###################################################
# Writes index HTML page to display RRD counters from
sub GenerateIndex {
    # Make sure the favicon is there
    if (! -e "$reportdir/ldms_core.ico") {
        if ( -e "ldms_core.ico") {
            copy("ldms_core.ico", "$reportdir/ldms_core.ico") or
            &LogWarn("Cannot copy ldms_core.ico to $reportdir - $!");
        }
    }
    if (! -e "$reportdir/ldms_core.css") {
        if ( -e "ldms_core.css") {
            copy("ldms_core.css", "$reportdir/ldms_core.css") or
            &LogWarn("Cannot copy ldms_core.css to $reportdir - $!");
        }
    }
    my $rrdtime = localtime;
    my $targetfile = $reportdir . "/index.html";
    my $TARGETFILE;
    open( $TARGETFILE, '>', "$targetfile" )
        or &LogDie("Can't open file $targetfile - $!");
    print $TARGETFILE <<"EOHTML";
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/dtd/xhtml11.dtd">
<!-- Begin Head -->
<html>
	<head>
		<title>ldms_core LANDesk Statistics Report</title>
		<meta http-equiv="refresh" content="86400" />
		<meta http-equiv="pragma" content="no-cache" />
		<meta http-equiv="cache-control" content="no-cache" />
		<meta http-equiv="expires" content="$rrdtime" />
		<meta http-equiv="generator" content="$prog $ver" />
		<meta http-equiv="date" content="$rrdtime" />
		<meta http-equiv="content-type" content="text/html; charset=iso-8859-1" />
        <link HREF="ldms_core.css" rel="stylesheet" type="text/css"> 
        <link REL="SHORTCUT ICON" HREF="ldms_core.ico">
	</head>
<body>
<img src="ldms_core_icon.png">
<H1>ldms_core LANDesk Statistics Report last updated at <A HREF="ldms_core-latest.html">$rrdtime</A>.</H1><br />
<hr>
<!-- End Head -->
<table>
<tr>
<!-- Begin `Inventory' Graph -->
<td>
    <a href="ldmsstats.html"><H2>LANDesk Management Suite Inventory</H2>
    <img src="ldmsstats-daily.png"></a>
</td>
<!-- End `Inventory' Graph -->
<!-- Begin `Unmanaged' Graph -->
<td>
    <a href="ldmsstats_udd.html"><H2>LANDesk Management Suite Unmanaged Devices</H2>
    <img src="ldmsstats_udd-daily.png"></a>
</td>
<!-- End `Unmanaged' Graph -->
</tr>
<tr>
<!-- Begin `Patch' Graph -->
<td>
    <a href="ldssstats.html"><H2>LANDesk Security Suite Vulnerabilities</H2>
    <img src="ldssstats-daily.png"></a>
</td>
<!-- End `Patch' Graph -->
<!-- Begin `Vuln Life' Graph -->
<td>
    <a href="ldssstats_life.html"><H2>LANDesk Security Suite Vulnerability Lifetime</H2>
    <img src="ldssstats_life-daily.png"></a>
</td>
<!-- End `Vuln Life' Graph -->
</tr>
</table>
<!-- Begin Footer Block -->
        <hr>
        Report page generated by <a href="http://www.droppedpackets.org/scripts/ldms_core">$prog $ver</a> using <A HREF="http://oss.oetiker.ch/rrdtool/">RRDtool</A>.
<!-- End Footer Block -->
	</body>
</html>


EOHTML
    close($TARGETFILE);
    if ($DEBUG) { &LogDebug("GeneratePage: Recreated $targetfile"); }
}
### End of GenerateIndex subroutine ############################################

### GeneratePage subroutine ###################################################
# Writes counter-specific HTML pages to display RRD traffic
sub GeneratePage {
    my ( $targetrrd, $description ) = @_;
    my $dayfile = $targetrrd . "-daily.png";
    my $weekfile = $targetrrd . "-weekly.png";
    my $monthfile = $targetrrd . "-monthly.png";
    my $yearfile = $targetrrd . "-annual.png";
    my $rrdtime = localtime;
    my $targetfile = $reportdir . "/" . $targetrrd . ".html";
    my $TARGETFILE;
    open( $TARGETFILE, '>', "$targetfile" )
        or &LogDie("Can't open file $targetfile - $!");
    print $TARGETFILE <<"EOHTML";
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/dtd/xhtml11.dtd">
<!-- Begin Head -->
<html>
	<head>
		<title>$description</title>
		<meta http-equiv="refresh" content="86400" />
		<meta http-equiv="pragma" content="no-cache" />
		<meta http-equiv="cache-control" content="no-cache" />
		<meta http-equiv="expires" content="$rrdtime" />
		<meta http-equiv="generator" content="$prog $ver" />
		<meta http-equiv="date" content="$rrdtime" />
		<meta http-equiv="content-type" content="text/html; charset=iso-8859-1" />
        <link HREF="ldms_core.css" rel="stylesheet" type="text/css"> 
        <link REL="SHORTCUT ICON" HREF="ldms_core.ico">
	</head>
<body>
<img src="ldms_core_icon.png">
<H1>$description last updated at <A HREF="ldms_core-latest.html">$rrdtime</A>.</H1><br />
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
<!-- Begin Footer Block -->
<hr>
        Report page generated by <a href="http://www.droppedpackets.org/scripts/ldms_core">$prog $ver</a> using <A HREF="http://oss.oetiker.ch/rrdtool/">RRDtool</A>.
<!-- End Footer Block -->
	</body>
</html>

EOHTML
    close($TARGETFILE);
    if ($DEBUG) { &LogDebug("GeneratePage: Recreated $targetfile"); }
}
### End of GeneratePage subroutine ############################################

### WriteReport subroutine ####################################################
sub WriteReport {
    $mailmessage =~ s/\n/<br \/>\n/gx;
    my $rrdtime = localtime;
    my ( $REPORTFILE, $reportfile );
    $reportfile = $reportdir . "/ldms_core-latest.html";
    open( $REPORTFILE, '>', "$reportfile" )
        or &LogDie("Can't open file $reportfile - $!");
    print $REPORTFILE <<"EOHTML";
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/dtd/xhtml11.dtd">
<!-- Begin Head -->
<html>
	<head>
		<title>ldms_core Latest Output Report</title>
		<meta http-equiv="pragma" content="no-cache" />
		<meta http-equiv="cache-control" content="no-cache" />
		<meta http-equiv="generator" content="$prog $ver" />
		<meta http-equiv="content-type" content="text/html; charset=iso-8859-1" />
        <link HREF="ldms_core.css" rel="stylesheet" type="text/css"> 
        <link REL="SHORTCUT ICON" HREF="ldms_core.ico">
	</head>
<body>
<img src="ldms_core_icon.png">
<H1>ldms_core LANDesk Statistics Report last updated at $rrdtime.</H1>
<br />
<hr>
<!-- End Head -->
<P>$mailmessage</P>
<!-- Begin Footer Block -->
        <hr>
        Report page generated by <a href="http://www.droppedpackets.org/scripts/ldms_core">$prog $ver</a> using <A HREF="http://oss.oetiker.ch/rrdtool/">RRDtool</A>.
<!-- End Footer Block -->
	</body>
</html>


EOHTML
    close($REPORTFILE);
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
    &Show_MainWindow;
    Win32::GUI::Dialog();
    if ($DEBUG) { &LogDebug("Returned to Setup from Show_MainWindow"); }

    # Get mail server info
    &Show_SecondWindow;
    Win32::GUI::Dialog();
    if ($DEBUG) { &LogDebug("Returned to Setup from Show_SecondWindow"); }

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
            "/patchdir"          => $PATCHDIR,
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
        &LogDebug( "Wrote $db_type, $db_instance, $db_name, $db_user, "
              . "$db_pass_storage, $mailserver, $mailfrom, "
              . "$mailto, $deletiondays, $PATCHDIR into "
              . "Monkeynoodle registry key." );
    }

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
    my $cli = Win32::GetShortPathName( abs_path($0) );
    $cli =~ s/\//\\/g;    # substitute forward slashes with backslashes
    my $script = $ldmain . "scripts\\ldms_core.ini";
    if ( -e $script ) {

        # We have a script file
        if ($DEBUG) { &LogDebug("$script exists."); }
    }
    else {

        # We need a script file
        if ($DEBUG) { &LogDebug("$script does not exist, creating it."); }
        my $SCRIPTFILE;
        open( $SCRIPTFILE, '>', "$script" )
          or &LogDie("Can't open file $script - $!");
        print $SCRIPTFILE "[MACHINES]\n";
        print $SCRIPTFILE "REMEXEC00=$cli, SYNC\n";
        close $SCRIPTFILE;
    }

    # Script definition
    &OpenDB;
    $sql   = "select count(*) from LD_TASK_CONFIG where CFG_NAME='ldms_core'";
    $count = &GetSingleString($sql);
    if ($count) {

        # We have a definition
        if ($DEBUG) { &LogDebug("ldms_core exists in LD_TASK_CONFIG."); }
    }
    else {

        # We need a definition
        $cfg_params = "\'ldms_core\'+char(0000)";
        $sql =
            "insert into LD_TASK_CONFIG "
          . "(LD_SCHEDULE_EXE_IDN, CFG_NAME, CFG_PARAMS) "
          . "values ('4','ldms_core','$cfg_params')";
        $sth = $dbh->prepare($sql)
          or &LogWarn("$sql caused $DBI::errstr");
        $sth->execute
          or &LogWarn("$DBI::errstr");
        $sth->finish();

        # Tell them what to do next
        Win32::GUI::MessageBox(
            0,
"Managed Script created; Please schedule a LANDesk task to run it. If you
previously used a Windows Scheduled Task, that may now be deleted.",
            "Setup complete!", 64
        );

    }

    &CloseDB;
    return 0;
}
###############################################################################

### Windowing Subroutines  ###################################################
sub Show_MainWindow {

    if ($DEBUG) { &LogDebug("Showing main setup window"); }

    # build window
    $main = Win32::GUI::Window->new(
        -name     => 'Main',
        -text     => 'ldms_core database setup',
        -width    => 350,
        -height   => 250,
        -class    => $ldms_core_class,
        -dialogui => 1,
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

    # Begin patchdir_override row
    $form_patchdir_override = $main->AddTextfield(
        -name    => "patchdir_override_field",
        -prompt  => "Patch Directory: ",
        -text    => $PATCHDIR,
        -tabstop => 1,
        -pos     => [ 110, 150 ],
        -size    => [ 200, 20 ],
    );

    # End patchdir_override row

    # Begin button row
    $btn_Default = $main->AddButton(
        -name    => 'Default',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,             # Give button darker border
        -ok      => 1,             # press 'Return' to click this button
        -pos     => [ 25, 175 ],
        -size    => [ 60, 20 ],
    );

    $btn_Cancel = $main->AddButton(
        -name    => 'Cancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,              # press 'Esc' to click this button
        -pos     => [ 100, 175 ],
        -size    => [ 60, 20 ],
    );

    $btn_DBInfo = $main->AddButton(
        -name    => 'DBInfo',
        -text    => 'Database',
        -tabstop => 1,
        -pos     => [ 175, 175 ],
        -size    => [ 60, 20 ],
    );

    $btn_Help = $main->AddButton(
        -name    => 'Help',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 175 ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $sb = $main->AddStatusBar();
    if ($updatemessage) {
        $sb->Text($updatemessage);
    }

    # calculate its size
    $ncw = $main->Width() - $main->ScaleWidth();
    $nch = $main->Height() - $main->ScaleHeight();
    $w   = $lbl_Instructions->Width() + 50 + $ncw;
    $h =
      $lbl_Instructions->Height() +
      $form_db_instance->Height() +
      $form_db_name->Height() +
      $form_db_user->Height() +
      $form_db_pass->Height() +
      $form_patchdir_override->Height() + 100 +
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
    return 0;
}
###############################################################################

sub Main_Terminate {
    return -1;
}

sub Main_Resize {
    $sb->Move( 0, $main->ScaleHeight - $sb->Height );
    $sb->Resize( $main->ScaleWidth, $sb->Height );
    return 0;
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
    $PATCHDIR = $form_patchdir_override->GetLine(0);

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
            &LogDebug( "Okay clicked in MainWindow: Opening database with "
                  . "$db_type, $db_instance, $db_name, $db_user, db_pass" );
        }
    }
    else {
        $dbh = DBI->connect( "DBI:Oracle:$db_name", $db_user, $db_pass )
          or Win32::GUI::MessageBox( 0, "$DBI::errstr",
            "Database connection failed", 48 );
        if ($DEBUG) {
            &LogDebug( "Okay clicked in MainWindow: Opening database with "
                  . "$db_type, $db_name, $db_user, db_pass" );
        }
    }
    if ( !$dbh ) {
        if ($DEBUG) { &LogDebug("Failed database connection"); }
        $sb->SetText( 0, "Connection failed, please try again." );
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
    while ( @rows = $sth->fetchrow_array() ) {
        $mailserver = $rows[0] || $A{s};
        $mailfrom   = $rows[1] || $A{f};
    }

    # Close the database
    $dbh->disconnect;
    if ($DEBUG) {
        &LogDebug("Read $mailserver, $mailfrom from database connection");
    }

    # If it succeeded, we're ready to close the window and move on.
    $main->Hide();
    return -1;
}
###############################################################################

sub Cancel_Click {
    if ($DEBUG) { &LogDebug("Cancel clicked in MainWindow"); }
    $main->Hide();

    &Log("$prog $ver exiting");

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

sub Help_Click {
    if ($DEBUG) { &LogDebug("Help clicked in Main Window"); }
    open_browser(
        'http://www.droppedpackets.org/scripts/ldms_core/ldms_core-manual');

    return 0;
}

sub DBInfo_Click {
    if ($DEBUG) { &LogDebug("DBInfo clicked in Main Window"); }
    open_browser(
'https://localhost/landesk/ManagementSuite/Core/ssl/information/DatabaseInformation.asmx?op=GetConnectionString'
    );
    return 0;
}

# This subroutine gets email information ######################################
sub Show_SecondWindow {

    # build window
    $second = Win32::GUI::Window->new(
        -name     => 'Second',
        -text     => 'ldms_core email and nmap setup',
        -width    => 350,
        -height   => 220,
        -class    => $ldms_core_class,
        -dialogui => 1,
    );

    # Add some stuff
    $lbl_email = $second->AddLabel(
        -name    => "lbl_email",
        -text    => "Please enter the required email and NMAP information.",
        -tabstop => 0,
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
    $btn_mailauth = $second->AddButton(
        -name    => 'btn_mailauth',
        -text    => 'Authorization',
        -tabstop => 1,
        -pos     => [ 320, 25 ],
        -size    => [ 75, 20 ],
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
    $btn_mailtest = $second->AddButton(
        -name    => 'btn_mailtest',
        -text    => 'Test Email',
        -tabstop => 1,
        -pos     => [ 320, 50 ],
        -size    => [ 75, 20 ],
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
        -pos     => [ 75, 200 ],
        -size    => [ 60, 20 ],
    );

    $btn_secondcancel = $second->AddButton(
        -name    => 'secondCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                 # press 'Esc' to click this button
        -pos     => [ 150, 200 ],
        -size    => [ 60, 20 ],
    );

    $btn_secondHelp = $second->AddButton(
        -name    => 'secondHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 225, 200 ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $sb2 = $second->AddStatusBar();

    # calculate its size
    $ncw = $second->Width() - $second->ScaleWidth();
    $nch = $second->Height() - $second->ScaleHeight();
    $w   = $lbl_email->Width() + 100 + $ncw;
    $h =
      $lbl_email->Height() +
      $form_mailserver->Height() +
      $form_mailfrom->Height() +
      $form_mailto->Height() +
      $form_deletiondays->Height() +
      $form_nmap->Height() +
      $form_nmap_options->Height() +
      $form_nmap_ulabel->Height() + 100 +
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
    return 0;
}
###############################################################################

sub Second_Terminate {
    return -1;
}

sub Second_Resize {
    $sb2->Move( 0, $second->ScaleHeight - $sb2->Height );
    $sb2->Resize( $second->ScaleWidth, $sb2->Height );
    return 0;
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
        &LogDebug(
"Okay clicked in SecondWindow, read $mailserver, $mailfrom, $mailto, $deletiondays"
        );
    }
    $second->Hide();
    return -1;
}

sub secondCancel_Click {
    if ($DEBUG) { &LogDebug("Cancel clicked in SecondWindow"); }

    &Log("$prog $ver exiting");

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

sub secondHelp_Click {
    if ($DEBUG) { &LogDebug("Help clicked in SecondWindow"); }
    open_browser(
        'http://www.droppedpackets.org/scripts/ldms_core/ldms_core-manual');

    return 0;
}

sub btn_mailauth_Click {
    $oldCursor = Win32::GUI::SetCursor($waitCursor);    #show hourglass ...
    &show_mailauth;
    return 0;
}

sub btn_mailtest_Click {

    # Read my variables
    $mailserver = $form_mailserver->GetLine(0);
    $mailfrom   = $form_mailfrom->GetLine(0);
    $mailto     = $form_mailto->GetLine(0);

    if ( $mailserver && $mailfrom && $mailto ) {
        $oldCursor = Win32::GUI::SetCursor($waitCursor);    #show hourglass ...
        $mailmessage = "This is a test message from $prog $ver.";
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

sub show_mailauth {

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
    my $auth_types     = $smtp_auth_test->auth_types;
    if ($DEBUG) {
        &LogDebug("$mailserver supports auth types: $auth_types");
    }
    my @mail_auth_options;
    if ($auth_types) {
        @mail_auth_options = split( / /, $auth_types );
    }
    else {
        Win32::GUI::MessageBox(
            0,
"I can't get a list of authentication types from that server -- are you sure about its name?",
            "Not so ready yet",
            32
        );
        return 0;
    }

    # Build the window
    $mailauth = Win32::GUI::Window->new(
        -name     => 'mailauth',
        -text     => 'ldms_core mail configuration',
        -width    => 450,
        -height   => 400,
        -class    => $ldms_core_class,
        -dialogui => 1,
    );

    # Add some stuff
    $lbl_mailinstructions = $mailauth->AddLabel(
        -name => "lbl_mailauth",
        -text => "Please enter the authorization for your email server.",
        -pos  => [ 5, 5 ],
        -size => [ 300, 20 ],
    );

    # Begin mail_auth_user field
    $form_mail_auth_user = $mailauth->AddTextfield(
        -name    => "mail_auth_user_field",
        -prompt  => "User name: ",
        -tabstop => 1,
        -text    => $mail_auth_user,
        -pos     => [ 85, 35 ],
        -size    => [ 200, 20 ],
    );

    # End mail_auth_user field

    # Begin mail_auth_pass field
    $form_mail_auth_pass = $mailauth->AddTextfield(
        -name     => "mail_auth_pass_field",
        -prompt   => "Password: ",
        -tabstop  => 1,
        -password => 1,
        -text     => $mail_auth_user,
        -pos      => [ 85, 55 ],
        -size     => [ 200, 20 ],
    );

    # End mail_auth_user field

    # Begin mail_auth_type field
    $lbl_mail_auth_type = $mailauth->AddLabel(
        -name => "lbl_mailauthtype",
        -text => "Type: ",
        -pos  => [ 50, 80 ],
        -size => [ 70, 20 ],
    );

    $form_mail_auth_type = $mailauth->AddCombobox(
        -name         => "mail_auth_type_field",
        -tabstop      => 1,
        -dropdownlist => 1,
        -vscroll      => 1,
        -pos          => [ 85, 78 ],
        -size         => [ 75, 120 ],
    );
    foreach my $auth_type (@mail_auth_options) {
        $form_mail_auth_type->AddString($auth_type);
        if ($DEBUG) {
            &LogDebug("mailauth window added auth type: $auth_type");
        }
    }

    # End mail_auth_type field

    # Begin button row
    $btn_mailauthDefault = $mailauth->AddButton(
        -name    => 'mailauthDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,                   # Give button darker border
        -ok      => 1,                   # press 'Return' to click this button
        -pos     => [ 75, 110 ],
        -size    => [ 60, 20 ],
    );

    $btn_mailauthCancel = $mailauth->AddButton(
        -name    => 'mailauthCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                   # press 'Esc' to click this button
        -pos     => [ 150, 110 ],
        -size    => [ 60, 20 ],
    );

    $btn_mailauthHelp = $mailauth->AddButton(
        -name    => 'mailauthHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 225, 110 ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $mailauthsb = $mailauth->AddStatusBar();

    # calculate its size
    $mailauthncw = $mailauth->Width() - $mailauth->ScaleWidth();
    $mailauthnch = $mailauth->Height() - $mailauth->ScaleHeight();
    $mailauthw   = $lbl_mailinstructions->Width() + 50 + $mailauthncw;
    $mailauthh =
      $lbl_mailinstructions->Height() +
      $form_mail_auth_pass->Height() +
      $form_mail_auth_user->Height() + +100 +
      $mailauthnch;

    # Don't let it get smaller than it should be
    $mailauth->Change( -minsize => [ $mailauthw, $mailauthh ] );

    # calculate its centered position
    # Assume we have the main window size in ($macw, $mach) as before
    $mailauthwx = ( $dw - $mailauthw ) / 2;
    $mailauthwy = ( $dh - $mailauthh ) / 2;

    # Resize, position and display
    $mailauth->Resize( $mailauthw, $mailauthh );
    $mailauth->Move( $mailauthwx, $mailauthwy );

    Win32::GUI::SetCursor($oldCursor);    #show previous arrow cursor again

    $mailauth->Show();
    return 0;
}

sub mailauth_Terminate {
    return -1;
}

sub mailauth_Resize {
    $mailauthsb->Move( 0, $mailauth->ScaleHeight - $mailauthsb->Height );
    $mailauthsb->Resize( $mailauth->ScaleWidth, $mailauthsb->Height );
    return 0;
}

sub form_mail_auth_type_GotFocus {
    $form_mail_auth_type->ShowDropDown(1);
    return 0;
}

sub mailauthDefault_Click {

    if ($DEBUG) { &LogDebug("Okay clicked in MailAuthWindow"); }

    # Read my variables
    $mail_auth_user = $form_mail_auth_user->GetLine(0);
    $mail_auth_pass = $form_mail_auth_pass->GetLine(0);
    $mail_auth_type =
      $form_mail_auth_type->Text(
        $form_mail_auth_type->GetString( $form_mail_auth_type->SelectedItem ) );
    if ($DEBUG) {
        &LogDebug(
"read $mail_auth_user, mail_auth_pass, $mail_auth_type from user input"
        );
    }
    $mailauth->Hide();
    return 0;
}

sub mailauthCancel_Click {
    if ($DEBUG) { &LogDebug("Cancel clicked in MailAuthWindow"); }
    $mailauth->Hide();
    return 0;
}

sub mailauthHelp_Click {
    if ($DEBUG) { &LogDebug("Help clicked in MailAuthWindow"); }
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
        ">EventViewer" => {
            -name    => "Event Viewer",
            -onClick => \&eventvwr
        },
        ">Exit" => {
            -name    => "Exit",
            -onClick => \&systrayexit
        }
    );
    $systraynotify = $systraymain->AddNotifyIcon(
        -name         => "ldms_core_systray",
        -icon         => $systrayicon,
        -tip          => "$prog $ver running\n",
        -balloon_icon => "info",
        -onClick      => \&systraymenu,
        -onRightClick => \&systraymenu,

    );
    return 0;
}

sub change_balloon {

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

sub eventvwr {
    system("eventvwr.msc");
    return 0;
}

sub systrayexit {
    &LogDie("Killed by user");
    return 0;
}
## End of Windowing Subroutines  ############################################

