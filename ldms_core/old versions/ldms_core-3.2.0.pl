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
# TODO -- plot non-RFC1918 addresses on a map
# TODO -- purty Charts, http://search.cpan.org/src/CHARTGRP/Chart-2.4.1/README
# TODO -- Find a way to detect stuck LPM Event Listeners
# TODO -- Cull software definitions with no installations
# TODO -- import ldms_deleteusers, auto-reassign to single user
# TODO -- Button to disable NMAP in UI
# TODO -- before NMAP, try NETBIOS OS lookup

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use Env;
use Cwd 'abs_path';
use DBI;
use IO::Handle;
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
# Preparation                                                               #
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

    # Go ahead and load all those windowing-related variables too
}

( my $prog = $0 ) =~ s/^         # command line from the beginning
                       .*[\\\/]  # without any slashes
                       //x;
my $ver = "3.2.0";

# Now we're running for real, so let's show off
&EnableSystray;

# Prepare logging system
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";

# Get the window handle so we can hide it
my ($DOS) = Win32::GUI::GetPerlWindow();

my $DEBUG = $A{d} || $A{debug} || 0;
my ( $logfile, $DEBUGFILE );

if ( !$DEBUG ) {

    # Hide console window
    Win32::GUI::Hide($DOS);
}

if ($DEBUG) {

    $logfile = $prog . "-" . $ver . "-" . &genfilename . ".log";
    open( $DEBUGFILE, '>', "$logfile" )
      or &LogDie("Can't open file $logfile : $!\n");
    $DEBUGFILE->autoflush();
    my @cli = %A;
    &LogDebug("$prog $ver starting in debug mode. $0 @cli");
    close($DEBUGFILE);
}

#############################################################################
# Variables                                                                 #
#############################################################################

# Global variables
my (
    $ldmain,          $PATCHDIR,       $db_type,
    $db_user,         $db_pass,        $db_name,
    $db_instance,     $reportdir,      $sql,
    $dbh,             $sth,            @row,
    @files,           @patchurls,      @patchcounts,
    @autofixcounts,   $mailserver,     $mailfrom,
    $mailto,          $mailmessage,    $sendemail,
    $mail_auth_user,  $mail_auth_pass, $mail_auth_type,
    $mailverbosity,   $DIR,            $FILE,
    $updatemessage,   $np,             $nmap_unidentified,
    @Address,         $allmachines,    @dupmachines,
    $dbscans,         $dbscansweek,    $allmachines_udd,
    $dbscans_udd,     $source,         $vulnlife,
    $dbscansweek_udd, @dupaddresses,   $daypercent,
    $weekpercent,     $daypercent_udd, %rtn,
    $weekpercent_udd, @dualboots,      $supercededvulncount,
    @supercededvulns, $update
);

# Default to zero
my (
    $deletiondays,  $osupdates,  $macupdates,
    $vendorupdates, $goodcount,  $recentvulns,
    $vulncount,     $patchtotal, $autofixtotal,
    $trashcount, $renamecount,   $compresscount, 
    $totalsize
) = 0;

# GUI variables
my (
    $ldms_core_icon, $ldms_core_class, $systrayicon,
    $systraymain,    $popupMenu,       $systraynotify
);

# Setup UI variables
my (
    $DBWindow,                $lbl_Instructions,
    $form_db_instance,        $form_db_name,
    $form_db_user,            $form_db_pass,
    $lbl_db_type,             $form_db_type,
    $db_type_binary,          $form_patchdir_override,
    $btn_DBWindowDefault,     $btn_DBWindowCancel,
    $btn_DBWindowHelp,        $btn_DBWindowDBInfo,
    $btn_browsepatchdir,      $btn_browsenmap,
    $DBWindowsb,              $ConfigWindow,
    $lbl_email,               $lbl_patch,
    $lbl_update,              $form_update,
    $form_mailserver,         $form_mailfrom,
    $form_mailto,             $form_deletiondays,
    $btn_ConfigWindowdefault, $btn_ConfigWindowcancel,
    $ConfigWindowsb,          $form_nmap,
    $form_nmap_u,             $form_nmap_options,
    $form_nmap_ulabel,        $btn_mailauth,
    $btn_ConfigWindowHelp,    $MailAuth,
    $lbl_mailinstructions,    $form_mail_auth_user,
    $form_mail_auth_pass,     $btn_MailAuthDefault,
    $btn_MailAuthCancel,      $btn_MailAuthHelp,
    $MailAuthsb,              $form_mail_auth_type,
    $lbl_mail_auth_type,      $btn_mailtest,
    $form_mailverbosity,      $lbl_mailverbosity,
    $w,                       $h,
    $ncw,                     $nch,
    $dw,                      $dh,
    $desk,                    $wx,
    $wy,                      $ConfigWindoww,
    $ConfigWindowh,           $ConfigWindowncw,
    $ConfigWindownch,         $ConfigWindowwx,
    $ConfigWindowwy,          $MailAuthw,
    $MailAuthh,               $MailAuthncw,
    $MailAuthnch,             $MailAuthwx,
    $MailAuthwy
);

# NMAP Variables and defaults
my $nmap         = Win32::GetShortPathName("C:/Program Files/nmap/nmap.exe");
my $nmap_options = "-A -T4 -P0 -n";

# Prepare encryption system
my $Blowfish_Cipher;
&PrepareCrypto;

# I like to read the event viewer
my $EventViewerhandle = Win32::EventLog->new( "Application", $COMPUTERNAME )
  or &LogWarn("Initialization: Can't open Application EventLog");

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

# Default verbosity is high
if ( !$mailverbosity ) { $mailverbosity = 5; }
# Default update frequency is weekly
if ( !$update ) { $update = 7; }
# Default deletion days is 30
if ( !$deletiondays ) { $deletiondays = 30; }

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
if ( $A{v} )            { $mailverbosity     = $A{v}; }
if ( $A{update} )       { $update            = $A{update}; }
if ( $A{m_user} )       { $mail_auth_user    = $A{m_user}; }
if ( $A{m_pass} )       { $mail_auth_pass    = $A{m_pass}; }
if ( $A{m_type} )       { $mail_auth_type    = $A{m_type}; }
if ( $A{x} )            { $deletiondays      = $A{x}; }
if ( $A{nmap} )         { $nmap              = $A{nmap}; }
if ( $A{nmap_options} ) { $nmap_options      = $A{nmap_options}; }
if ( $A{u} )            { $nmap_unidentified = $A{nmap_unidentified}; }

# Report deletion days... this has been annoying with support
if ($DEBUG) { &LogDebug("Deletion days is $deletiondays"); }

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
             [-v=(1-5)] [-update=(0-7)]
			 
	-d(ebug)	 debug
	-x=[number]	 delete scans and patches more than [number] days old. Files go
                  to the Recycle Bin. Default is off. This option also controls
                  removal of unmanaged device records which are no longer on
                  the network.
	-m=me\@here	 email address to send output report to.
	-f=ld\@here	 email address to send output report from.
	-s=host		 email server to send output report through.
    -v           verbosity threshold for email sending.
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
	-update      Days before checking online for an updated version

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program maintains your LANDesk core server. It provides HTML reports 
and will email you if there's something important.
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
        &LogDebug("Cannot find NMAP at $nmap");
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
&DoVulnLife;
&DoPatchStats;

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
if ( $sendemail <= $mailverbosity || $DEBUG ) {
    &Log("sendemail is $sendemail, mailverbosity is $mailverbosity");
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
$systraynotify->Remove();

exit 0;

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
sub zeropad {

    my $ip = shift;

    # Pad IP Addresses with zeroes for use in LANDesk database
    my $return = sprintf( "%03d.%03d.%03d.%03d", split /\./x, $ip );
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
    if ( $target =~ /$range/x ) {

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

    if ($update == 0) {
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
                &LogDebug( "lastcheck was $lastcheck, weekago was $weekago"
                      . " skipping update check." );
            }
            return 0;
        }
    }

    my $url     = 'http://www.droppedpackets.org/scripts/ldms_core/version';
    my $content = get $url;
    my ( $onlineversion, $myversion );
    if ( defined($content) ) {
        $myversion = $ver;
        $content =~ m{<p>latest version is ([\d.]+)<br /></p>};
        if ($1) {
            $onlineversion = $1;
        }

        if ($DEBUG) { &LogDebug("onlineversion is $onlineversion"); }

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
        $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
        my $output = &Trim( $sth->fetchrow() );
        $sth->finish;
        return $output;
    }
    else {
        &LogDie("GetSingleString routine called with no database handle!");
## Please see file perltidy.ERR
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
        $sth = $dbh->prepare($sql) or &LogWarn("$sql caused $DBI::errstr\n");

        # Is the user trying to kill us?
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
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
        $sth = $dbh->prepare($sql) or &LogWarn("$sql caused $DBI::errstr\n");

        # Is the user trying to kill us?
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
        while ( @row = $sth->fetchrow_array() ) {
            push( @output, &Trim( $row[0] ) . " - " . &Trim( $row[1] ) );
            Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        }
        $sth->finish;
        return @output;
    }
    else {
        &LogDie("GetTwoColumnList routine called with no database handle!");
        return 1;
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
        $sth->execute or &LogDie("$sql caused $DBI::errstr\n");
        $sth->finish;
        return 0;
    }
    else {
        &LogDie("DoDBAction routine called with no database handle!");
        return 1;
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
# delete this file, unless DEBUG is set; then just talk about deleting it
sub DeleteFile {

    my ( $targetfile, $filetime ) = @_;
    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
    if ($DEBUG) {
        my $deldays = floor(
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

    open( $DEBUGFILE, '>>', "$logfile" )
      or &LogDie("Can't open file $logfile : $!\n");
    $DEBUGFILE->autoflush();
    print $DEBUGFILE "$msg\n";
    close($DEBUGFILE);
    $mailmessage .= "$msg\n";
    return 0;
}

### Calculate Inventory percentages ###########################################
sub DoInventoryMath {
    my $dupcount;
    my $dupreport;

    # Look for public key hash errors
    my $schemaerrors = &CountSchemaErrors();
    if ($schemaerrors) {
        $sendemail = 2;
        &Log("$schemaerrors Public Key hash errors in the last day.");
    }

    # Do you have machines?
    if ($allmachines) {

        # X% of your machines scanned in today
        if ($dbscans) {
            $daypercent = int( ( $dbscans / $allmachines ) * 100 );

            # Look for public key hash errors
            my $pkhasherrors = &CountHashErrors();
            my $hashpercent;
            if ($pkhasherrors) {
                $hashpercent = int( ( $pkhasherrors / $dbscans ) * 100 );
                if ( $hashpercent > 10 ) { $sendemail = 2; }
                &Log("$pkhasherrors Public Key hash errors in the last day.");
            }

            # Rescan forced?
            my $forcedfullscans = &CountForcedScans();
            my $forcedpercent;

            # X% of today's scans had full rescans forced on them
            if ($forcedfullscans) {
                $forcedpercent = int( ( $forcedfullscans / $dbscans ) * 100 );
                if ( $forcedpercent > 10 ) { $sendemail = 2; }
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
                &Log(   "Less than half of your machines have scanned in the "
                      . "last seven days; you should consider more frequent "
                      . "scanning to prevent stale data." );
                $sendemail = 3;
            }
        }
    }

    # Do you have duplicates?
    if (@dupmachines) {
        $dupcount = 0;
        foreach my $dup (@dupmachines) {
            $dupreport .= "$dup\n";
            $dupcount++;
        }
        if ($dupcount) {
            if ( $dupcount == 1 ) {
                $dupreport =
                  "Duplicate computer record detected:\n" . $dupreport;
            }
            else {
                $dupreport =
                  "Duplicate computer records detected:\n" . $dupreport;
            }
            $sendemail = 5;
            Log("$dupcount $dupreport");
        }
    }
    if (@dupaddresses) {
        $dupcount = 0;
        foreach my $dup (@dupaddresses) {
            if ( &IsIPAddress($dup) ) {
                $dupreport .= "$dup\n";
                $dupcount++;
            }
        }
        if ($dupcount) {
            if ( $dupcount == 1 ) {
                $dupreport = "Duplicate IP Address detected:\n" . $dupreport;
            }
            else {
                $dupreport = "Duplicate IP Addresses detected:\n" . $dupreport;
            }
            $sendemail = 5;
            Log("$dupcount $dupreport");
        }
    }

    # Do you have dual booting machines?
    if (@dualboots) {
        $dupcount = 0;
        foreach my $dup (@dualboots) {
            $dupreport .= "$dup\n";
            $dupcount++;
        }
        if ($dupcount) {
            if ( $dupcount == 1 ) {
                $dupreport = "Dual booting machine detected:\n" . $dupreport;
            }
            else {
                $dupreport = "Dual booting machines detected:\n" . $dupreport;
            }
            $sendemail = 5;
            &Log("$dupcount $dupreport");
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
sub DoVulnLife {

    my $vulnmessage;

    # Your vulnerabilities live this long
    if ($vulnlife) {
        if ($DEBUG) { &LogDebug("Calculating how long vulns live"); }
        my ( $vulndays, $vulnhours, $vulnminutes, $vulnseconds ) =
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
                $sendemail = 3;
            }
        }
    }
    else {
        $vulnmessage =
          "Vulnerabilities go unpatched (by LANDesk at least) forever.";
        $sendemail = 3;
    }

    # Report on repair timing
    &Log("$vulnmessage\n");
    return 0;
}

sub DoPatchStats {

    # Total up patch counts and autofix counts
    if (@patchcounts) {
        foreach my $p (@patchcounts) {
            my ( $d, $c ) = split( / - /x, $p );
            $patchtotal += $c;
        }
    }
    if (@autofixcounts) {
        foreach my $p (@autofixcounts) {
            my ( $d, $c ) = split( / - /x, $p );
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
    if ($DEBUG) {
        &LogDebug("GetLDMSData, allmachines_udd=$allmachines_udd");
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
    if ($DEBUG) {
        &LogDebug("GetLDMSData, dbscansweek_udd=$dbscansweek_udd");
    }

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
    $sql       = "SELECT count(vul_id) from vulnerability where status != '0'";
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
      )
      or &LogWarn(
        "Problem graphing from ldmsstats: " . map { $rtn{$_}->[0] }
          keys %rtn
      );

    if ($DEBUG) {
        &LogDebug(
            "Logged LDMS RRD statistics: " . map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldmsstats",
        "LANDesk Management Suite Inventory Statistics" );

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
      )
      or &LogWarn(
        "Problem graphing from ldmsstats_udd: " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "Logged LDMS UDD RRD statistics: " . map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldmsstats_udd",
        "LANDesk Management Suite Unmanaged Device Statistics" );

    &Log($ldmsmessage);
    return 0;
}

### Report on LDSS Statistics ###############################################
sub ReportLDSSStats {

    # Update RRD too
    $ldssrrd_life->update( VulnLife => $vulnlife )
      or &LogWarn("Problem writing to ldssstats_life: $!");
    %rtn = $ldssrrd_life->graph(
        destination      => "$reportdir",
        title            => "LDSS Vulnerability Duration",
        vertical_label   => "Detection to Repair",
        interlaced       => "",
        source_drawtypes => "AREA"
      )
      or &LogWarn(
        "Problem graphing from ldssstats_life: " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "Logged LDSS RRD Life statistics: " . map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldssstats_life",
        "LANDesk Security Suite Vulnerability Lifetime" );

    # Warn if data is seeming stale
    if ( $recentvulns == 0 ) {
        &Log(   "No new vulnerabilities have been downloaded in the last seven "
              . "days; is your scheduled download still working?" );
        $sendemail = 2;
    }

    # Report on patch statistics
    if (@patchcounts) {
        my $patchcountsreport = "Detected vulnerability counts by severity:\n";
        foreach my $patchtypecount (@patchcounts) {
            $patchcountsreport .= "$patchtypecount\n";
        }
        &Log("$patchcountsreport");
    }

    # How many of those are autofix?
    if (@autofixcounts) {
        my $autofixreport =
          "Detected vulnerabilities set to autofix by severity:\n";
        foreach my $patchtypecount (@autofixcounts) {
            $autofixreport .= "$patchtypecount\n";
        }
        &Log("$autofixreport");
    }

    # Update RRD too
    $ldssrrd->update(
        ScannedVulns  => $vulncount,
        DetectedVulns => $patchtotal,
        AutofixVulns  => $autofixtotal
    ) or &LogWarn("Problem writing to ldssstats: $!");
    %rtn = $ldssrrd->graph(
        destination    => "$reportdir",
        title          => "LDSS Vulnerability Statistics",
        vertical_label => "All / Detected / Autofix",
        interlaced     => ""
      )
      or &LogWarn(
        "Problem graphing from ldssstats: " . map { $rtn{$_}->[0] }
          keys %rtn
      );
    if ($DEBUG) {
        &LogDebug(
            "Logged LDSS RRD statistics: " . map { $rtn{$_}->[0] }
              keys %rtn
        );
    }
    &GeneratePage( "ldssstats",
        "LANDesk Security Suite Vulnerability Statistics" );

    # Report on manual patch download requirements
    if (@patchurls) {
        my $patchurlsreport = "Manual patch downloads required:\n";
        foreach my $patchurl (@patchurls) {
            $patchurlsreport .= "$patchurl\n";
        }
        $sendemail = 4;
        &Log("$patchurlsreport");
    }

    # Create the RRD Index page
    &GenerateIndex;
    return 0;
}

### Count pending scans subroutine ############################################
sub CountPendingScans {
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
    while ( $source = readdir($DIR) ) {
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

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
    while ( $source = readdir($DIR) ) {
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

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
    my $alertcount = 0;
    while ( $source = readdir($DIR) ) {
        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

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
    return $alertcount;
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
    while ( $source = readdir($DIR) ) {

        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

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
    return $sdcount;
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

### Look for database schema errors in the Event Viewer #####################
# Need to limit this to a single day's data
sub CountSchemaErrors {
    my ( $handle, $base, $recs, %Event, $record, $result );

    # One day ago
    my $TIME_LIMIT = time() - 86400;

    # if this is set, we also retrieve the full text of every
    # message on each Read( )
    local $Win32::EventLog::GetMessageText = 0;

    $handle = Win32::EventLog->new( "Application", $COMPUTERNAME )
      or &LogWarn("CountSchemaErrors Can't open Application EventLog");

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
            if ( $Event{EventType} == 4100 and $Event{EventID} == 0 ) {
                local $Win32::EventLog::GetMessageText = 1;
                my $text = $EventViewerhandle->GetMessageText();
                if ($text =~ m/^The size of "/) {
                    &Log($text);
                    $result++;
                }
            }
        }
        $record++;
    }
    if ($result) {
        if ($DEBUG) {
            &LogDebug(
                "CountSchemaErrors found result of $result, record of $record.");
        }
        return $result;
    }
    else {
        if ($DEBUG) {
            &LogDebug("CountSchemaErrors found nothing.");
        }
        return 0;
    }
}
###############################################################################

### Clean up temp scan files #################################################
sub CullTMP {
    my $ldscan = $ldmain . "ldscan";
    if ( !-e $ldscan ) {
        &LogWarn("Directory $ldscan doesn't seem to exist?");
        return 1;
    }

    my $tmpcount;
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
### Old Patch cleanup subroutine ##############################################
sub CullPatches {

    my $PATCHDIR = $ldmain . "ldlogon\\patch";
    if ( !-e $PATCHDIR ) {
        &LogWarn("Directory $PATCHDIR doesn't seem to exist?");
        return 1;
    }

    my $patchcount;
    my $netdrive = 0;
    if ($DEBUG) { &LogDebug("Analyzing patches in $PATCHDIR"); }
    if ( $PATCHDIR =~ m/^\\\\/x ) {
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
                    if ($DEBUG) {
                        &LogDebug( "stat() says $file atime " . "is $atime" );
                    }
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

    # Open Database
    &OpenDB;

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

        # Do the marker file
        my $purgemarker = $ldmain . "alertqueue\\purge.sig";
    
        # Check the file
        if ( !-e $purgemarker ) {

            # touch the purge marker;
            open( $FILE, '>', "$purgemarker" )
              or &LogWarn("CullAlerts: Can't create $purgemarker : $!");
            print $FILE "\n";
            close($FILE);
            if ($DEBUG) { &LogDebug("created $purgemarker"); }
        }

        # Report our activity
        if ( $alertpurges > 0 ) {
            &Log(   "Marked $alertpurges Alert records for purging which were "
                  . "older than $deletiondays days." );
        }
    }

    # Close database
    &CloseDB;

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
        if ( $ldms_version == 88 ) {
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
            if ( $ldms_version == 88 ) {
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

    my $SCANDIR = $ldmain . "ldscan\\errorscan";
    if ( !-e $SCANDIR ) {
        &LogWarn("Directory $SCANDIR doesn't seem to exist?");
        return 1;
    }

    # Open the database
    &OpenDB;

    $trashcount  = 0;
    $renamecount = 0;

    my $netdrive = 0;
    if ( $SCANDIR =~ m/^\\\\/x ) {
        $netdrive = 1;
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
            if ( $netdrive == 1 ) {
                $trashcount++;

                # Stat won't work on network drives
                &DeleteFile( $file, localtime );
            }
            my $time = eval {
                time() - eval { $deletiondays * 86400 };
            };

            # stat, 8 is ATIME, 9 is MTIME, 10 is CTIME
            my $mtime = ( stat( $SCANDIR . "\\" . $source ) )[8]
              or &LogWarn("Can't access file $source : $!\n");
            if ( $mtime < $time ) {
                $trashcount++;
                &DeleteFile( $SCANDIR . "\\" . $source, $mtime );
            }
        }

        # Ignore scan files that were already renamed
        next if $source =~ /^_/x;

        # Look for a good name
        $file = $SCANDIR . "\\" . $source;
        open( $FILE, '<', "$file" )
          or &LogWarn("Can't open file $file : $!\n");
        while ( my $line = <$FILE> ) {
            my @parts = split( /=/x, $line );
            $newname = &GetNewName(@parts);
            if ( $newname != 0 ) {
                last;
            }
        }
        close($FILE);

        # if we weren't able to get something, we don't move the file.
        # if debug is off, try to move the file and fail safely if we can't.
        # if debug is on, just print what would have been done.
        if ($newname) {
            $newname = $SCANDIR . "\\_" . $newname . "_" . $source;
            if ($DEBUG) {
                &LogDebug("I would be renaming $file to $newname");
            }
            else {
                if ( copy( "$file", "$newname" ) ) {
                    unlink($file)
                      || &LogWarn("CullScanFiles: unlink $file : $!");
                    $renamecount++;
                }
                else {
                    &LogWarn("CullScanFiles: copy $file, $newname : $!");
                }
            }
        }
        else {
            if ($DEBUG) {
                &LogDebug("couldn't get anything from $source");
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

### Does this line contain a new name subroutine ############################
sub GetNewName {
    my @parts = @_;

    # If the UUID is in the database, get the device name
    if ( $parts[0] =~ m/^Device ID/x ) {
        my $uuid = &Trim( $parts[1] );
        if ($DEBUG) { &LogDebug("$source is from $uuid"); }

        $sql = "select devicename from computer where deviceid='$uuid'";
        my $devicename = &GetSingleString($sql);
        if ($devicename) {
            return $devicename;
        }
    }

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

    # If the scan didn't have Device ID in it, we'll try each of these.
    # The first one to match wins.
    if ( $parts[0] =~ m/^Device Name/x ) {
        $marker = &Trim( $parts[1] );
        if ($DEBUG) { &LogDebug("$source is from $marker"); }
        return $marker;
    }
    if ( $parts[0] =~ m/^Network - TCPIP - Host Name/x ) {
        $marker = &Trim( $parts[1] );
        if ($DEBUG) { &LogDebug("$source is from $marker"); }
        return $marker;
    }
    if ( $parts[0] =~ m/^Network - TCPIP - Address/x ) {
        $marker = &Trim( $parts[1] );
        if ($DEBUG) { &LogDebug("$source is from $marker"); }
        return $marker;
    }

    # If all else fails, return 0
    return 0;
}

### Stored scanfile cleanup subroutine ####################################
sub CompressStorageFiles {

    my $STORAGEDIR = $ldmain . "ldscan\\storage";
    if ( !-e $STORAGEDIR ) {
        if ($DEBUG) {
            &LogDebug("Directory $STORAGEDIR doesn't seem to exist?");
        }
        return 1;
    }

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
                        "$source is $days days old, should be compressed\n");
                }
                else {
                    my $file_member =
                      $zip->addFile( $STORAGEDIR . "\\" . $source, $source );
                    $filestokill[$compresscount] = $STORAGEDIR . "\\" . $source;
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
            my $outputfile = $prog . "-" . $ver . "-" . &genfilename . ".log";
            &Log( "Something is wrong with email -- writing output report file "
                  . "to $outputfile" );
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

    # Open the database
    if ( $db_type eq "SQL" ) {
        $dbh = DBI->connect(
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
        "CBA8",
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
            "IsAutomatic called without a service to check. " . "$servicekey" );
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
            "Checked $servicetarget, current state = $status{CurrentState}.");
    }
    if ( $status{CurrentState} == 1 ) {
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

    my ($nmapcount, $maxnmapcount);

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
    my @Address_np;
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
              . "$newmac, $hostaddr" );
        return 1;
    }

    # Sanitize the new MAC Address
    $newmac =~ s/://gx;
    $newmac =~ s/-//gx;
    chomp($newmac);

    Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");

    # Update the MAC Address if it didn't exist before
    $sql = "select top 1 PHYSADDRESS from UNMANAGEDNODES WHERE IPADDRESS=?";
    my $oldmac = &GetSingleString($sql);

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
              . "$vendor_id, $hostaddr" );
        return 1;
    }

    # Update the Manufacturer if it didn't exist before
    # The field only exists in 8.8 and newer
    if ( $ldms_version >= 88 ) {

        Win32::GUI::DoEvents() >= 0 or &LogDie("Killed by user.");
        $sql =
          "select top 1 MANUFACTURER from UNMANAGEDNODES WHERE IPADDRESS=?";
        my $oldman = &GetSingleString($sql);

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
        $reportdir = $ldmain . "reports\\ldms_core";

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
        $update      = $RegKey->GetValue("update");

        # Decrypt what we got from the registry
        $db_pass        = &Decrypt($db_pass);
        $db_user        = $RegKey->GetValue("db_user");
        $mailserver     = $RegKey->GetValue("mailserver");
        $mailfrom       = $RegKey->GetValue("mailfrom");
        $mailto         = $RegKey->GetValue("mailto");
        $mailverbosity  = $RegKey->GetValue("mailverbosity");
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
    if ( !-e $reportdir ) { &makeDir($reportdir); }
    return 0;
}
### End of PrepareRRD subroutine ##############################################

### GenerateIndex subroutine ###################################################
# Writes index HTML page to display RRD counters from
sub GenerateIndex {

    # Make sure the favicon is there
    if ( !-e "$reportdir/ldms_core.ico" ) {
        if ( -e "ldms_core.ico" ) {
            copy( "ldms_core.ico", "$reportdir/ldms_core.ico" )
              or &LogWarn("Cannot copy ldms_core.ico to $reportdir - $!");
        }
    }
    if ( !-e "$reportdir/ldms_core.css" ) {
        if ( -e "ldms_core.css" ) {
            copy( "ldms_core.css", "$reportdir/ldms_core.css" )
              or &LogWarn("Cannot copy ldms_core.css to $reportdir - $!");
        }
    }
    my $rrdtime    = localtime;
    my $targetfile = $reportdir . "/index.html";
    my $output = <<"EOHTML";
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
    open( $FILE, '>', "$targetfile" )
      or &LogDie("Can't open file $targetfile - $!");
    print $FILE $output;
    close($FILE);
    if ($DEBUG) { &LogDebug("GeneratePage: Recreated $targetfile"); }
    return 0;
}
### End of GenerateIndex subroutine ############################################

### GeneratePage subroutine ###################################################
# Writes counter-specific HTML pages to display RRD traffic
sub GeneratePage {
    my ( $targetrrd, $description ) = @_;
    my $dayfile    = $targetrrd . "-daily.png";
    my $weekfile   = $targetrrd . "-weekly.png";
    my $monthfile  = $targetrrd . "-monthly.png";
    my $yearfile   = $targetrrd . "-annual.png";
    my $rrdtime    = localtime;
    my $targetfile = $reportdir . "/" . $targetrrd . ".html";
    my $output =<<"EOHTML";
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
    my $reportfile = $reportdir . "/ldms_core-latest.html";
    my $output =<<"EOHTML";
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
    open( $FILE, '>', "$reportfile" )
      or &LogDie("Can't open file $reportfile - $!");
    print $FILE $output;
    close($FILE);
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
    if ($DEBUG) { &LogDebug("Returned to Setup from DBWindow_Show"); }

    # Get mail server info
    &ConfigWindow_Show;
    Win32::GUI::Dialog();
    if ($DEBUG) { &LogDebug("Returned to Setup from Show_ConfigWindow"); }

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
            "/update"            => $update,
            "/patchdir"          => $PATCHDIR,
            "/mailserver"        => $mailserver,
            "/mailfrom"          => $mailfrom,
            "/mailto"            => $mailto,
            "/mail_auth_user"    => $mail_auth_user,
            "/mail_auth_pass"    => $mail_auth_pass,
            "/mail_auth_type"    => $mail_auth_type,
            "/mailverbosity"     => $mailverbosity,
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
    my $cfg_params;

    # Script file
    my $cli = Win32::GetShortPathName( abs_path($0) );
    $cli =~ s/\//\\/gx;    # substitute forward slashes with backslashes
    my $script = $ldmain . "scripts\\ldms_core.ini";
    if ( -e $script ) {

        # We have a script file
        if ($DEBUG) { &LogDebug("$script exists."); }
    }
    else {

        # We need a script file
        if ($DEBUG) { &LogDebug("$script does not exist, creating it."); }
        open( $FILE, '>', "$script" )
          or &LogDie("Can't open file $script - $!");
        print $FILE "[MACHINES]\n";
        print $FILE "REMEXEC00=$cli, SYNC\n";
        close $FILE;
    }

    # Script definition
    &OpenDB;
    $sql = "select count(*) from LD_TASK_CONFIG where CFG_NAME='ldms_core'";
    my $count = &GetSingleString($sql);
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
"Managed Script created; Please schedule a LANDesk task to run it. If you "
              . "previously used a Windows Scheduled Task, that may now be deleted.",
            "Setup complete!",
            64
        );

    }

    &CloseDB;
    return 0;
}
###############################################################################

### Windowing Subroutines  ###################################################
sub DBWindow_Show {

    my $leftmargin   = 120;
    my $rightmargin  = 25;
    my $bottommargin = 50;
    my $nexthoriz    = 5;

    if ($DEBUG) { &LogDebug("Showing database setup window"); }

    # build window
    $DBWindow = Win32::GUI::Window->new(
        -name     => 'DBWindow',
        -text     => 'ldms_core database setup',
        -class    => $ldms_core_class,
        -dialogui => 1,
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
    $btn_DBWindowDefault = $DBWindow->AddButton(
        -name    => 'DBWindowDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,                   # Give button darker border
        -ok      => 1,                   # press 'Return' to click this button
        -pos => [ 25, $nexthoriz += 25 ],
        -size => [ 60, 20 ],
    );

    $btn_DBWindowCancel = $DBWindow->AddButton(
        -name    => 'DBWindowCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                     # press 'Esc' to click this button
        -pos     => [ 100, $nexthoriz ],
        -size    => [ 60, 20 ],
    );

    $btn_DBWindowDBInfo = $DBWindow->AddButton(
        -name    => 'DBWindowDBInfo',
        -text    => 'Database',
        -tabstop => 1,
        -pos     => [ 175, $nexthoriz ],
        -size    => [ 60, 20 ],
    );

    $btn_DBWindowHelp = $DBWindow->AddButton(
        -name    => 'DBWindowHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, $nexthoriz ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $DBWindowsb = $DBWindow->AddStatusBar();
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

sub DBWindow_Terminate {
    return -1;
}

sub DBWindow_Resize {
    $DBWindowsb->Move( 0, $DBWindow->ScaleHeight - $DBWindowsb->Height );
    $DBWindowsb->Resize( $DBWindow->ScaleWidth, $DBWindowsb->Height );
    return 0;
}

# What do do when the button is clicked #######################################
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
          or Win32::GUI::MessageBox( 0, "$DBI::errstr",
            "Database connection failed", 48 );
        if ($DEBUG) {
            &LogDebug( "Okay clicked in DBWindow: Opening database with "
                  . "$db_type, $db_instance, $db_name, $db_user, db_pass" );
        }
    }
    else {
        $dbh = DBI->connect( "DBI:Oracle:$db_name", $db_user, $db_pass )
          or Win32::GUI::MessageBox( 0, "$DBI::errstr",
            "Database connection failed", 48 );
        if ($DEBUG) {
            &LogDebug( "Okay clicked in DBWindow: Opening database with "
                  . "$db_type, $db_name, $db_user, db_pass" );
        }
    }
    if ( !$dbh ) {
        if ($DEBUG) { &LogDebug("Failed database connection"); }
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
        $mailserver = $row[0] || $A{s};
        $mailfrom   = $row[1] || $A{f};
    }

    # Close the database
    $dbh->disconnect;
    if ($DEBUG) {
        &LogDebug("Read $mailserver, $mailfrom from database connection");
    }

    # If it succeeded, we're ready to close the window and move on.
    $DBWindow->Hide();
    return -1;
}
###############################################################################

sub DBWindowCancel_Click {
    if ($DEBUG) { &LogDebug("Cancel clicked in DBWindow"); }
    $DBWindow->Hide();

    &Log("$prog $ver exiting");

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

sub DBWindowHelp_Click {
    if ($DEBUG) { &LogDebug("Help clicked in DBWindow"); }
    open_browser(
        'http://www.droppedpackets.org/scripts/ldms_core/ldms_core-manual');

    return 0;
}

sub DBWindowDBInfo_Click {
    if ($DEBUG) { &LogDebug("DBInfo clicked in DBWindow"); }
    open_browser(
'https://localhost/landesk/ManagementSuite/Core/ssl/information/DatabaseInformation.asmx?op=GetConnectionString'
    );
    return 0;
}

sub ConfigWindowBrowsePatchDir_Click {
    if ($DEBUG) { &LogDebug("ConfigWindowBrowsePatchDir clicked"); }

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

    my $leftmargin   = 120;
    my $rightmargin  = 50;
    my $bottommargin = 50;
    my $nexthoriz    = 5;

    # build window
    $ConfigWindow = Win32::GUI::Window->new(
        -name     => 'ConfigWindow',
        -text     => 'ldms_core email and nmap setup',
        -class    => $ldms_core_class,
        -dialogui => 1,
    );

    # Begin days to deletion row
    $form_deletiondays = $ConfigWindow->AddTextfield(
        -name    => "deletiondays_field",
        -prompt  => "Purge old files after X Days (0 to disable):",
        -tabstop => 1,
        -text    => $deletiondays,
        -pos     => [ $leftmargin + 100, $nexthoriz ],
        -size    => [ 40, 20 ],
    );

    $lbl_patch = $ConfigWindow->AddLabel(
        -name    => "lbl_patch",
        -text    => "Please enter the actual location of your patch directory.",
        -tabstop => 0,
        -pos     => [ 15, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    # Begin patchdir_override row
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
        -pos     => [ $form_patchdir_override->Width() + 90, $nexthoriz ],
        -size    => [ 60, 20 ],
    );

    # End patchdir_override row

    # Begin Email information
    $lbl_email = $ConfigWindow->AddLabel(
        -name    => "lbl_email",
        -text    => "Please enter the required email sending information.",
        -tabstop => 0,
        -pos     => [ 15, $nexthoriz += 25 ],
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
        -pos     => [ 15, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    $form_mailverbosity = $ConfigWindow->AddSlider(
        -name    => "mailverbosity_field",
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size     => [ 200, 20 ],
        -selrange => 0,
    );
    $form_mailverbosity->SetRange( 1, 5 );
    $form_mailverbosity->SetPos($mailverbosity);
    $form_mailverbosity->SetBuddy( 0,
        $ConfigWindow->AddLabel( -text => "More" ) );
    $form_mailverbosity->SetBuddy( 1,
        $ConfigWindow->AddLabel( -text => "Less" ) );

    # End mail verbosity slider rows

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
        -pos     => [ $form_nmap->Width() + $leftmargin, $nexthoriz ],
        -size    => [ 60, 20 ],
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

    # Begin nmap unidentified row (label and checkbox)
    $form_nmap_ulabel = $ConfigWindow->AddLabel(
        -name => "nmap_ulabel",
        -text => "Should nmap skip previously unidentified nodes?",
        -pos  => [ 5, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    $form_nmap_u = $ConfigWindow->AddCheckbox(
        -name    => "form_nmap_u",
        -tabstop => 1,
        -Checked => $nmap_unidentified,
        -pos     => [ $leftmargin + 135, $nexthoriz - 3 ],
        -size    => [ 20, 20 ],
    );

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
    $form_update->SetBuddy( 0,
        $ConfigWindow->AddLabel( -text => "Weekly" ) );
    $form_update->SetBuddy( 1,
        $ConfigWindow->AddLabel( -text => "Never" ) );

    # End update frequency slider rows

    # Begin button row
    $btn_ConfigWindowdefault = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,                     # Give button darker border
        -ok      => 1,                     # press 'Return' to click this button
        -pos => [ 75, $nexthoriz += 25 ],
        -size => [ 60, 20 ],
    );

    $btn_ConfigWindowcancel = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                      # press 'Esc' to click this button
        -pos     => [ 150, $nexthoriz ],
        -size    => [ 60, 20 ],
    );

    $btn_ConfigWindowHelp = $ConfigWindow->AddButton(
        -name    => 'ConfigWindowHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 225, $nexthoriz ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $ConfigWindowsb = $ConfigWindow->AddStatusBar();
    if ($updatemessage) {
        $ConfigWindowsb->Text($updatemessage);
    }

    # calculate its size
    $ConfigWindowncw = $ConfigWindow->Width() - $ConfigWindow->ScaleWidth();
    $ConfigWindownch = $ConfigWindow->Height() - $ConfigWindow->ScaleHeight();
    $ConfigWindoww =
      $leftmargin +
      $form_patchdir_override->Width() +
      $rightmargin +
      $ConfigWindowncw;
    $ConfigWindowh = $nexthoriz + $bottommargin + $ConfigWindownch;

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

sub ConfigWindow_Terminate {
    return -1;
}

sub ConfigWindow_Resize {
    $ConfigWindowsb->Move( 0,
        $ConfigWindow->ScaleHeight - $ConfigWindowsb->Height );
    $ConfigWindowsb->Resize( $ConfigWindow->ScaleWidth,
        $ConfigWindowsb->Height );
    return 0;
}

sub ConfigWindowDefault_Click {

    # Read my variables
    $PATCHDIR          = $form_patchdir_override->GetLine(0);
    $mailserver        = $form_mailserver->GetLine(0);
    $mailfrom          = $form_mailfrom->GetLine(0);
    $mailto            = $form_mailto->GetLine(0);
    $deletiondays      = $form_deletiondays->GetLine(0);
    $nmap              = Win32::GetShortPathName( $form_nmap->GetLine(0) );
    $nmap_options      = $form_nmap_options->GetLine(0);
    $nmap_unidentified = $form_nmap_u->Checked();
    $mailverbosity     = $form_mailverbosity->GetPos();
    $update            = $form_update->GetPos();

    if ($DEBUG) {
        &LogDebug( "Okay clicked in ConfigWindow, read "
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
    if ($DEBUG) { &LogDebug("Cancel clicked in ConfigWindow"); }

    &Log("$prog $ver exiting");

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

sub ConfigWindowBrowseNMAP_Click {
    if ($DEBUG) { &LogDebug("BrowseNMAP clicked"); }

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

sub ConfigWindowHelp_Click {
    if ($DEBUG) { &LogDebug("Help clicked in ConfigWindow"); }
    open_browser(
        'http://www.droppedpackets.org/scripts/ldms_core/ldms_core-manual');

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
            "Can't get a list of authentication types from $mailserver",
            "Not so ready yet", 32
        );
        return 0;
    }

    # Build the window
    $MailAuth = Win32::GUI::Window->new(
        -name     => 'MailAuth',
        -text     => 'ldms_core mail configuration',
        -width    => 450,
        -height   => 400,
        -class    => $ldms_core_class,
        -dialogui => 1,
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
        $form_mail_auth_type->AddString($auth_type);
        if ($DEBUG) {
            &LogDebug("MailAuth window added auth type: $auth_type");
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
        -size => [ 60, 20 ],
    );

    $btn_MailAuthCancel = $MailAuth->AddButton(
        -name    => 'MailAuthCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                     # press 'Esc' to click this button
        -pos     => [ 150, $nexthoriz ],
        -size    => [ 60, 20 ],
    );

    $btn_MailAuthHelp = $MailAuth->AddButton(
        -name    => 'MailAuthHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 225, $nexthoriz ],
        -size    => [ 60, 20 ],
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
    $MailAuth->Hide();
    return 0;
}

sub MailAuthCancel_Click {
    if ($DEBUG) { &LogDebug("Cancel clicked in MailAuthWindow"); }
    $MailAuth->Hide();
    return 0;
}

sub MailAuthHelp_Click {
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

