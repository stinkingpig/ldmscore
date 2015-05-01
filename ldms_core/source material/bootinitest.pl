
use strict;
use Env;
use Readonly;
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
use Sys::Hostname;

my $DEBUG;

# Setup Windows OLE object for reading WMI
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

sub HealthCheckBootIni {
    my ($PAE, $TGB) = &ReadBootIni;
    &ReadBootIni;
    my $RAM = &CountRAM;
    my $SQLonCore = &LocalSQL;

    # If SQL is on the core
    if ($SQLonCore) {
        # If there's more than 5000 MB of RAM
        if ($RAM > 5000) {
            # PAE should be enabled
            if ($PAE != 1) { 
                &Log("/PAE should be enabled for optimal SQL server "
                . "performance. See "
                . "http://community.landesk.com/support/docs/DOC-2356"
                . " and "
                . "http://msdn.microsoft.com/en-us/library/aa366796(VS.85).aspx"
                . " for more information.");
            }
            # TGB should be enabled
            if ($TGB != 1) { 
                &Log("/3GB should be enabled for optimal SQL server "
                . "performance. See "
                . "http://community.landesk.com/support/docs/DOC-2356"
                . " and "
                . "http://msdn.microsoft.com/en-us/library/bb613473(VS.85).aspx"
                . " for more information.");
            }
        }
    } else {
    # If SQL is not on the core
        # If there's more than 5000 MB of RAM
        if ($RAM > 5000) {
            # PAE should be enabled
            if ($PAE != 1) { 
                &Log("/PAE should be enabled for optimal core server "
                . "performance. See "
                . "http://community.landesk.com/support/docs/DOC-2681"
                . " and "
                . "http://msdn.microsoft.com/en-us/library/aa366796(VS.85).aspx"
                . " for more information.");
            }
        }
    }
    return 0;
}

sub ReadBootIni {
    my ($bootinifile, $FILE);
    my ($PAE, $TGB) = 0,0;
    if ($WINDIR) {
        my $drive = $WINDIR;
        $drive =~ s/\\.*/\\/;
        $bootinifile = $drive . "boot.ini";
    } else {
        $bootinifile = "C:\\boot.ini";
    }

    open( $FILE, '<', "$bootinifile" )
     or &LogWarn("ReadBootIni: Can't read $bootinifile : $!");
    my $bootini;
     while(<$FILE>) {
        my $defaultboot = 0;
        if ($_ =~ /^default/x) {
            my @parts = split( /=/x, $_ );
            $defaultboot = $parts[1];
        }
        if ($_ =~ /^multi/) {
            my @parts = split( /=/x, $_ );
            if (chomp($parts[0]) eq chomp($defaultboot)) {
                if ($parts[1] =~ /\/PAE/i) { 
                    $PAE = 1;
                    print "PAE enabled\n"; 
                }
                if ($parts[1] =~ /\/3GB/i) { 
                    $TGB = 1;
                    print "3GB enabled\n"; 
                }
            }
       }
    }
    close($FILE);
    return ($PAE, $TGB);
}

sub CountRAM {
    my $output = 'unknown';
    my $SystemList = $objWMIService->ExecQuery("SELECT * FROM Win32_OperatingSystem");
    if ( $SystemList->Count > 0 ) {
        foreach my $System ( in $SystemList) {
            $output = int($System->TotalVisibleMemorySize / 1024 );
        }
    }
    if ($output ne 'unknown') {
        return $output;
    } else {
        return -1;
    }
}

# Is this core using a local SQL server?
sub LocalSQL {
    my $db_instance = 'geode';
    my $hostname = hostname;
    my $SQLonCore = 0;
    if ($hostname eq $db_instance) { 
        return 1;
    }
    return 0;
}

