#############################################################################
# ldms_nmap_udd.pl, v 1.8                                                   #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_nmap                          #
# Thanks to $Bill Luebkert for the command-line handling.                   #
#############################################################################
#
# See README_ldms_nmap_udd.txt for documentation.

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use warnings;
use strict;
use DBI;
use Win32::API::Prototype; # http://www.roth.net/perl/packages

#############################################################################
# Configuration                                                             #
#############################################################################
my $sql;
my @row;
# where should I write logs?
my $logpath = Win32::GetShortPathName($ENV{TEMP});
# where does NMAP live?
my $nmap = Win32::GetShortPathName("C:/Program Files/nmap/nmap.exe");
my $nmap_options = "-O -P0 -n";
my $time = localtime();
$time =~ s/[ |:]/-/g;
use POSIX ":sys_wait_h";
# got more RAM? Then raise this number.
use constant MAX_KIDS => 5;

our %A;		# get commandline switches into %A
for (my $ii = 0; $ii < @ARGV; ) {
	last if $ARGV[$ii] =~ /^--$/;
	if ($ARGV[$ii] !~ /^-{1,2}(.*)$/) { $ii++; next; }
	my $arg = $1; splice @ARGV, $ii, 1;
	if ($arg =~ /^([\w]+)=(.*)$/) { $A{$1} = $2; } else { $A{$1}++; }
}

my $DEBUG= $A{d} || 1;
my $network = shift;
my $db_user = $A{db_user} || 'sa';
my $db_pass = $A{db_pass} || 'landesk';
my $db_name = $A{db_name} || 'lddb';
my $db_instance = $A{db_instance} || 'GRANITE\LDMSDATA';
(my $prog = $0) =~ s/^.*[\\\/]//;
my $ver = "1.6";
my $usage = <<EOD;

Usage: $prog [-d] [-u] [-h]
			 -db_user=USER -db_pass=PASS -db_name=DB [-db_instance=SERVER] 
	-d			debug
	-h(elp)		this display
	db_instance is usually the name of your SQL Server

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This script will properly identify the OS of the machines in Unmanaged Devices
The latest version lives at 
http://www.droppedpackets.org/networking/ldms_nmap

EOD

#############################################################################
# The Main Loop -- Casual Users Shouldn't Edit Past Here                    #
#############################################################################
die $usage if $A{h} or $A{help};

my $logfile = $logpath."Nmap-".$time.".log";
open(LOG, "> $logfile") or die "Couldn't open $logfile for writing: $!\n";
my $tmpdir = $ENV{TEMP}."/nmaptmp";
my (@Computer, @OS, @Address);

# Open the database
my $DSN = "driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass";
my $dbh = DBI->connect("dbi:ODBC:$DSN") or die "$DBI::errstr\n";

# Set the process priority so we don't murderize the CPU.
ApiLink( 'kernel32.dll', "BOOL SetPriorityClass( HANDLE hThread, DWORD dwPriorityClass )" ) || die "Unable to load SetPriorityClass()";
ApiLink( 'kernel32.dll', "HANDLE OpenProcess()" ) || die "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "HANDLE GetCurrentProcess()" ) || die "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "BOOL CloseHandle( HANDLE )" ) || die "Unable to load CloseHandle()";
my $hProcess = GetCurrentProcess();
if ( 0 == SetPriorityClass( $hProcess, 0x00000040) ) {
	print LOG "Unable to set master PID scheduling priority to low.\n";
} else {
	print LOG "master PID scheduling priority set to low.\n";
}
CloseHandle( $hProcess );

print LOG "Scanning all unmanaged nodes in $network\n";
$sql="select UNMANAGEDNODES_IDN,IPADDRESS from UNMANAGEDNODES where OSNAME is null";

my $count=0;
my $sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
while (@row = $sth->fetchrow) {
	$Computer[$count] = &trim($row[0]);
	$Address[$count] = &trim($row[1]);
	$count ++;
}
$sth->finish();

# If we've got target nodes, we've got work to do.
if ($count >= 1) {
	if (!-e $tmpdir) { mkdir("$tmpdir", 0700) || die "cannot create $tmpdir: $!"; }
	my $y = 0;
	my (%children, $quit) = ((), 0);
	while (!$quit) {
		reap(\%children);
		if ((keys %children) <= MAX_KIDS) {
			if (my $pid = fork()) {
				$children{$pid} = 1;
				sleep 1;
				# Set the process priority so we don't murderize the CPU.
				ApiLink( 'kernel32.dll', "BOOL SetPriorityClass( HANDLE hThread, DWORD dwPriorityClass )" ) || die "Unable to load SetPriorityClass()";
				ApiLink( 'kernel32.dll', "HANDLE OpenProcess()" ) || die "Unable to load GetCurrentProcess()";
				ApiLink( 'kernel32.dll', "HANDLE GetCurrentProcess()" ) || die "Unable to load GetCurrentProcess()";
				ApiLink( 'kernel32.dll', "BOOL CloseHandle( HANDLE )" ) || die "Unable to load CloseHandle()";
				my $hProcess = GetCurrentProcess();
				if ( 0 == SetPriorityClass( $hProcess, 0x00000040) ) {
					print LOG "Unable to set NMAP child PID scheduling priority to low.\n";
				} else {
					print LOG "NMAP child PID scheduling priority set to low.\n";
				}
  				CloseHandle( $hProcess );
			} else {
				&nmap($Computer[$y],$Address[$y]);
				exit;
			}
			if ($y < $count) {
				$y++;
			}
			if ($y == $count) {
				$quit = 1;
			}
		}
	sleep(1);
	}
	# reap any stragglers
	while (keys %children) {
		reap(\%children);
		sleep(1);
	}
} else {
	print "No targets selected.\n";
	print LOG "No targets selected.\n";
	exit;
}

# Now it's time to do the database insertion
print LOG "Finished scanning, beginning database insertion.\n";
opendir(DIR,"$tmpdir");
while (my $file=readdir(DIR)) {
	next if $file =~ /^\.\.?$/;
	$file = $tmpdir."/".$file;
	open(FILE, "$file") or die "Can't open $file: $!\n";
	for my $line (<FILE>) {
		# Maybe in the next version we should check the old record to see if it's worse than the new one,
		$sth = $dbh->prepare($line) or die "$DBI::errstr\n";
		$sth->execute or die "$DBI::errstr\n";
		$sth->finish();	
	}
	close(FILE);
	unlink($file);
}
closedir(DIR);

# and clean up.
print LOG "Finished database insertion.\n";
rmdir($tmpdir);
$dbh->disconnect;
close LOG;
exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################
sub nmap($$) {
	my $OS;
	my @results = `"$nmap" $nmap_options $_[1]`;
	foreach my $line (@results) {
		if ($line =~ m/^OS details/) {
			my @parts = split(/\:/,$line);
			$OS = &trim($parts[1]);
		}
	}
	if ($OS) {
		# write scan to a file in tmpdir
		my $outfile = $tmpdir."/".$_[1].".tmp";
		open(FILE, ">$outfile") || die "cannot write temporary file: $!";
		print FILE "update UNMANAGEDNODES set OSNAME='$OS' where UNMANAGEDNODES_IDN='$_[0]';";
		close(FILE);
		# Log that I scanned node at time
		print LOG "Scanned $_[1] at ".localtime()."\n";
		print "Scanned $_[1] at ".localtime()."\n";
	} else {
		print LOG "Failed scan of $_[1] at ".localtime()."\n";
		print "Failed scan of $_[1] at ".localtime()."\n";
	}
}

sub reap {
	my ($kids) = @_;
	for (keys %{$kids}) {
		next if waitpid($_,WNOHANG()) != -1;
		delete $kids->{$_};
	}
}

sub trim($) {
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

