#############################################################################
# ldms_errorscan_parser.pl, v 1.1                                           #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_errorscan_parser              #
# Thanks to $Bill Luebkert for the command-line handling.                   #
#############################################################################
#
# See README_ldms_errorscan_parser.txt for documentation.

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use DBI;
use Win32;
use File::Copy;

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

my $DEFDIR = 'C:\Program Files\LANDesk\ManagementSuite\ldscan\errorscan';
my $errordir = shift || $DEFDIR;
my $dir = Win32::GetShortPathName($errordir);
my $db_user = 'foo';
my $db_pass = 'bar';
my $db_name = 'baz';
my $db_instance = 'SERVER\LDMSDATA';
my $DEBUG = $A{d} || 0;

#############################################################################
# Main Loop                                                                 #
#############################################################################
(my $prog = $0) =~ s/^.*[\\\/]//;
my $usage = <<EOD;

Usage: $prog [-d] [-h] [<error_dir>]
	-d		debug
	-h(elp)		this display
	<error_dir>	directory to find scan files (Def:
			$DEFDIR)

ldms_errorscan_parser.pl v 1.1
Jack Coates, jack\@monkeynoodle.org, released under GPL
This script will rename the scan files in ErrorScan to the computer name, for
easier troubleshooting.
The latest version lives at http://www.monkeynoodle.org/comp/landesk/ldms_errorscan_parser.

EOD
die $usage if $A{h} or $A{help};

# Open the database
my $DSN = "driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass";
my $dbh = DBI->connect("dbi:ODBC:$DSN") or die "$DBI::errstr\n";

### Set the trace output back to STDERR at level 9 and prepare()
# DBI->trace( 9, undef );

opendir(DIR,"$dir");
my $newname;
while (my $source=readdir(DIR)) {
	# Next file if we're at the top or the file was already done
	next if $source =~ /^\.\.?$/;
	next if $source =~ /^_/;
	my $file = $dir."\\".$source;
	open(FILE, "$file") or die "Can't open file $file: $!\n";
	for my $line (<FILE>) {
		my @parts = split(/=/,$line);
		# If the UUID is in the database, get the device name
		if ($parts[0] =~ m/^Device ID/) {
			my $uuid = &trim($parts[1]);
			my $sql = "select devicename from computer where deviceid=?";
			my $sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
			$sth->execute($uuid) or die "$DBI::errstr\n";
			my @row = $sth->fetchrow();
			# If the device name is already used as the filename,
			# move on to the next file. Otherwise, rename.
			if (!$row[0] =~ m/$source/i ) {
				print "doing it!\n";
				$newname = $dir."\\_".$row[0].$source;
				last;
			} else {
				$newname = $dir."\\_".$source;
				last;
			}
			next;
		} else {
			# If there was no match in the database, look for a device name
			# or a host name or an IP address in the scan file.
			if ($parts[0] =~ m/^Device Name/) {
				my $marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker.$source;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Host Name/) {
				my $marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker.$source;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Address/) {
				my $marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker.".".$source;
			}
			last;
		}
	}
	close(FILE);
	# if we weren't able to get something, we don't move the file.
	# if debug is off, try to move the file and fail safely if we can't.
	# if debug is on, just print what would have been done.
	if ($newname) {
		if ($DEBUG) { 
			print "copying $file to $newname\n";
		} else {
			if (copy("$file","$newname")) {
				unlink($file) || warn "unlink $file: $!";
			} else {
				warn "copy $file, $newname: $!";
			}
		}
	}
}

sub trim($) {
	my $string = shift;
	$string =~ s/^\s+|\s+$//;
	$string =~ s/\'|\"//g;
	$string =~ s/\n|\r//g;
	return $string;
}

