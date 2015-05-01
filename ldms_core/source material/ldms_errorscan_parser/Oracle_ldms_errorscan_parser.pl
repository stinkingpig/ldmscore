#############################################################################
# ldms_errorscan_parser.pl, v 1.3                                           #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_errorscan_parser              #
# Thanks to $Bill Luebkert for the command-line handling.                   #
# Thanks to Ken Hansen for debugging.                                       #
#############################################################################
#
# See README_ldms_errorscan_parser.txt for documentation.
#

#############################################################################
# Modified by Charles Tank for use with LANDesk database on Oracle/HPUX.    #
# charles.tank@direcway.com                                                 #
#############################################################################

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
my $db_user = 'ora_user';
my $db_pass = 'ora_pass';
my $db_name = 'ora_name';
# my $db_instance = 'SERVER\LDMSDATA';
my $DEBUG = $A{d} || 0;
my $UNDO = $A{u};

#############################################################################
# Main Loop                                                                 #
#############################################################################
(my $prog = $0) =~ s/^.*[\\\/]//;
my $ver = "1.3";
my $newname;
my $file;
my $marker;
my $usage = <<EOD;

Usage: $prog [-d] [-u] [-h] [<error_dir>]
	-d			debug
	-u			undo any previous changes
	-h(elp)		this display
	<error_dir>	directory to find scan files (Def:
			$DEFDIR)

ldms_errorscan_parser.pl v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This script will rename the scan files in ErrorScan to the computer name, for
easier troubleshooting.
The latest version lives at 
http://www.monkeynoodle.org/comp/landesk/ldms_errorscan_parser.

EOD
die $usage if $A{h} or $A{help};

if ($UNDO) {
	opendir(DIR,"$dir");
	while (my $source=readdir(DIR)) {
		# Next file if we're at the top or the file was already done
		if ($source =~ /^\.\.?$/) { next; }
		if (!$source =~ /^_/) { next; }
		if ($source =~ /^_/) {
			my $newname = $source;
			# if filename begins with an _, select everything that isn't
			# an underscore to the end of the filename
			if ($newname =~ s/(_.*_)(.*)/$2/g) {
				my $newfile = $dir."\\".$newname;
				my $oldfile = $dir."\\".$source;
				if ($DEBUG) { 
					print "I would be copying $oldfile to $newfile\n";
				} else {
					if (copy("$oldfile","$newfile")) {
						unlink($oldfile) || warn "unlink $oldfile: $!";
					} else {
						warn "copy $oldfile, $newfile: $!";
					}
				}
			}
		}
	}
	exit;
}

# Open the database
my $dbh = DBI->connect("DBI:Oracle:$db_name", $db_user, $db_pass)
   or die "Couldn't connect to database: " . DBI->errstr;
### Set the trace output back to STDERR at level 9 and prepare()
# DBI->trace( 9, undef );

# Get the deviceid>computer mappings
my $sql = "select deviceid,devicename from computer";
my $sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
my ($rows, @rows,%nodes,@nodes,$nodes,$key,$value);

while (@rows = $sth->fetchrow_array()) {
	if ($rows[0]) {
		$rows[0] =~ s/ //g;
		}
	if ($rows[1]) {
		$rows[1] =~ s/ //g;
		}
	$nodes{$rows[0]} = $rows[1];
	if ($DEBUG) {
		print "$rows[0] \t $rows[1]\n";
		}
	}

opendir(DIR,"$dir");
while (my $source=readdir(DIR)) {
	# Next file if we're at the top or the file was already done
	next if $source =~ /^\.\.?$/;
	next if $source =~ /^_/;
	$file = $dir."\\".$source;
	open(FILE, "$file") or die "Can't open file $file: $!\n";
	for my $line (<FILE>) {
		my @parts = split(/=/,$line);
		# If the UUID is in the database, get the device name
		if ($parts[0] =~ m/^Device ID/) {
			my $uuid = &trim($parts[1]);
			my $devicename=$nodes{$uuid};
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
				$marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker."_".$source;
				last;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Host Name/) {
				$marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker."_".$source;
				last;
			} elsif ($parts[0] =~ m/^Network - TCPIP - Address/) {
				$marker = &trim($parts[1]);
				$newname = $dir."\\_".$marker."_".$source;
				last;
			}
			# If all else fails, undef $newname
			if ($DEBUG) { print "couldn't get anything from $source\n"; }
			$newname = undef;
		}
	}
	close(FILE);
	# if we weren't able to get something, we don't move the file.
	# if debug is off, try to move the file and fail safely if we can't.
	# if debug is on, just print what would have been done.
	if ($newname) {
		if ($DEBUG) { 
			print "I would be copying $file to $newname\n";
		} else {
			if (copy("$file","$newname")) {
				unlink($file) || warn "unlink $file: $!";
			} else {
				warn "copy $file, $newname: $!";
			}
		}
	}


	}

exit;


sub trim($) {
	my $string = shift;
	$string =~ s/^\s+|\s+$//;
	$string =~ s/\'|\"//g;
	$string =~ s/\n|\r//g;
	return $string;
	}

