#############################################################################
# ldms_status.pl, v 0.1                                                     #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_whatever                      #
#############################################################################
#
# See README_ldms_status.txt for documentation.
#

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use DBI;
use Win32;
use Win32::EventLog;
use File::Copy;
# use Statistics::Distribution;

#############################################################################
# Variables                                                                 #
#############################################################################
my $prog = "ldms_status";
my $ver = "0.1";

our %A;		# get commandline switches into %A
for (my $ii = 0; $ii < @ARGV; ) {
	last if $ARGV[$ii] =~ /^--$/;
	if ($ARGV[$ii] !~ /^-{1,2}(.*)$/) { $ii++; next; }
	my $arg = $1; splice @ARGV, $ii, 1;
	if ($arg =~ /^([\w]+)=(.*)$/) { $A{$1} = $2; } else { $A{$1}++; }
}

my $DEFDIR = 'C:\Program Files\LANDesk\ManagementSuite';
my $ldmain = shift || $DEFDIR;
my $errordir = shift || $DEFDIR;
my $dir = Win32::GetShortPathName($errordir);
# my $db_user = $A{db_type} || 'SQL';
my $db_user = $A{db_user} || 'sa';
my $db_pass = $A{db_pass} || 'landesk';
my $db_name = $A{db_name} || 'lddb';
my $db_instance = $A{db_instance} || 'GRANITE\LDMSDATA';

my $DEBUG = $A{d} || 0;
my $usage = <<EOD;

Usage: $prog [-d] [-h] -db_user=USER -db_pass=PASS -db_name=DB [-db_instance=SERVER] 
			 <error_dir>
	-d			debug
	-h(elp)		this display
	db_instance is only necessary for SQL Servers, Oracle environments will pick it up from a properly configured client.
	<error_dir>	directory to find scan files (Def:
			$DEFDIR)

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This script will rename the scan files in ErrorScan to the computer name, for
easier troubleshooting.
The latest version lives at 
http://www.monkeynoodle.org/comp/landesk/ldms_status.

EOD

my $time = localtime();
# How far back to dig (yesterday by default)?
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time-86400);
$year+=1900;
$mon+=1;

my $message="************************************************************************\n";
$message.="LANDESK STATUS REPORT -- $time\n";
$message.="************************************************************************\n";

#############################################################################
# Main Loop                                                                 #
#############################################################################
# Open the database
my $DSN = "driver={SQL Server};Server=$db_instance;Database=$db_name;UID=$db_user;PWD=$db_pass";
my $dbh = DBI->connect("dbi:ODBC:$DSN") or die "$DBI::errstr\n";

# some handy numbers
my $sql="select count(*) from computer where deviceid != 'Unassigned'";
my $sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
$sth->execute or die "$DBI::errstr\n";
my $allmachines=$sth->fetchrow();
$sth->finish();
$message .= "There are $allmachines nodes in the database.\n";

#call each scan in turn, gather the results
$message .= "&CheckScans nodes successfully reported hardware inventory in the last 24 hours.\n";
$message .= "There are &CheckQueuedScans scans in the ldscan queue.\n";
$message .= "There are &CheckErrorScans scans in the lderror dump.\n";
#do any formatting required and mail the result
print "$message\n";
exit 0;

#############################################################################
# Subfunctions                                                              #
#############################################################################

sub CheckScans() {
	# How many scans came in today?
	my $day = "$year-$mon-$mday $hour:$min:$sec";
	$sql="select count(*) FROM computer where hwlastscandate >= '$day'";
	$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
	$sth->execute or die "$DBI::errstr\n";
	$sth->finish();
	my $dbscans = $sth->fetchrow();
	#return result array with raw count and distribution information
	return ($dbscans);
}

sub CheckQueuedScans() {
	# How many scans sitting in queue?
	my ($count);
	opendir(DIR,"$DEFDIR\\ldscan");
	while (my $file=readdir(DIR)) {
		if ($file =~ /^\.\.?$/) { next; }
		$count++;
	}
	closedir(DIR);
	#return result array with raw count and distribution information
	return ($count);
}

sub CheckErrorScans() {
	# How many error scans came in today?
	my ($count);
	my @time;
	opendir(DIR,"$DEFDIR\\ldscan\\errorscan");
	while (my $file=readdir(DIR)) {
		next if $file =~ /^\.\.?$/;
		$count++;
	}
	closedir(DIR);
	#return result array with raw count and distribution information
	return ($count);
}

sub CheckLag() {
	# for each machine in the database, when was the last scan?
	# Count up the ones older than 24 hours and present as a percentage of total
	my $sql="select devicename,lastupdinvsvr from computer where lastupdinvsvr < DateAdd(d,-5,getdate()) order by lastupdinvsvr";
	$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
	$sth->execute or die "$DBI::errstr\n";
	$sth->finish();
	my @computers = $sth->fetcharray();
	return (@computers);
}

sub CheckTasks() {
	# by task/policy, what's in waiting/active/done/failed? percentages, and
	# reminders of what those mean
}

sub CheckVulns() {
	# select the top 10 detected vulns listed by number of machines infected
	my $sql="select top 10 cv.vul_id, count(cv.vul_id) from computervulnerability as cv, vulnerability as v where cv.detected='1' and cv.vul_id=v.vul_id and v.severity='1' group by cv.vul_id,v.vul_id order by count(cv.vul_id) desc, cv.vul_id";
	$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
	$sth->execute or die "$DBI::errstr\n";
	$sth->finish();
	my @results = $sth->fetcharray();
	return @results;
}

sub CheckDupes() {
	# records in computer which have the same devicename but different uuids
	# for extra points, join networksoftware physical address
	my $sql="set nocount on; select distinct [computer].[computer_idn], [computer].[devicename] from [computer] inner join [computer] as t1 on [computer].[devicename] = t1.[devicename] where [computer].[computer_idn] <> t1.[computer_idn] order by [computer].[devicename], [computer].[computer_idn] asc; set rowcount 0; set nocount off";
	$sth = $dbh->prepare($sql) or die "$DBI::errstr\n";
	$sth->execute or die "$DBI::errstr\n";
	$sth->finish();
	my @results = $sth->fetcharray();
	return @results;
}

sub CheckLogs() {
	# check Windows Event Log for any LANDesk service events
	# count up number of full-scans-forced per day, check for excessive time 
	# spent on maintenance, count up sql insertion errors, report on anything 
	# really awful like service crashes.
}

sub CheckServices() {
	# if I'm on the core, check that the LANDesk services are running.
}

sub CheckUDD() {
	# Manageable machines in UNMANAGEDNODES shouldn't be more than 5 or 10 percent of the total number
}
