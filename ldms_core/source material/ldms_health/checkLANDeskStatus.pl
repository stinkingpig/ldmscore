#!/os/tools/bin/Perl -w  # Use -w to produce warnings

#***************************************************************
# Style guidance
# See below for style
# This section will not exist in scripts
#***************************************************************


# name.pl
# Author
# Genentech
# Date

#***************************************************************
# Description
#   <# Get the lib dir Brief Description>
#   See POD below for further description
#***************************************************************

#***************************************************************
# Packages
#use FindBin qw($Bin);
#use lib ("$Bin/../lib","$Bin/../../lib");
#use LoadGneLibPath;


# Standard Perl Modules
use strict;
use Getopt::Long;
use DBI;

# Genentech Modules
# ...

#***************************************************************

#***************************************************************
# Constants
#   See GNE_Consts.pm
#
# Centralize any script specific constants here
# Common constants should go into GNE_Consts
# $CONSTANTS::MYCONST = "Whatever";
$CONSTS::LDSERVER = "landesk1";
$CONSTS::PRDDATASRC = "landprd1";
$CONSTS::PRDLOGIN = "landldms";
$CONSTS::PRDPASSWD = "dmsqwer1";
$CONSTS::DMDATASRC = "landprd2";
$CONSTS::DMLOGIN = "landdm";
$CONSTS::DMPASSWD = "dmsqwer1";

#$CONSTS::LDSERVER = "landeskdev";
#$CONSTS::PRDDATASRC = "landtst1";
#$CONSTS::PRDPASSWD = "manager";
#$CONSTS::DMDATASRC = "landtst2";
#$CONSTS::DMPASSWD = "manager";

#$CONSTS::LDSERVER = "landesk2";
#$CONSTS::PRDDATASRC = "landuat1";
#$CONSTS::PRDPASSWD = "manager";
#$CONSTS::DMDATASRC = "landuat2";
#$CONSTS::DMPASSWD = "manager";
#***************************************************************

#***************************************************************
# Main
#***************************************************************
main: {

  # Disable buffering on STDOUT and STDERR
  select(STDERR);
  $| = 1;
  select(STDOUT);
  $| = 1;

  # local variables
  my @errs;
  my @eventList;
  my $event;
  my %eventHash;
  my @fields;
  my ($server,$severity,$dateTime,$source,$id,$user,$string);
  my $srcID;
  my %sevEvents;
  my %srcIDEvents;
  my %ldProdStats;
  my %ldDMStats;
  my $rh_event;

  CheckDirs(["//$CONSTS::LDSERVER/LDMain/LDScan","//$CONSTS::LDSERVER/LDMain/LDScan/ErrorScan",
             "//$CONSTS::LDSERVER/LDMain/LDScan/DMScan","//$CONSTS::LDSERVER/LDMain/LDScan/DMScan/ErrScanDM"],\@errs);

  GetEvents(\@eventList,@errs);

  print "Event log has " . scalar(@eventList) . " events\n";

  foreach $event (@eventList){

    #print "$event\n\n";
    # Iterate through each event - break into sub components
    # Example:
    # server severity date time source id user message
    # LANDESK1 Information 050616 11:39:20 Intel Inventory Server 4 NA Started processing machine: Device ID: {7DFDF79 ...
    # if ($event =~ /(\S+)\s+(\S+)\s+(\d+\s\d+\:\d+\:\d+)\s+(.+)\s+(\d+)\s+(\S+)\s+(.+)/){
    if ($event =~ /^\s*(\S+)\s+(\S+)\s+(\d+\s\d+\:\d+\:\d+)\s+(.+)\s+(\d+)\s+(NA)\s+(.+)/){
      ($server,$severity,$dateTime,$source,$id,$user,$string) = ($1,$2,$3,$4,$5,$6,$7);
      $rh_event = {server=>$server,severity=>$severity,datetime=>$dateTime,source=>$source,id=>$id,user=>$user,string=>$string};
      # print "$event:\n\t" . join("\n\t",($server,$severity,$dateTime,$source,$id,$user,$string)) . "\n";
    } else {
      print STDERR "Can't parse event\n\t$event\n";
      next;
    }

    # Categorize by severity
    $sevEvents{$severity} = {ra_events=>[],rh_srcIDs=>{}}
      if (not exists $sevEvents{$severity});
    push @{$sevEvents{$severity}->{ra_events}},$rh_event;

    # Categorize by source and event ID
    $srcID = "$source - $id";
    if (not exists $srcIDEvents{$srcID}){
      $srcIDEvents{$srcID} = [];
      # also catalog by severity
      $sevEvents{$severity}->{rh_srcIDs}->{$srcID} = $srcID;
    }
    push @{$srcIDEvents{$srcID}},$rh_event;

  } # foreach $event

  # Results by severity
  print "Events by severity:\n";
  foreach $severity (sort keys %sevEvents){
    print "\t$severity:\t" . scalar(@{$sevEvents{$severity}->{ra_events}}) . "\n";
  }

  # Results by source ID
  print "Events by source - id:\n";
  foreach $severity (qw (Error Warning Information)){
    print "$severity\n";
    foreach $srcID (sort keys %{$sevEvents{$severity}->{rh_srcIDs}}){
      print "\t$srcID:\t" . scalar(@{$srcIDEvents{$srcID}}) . "\n";
      $rh_event = ${$srcIDEvents{$srcID}}[0];
      $string = substr($rh_event->{string},0,50);
      print "\t\t$string\n";
    }
  }

  # Calc device processing stats
  CalcProcessingStats(\%srcIDEvents,\@errs);

  # Get SQL Errors
  GetSQLErrors(\%srcIDEvents,\@errs);
  GetObjectIDErrors(\%srcIDEvents,\@errs);

  GetDBStats($CONSTS::PRDDATASRC,$CONSTS::PRDLOGIN,$CONSTS::PRDPASSWD,\%ldProdStats,\@errs);
  GetDBStats($CONSTS::DMDATASRC,$CONSTS::DMLOGIN,$CONSTS::DMPASSWD,\%ldDMStats,\@errs);

  GetScanStats(\@errs);
}; # main
#***************************************************************

#***************************************************************
# sub
# Description
#
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   None
#
sub GetEvents{
  my ($ra_eventList,$ra_errs) = @_;

  my $cmd;

  $cmd = "//snitch/cmtoolsprod/citcm/cmtools/pkgtools/3rdParty/eldump -A 24 -s \\\\$CONSTS::LDSERVER -T Error Warning Information -O oTdtSeus -l application -l system";
  print "Invoking $cmd\n";
  chomp (@$ra_eventList = `$cmd`);
  return @$ra_eventList;

  open(FH,"ld-ellog-050608.txt") or die "Can't open event log file\n\t$!\n";
  chomp (@$ra_eventList = <FH>);
  close FH;

} # End GetEvents
#***************************************************************

#***************************************************************
# sub CalcProcessingStats(\%srcIDEvents,\@errs)
# Description
#
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   None
#
sub CalcProcessingStats {
  my ($rh_srcIDEvents,$ra_errs) = @_;

  my $rh_event;
  my $string;
  my $devID;
  my %devIDEvents;
  my $min;
  my $sec;
  my $totalTime;
  my $nProcessed;
  my $procSecs;

  # Check for # of machines processed
  foreach $rh_event (@{$rh_srcIDEvents->{"Intel Inventory Server - 4"}}){
    $string = $rh_event->{string};
    if ($string =~ /Device ID:\s+(.+)/){
      $devID = $1;
      $devIDEvents{$devID} = {start=>0,end=>0}
        if (not exists $devIDEvents{$devID});
      $devIDEvents{$devID}->{start}++;
    } else {
      print STDERR "Can't parse dev id\n\t$string\n";
    }
  }

  $totalTime = 0;
  foreach $rh_event (@{$rh_srcIDEvents->{"Intel Inventory Server - 5"}}){
    $string = $rh_event->{string};
    if ($string =~ /Device ID:\s+(.+)\s+Elapsed Time\:\s+(\d+)\:(\d+)/){
      ($devID,$min,$sec) = ($1,$2,$3);
      $devIDEvents{$devID} = {start=>0,end=>0}
        if (not exists $devIDEvents{$devID});
      $devIDEvents{$devID}->{end}++;

      # Capture time processing
      $procSecs = $sec + ($min * 60);
      $totalTime += $procSecs;

    } else {
      print STDERR "Can't parse dev id\n\t$string\n";
    }
  }
  $nProcessed = scalar(@{$rh_srcIDEvents->{"Intel Inventory Server - 5"}});
  print "Machines processed:\t$nProcessed\n";
  print "Unique machines:\t" . scalar(keys %devIDEvents) . "\n";
  printf ("Ave processing time:\t%.2f seconds\n",$totalTime/$nProcessed);
  print ("$totalTime/$nProcessed\n");
  print "\n";

} # End CalcProcessingStats
#***************************************************************

#***************************************************************
# sub 
# Description
#   
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   None
#
sub GetSQLErrors {
  my ($rh_srcIDEvents,$ra_errs) = @_;

  my $event;
  my $sqlErr;
  my %devIDEvents;
  my @sqlErrs;

  # Check for # of machines processed
  foreach $event (@{$rh_srcIDEvents->{"Intel DataMart Utility - 19"}}){
    if ($event =~ /The following SQL statement failed:\s+(.+)/){
      $sqlErr = $1;
      $sqlErr = $1
        if ($sqlErr =~ /(.*)\s*Error moving object/);
      next if ($sqlErr !~ /S+/);
      push @sqlErrs,$sqlErr;
    }
  }

  if (scalar @sqlErrs){
    print "\nSQL Errors:\n\t" . join("\n\t",sort @sqlErrs) . "\n\n";
  } else {
    print "No SQL Errors\n";
  }

} # End GetSQLErrors
#***************************************************************

#***************************************************************
# sub 
# Description
#   
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   None
#
sub GetObjectIDErrors {
  my ($rh_srcIDEvents,$ra_errs) = @_;

  my $event;
  my $objID;
  my @objIDs;
  my %devIDEvents;
  my %rootObjs;
  my $rootObj;
  my $sql;
  my @qResults;
  my $deviceName;
  my $ra_resultRow;
  my %mappedObjs;
  my $mappedObj;

  # Check for # of machines processed
  foreach $event (@{$rh_srcIDEvents->{"Intel DataMart Utility - 19"}}){
    if ($event =~ /Error moving object id:\s+(\d+)/){
      push @objIDs,$1;
    }
  }

  return if (not scalar @objIDs);

  # Get the id of the root (the computer)
  foreach $objID (@objIDs){
    if (exists $mappedObjs{$objID}){
      #print "$objID already mapped to $mappedObjs{$objID}\n";
      next;
    }

    $sql = "SELECT unique object_root_idn FROM ld_objectattribute WHERE object_idn=$objID";
    QueryDB($sql,$CONSTS::PRDDATASRC,$CONSTS::PRDLOGIN,$CONSTS::PRDPASSWD,\@qResults,\$ra_errs);
    if ($rootObj = ${$qResults[0]}[0]){
      $rootObjs{$rootObj} = 1;
    } else {
      print STDERR "Can't locate root for object id $objID\n";
      next;
    }

    # Get all of the objects that have this root object
    $sql = "SELECT object_idn FROM ld_objectattribute WHERE object_root_idn=$rootObj";
    QueryDB($sql,$CONSTS::PRDDATASRC,$CONSTS::PRDLOGIN,$CONSTS::PRDPASSWD,\@qResults,\$ra_errs);
    foreach $ra_resultRow (@qResults){
      $mappedObj = ${$ra_resultRow}[0];
      $mappedObjs{$mappedObj} = $rootObj;
      #print "Mapped $mappedObj to $rootObj\n";
    }
  }

  # Get the device names for all root objects
  foreach $rootObj (keys %rootObjs){
    $sql = "SELECT Display_Name FROM ld_ObjectRoot WHERE object_root_idn=$rootObj";
    QueryDB($sql,$CONSTS::PRDDATASRC,$CONSTS::PRDLOGIN,$CONSTS::PRDPASSWD,\@qResults,\$ra_errs);
    $deviceName = ${$qResults[0]}[0];
    $rootObjs{$rootObj} = $deviceName;
  }

  print "Unable to move records for the following devices:\n\t";
  print join("\n\t",sort values %rootObjs) . "\n\n";

} # End GetObjectIDErrors
#***************************************************************

#***************************************************************
# sub GetDBStats($dataSource,$dbLogin,$dbPasswd,\%dbStats,\@errs)
# Description
#   Use ODBC to get stats on the LANDesk DB
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   None
#
sub GetDBStats{
  my ($dataSource,$dbLogin,$dbPasswd,$rh_dbStats,$ra_errs) = @_;

  my $dbh;
  my $sth;
  my @row;
  my $tableName;

  if (not ($dbh = DBI->connect( "dbi:ODBC:$dataSource",$dbLogin,$dbPasswd))){
    push @$ra_errs,"Database connection not made: $DBI::errstr";
    return undef;
  }

  $sth = $dbh->prepare("SELECT table_name,num_rows FROM user_tables");
  $sth->execute;

  while ( @row = $sth->fetchrow_array ) {
    $rh_dbStats->{$row[0]} = int($row[1]);
  }

  $dbh->disconnect;

  print "DB Stats for $dataSource\n";
  foreach $tableName (sort keys %$rh_dbStats){
    print "\t$tableName:\t$rh_dbStats->{$tableName}\n";
  }
  print "\n";

  return scalar keys %$rh_dbStats;

} # End GetDBStats
#***************************************************************

#***************************************************************
# sub GetScanStats(\@errs)
# Description
#   Get scan stats
#   Production, last hardware and software scan dates are stored in LD_ObjectAttribute table
#     Last hardware scan : in OA_VAL_INT or OA_VAL_STR where OCA_IDN = 29
#     Last software scan : in OA_VAL_INT or OA_VAL_STR where OCA_IDN = 30
#   Datamart in HWLastScanDate and SWLastScanDate in Computer table
#
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   This needs modularization
#
sub GetScanStats{
  my ($ra_errs) = @_;

  my @scanTimes;
  my @qResults;

  # Query production for last hardware scan
  print "\nQuerying Production DB for last hardware scan data\n";
  QueryDB("SELECT OA_VAL_INT FROM ld_objectattribute WHERE oca_idn=29",$CONSTS::PRDDATASRC,$CONSTS::PRDLOGIN,$CONSTS::PRDPASSWD,\@qResults,\$ra_errs);
  AnalyzeScanData(\@qResults,$ra_errs);

  # Query production for last software scan
  print "\nQuerying Production DB for last software scan data\n";
  QueryDB("SELECT OA_VAL_INT FROM ld_objectattribute WHERE oca_idn=30",$CONSTS::PRDDATASRC,$CONSTS::PRDLOGIN,$CONSTS::PRDPASSWD,\@qResults,\$ra_errs);
  AnalyzeScanData(\@qResults,$ra_errs);

  print "\nQuerying Datamart DB for last hardware scan data\n";
  QueryDB("SELECT hwlastscandate FROM computer",$CONSTS::DMDATASRC,$CONSTS::DMLOGIN,$CONSTS::DMPASSWD,\@qResults,\$ra_errs);
  AnalyzeScanData(\@qResults,$ra_errs);

  print "\nQuerying Datamart DB for last software scan data\n";
  QueryDB("SELECT swlastscandate FROM computer",$CONSTS::DMDATASRC,$CONSTS::DMLOGIN,$CONSTS::DMPASSWD,\@qResults,\$ra_errs);
  AnalyzeScanData(\@qResults,$ra_errs);


  # Alternative for production
  my $sql = "  SELECT o1.oa_val_str as DeviceID,
        o2.oa_val_str as DeviceName,
        o3.oa_val_str as LastHWScan,
        o4.oa_val_str as LastSWScan
  FROM ld_objectattribute o1, ld_objectattribute o2, ld_objectattribute o3, ld_objectattribute o4
  where 
    o1.OBJECT_IDN = o2.OBJECT_IDN
    AND o3.OBJECT_IDN = o4.OBJECT_IDN
    AND o2.OBJECT_IDN = o3.OBJECT_IDN
    AND o1.oca_idn = 18
        AND o2.oca_idn = 22
            AND o3.oca_idn = 29
                AND o4.oca_idn = 30";

} # End GetScanStats
#***************************************************************

#***************************************************************
# sub QueryDB
# Description
#   
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   None
#
sub QueryDB {
  my ($sql,$dataSource,$dbLogin,$dbPasswd,$ra_results,$ra_errs) = @_;

  my $sth;
  my @row;

  undef @$ra_results;
  my $dbh;

  if (not ($dbh = DBI->connect( "dbi:ODBC:$dataSource",$dbLogin,$dbPasswd))){
    push @$ra_errs,"Database connection not made: $DBI::errstr";
    return undef;
  }

  print "$sql\n";
  $sth = $dbh->prepare($sql);
  $sth->execute;

  while ( @row = $sth->fetchrow_array ) {
    push @$ra_results,[@row];
  }

  $dbh->disconnect;

} # End QueryDB
#***************************************************************

#***************************************************************
# sub 
# Description
#   
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   None
#
sub AnalyzeScanData {
  my ($ra_qResults,$ra_errs) = @_;


  my $ra_row;
  my $now;
  my $lastScan;
  my $lag;
  my $lagDays;
  my $totalLag;
  my %lagBucket;
  my $nScans;
  my @scans;

  $now = time;
  $nScans = 0;

  foreach $ra_row (@$ra_qResults){
    $lastScan = $$ra_row[0];
    push @scans,$lastScan;
    $lastScan = 0 if (not $lastScan);

    # Calc lag - time between last scan and now
    $lag = $now - $lastScan;

    # Convert lag to days
    $lagDays = int($lag/(24*60*60));

    # Bucket
    $lagBucket{$lagDays} = 0
      if (not exists $lagBucket{$lagDays});
    $lagBucket{$lagDays} += 1;

    # Don't count corrupt data
    next if ($lag < 0 or $lagDays > 30);

    $nScans++;
    $totalLag += $lag;

  }
  foreach $lag (sort {$a<=>$b} keys %lagBucket){
    print "$lag days: $lagBucket{$lag}\n";
  }
  printf ("Ave lag: %.2f\n",($totalLag/(24*60*60))/$nScans);
  print "# valid scans: $nScans\n\t(Scans over 30 days discounted)\n";

#  print "All Scans:\t" . join("\t",sort @scans) . "\n\n\n";


} # End AnalyzeScanData
#***************************************************************

#***************************************************************
# sub CheckDirs(\@dirs,\@errs)
# Description
#   Report # of files in each directory
# Parameters
#   In
#   Changed
# Return
#   None
# Side Effects
#   None
# Issues
#   None
#
sub CheckDirs {
  my ($ra_dirs,$ra_errs) = @_;

  my $dirName;
  my $nFiles;
  my $dirEntry;

  foreach $dirName (@$ra_dirs){
    $nFiles = 0;
    if (not opendir(DH,$dirName)){
      print "Can't open directory $dirName\n\t:$!\n";
      push @$ra_errs, "Can't open directory $dirName\n\t:$!\n";
      next;
    }
    while (defined($dirEntry = readdir(DH))) {
      $nFiles ++ if (not -d $dirEntry);
    }
    print "$dirName - # files:\t$nFiles\n";
  }

} # End CheckDirs
#***************************************************************
