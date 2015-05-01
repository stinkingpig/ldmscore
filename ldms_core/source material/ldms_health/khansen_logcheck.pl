#!/os/tools/bin/Perl -w  # Use -w to produce warnings

 

# CheckLANDeskStatus-8.pl

# Ken Hansen

# Genentech

# 10/05

 

#***************************************************************

# Description

#   Check the status of a LANDesk 8 System

#***************************************************************

 

#***************************************************************

# Packages

use FindBin qw($Bin);

 

# Add local libs to path in order of precedence

use lib ("$Bin/../pkgtools/lib");

use lib ("$Bin/../lib");

use lib ("$Bin/lib");

 

# Standard Perl Modules

use strict;

use warnings;

use Carp;

use Getopt::Long;

use DBI;

use Win32::EventLog;

 

# Standard Perl Modules loaded w/ ppm

use Log::Log4perl qw(get_logger :levels);

use Readonly;

use List::MoreUtils qw( any );

 

# Genentech Modules

use Debug;

use Log;

 

#***************************************************************

 

#***************************************************************

# Constants

Readonly my $SERVER => 'landesk8';

Readonly my $DATA_SRC => 'macldprod';

Readonly my $LOGIN => 'sa';

Readonly my $PASSWD => 'p@ssw0rd';

 

Readonly my %SEVERITY_FOR_EVENT_TYPE =>

    (1 => 'Error',

     2 => 'Warning',

     4 => 'Information',

     8 => 'Audit Success',

     16 => 'Audit Failure',

 );

 

#***************************************************************

 

#***************************************************************

# Main

#***************************************************************

main: {

 

  # local variables

  my @errs;

  my $cut_off_epoch;

  my @event_list;

 

  # Calc epoch of 24 hours ago

  $cut_off_epoch = time - 24*60*60;

 

  # Initialize logging

  Log::InitLog4Perl('','', \@errs );

  my $logger = get_logger("");

 

  CheckDirs(["//$SERVER/LDMain/LDScan","//$SERVER/LDMain/LDScan/ErrorScan"],$cut_off_epoch, \@errs);

 

  get_event_logs($SERVER,$cut_off_epoch,\@event_list,\@errs);

 

  my %sevEvents;

  my %srcIDEvents;

  my $rh_event;

  foreach $rh_event (@event_list){

      # Categorize by severity

      if (not exists $SEVERITY_FOR_EVENT_TYPE{$rh_event->{EventType}}){

          croak "no sevrity for $rh_event->{EventType}\n";

      }

      my $severity = $SEVERITY_FOR_EVENT_TYPE{$rh_event->{EventType}};

      $sevEvents{$severity} = {ra_events=>[],rh_srcIDs=>{}}

          if (not exists $sevEvents{$severity});

      push @{$sevEvents{$severity}->{ra_events}},$rh_event;

 

      # Categorize by source and event ID

      my $srcID = "$rh_event->{Source} - $rh_event->{EventID}";

      if (not exists $srcIDEvents{$srcID}){

          $srcIDEvents{$srcID} = [];

          # also catalog by severity

          $sevEvents{$severity}->{rh_srcIDs}->{$srcID} = $srcID;

      }

      push @{$srcIDEvents{$srcID}},$rh_event;

 

  } # foreach $event

 

  # Results by severity

  $logger->info( "Events by severity:\n");

  my $severity;

  foreach $severity (sort keys %sevEvents){

    $logger->info( "\t$severity:\t" . scalar(@{$sevEvents{$severity}->{ra_events}}) . "\n");

  }

 

  # Results by source ID

  $logger->info( "Events by source - id:\n");

  foreach $severity (qw (Error Warning)){

    $logger->info( "$severity\n");

    foreach my $srcID (sort keys %{$sevEvents{$severity}->{rh_srcIDs}}){

      $logger->info( "\t$srcID:\t" . scalar(@{$srcIDEvents{$srcID}}) . "\n");

      $rh_event = ${$srcIDEvents{$srcID}}[0];

      my $string = substr($rh_event->{Strings},0,80);

      $logger->info( "\t\t$string\n");

    }

  }

 

 

}; # main

#***************************************************************

 

#***************************************************************

sub get_event_logs {

    my ($server,$cut_off_epoch,$ra_event_list,$ra_errs) = @_;

 

    my $ev_handle;

    my $recs;

    my $base;

    my $record_number;

    my $log_type;

    my $rh_event;

    my $event_field;

 

    my $logger = get_logger("get_event_logs\n");

    $logger->trace( "sub get_event_logs(" . join( ",", @_ ) . ")\n" );

 

    # Check args

    croak "Undefined arguments passed\n" if any {! defined $_} ($server,$cut_off_epoch,$ra_event_list,$ra_errs);

 

  LOG_TYPE:

    foreach $log_type (qw (System Application Security)){

 

        $logger->info("Retrieving $log_type events\n");

 

        if (not $ev_handle=Win32::EventLog->new($log_type, $server)) {

            $logger->fatal("Can't open $log_type EventLog\n");

            croak;

        }

 

        if (not $ev_handle->GetNumber($recs)) {

            $logger->fatal("Can't get number of EventLog records\n");

            croak;

        } else {

            $logger->info("# of Event log records: $recs\n");

        }

 

        if (not $ev_handle->GetOldest($base)) {

            $logger->fatal("Can't get number of oldest EventLog record\n");

            croak;

        } else {

            $logger->info("oldest Event log record: $base\n");

        }

 

        foreach $record_number (reverse ($base .. ($base+$recs-1))) {

            $rh_event = {};

            if (not $ev_handle->Read(EVENTLOG_BACKWARDS_READ|EVENTLOG_SEEK_READ,

                                     $record_number,

                                     $rh_event)) {

                $logger->fatal("Can't read EventLog entry #$record_number\n");

                croak;

            }

 

            # Go on to next log if we hit a record older than cutoff

            if ($rh_event->{TimeGenerated} < $cut_off_epoch) {

                next LOG_TYPE;

            }

 

            # Get the message text if source is eventlog

            if ($rh_event->{Source} eq 'EventLog') {

                Win32::EventLog::GetMessageText($rh_event);

                chomp $rh_event->{Message};

            }

 

            push @{$ra_event_list},$rh_event;

        }

        $ev_handle->Close();

    }

 

    $logger->info ("Events reported: " . scalar(@{$ra_event_list}) . "\n");

 

} # End get_event_logs

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

  my ($ra_dirs,$mTimeThresh,$ra_errs) = @_;

 

  my $dirName;

  my $nNewFiles;

  my $dirEntry;

  my $fullPath;

  my @stat;

  my $mTime;

  my $nAllFiles;

 

    my $logger = get_logger("get_event_logs\n");

    $logger->trace( "sub get_event_logs(" . join( ",", @_ ) . ")\n" );

 

  foreach $dirName (@$ra_dirs){

    $nNewFiles = $nAllFiles = 0;

    if (not opendir(DH,$dirName)){

      $logger->info( "Can't open directory $dirName\n\t:$!\n");

      push @$ra_errs, "Can't open directory $dirName\n\t:$!\n";

      next;

    }

    while (defined($dirEntry = readdir(DH))) {

      # Skip . and ..

      next if ($dirEntry eq '.' or $dirEntry eq '..');

 

      # Pre-prend the dir so we can access it

      $fullPath = "$dirName/$dirEntry";

 

      # skip directories

      next if (-d $fullPath);

 

      $nAllFiles ++;

 

      @stat = stat($fullPath);

      $mTime = $stat[9];

 

      if ($mTime > $mTimeThresh){

        $nNewFiles ++;

      }

    }

    $logger->info( "$dirName - \t$nAllFiles files\t$nNewFiles new\n");

  } # end foreach

 

} # End CheckDirs

#***************************************************************
