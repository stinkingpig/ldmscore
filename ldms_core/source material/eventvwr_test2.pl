use strict;
use Env;
use Win32::EventLog;
my $EventViewerhandle = Win32::EventLog->new( "Application", $COMPUTERNAME )
  or print "Initialization: Can't open Application EventLog";

my $now_string = localtime;
print "starting at $now_string\n";

    my ( $handle, $base, $recs, %Event, $record, $result );

    # One day ago
    my $TIME_LIMIT = time() - 864000000;

    # if this is set, we also retrieve the full text of every
    # message on each Read( )
    local $Win32::EventLog::GetMessageText = 0;

    $handle = Win32::EventLog->new( "Application", $COMPUTERNAME )
      or print "CountSchemaErrors Can't open Application EventLog";

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
        if ( $Event{Source} eq "LANDesk Inventory Server" ) {
            if ( $Event{EventID} == 4100 ) {
                my $text = $Event{Strings};
                if ( defined($text) ) {
                    if ( $text =~ m/The size of / ) {
                        print "SIZE ERROR: $text\n";
                        $result++;
                    }
                    if ( $text =~ m/Table:/ ) {
                        print "TABLE ERROR: $text\n";
                        $result++;
                    }
                }
            }
        }
        $record++;
    }
    if ($result) {
        print "RESULT: $result\n";
    }
    else {
      print "CountSchemaErrors found nothing.\n";
    }

$now_string = localtime;
print "ending at $now_string\n";

