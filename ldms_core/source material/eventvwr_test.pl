use strict;
use Env;
use Win32::EventLog;

my $now_string = localtime;
print "starting at $now_string\n";

my ($handle, $base, $recs, $hashRef, $x);

 $handle=Win32::EventLog->new("Application", $COMPUTERNAME)
        or die "Can't open Application EventLog\n";
 $handle->GetNumber($recs)
        or die "Can't get number of EventLog records\n";
 $handle->GetOldest($base)
        or die "Can't get number of oldest EventLog record\n";

my $forcedfullscans=0;

 while ($x < $recs) {
        $handle->Read(EVENTLOG_FORWARDS_READ|EVENTLOG_SEEK_READ,
                                  $base+$x,
                                  $hashRef)
                or die "Can't read EventLog entry #$x\n";
        if ($hashRef->{Source} eq "LANDesk Inventory Server") {
				if ($hashRef->{EventType} eq 2 and $hashRef->{EventID} eq 2391) {
					$forcedfullscans++;
				}
        }
        $x++;
 }

print "$forcedfullscans Forced full scans\n";

$now_string = localtime;
print "ending at $now_string\n";

