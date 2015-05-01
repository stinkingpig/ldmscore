use strict;
use warnings;
use DateTime;
use DateTime::Locale::en_US;

my $dt = DateTime->now;

print "DateTime: " . $dt->ymd . "-" . $dt->hms('-') . "\n";

print "localtime: " . localtime() . "\n";

my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
$year += 1900;
$mon = (sprintf "%02d", $mon);
$mday = (sprintf "%02d", $mday);
print "$year-$mon-$mday\n";

