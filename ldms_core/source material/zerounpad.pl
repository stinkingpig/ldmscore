
ZeroUnPad(shift);


sub ZeroUnPad {

    my $ip = shift;
    my $return;

    # Remove padding zeroes from IP Addresses
    my @temp = split( /\./x, $ip );
    foreach my $octet (@temp) {
        $return .= &AtoI($octet);
        $return .= ".";
    }

    # knock that last period off
    $return = substr( $return, 0, -1 );
    print "ZeroUnPad: turned $ip into $return\n";
    return $return;
}

### ASCII to Integer subroutine ###############################################
sub AtoI {
    my $t = 0;
    foreach my $d ( split( //, shift() ) ) {
        $t = $t * 10 + $d;
    }
    return $t;
}

