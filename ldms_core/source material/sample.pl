use PerlTray;

our @anim = qw(icon1 icon2 icon3 icon4);

sub show_balloon {
    Balloon("This is the message", "Balloon Title", "Error", 15);
}

sub PopupMenu {
    return [["*ActiveState", "Execute 'http://www.ActiveState.com'"],
	    ["MessageBox", sub { MessageBox("This is a $_!") }],
	    ["Effects", [["Animate", 'SetAnimation("0:20", $freq, @anim)'],
			 ["*Ballon", \&show_balloon],
			 ["Timer",   'SetTimer(":2.500")'],
			 ["Icon1",   sub {SetIcon($_)}],
			 ["Icon2"],
			]],
	    ["--------"],

 	    ["o Fast   :50",  \$freq],
 	    ["x Medium :100"],
 	    ["o Slow   :200"],

# 	    ["o Fast",   '$freq =  50', $freq==50],
# 	    ["o Medium", '$freq = 100', $freq==100],
# 	    ["o Slow",   '$freq = 200', $freq==200],

	    ["--------"],
	    ["_ Unchecked", ""],
	    ["v Checked", undef, 1],
	    ["v Checked", \$check],
	    ["--------"],
	    ["  E&xit", "exit"],
	   ];
}

sub ToolTip { localtime }

sub Timer {
    SetTimer(0);
    Balloon("Timer triggered Message", "The Balloon", "Info", 5);
}

sub TimeChange {
    Balloon(scalar localtime, "System Time Changed", "Info", 5);
}
