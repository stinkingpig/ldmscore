use Win32::GUI;

my ($foo, $bar, $baz);

&mainwin;
&maintab;
&HideEverything;
&ShowTab1;

Win32::GUI::Dialog();

sub Mainwin_Terminate {
   return -1;
}

sub mainwin {
    my $main_class = new Win32::GUI::Class(
        -name    => "temp_Class",
    );


    $Mainwin = new Win32::GUI::Window(
          -left   => 612,
          -top    => 15,
          -width  => 400,
          -height => 455,
          -name   => "Mainwin",
          -text   => "Window Title",
          -class  => $main_class
          );

    $foo = $Mainwin->AddTextfield(
        -name    => "foo",
        -prompt  => "foo:",
        -tabstop => 1,
        -text    => "turlingdrome",
        -pos     => [ 100, 100 ],
        -size    => [ 200, 20 ],
    );

    $bar = $Mainwin->AddTextfield(
        -name    => "bar",
        -prompt  => "bar:",
        -tabstop => 1,
        -text    => "qwazzlehockey",
        -pos     => [ 100, 100 ],
        -size    => [ 200, 20 ],
    );

    $baz = $Mainwin->AddTextfield(
        -name    => "baz",
        -prompt  => "baz:",
        -tabstop => 1,
        -text    => "shinjickle",
        -pos     => [ 100, 100 ],
        -size    => [ 200, 20 ],
    );

    $Mainwin->Show();
}

sub maintab{
    $Maintab = $Mainwin->AddTabStrip(
                     -left   => 10,   
                     -top    => 10, 
                     -width  => $Mainwin->ScaleWidth - 20,
                     -height => $Mainwin->ScaleHeight - 50,
                     -name   => "Maintab",
                     -onChange => \&TabChanged,
    );

    $Maintab->InsertItem(-text => "Tab1");
    $Maintab->InsertItem(-text => "Tab2");
    $Maintab->InsertItem(-text => "Tab3");
    $Maintab->InsertItem(-text => "Tab4");
    $Maintab->InsertItem(-text => "Tab5");

}

sub TabChanged {
    &HideEverything;
    #what tab is it now?
    my $newtab = $Maintab->SelectedItem();
    #tab 1
    if ($newtab == 0) {
        &ShowTab1;
    }
    #tab 2
    if ($newtab == 1) {
        &ShowTab2;
    }
    if ($newtab == 2) {
        &ShowTab3;
    }
}

sub HideEverything {
    # hide everything
    # note that the prompt option in addtextbox auto-creates a new label,
    # which must be hidden and shown separately. 
    $foo->Hide();
    Win32::GUI::Hide($Mainwin->foo_Prompt()->{-handle});
    $bar->Hide();
    Win32::GUI::Hide($Mainwin->bar_Prompt()->{-handle});
    $baz->Hide();
    Win32::GUI::Hide($Mainwin->baz_Prompt()->{-handle});
}

sub ShowTab1 {
    Win32::GUI::Show($Mainwin->foo_Prompt()->{-handle});
    $foo->Show();
}
sub ShowTab2 {
    Win32::GUI::Show($Mainwin->bar_Prompt()->{-handle});
    $bar->Show();
}
sub ShowTab3 {
    Win32::GUI::Show($Mainwin->baz_Prompt()->{-handle});
    $baz->Show();
}
