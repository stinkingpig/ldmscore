use strict;
use Win32::GUI;

my $mainform;

$mainform = Win32::GUI::Window->new(-name=>'main',-text=>'tabstrip test',-width=>800,-height=>600,-dialogui=>1);

$mainform->AddTabStrip(-name=>"tab",-width=>770,-height=>550,-left=>10,-top=>10);

$mainform->tab->InsertItem(-name=>'Tab1',-text=>" Tab1 ",-border=>0,top=>10,-addstyle=>WS_TABSTOP);
$mainform->tab->InsertItem(-name=>'Tab2',-text=>" Tab2 ",-border=>0,top=>10,-addstyle=>WS_TABSTOP);
$mainform->tab->InsertItem(-name=>'Tab3',-text=>" Tab3 ",-border=>0,top=>10,-addstyle=>WS_TABSTOP);

$mainform->Show();
Win32::GUI::Dialog();

exit;

main_Terminate
{
    $mainform->Hide();
    return -1;
}

