#############################################################################
# ldms_core.pl                                                              #
# (c) 2005-2008 Jack Coates, jack@monkeynoodle.org                          #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/                                            #
#############################################################################

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################

package Common;

use strict;
use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

#############################################################################
# Variables                                                                 #
#############################################################################

$VERSION     = 1.00;
@ISA         = qw(Exporter);
@EXPORT      = ();
@EXPORT_OK   = qw(func1 func2);
%EXPORT_TAGS = ( DEFAULT => [qw(&func1)],
                 Both    => [qw(&func1 &func2)]);

#############################################################################
# Subroutines                                                               #
#############################################################################


1;

