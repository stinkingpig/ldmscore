#############################################################################
# ldms_errorscan_parser.pl, v 1.9                                           #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/scripts/ldms_errorscan_parser/              #
# Thanks to $Bill Luebkert for the command-line handling.                   #
# Thanks to Ken Hansen for debugging.                                       #
# Thanks to Charles Tank for Oracle support.                                #
#############################################################################
#
# This utility renames files in the ErrorScan directory to indicate which 
# client node produced those scan files. There is an undo functionality to 
# put the files back like they were.
#
# Design notes and gotchas
# 1) It does not need to run on the core server; any machine with database
# access and write access to the ldmain share will do. Simply use the UNC
# path to the share or map a drive.
#
# 2) I realize that many Windows administrators will be unfamiliar with Perl
# As noted above, this is open code and you are perfectly welcome to port it
# to another language so long as you credit me for the basic design. As a
# reimplementation, there would be no need to release the resulting script
# under the GPL (though I would appreciate it if you'd send me a copy and 
# give me permission to post it on the web).
#

# CHANGELOG
# 1.0 -- initial release
# 1.1 -- added rename after scan contents if database check fails
# 1.2 -- added undo mode, removed check for files named after the machine
# 1.3 -- improved speed of database access, fixed assorted bugs
# 1.5 -- Oracle support, all options are on the command line now
# 1.6 -- delete files older than X days
# 1.7 -- Log with the Windows Event Viewer service
# 1.8 -- Take configuration from the registry, if available
# 1.9 -- Compress storage scans older than X days
