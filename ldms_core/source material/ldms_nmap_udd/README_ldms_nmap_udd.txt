#############################################################################
# ldms_nmap_udd.pl, v 2.7                                                   #
# (c) 2005 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/network/ldms_nmap                           #
# Thanks to $Bill Luebkert for the command-line handling.                   #
#############################################################################
#
# This utility uses nmap to detect the OS on unmanaged nodes.
# It is greatly simplified from previous versions -- it now works on a single
# machine at a time, allowing for graceful handling of error conditions and 
# interruptions, albeit in a slower fashion.
#
# The script reads in all records from unmanaged nodes which do not have OS
# Name set. It calls nmap, finds the OS Name, and updates one record at a 
# time.
#
# CHANGELOG
# 2.8 -- Port MAC address update feature from ldms_nmap_lpm. If a node is in 
# the database, has a poor OSNAME, and has no MAC address, the program will
# attempt to correct the MAC address field
# 2.7 -- Optionally skip nodes that NMAP has had trouble with
# 2.6 -- Sort by most recently seen, not random
# 2.5 -- Enable service scanning, be clearer about guesses
# 2.4 -- NMAP 4.21ALPHA4 compatible
# 2.3.3 - Useful error if NMAP can't be found.
# 2.3.2 - Exclude when XDDEXCEPTION is toggled.
# 2.3.1 - Erm, it's LASTSCANTIME, not LASTSCANDATE. Test twice, upload once.
# 2.3 -- Debug mode, cleaner and better logging, truncate long results.
# 2.2 -- Gather configuration from database, untested Oracle support
# 2.1 -- NMAP 4.20 compatibility, replaces UNIX and UNKNOWN labels, hides 
# window
# 2.0 -- Ditched multi-threading and temp files for simpler architecture
