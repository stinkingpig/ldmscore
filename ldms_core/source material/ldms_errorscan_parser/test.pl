use Win32::OLE;
$Win32::OLE::Warn = 3;
use Win32::OLE::Variant;

# ------ SCRIPT CONFIGURATION ------
$strFilePath = 'g://ldscan/errorscan/sca36e.scn';
$dir = 'g:\ldscan\errorscan/';
$file = 'sca36e.scn';
$strComputer = '.';
# ------ END CONFIGURATION ---------

my $ctime=(stat($dir.$file))[10] or die "stat($dir.$source) failed: $!\n";
print "$ctime\n";

my $ctime = -M "$strFilePath";
print "$ctime\n";
my $time = time();
print "$time\n";

$objWMI = Win32::OLE->GetObject('winmgmts:\\\\' . $strComputer . '\\root\\cimv2');
$objFile = $objWMI->Get('CIM_Datafile="' . $strFilePath . '"');
print $objFile->Name, "\n";
print ' Creation Date: ' . $objFile->CreationDate, "\n";
my $ltime=localtime();
print "$ltime\n";

my $fso = Win32::OLE->new("Scripting.FileSystemObject");
my $file = $fso->GetFile($strFilePath) or die Win32::OLE->LastError;
print $file->DateLastModified;

