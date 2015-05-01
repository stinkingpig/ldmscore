;NSIS Modern User Interface
;Script automatically created by Mihov NSIS Helper 3.3
;http://freeware.mihov.com
;-----------------------------------------------------
!include "MUI.nsh"
SetCompressor /SOLID lzma
SetCompress force
!define VERSION "3.9.3" 
Name "ldms_core version ${VERSION}"
OutFile "ldms_core_setup.exe"
InstallDir "$PROGRAMFILES\Monkeynoodle\ldms_core"

;Get install folder from registry for updates
InstallDirRegKey HKCU "Software\ldms_core" ""
 
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\ldms_core.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "/setup"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
ShowUninstDetails show

Section "Program Files"
  SetOutPath "$INSTDIR"
  File "ldms_core.exe"
  File "ldms_core.ico"
  File "ldms_core_icon.png"
  File "ldms_core.css"
  File "ldms_core.pl"
  File "ldms_core.perlapp"
  File "ldms_core_setup.nsi"
 
  ;Store install folder
  WriteRegStr HKCU "Software\ldms_core" "" $INSTDIR
 
  ## database name
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "db_name"
  ${If} $0 == ""
    ReadRegStr $1 HKLM "Software\LANDesk\ManagementSuite\Core\Connections\Local" "Database"
    ${If} $1 == ""
      WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "db_type" "SQL"
    ${Else}
      WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "db_type" "ORA"
    ${EndIf}
  ${EndIf}

  ## database type
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "db_type"
  ${If} $0 == ""
    ReadRegStr $1 HKLM "Software\LANDesk\ManagementSuite\Core\Connections\Local" "IsOracle"
    ${If} $1 == "false"
      WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "db_type" "SQL"
    ${Else}
      WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "db_type" "ORA"
    ${EndIf}
  ${EndIf}

  ## database reindex trigger
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "dbreindex_do"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "dbreindex_do" "1"
  ${EndIf}

  ## show system tray icon
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "showsystray"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "showsystray" "0"
  ${EndIf}

  ## nmap binary location
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "nmap"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "nmap" "$PROGRAMFILES\nmap\nmap.exe"
  ${EndIf}

  ## nmap commandline options
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "nmap_options"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "nmap_options" "-A -T4 -P0 -n --host_timeout 5m"
  ${EndIf}

  ## nmap unidentified
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "nmap_unidentified"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "nmap_unidentified" "1"
  ${EndIf}

  ## nmap maximum target count
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "nmap_max"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "nmap_max" "10"
  ${EndIf}

  ## nmap trigger
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "nmap_do"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "nmap_do" "0"
  ${EndIf}

  ## patch action trigger
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "patch_do"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "patch_do" "1"
  ${EndIf}

  ## patch location
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "patchdir"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "patchdir" "$PROGRAMFILES\LANDesk\MANAGE~1\ldlogon\patch"
  ${EndIf}

  ## vuln aggression level
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "cullvulnsaggression"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "cullvulnsaggression" "2"
  ${EndIf}

  ## mail verbosity
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "mailverbosity"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "mailverbosity" "6"
  ${EndIf}

  ## update check frequency
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "update"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "update" "7"
  ${EndIf}

  ## deletion days
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "deletiondays"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "deletiondays" "30"
  ${EndIf}

  ## network map floor
  ReadRegStr $0 HKLM "Software\Monkeynoodle\ldms_core" "mapfloor"
  ${If} $0 == ""
    WriteRegStr HKLM "Software\Monkeynoodle\ldms_core" "mapfloor" "10"
  ${EndIf}

###############################  reg2nsis end  #################################

 ;Create uninstaller
 WriteUninstaller "$INSTDIR\Uninst.exe"
 
  WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\ldms_core" "DisplayName" "ldms_core ${VERSION} (remove only)"
  WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\ldms_core" "UninstallString" '"$INSTDIR\uninst.exe"'
  WriteUnInstaller "uninst.exe"
SectionEnd
 
Section "Start Menu Shortcuts"
  SetShellVarContext all
  CreateDirectory "$SMPROGRAMS\Monkeynoodle\ldms_core"
  CreateShortCut "$SMPROGRAMS\Monkeynoodle\ldms_core\Uninstall ldms_core.lnk" "$INSTDIR\uninst.exe" "" "$INSTDIR\uninst.exe" 0
  CreateShortCut "$SMPROGRAMS\Monkeynoodle\ldms_core\ldms_core.lnk" "$INSTDIR\ldms_core.exe" "" "$INSTDIR\ldms_core.exe" 0
  CreateShortCut "$SMPROGRAMS\Monkeynoodle\ldms_core\ldms_core setup.lnk" "$INSTDIR\ldms_core.exe" "/setup" "$INSTDIR\ldms_core.exe" 0
  CreateShortCut "$SMPROGRAMS\Monkeynoodle\ldms_core\generate network map.lnk" "$INSTDIR\ldms_core.exe" "/map" "$INSTDIR\ldms_core.exe" 0
SectionEnd
 
Section "Uninstall"
  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\ldms_core.exe"
  Delete "$INSTDIR\ldms_core.ico"
  Delete "$INSTDIR\ldms_core.css"
  Delete "$INSTDIR\ldms_core_icon.png"
  Delete "$INSTDIR\ldms_core.pl"
  Delete "$INSTDIR\ldms_core.perlapp"
  Delete "$INSTDIR\ldms_core_setup.nsi"
  Delete "$INSTDIR\Uninst.exe"
  RMDir "$INSTDIR"
 
  ; remove shortcuts, if any.
  SetShellVarContext all
  Delete "$SMPROGRAMS\Monkeynoodle\ldms_core\Uninstall ldms_core.lnk"
  Delete "$SMPROGRAMS\Monkeynoodle\ldms_core\ldms_core.lnk"
  Delete "$SMPROGRAMS\Monkeynoodle\ldms_core\ldms_core setup.lnk"
  Delete "$SMPROGRAMS\Monkeynoodle\ldms_core\generate network map.lnk"
  RMDir "$SMPROGRAMS\Monkeynoodle\ldms_core"
 
  DeleteRegKey HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ldms_core"
  DeleteRegKey /ifempty HKCU "Software\ldms_core"
SectionEnd

