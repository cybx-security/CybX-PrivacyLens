; PrivacyLens Setup - the Windows setup wizard (NSIS 3).
;
; The wizard is deliberately thin. It unpacks the program into Program
; Files and then runs "privacylens.exe install -wizard", which does the real
; work (scan settings, weekly task, permissions, OCR tools) and whose output
; is shown in the details pane; the wizard then adds the Start Menu shortcut
; and the Installed-apps entry itself. One installer implementation, whether
; it is reached through this wizard, the zip's double-click script, or an
; RMM running the command.
;
; Built by scripts/build-all.sh:
;   makensis -DVERSION=0.9.6 -DSRC_AMD64=<dir> -DSRC_ARM64=<dir> \
;            -DGUIDE=<docx> -DICON=<ico> -DOUTFILE=<setup.exe> installer.nsi
; SRC_* are folders holding privacylens.exe and privacylens-gui.exe for that
; CPU; the one wizard carries both and installs the right pair.
;
; Silent use (RMM, scripts):  PrivacyLens-Setup-x.y.z.exe /S [/NOOCR]
; Silent removal:             "%ProgramFiles%\PrivacyLens\Uninstall.exe" /S [/PURGE]
; Exit code 0 = success, 2 = failed.

Unicode true
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"
!include "Sections.nsh"
!include "FileFunc.nsh"

!ifndef VERSION
  !error "VERSION is not defined (build with scripts/build-all.sh)"
!endif

Name "PrivacyLens"
OutFile "${OUTFILE}"
; Fixed location: the scheduled task, shortcut, and status check all rely on
; it, so there is no folder-picker page.
InstallDir "$PROGRAMFILES64\PrivacyLens"
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show
BrandingText "PrivacyLens ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "PrivacyLens"
VIAddVersionKey "CompanyName" "CybX"
VIAddVersionKey "FileDescription" "PrivacyLens Setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright (c) CybX"

Var Purge

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
; Stay on the progress page when done so the summary can be read.
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

!define MUI_WELCOMEPAGE_TITLE "Welcome to PrivacyLens ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "PrivacyLens finds personal information - Social Security numbers, card numbers, medical and bank details - stored in files on this computer, and shows you exactly where it is.$\r$\n$\r$\nSetup will:$\r$\n$\r$\n   -  install PrivacyLens for everyone who uses this computer$\r$\n   -  add it to the Start Menu$\r$\n   -  schedule an automatic scan every Sunday at 2:00 AM$\r$\n$\r$\nNothing PrivacyLens finds ever leaves this computer.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME

!define MUI_COMPONENTSPAGE_SMALLDESC
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TITLE "PrivacyLens is installed"
!define MUI_FINISHPAGE_TEXT "To use it, open the Start Menu and type PrivacyLens.$\r$\n$\r$\nIt opens in your web browser: choose the folders to check and click Scan. Every scan is saved automatically.$\r$\n$\r$\nTo remove PrivacyLens later, go to Settings > Apps > Installed apps."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open PrivacyLens now"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; Setup runs elevated; starting the app directly would run it - and the
; browser it opens - as administrator. Going through Explorer starts it as
; the signed-in user, exactly like the Start Menu shortcut does.
Function LaunchApp
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\privacylens-gui.exe"'
FunctionEnd

; StopApp closes any running PrivacyLens window launcher, which would
; otherwise keep its file locked. The launcher idles in the background for a
; few minutes after its browser tab is closed, so "it isn't open" is not
; something the user can reliably see.
!macro StopApp
  nsExec::Exec 'taskkill /F /IM privacylens-gui.exe'
  Pop $0
  Sleep 500
!macroend

Section "PrivacyLens" SecMain
  SectionIn RO
  SetShellVarContext all
  !insertmacro StopApp

  SetOutPath "$INSTDIR"
  SetOverwrite try
  ClearErrors
  ${If} ${IsNativeARM64}
    File "/oname=privacylens.exe" "${SRC_ARM64}/privacylens.exe"
    File "/oname=privacylens-gui.exe" "${SRC_ARM64}/privacylens-gui.exe"
  ${Else}
    File "/oname=privacylens.exe" "${SRC_AMD64}/privacylens.exe"
    File "/oname=privacylens-gui.exe" "${SRC_AMD64}/privacylens-gui.exe"
  ${EndIf}
  File "/oname=PrivacyLens User Guide.docx" "${GUIDE}"
  ${If} ${Errors}
    MessageBox MB_ICONSTOP|MB_OK "Setup could not replace the PrivacyLens program files - they are in use.$\r$\n$\r$\nIf a PrivacyLens scan is running, wait for it to finish, then run Setup again." /SD IDOK
    SetErrorLevel 2
    Abort "The PrivacyLens program files are in use."
  ${EndIf}
  ; Written before "privacylens install" runs so the Installed-apps entry
  ; it registers points at this graphical uninstaller.
  WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

Section "OCR tools (read scanned documents and photos)" SecOCR
  ; Nothing to copy: this only decides whether the configure step below
  ; installs Tesseract and Poppler.
SectionEnd

Section "-Configure"
  StrCpy $1 ""
  ${IfNot} ${SectionIsSelected} ${SecOCR}
    StrCpy $1 " -no-ocr"
  ${EndIf}
  DetailPrint "Setting up PrivacyLens (this can take a few minutes)..."
  nsExec::ExecToLog '"$INSTDIR\privacylens.exe" install -wizard$1'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "Setup could not finish (code $0).$\r$\n$\r$\nThe list in the Setup window shows the step that failed. Fix that and run Setup again - it is safe to repeat." /SD IDOK
    SetErrorLevel 2
    Abort "PrivacyLens setup did not complete."
  ${EndIf}

  ; Start Menu shortcut and Installed-apps entry, created here rather than
  ; by privacylens.exe (-wizard tells it to leave them alone): from an
  ; installer these are ordinary; from a freshly installed program shelling
  ; out to PowerShell and reg.exe they look like malware to antivirus
  ; behavior monitoring.
  SetShellVarContext all
  CreateShortcut "$SMPROGRAMS\PrivacyLens.lnk" "$INSTDIR\privacylens-gui.exe" "" "$INSTDIR\privacylens-gui.exe" 0 SW_SHOWNORMAL "" "Find personal data (PII) stored on this computer"
  DetailPrint "Start Menu shortcut: PrivacyLens"
  !define ARP "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyLens"
  WriteRegStr HKLM "${ARP}" "DisplayName" "PrivacyLens"
  WriteRegStr HKLM "${ARP}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${ARP}" "Publisher" "CybX"
  WriteRegStr HKLM "${ARP}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${ARP}" "DisplayIcon" "$INSTDIR\privacylens.exe"
  WriteRegStr HKLM "${ARP}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${ARP}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${ARP}" "NoModify" 1
  WriteRegDWORD HKLM "${ARP}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${ARP}" "EstimatedSize" "$0"
  DetailPrint "Listed under Settings > Apps > Installed apps"
SectionEnd

; After the sections: it refers to ${SecOCR}, which exists only once the
; section has been declared.
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP|MB_OK "PrivacyLens needs a 64-bit version of Windows." /SD IDOK
    SetErrorLevel 2
    Quit
  ${EndIf}
  SetRegView 64
  ; /NOOCR on the command line unticks the OCR component (for silent installs).
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/NOOCR" $1
  ${IfNot} ${Errors}
    !insertmacro UnselectSection ${SecOCR}
  ${EndIf}
FunctionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "The PrivacyLens program, its Start Menu entry, and the automatic weekly scan."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecOCR} "Lets PrivacyLens read text inside scanned documents and photos. Downloads the free Tesseract and Poppler tools (about 65 MB)."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function un.onInit
  SetRegView 64
  StrCpy $Purge ""
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/PURGE" $1
  ${IfNot} ${Errors}
    StrCpy $Purge " -purge"
  ${EndIf}
  ; Interactive removal asks; silent removal keeps the data unless /PURGE.
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete your scan settings, saved reports, and the findings log?$\r$\n$\r$\nChoose No to keep them (recommended) - they are your records of what was found." /SD IDNO IDNO keepData
    StrCpy $Purge " -purge"
  keepData:
FunctionEnd

Section "Uninstall"
  SetShellVarContext all
  !insertmacro StopApp
  ; Removes the weekly task, the shortcut, the Installed-apps entry, and
  ; (with -purge) the data folder.
  nsExec::ExecToLog '"$INSTDIR\privacylens.exe" uninstall -wizard$Purge'
  Pop $0
  ; Only files Setup put here are deleted, and the folder only if that
  ; leaves it empty.
  Delete "$INSTDIR\privacylens.exe"
  Delete "$INSTDIR\privacylens.exe.new"
  Delete "$INSTDIR\privacylens-gui.exe"
  Delete "$INSTDIR\privacylens-gui.exe.new"
  Delete "$INSTDIR\PrivacyLens User Guide.docx"
  Delete "$INSTDIR\Uninstall.exe"
  ; On Windows 11, Uninstall.exe stays locked for as long as this temporary
  ; copy of it is running (it cannot be deleted even though the original
  ; process has exited), which would leave one stray file in an otherwise
  ; empty folder. A locked program file can still be renamed, so move it
  ; out to the temp folder and let Windows delete it there at the next
  ; restart. (Deleting it in place at restart is not safe: a reinstall
  ; before then would lose its new uninstaller.)
  ${If} ${FileExists} "$INSTDIR\Uninstall.exe"
    GetTempFileName $2
    Delete $2
    Rename "$INSTDIR\Uninstall.exe" $2
    Delete /REBOOTOK $2
  ${EndIf}
  RMDir "$INSTDIR"
  ; Normally already gone ("privacylens uninstall" removes both); repeated
  ; here in case the program itself could not run.
  Delete "$SMPROGRAMS\PrivacyLens.lnk"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyLens"
SectionEnd
