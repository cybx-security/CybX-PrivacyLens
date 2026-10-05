@echo off
rem Double-click uninstaller for PrivacyLens (the same thing as
rem Settings > Apps > Installed apps > PrivacyLens > Uninstall).
setlocal
title PrivacyLens Uninstall
set "INSTALLED=%ProgramFiles%\PrivacyLens\privacylens.exe"
if exist "%INSTALLED%" (
  "%INSTALLED%" uninstall -pause
) else if exist "%~dp0privacylens.exe" (
  "%~dp0privacylens.exe" uninstall -pause
) else (
  echo.
  echo   PrivacyLens does not appear to be installed on this computer.
  echo.
  pause
)
