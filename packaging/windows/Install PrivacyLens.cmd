@echo off
rem Double-click installer for PrivacyLens. The real work is done by
rem "privacylens.exe install", which asks Windows for administrator
rem permission itself and shows its progress in a window of its own.
setlocal
title PrivacyLens Setup
if not exist "%~dp0privacylens.exe" (
  echo.
  echo   PrivacyLens Setup cannot find its files.
  echo.
  echo   This usually means the zip was opened without being extracted.
  echo   Right-click the zip, choose "Extract All", open the extracted
  echo   folder, and double-click "Install PrivacyLens" there.
  echo.
  pause
  exit /b 1
)
"%~dp0privacylens.exe" install -pause
