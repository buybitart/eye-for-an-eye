@echo off
rem Eye for an Eye - Stopping. P17 section 15.
rem
rem This file only calls the installed program. It contains no logic of its own,
rem so there is nothing here that can disagree with the tested command.

setlocal
cd /d "%~dp0"

set "EFAE_EXE=%LOCALAPPDATA%\eye-for-an-eye\runtime\Scripts\eye-for-an-eye.exe"
if not exist "%EFAE_EXE%" (
  echo.
  echo  What happened
  echo    Eye for an Eye is not installed on this computer yet.
  echo.
  echo  Is my computer safe
  echo    Yes. Nothing is running.
  echo.
  echo  What to do next
  echo    Double-click Install-EyeForAnEye.cmd first.
  echo.
  pause
  exit /b 2
)

"%EFAE_EXE%" stop %*
set "EFAE_CODE=%ERRORLEVEL%"
echo.
pause
exit /b %EFAE_CODE%
