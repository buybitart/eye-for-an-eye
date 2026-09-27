@echo off
rem Eye for an Eye - beginner installer launcher. P17 section 4.
rem
rem This file finds a Python 3.12 and hands over to scripts\install_windows.py.
rem That is all it does. Installation logic lives in the Python file because a
rem .cmd file cannot be tested properly and this one must never need fixing.
rem
rem It asks for no Administrator rights. If something asks you for them while
rem this runs, stop and find out what is asking.

setlocal
cd /d "%~dp0"

set "EFAE_PY="
py -3.12 -c "import sys" >nul 2>&1 && set "EFAE_PY=py -3.12"
if not defined EFAE_PY (
  python -c "import sys;raise SystemExit(0 if sys.version_info[:2]==(3,12) else 1)" >nul 2>&1 && set "EFAE_PY=python"
)

if not defined EFAE_PY (
  echo.
  echo ============================================================
  echo  What happened
  echo    Python 3.12 is not installed, or Windows cannot find it.
  echo.
  echo  Is my computer safe
  echo    Yes. Nothing was installed and nothing was changed.
  echo.
  echo  What to do next
  echo    1. Open https://www.python.org/downloads/
  echo    2. Install Python 3.12.
  echo    3. Tick "Add python.exe to PATH" during setup.
  echo    4. Double-click this file again.
  echo ============================================================
  echo.
  pause
  exit /b 2
)

rem The installer lives at scripts\install_windows.py in a source checkout, and
rem at app\scripts\install_windows.py in the beginner release archive, where the
rem launchers sit at the top so they are the first thing a person sees. Found by
rem unpacking the archive and double-clicking, which is the only way this kind of
rem bug ever shows up.
set "EFAE_INSTALLER="
if exist "scripts\install_windows.py" set "EFAE_INSTALLER=scripts\install_windows.py"
if not defined EFAE_INSTALLER if exist "app\scripts\install_windows.py" set "EFAE_INSTALLER=app\scripts\install_windows.py"

if not defined EFAE_INSTALLER (
  echo.
  echo  What happened
  echo    Some of the program files are missing from this folder.
  echo.
  echo  Is my computer safe
  echo    Yes. Nothing was installed.
  echo.
  echo  What to do next
  echo    1. Unzip the whole download again, keeping the folders as they are.
  echo    2. Run this file from inside the unzipped folder.
  echo.
  pause
  exit /b 2
)

%EFAE_PY% "%EFAE_INSTALLER%" %*
set "EFAE_CODE=%ERRORLEVEL%"
echo.
pause
exit /b %EFAE_CODE%
