@echo off
REM Запуск netmon. Сначала пробуем виртуальное окружение .venv,
REM затем лаунчер py, затем python из PATH.
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m netmon
  goto :done
)

where py >nul 2>nul
if %errorlevel%==0 (
  py -m netmon
  goto :done
)

python -m netmon

:done
pause
