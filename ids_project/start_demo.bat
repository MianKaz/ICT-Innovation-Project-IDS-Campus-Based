@echo off
cd /d %~dp0
if exist ids\Scripts\activate.bat call ids\Scripts\activate.bat
python main.py
pause
