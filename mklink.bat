@echo off
cd /d %~dp0
mklink /D FridaDevKit ..\FridaSolo\FridaDevKit
echo "Finish"
pause