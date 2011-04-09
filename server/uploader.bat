@echo off
set PYTHONOPTIMIZE=x
"%~dp0..\local\py25.exe" uploader.py || pause
@echo on