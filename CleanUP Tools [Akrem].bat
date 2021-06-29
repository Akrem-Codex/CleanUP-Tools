@echo off     
   
:Administrator
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (echo Requesting Administrator, BY Akrem. goto CMDAkrem) else ( goto Delete_Vbs )

:CMDAkrem
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\Akrem.vbs"
echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\Akrem.vbs"
"%temp%\Akrem.vbs"
exit /B

:Delete_Vbs
del /f /s /q "%temp%\Akrem.vbs"

:Menu
mode 57,31
title CleanUP Tools [Akrem]
color 9
************************
cls
echo.
echo.   Coded File By Akrem, https://github.com/Akrem-Coder  
echo. _______________________________________________________
echo. .                SPEED UP YOUR COMPUTER               .
echo. _______________________________________________________
echo. . Delete "Recent"                                     .
echo. . Delete "BackUP"                                     .
echo. . Delete "Caches"                                     .
echo. . Delete "Cookies"                                    .
echo. . Delete "History"                                    .
echo. . Delete "Prefetch"                                   .
echo. . Delete "Event Log"                                  .
echo. . Delete "Temporary "                                 .
echo. . Delete "History Run"                                .
echo. . Delete "Event Trace Log"                            .
echo. . Delete "Cache Thumbnail"                            .
echo. . Delete "MiniDump,MemoryDump"                        .
echo. . Delete "Windows Update History"                     .
echo. . Delete "Windows Error Reporting"                    .
echo. . Delete "Temporary Internet Files"                   .
echo. _______________________________________________________
echo. .                SPEED UP YOUR INTERNET               .
echo. _______________________________________________________
echo. . "Fix PinG"                                          .
echo. . "HTTP Reset - IP Reset"                             .
echo. . "Flush Dns Cache -  Wlan Refresh"                   .
echo. . "Branch Cache Reset - Win Sock Reset"               .
echo. _______________________________________________________
echo.    IF You Want To Complete Mission, Press ENTER KEY:   
pause>nul

:Clear Temp
cls
del /f /s /q "%systemdrive%\*.evtx"
del /f /s /q "%systemdrive%\*.tmp"
del /f /s /q "%systemdrive%\*._mp"
del /f /s /q "%systemdrive%\*.log"
del /f /s /q "%systemdrive%\*.chk"
del /f /s /q "%systemdrive%\*.old"
del /f /s /q "%systemdrive%\*.SWP"
cls
del /f /s /q "C:\*.evtx"
del /f /s /q "C:\*.tmp"
del /f /s /q "C:\*._mp"
del /f /s /q "C:\*.log"
del /f /s /q "C:\*.chk"
del /f /s /q "C:\*.old"
del /f /s /q "C:\*.SWP"
cls
del /f /s /q "E:\*.evtx"
del /f /s /q "E:\*.tmp"
del /f /s /q "E:\*._mp"
del /f /s /q "E:\*.log"
del /f /s /q "E:\*.chk"
del /f /s /q "E:\*.old"
del /f /s /q "E:\*.SWP"
cls
del /f /s /q "D:\*.evtx"
del /f /s /q "D:\*.tmp"
del /f /s /q "D:\*._mp"
del /f /s /q "D:\*.log"
del /f /s /q "D:\*.chk"
del /f /s /q "D:\*.old"
del /f /s /q "D:\*.SWP"
cls
del /f /s /q "F:\*.evtx"
del /f /s /q "F:\*.tmp"
del /f /s /q "F:\*._mp"
del /f /s /q "F:\*.log"
del /f /s /q "F:\*.chk"
del /f /s /q "F:\*.old"
del /f /s /q "F:\*.SWP"
cls
del /f /s /q "%windir%\*.bak"
cls
del /f /s /q "%systemdrive%\Windows\System32\winevt\Logs\*.*"
cls
del /f /s /q "%systemdrive%\Windows\System32\LogFiles\*.*"
cls
del /f /s /q "%SystemRoot%\MEMORY.DMP"
del /f /s /q "%SystemRoot%\Minidump.dmp"
del /f /s /q "%SystemRoot%\Minidump\*.*"
del /f /s /q "%SystemRoot%\Minidump\"
rd /s /q "%SystemRoot%\Minidump\"
md "%SystemRoot%\Minidump\"
cls
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
cls
del /f /s /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*"
rd /s /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*"
md "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\"
cls
del /f /s /q "%userprofile%\AppData\Local\Microsoft\Windows\History\*.*"
rd /s /q "%userprofile%\AppData\Local\Microsoft\Windows\History\"
md "%userprofile%\AppData\Local\Microsoft\Windows\History\"
cls
del /f /s /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Cookies\*.*"
rd /s /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Cookies\*.*"
md "%userprofile%\AppData\Roaming\Microsoft\Windows\Cookies\*.*"
cls
del /f /s /q "%windir%\temp\*.*"
del /f /s /q "%windir%\temp\"
rd /s /q "%windir%\temp"
cls
del /f /s /q "%windir%\prefetch\*.*"
del /f /s /q "%windir%\prefetch\"
rd /s /q "%windir%\prefetch\"
md "%windir%\prefetch\"
cls
del /f /s /q "%USERPROFILE%\AppData\Local\Temp\*.*"
del /f /s /q "%USERPROFILE%\AppData\Local\Temp\"
cls
del /f /q "%userprofile%\cookies\*.*"
del /f /q "%userprofile%\cookies\"
rd /s /q "%userprofile%\cookies\"
cls
del /f /s /q "%userprofile%\Local Settings\Temporary Internet Files\*.*"
cls
del /f /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files\*.*"
del /f /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files\"
rd /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files\"
cls
del /f /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\Caches\"
del /f /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\Caches\*.*"
cls
del /f /s /q "%systemdrive%\ProgramData\Microsoft\Windows\Caches\*.*"
rd /s /q "%systemdrive%\ProgramData\Microsoft\Windows\Caches\"
cls
del /f /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\WER\*.*"
rd /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\WER\"
cls
del /f /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\WER\ReportArchive\*.*"
rd /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\WER\ReportArchive\"
cls
del /f /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\WER\ReportQueue\*.*"
rd /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\WER\ReportQueue\"
cls
del /f /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\WER\ERC\*.*"
rd /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\WER\ERC\"
cls
del /f /s /q "%systemdrive%\ProgramData\Microsoft\Windows\WER\ReportQueue\*.*"
rd /s /q "%systemdrive%\ProgramData\Microsoft\Windows\WER\ReportQueue\"
cls
del /f /s /q "%systemdrive%\ProgramData\Microsoft\Windows\WER\ReportArchive\*.*"
rd /s /q "%systemdrive%\ProgramData\Microsoft\Windows\WER\ReportArchive\"
cls
del /f /s /q "%userprofile%\AppData\Local\Microsoft\Windows\Explorer\*.db"
del /f /s /q "%userprofile%\AppData\Local\Microsoft\Windows\Explorer\*.etl"
del /f /s /q "%userprofile%\AppData\Local\Microsoft\Windows\Explorer\ThumbCacheToDelete\*.tmp"
rd /s /q "%userprofile%\AppData\Local\Microsoft\Windows\Explorer\ThumbCacheToDelete\"
cls
%SystemRoot%\System32\Cmd.exe /c Cleanmgr /sageset:65535 & Cleanmgr /sagerun:65535
cls
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 1
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 16
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 16
cls
netsh wlan refresh & 
netsh int ip reset all & 
netsh branchcache reset & 
netsh winsock reset all & 
netsh int tcp reset all & 
netsh int udp reset all & 
netsh int ipv4 reset all & 
netsh int ipv6 reset all & 
netsh int portproxy reset all & 
netsh int httpstunnel reset all & 
cls
ipconfig /renew & 
ipconfig /flushdns & 
ipconfig /renew EL* & 
ipconfig /registerdns & 

:Termine
mode 40,5
title CleanUP Tools [Akrem]
cls
echo.
echo.
echo         Processed Successfully!
echo.
pause>nul