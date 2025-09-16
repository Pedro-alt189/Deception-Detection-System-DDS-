@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Administrator rights required. Restart...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

go list -m github.com/google/gopacket >nul 2>&1
if %errorLevel% neq 0 (
    echo Cant find gopacket installing..
    go get github.com/google/gopacket/pcap
)

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Npcap" | findstr "DisplayName" >nul
if %errorLevel% neq 0 (
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "WinPcap" | findstr "DisplayName" >nul
    if %errorLevel% neq 0 (
        echo Download and install script from https://nmap.org/npcap/ and restart script
        pause
        exit /b
    )
)
set GO_FILE=main.go
echo Starting %GO_FILE%...
go run "%GO_FILE%"

pause
