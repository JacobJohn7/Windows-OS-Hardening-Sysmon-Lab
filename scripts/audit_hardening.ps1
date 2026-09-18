# audit_hardening.ps1 - Audit script for Windows 10 CIS Hardening & Telemetry
# Author: Jacob John

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Windows Security Hardening & Audit Verification" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check SMBv1 Status
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -ErrorAction SilentlyContinue
if ($smb1 -and $smb1.State -eq "Disabled") {
    Write-Host "[+] SMBv1 Protocol: DISABLED (Secure)" -ForegroundColor Green
} else {
    Write-Host "[!] SMBv1 Protocol: ENABLED (Insecure - Disable required)" -ForegroundColor Red
}

# 2. Check PowerShell Script Block Logging
$scriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$scriptBlock = Get-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
if ($scriptBlock -and $scriptBlock.EnableScriptBlockLogging -eq 1) {
    Write-Host "[+] PowerShell Script Block Logging: ENABLED (Event ID 4104 active)" -ForegroundColor Green
} else {
    Write-Host "[!] PowerShell Script Block Logging: DISABLED" -ForegroundColor Yellow
}

# 3. Check LLMNR / NetBIOS Status
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$llmnr = Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
    Write-Host "[+] LLMNR Protocol: DISABLED (Mitigates Responder poison attacks)" -ForegroundColor Green
} else {
    Write-Host "[!] LLMNR Protocol: ENABLED" -ForegroundColor Yellow
}

# 4. Check Sysmon Service Status
$sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
if ($sysmon -and $sysmon.Status -eq "Running") {
    Write-Host "[+] Sysmon Service: RUNNING (Operational Channel Active)" -ForegroundColor Green
} else {
    Write-Host "[!] Sysmon Service: NOT RUNNING" -ForegroundColor Red
}

Write-Host ""
Write-Host "[+] Audit Check Complete." -ForegroundColor Cyan
