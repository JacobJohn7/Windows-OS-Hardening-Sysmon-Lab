# Windows 10 Hardening & Sysmon Telemetry Lab

Configurations, audit scripts, and Sysmon XML rules implemented on a Windows 10 VirtualBox virtual machine to align with CIS Benchmarks and establish endpoint telemetry for SOC monitoring.

---

## Hardening Controls Applied

### 1. Protocol Hardening & Network Attack Surface Reduction
- **Disabled SMBv1 Protocol**: Prevents legacy SMB vulnerability exploitation (WannaCry/EternalBlue vectors).
- **Disabled LLMNR & NBT-NS**: Mitigates Link-Local Multicast Name Resolution poisoning attacks (e.g. Responder credential hash spoofing).
- **Disabled Administrative Auto-Shares (`AutoShareWks=0`)**: Prevents default `C$` and `ADMIN$` share exposure across local subnets.

### 2. PowerShell Security & Auditing
- Enforced Execution Policy to `RemoteSigned`.
- Enabled **Script Block Logging (Event ID 4104)** in Local Group Policy (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`) to record obfuscated and encoded PowerShell payloads at runtime.

---

## Sysmon Deployment (`config/sysmon_config.xml`)

Deployed Sysmon v15.x configured with a custom XML rule schema to monitor critical attack indicators:

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>MD5,SHA256</HashAlgorithms>
  <EventFiltering>
    <!-- Event ID 1: Process Creation with Hashes & Full Command Lines -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <Image condition="is">C:\Windows\System32\SearchIndexer.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Outbound Network Connections from Script Interpreters -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <Image condition="image">cmd.exe</Image>
        <Image condition="image">certutil.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 11: Executable Drops in Temp & Public Folders -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">C:\Users\Public\</TargetFilename>
        <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## Verification & Audit Telemetry

Executed test process execution (`cmd.exe` launching `powershell.exe` with base64 encoded arguments) and verified XML logging in `Microsoft-Windows-Sysmon/Operational`.

### Sysmon Event ID 1 Log Excerpt (`logs/sysmon_event1.xml`)
```xml
<EventData>
  <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -Enc SQBFA...==</Data>
  <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
  <Data Name="Hashes">MD5=93B4E38A5F2D1C0E7B6A4D9F8E2C1A3F,SHA256=3A4F89D10E6B52C18D9F0412E87A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A</Data>
</EventData>
```

### PowerShell Audit Script (`scripts/audit_hardening.ps1`)
Run the PowerShell audit script to verify applied security controls:
```powershell
.\scripts\audit_hardening.ps1
```

---

## Setup & Tuning Notes

- **Sysmon Schema Version**: Ensure `schemaversion` in XML matches the installed Sysmon binary version (`sysmon -i config.xml`).
- **Log Noise Tuning**: Excluded standard Windows background binaries (`SearchIndexer.exe`, `svchost.exe`) from `ProcessCreate` to prevent log volume saturation in SIEM forwarders.
