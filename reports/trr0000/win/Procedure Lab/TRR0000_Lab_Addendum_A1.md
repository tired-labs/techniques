# TRR0000 Lab Addendum A1 — Telemetry Validation

**Source:** TRR0000 Technical Audit (2026-03-17)
**Purpose:** Validate telemetry gaps identified by audit before opening a TRR revision cycle
**Scope:** Sysmon 7 (ImageLoad) and ETW EID 154 (AssemblyLoad) behavior for compiled assemblies loaded by `w3wp.exe`

---

## Prerequisites

This addendum assumes the lab environment from the TRR0000 Lab Recreation Guide is still deployed (IIS with ASP/ASP.NET features, Sysmon, test shell directories). If the environment has been torn down, re-execute Phases 1–4 of the original lab guide before proceeding.

### Sysmon Configuration Update

The original lab Sysmon config may not include `ImageLoad` rules. Update the config to capture DLL loads into `w3wp.exe`.

Add the following to your Sysmon config and reload:

```xml
<RuleGroup name="ImageLoad" groupRelation="or">
    <ImageLoad onmatch="include">
        <Image condition="image">w3wp.exe</Image>
    </ImageLoad>
</RuleGroup>
```

Reload the config:

```powershell
sysmon -c <path-to-updated-config.xml>
```

Verify the rule is active:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 | Select-Object Id
```

### ETW Session Setup (Optional)

To simultaneously validate ETW EID 154 (Microsoft-Windows-DotNETRuntime AssemblyLoad), start a trace session before executing scenarios. This is optional — Sysmon 7 is the primary target.

```powershell
# Start ETW trace for .NET Runtime AssemblyLoad events
logman create trace DotNetAssemblyTrace -p "Microsoft-Windows-DotNETRuntime" 0x8 -o C:\Tools\TRR0000_logs\addendum_a1\etw_assemblyload.etl -f bincirc -max 256
logman start DotNetAssemblyTrace
```

Stop after all scenarios are complete:

```powershell
logman stop DotNetAssemblyTrace
logman delete DotNetAssemblyTrace
```

Parse the ETL for AssemblyLoad events (EID 154):

```powershell
Get-WinEvent -Path "C:\Tools\TRR0000_logs\addendum_a1\etw_assemblyload.etl" -Oldest |
    Where-Object { $_.Id -eq 154 } |
    Format-List TimeCreated, Message
```

---

## Evidence Collection

Create a log directory for this addendum:

```powershell
New-Item -Path "C:\Tools\TRR0000_logs\addendum_a1" -ItemType Directory -Force
```

Before each scenario, clear the Sysmon log to isolate telemetry:

```powershell
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
```

After each scenario, export Sysmon 7 events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 7 } |
    Export-Csv "C:\Tools\TRR0000_logs\addendum_a1\scenario_N_sysmon7.csv" -NoTypeInformation
```

Replace `N` with the scenario number.

---

## Scenario 1 — Standard ASPX Compilation (Procedure A/B)

**Objective:** Determine whether Sysmon 7 fires when `w3wp.exe` loads the compiled `App_Web_*.dll` from Temporary ASP.NET Files after first-request ASPX compilation.

**Why this matters:** The audit claims Sysmon 7 observes this operation. Prior work on TRR0029 found that Sysmon EID 7 does not fire for CLR-managed assembly loads. This scenario resolves the contradiction for this specific case.

**Setup:**

Recycle the app pool to force recompilation on next request:

```powershell
Import-Module WebAdministration
Restart-WebAppPool -Name "DefaultAppPool"
```

Delete any previously compiled artifacts:

```powershell
Get-ChildItem "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\" -Recurse -Filter "*.dll" | Remove-Item -Force
```

**Execution:**

Clear Sysmon, then request the Procedure A test shell:

```powershell
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_a/shell.aspx?cmd=whoami" -UseBasicParsing
```

**Capture:**

Wait 5 seconds for telemetry to flush, then export:

```powershell
Start-Sleep -Seconds 5
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 7 } |
    Export-Csv "C:\Tools\TRR0000_logs\addendum_a1\scenario_1_sysmon7.csv" -NoTypeInformation
```

**What to look for:**

- Any Sysmon 7 event where `Image` is `w3wp.exe` and `ImageLoaded` points to a DLL in `Temporary ASP.NET Files\`
- If present: Sysmon 7 observes compiled ASPX assembly loads — the audit finding is correct
- If absent: Sysmon 7 does not fire for CLR-managed loads in this context — consistent with TRR0029 findings

Also check for Sysmon 7 events for `csc.exe` itself (the compiler process spawn) — these are expected and already covered by Sysmon 1.

---

## Scenario 2 — Non-Standard Extension Compilation (Procedure C Custom Handler)

**Objective:** Determine whether Sysmon 7 behavior differs when ASP.NET compiles a non-standard extension (`.txt`, `.info`) through handler remapping.

**Why this matters:** If Sysmon 7 fires here but not in Scenario 1, the compilation path for remapped extensions may differ. If behavior is identical to Scenario 1, this confirms the same telemetry gap (or coverage) applies.

**Setup:**

Recycle the app pool and clear compiled artifacts for the Proc C test directories:

```powershell
Restart-WebAppPool -Name "DefaultAppPool"
Get-ChildItem "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\" -Recurse -Filter "*.dll" | Remove-Item -Force
```

**Execution:**

Clear Sysmon, then request the Proc C1 test shell (`.txt` mapped to ASP.NET):

```powershell
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_c1/readme.txt?cmd=whoami" -UseBasicParsing
```

**Capture:**

```powershell
Start-Sleep -Seconds 5
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 7 } |
    Export-Csv "C:\Tools\TRR0000_logs\addendum_a1\scenario_2_sysmon7.csv" -NoTypeInformation
```

**What to look for:**

- Same criteria as Scenario 1: Sysmon 7 with `w3wp.exe` loading a DLL from Temporary ASP.NET Files
- Compare results with Scenario 1 — behavior should be identical since the compilation mechanism is the same (`PageBuildProvider` → `csc.exe` → DLL load)

---

## Scenario 3 — Pre-Compiled IHttpHandler DLL in bin/

**Objective:** Determine whether Sysmon 7 fires when `w3wp.exe` loads a pre-compiled `IHttpHandler` DLL from an application's `bin/` directory — no ASP.NET compilation step involved.

**Why this matters:** This is the Notable 1 variant identified by the audit. A pre-compiled DLL in `bin/` is loaded directly by the CLR without `csc.exe` involvement. If Sysmon 7 fires here, it's the only telemetry source for this variant (no compilation artifacts, no `csc.exe` spawn). If it doesn't fire, this variant has a significant observability gap.

**Setup:**

Create a test directory and convert it to an IIS Application:

```powershell
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_c3" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_c3\bin" -ItemType Directory -Force

Import-Module WebAdministration
New-WebApplication -Name "test_shells/proc_c3" -Site "Default Web Site" -PhysicalPath "C:\inetpub\wwwroot\test_shells\proc_c3" -ApplicationPool "DefaultAppPool"
```

Create the `IHttpHandler` source file and compile it:

```powershell
@'
using System;
using System.Web;

public class ShellHandler : IHttpHandler
{
    public bool IsReusable { get { return true; } }

    public void ProcessRequest(HttpContext context)
    {
        context.Response.ContentType = "text/plain";
        context.Response.Write("Pre-compiled IHttpHandler active\n");
        context.Response.Write("Server: " + Environment.MachineName + "\n");
        context.Response.Write("Time: " + DateTime.Now.ToString() + "\n");
        context.Response.Write("User: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name + "\n");
    }
}
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c3\ShellHandler.cs" -Encoding UTF8
```

Compile to a DLL in the `bin/` directory:

```powershell
& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:library /reference:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Web.dll" /out:"C:\inetpub\wwwroot\test_shells\proc_c3\bin\ShellHandler.dll" "C:\inetpub\wwwroot\test_shells\proc_c3\ShellHandler.cs"
```

Expected output: `Microsoft (R) Visual C# Compiler...` with no errors.

Create the `web.config` that registers the handler:

```powershell
@'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="ShellHandler" path="*.shell" verb="*"
                 type="ShellHandler"
                 resourceType="Unspecified"
                 preCondition="integratedMode,runtimeVersionv4.0" />
        </handlers>
    </system.webServer>
</configuration>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c3\web.config" -Encoding UTF8
```

**Execution:**

Recycle the app pool, clear Sysmon, then request the handler:

```powershell
Restart-WebAppPool -Name "DefaultAppPool"
Start-Sleep -Seconds 3
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_c3/anything.shell" -UseBasicParsing
```

**Capture:**

```powershell
Start-Sleep -Seconds 5
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 7 } |
    Export-Csv "C:\Tools\TRR0000_logs\addendum_a1\scenario_3_sysmon7.csv" -NoTypeInformation
```

**What to look for:**

- Sysmon 7 event where `Image` is `w3wp.exe` and `ImageLoaded` points to `ShellHandler.dll` in the `bin/` directory
- If present: Sysmon 7 is the key telemetry source for this variant — add to DDM
- If absent: this variant has no standard telemetry beyond the prerequisite file operations (Write Config + Create New File) and IIS W3C logs
- Also note whether Temporary ASP.NET Files contains any artifacts — if it does, the "skips all compilation telemetry" claim from the audit needs qualification

---

## Results Template

Record findings here after execution.

| Scenario | Sysmon 7 Fired? | ImageLoaded Path | ETW EID 154 Fired? | Notes |
|----------|-----------------|------------------|---------------------|-------|
| 1 — Standard ASPX | | | | |
| 2 — Non-standard ext | | | | |
| 3 — Pre-compiled DLL | | | | |

---

## Decision Matrix

Use this matrix to determine next steps based on results:

| Scenario 1 | Scenario 2 | Scenario 3 | Action |
|------------|------------|------------|--------|
| No | No | No | Sysmon 7 does not observe any assembly loads in w3wp.exe. Do not add to DDM. Audit Notable 2 rejected. Pre-compiled DLL variant (Notable 1) has no unique telemetry — document as blind spot. |
| No | No | Yes | Sysmon 7 fires only for native/pre-compiled loads, not CLR-managed compilation output. Add Sysmon 7 label to Execute Code (n6) for Proc C pre-compiled variant only. Critical detection finding — only telemetry for this variant. |
| Yes | Yes | Yes | Sysmon 7 fires for all assembly loads into w3wp.exe. Add to Compile ASPX (n7) for Scenarios 1/2 and Execute Code (n6) for Scenario 3. Audit Notable 2 confirmed. |
| Yes | Yes | No | Unexpected. Investigate whether bin/ DLL loading uses a different CLR path. |

---

## Cleanup

After completing all scenarios:

```powershell
# Remove Scenario 3 test artifacts
Remove-WebApplication -Name "test_shells/proc_c3" -Site "Default Web Site"
Remove-Item -Path "C:\inetpub\wwwroot\test_shells\proc_c3" -Recurse -Force

# Stop ETW trace if running
logman stop DotNetAssemblyTrace 2>$null
logman delete DotNetAssemblyTrace 2>$null

# Restore original Sysmon config (remove ImageLoad rule if not needed)
sysmon -c <path-to-original-config.xml>
```
