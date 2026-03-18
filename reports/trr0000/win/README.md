# File-Based Web Shell Execution via IIS

## Metadata

| Key          | Value                                          |
|--------------|------------------------------------------------|
| ID           | TRR0000                                        |
| External IDs | [T1505.003]                                    |
| Tactics      | Persistence                                    |
| Platforms    | Windows                                        |
| Contributors | John McGuinness                                |

### Scope Statement

This TRR covers file-based web shells executed through IIS handler mappings on
Windows. ASP.NET Core is excluded because IIS acts as a reverse proxy to Kestrel
rather than executing code through its own handler pipeline. PHP via FastCGI is
similarly excluded as requests are handed off to `php-cgi.exe` outside the IIS
execution model.

## Technique Overview

A web shell is a malicious script placed on a web server that gives an attacker
remote command execution through the server's HTTP request-handling mechanisms.
File-based web shells persist as script files on disk and execute through the
server's handler mappings. They are attractive to adversaries because they
survive reboots, blend with normal web traffic on ports 80/443, and require no
additional dependencies.

## Technical Background

### IIS Architecture

Internet Information Services (IIS) is Microsoft's web server, available as an
installable server role in Windows Server. Every web shell on IIS must pass
through the same request processing pipeline regardless of the shell's
implementation.

#### `HTTP.sys`

All HTTP/HTTPS traffic destined for IIS passes through `HTTP.sys`, a kernel-mode
driver that listens on configured ports (typically 80 and 443). `HTTP.sys`
handles connection management, caching, and request routing. When a request
requires application code, `HTTP.sys` routes it to the appropriate application
pool based on site bindings. The Windows Process Activation Service (`WAS`)
mediates between `HTTP.sys` and the worker process, managing application pool
lifecycle and process activation. `HTTP.sys` and `WAS` operate at the kernel and
system service level respectively, below the reach of most telemetry sources.

#### Application Pools

An application pool is an isolation boundary within IIS. Each pool runs as its
own instance of the worker process `w3wp.exe`, with its own security identity
and resource limits. The pool's configured identity determines the security
context under which all code executes - including web shell code.

By default, pools run under low-privilege virtual accounts (e.g., `IIS
AppPool\DefaultAppPool`). Administrators are able to configure pools to use
higher-privilege accounts such as `NetworkService`, domain service accounts, or
`LocalSystem`. The web shell inherits whatever permissions the pool identity
has.

#### The IIS Worker Process (`w3wp.exe`)

The worker process `w3wp.exe` is the most important component for understanding
web shell execution. It loads and executes requested files using the appropriate
scripting engine, runs under the application pool's identity, and can spawn
child processes.

When a web shell executes OS commands by starting external programs (such as
`cmd.exe` or `powershell.exe`), those programs appear as child processes of
`w3wp.exe`.

Web shells that operate exclusively through .NET framework APIs (e.g.,
`System.IO.File`, `System.Net.WebClient`, `System.Data.SqlClient`) execute
entirely within `w3wp.exe` without spawning a child process. This distinction is
the basis for two of the procedures in this TRR.

### Handler Mappings

IIS uses handler mappings to determine how to process a requested file. When a
request arrives, IIS examines the file extension to determine whether the file
should be served as static content or processed by a scripting engine.

The extensions mapped to executable handlers depend on which role services are
installed. The ASP.NET role service maps `.aspx` to the ASP.NET engine, `.ashx`
to the generic handler, and `.asmx` to the web service handler. The Classic ASP
role service - installed separately - maps `.asp` to `asp.dll`. Neither role
service is present on a default IIS installation; each must be explicitly
enabled under Application Development Features in the IIS role configuration.

IIS also supports Server-Side Includes (SSI) via `ssinc.dll`. If enabled, files
with extensions `.shtml`, `.stm`, and `.shtm` can execute directives such as
`<!--#exec cmd="command">`. The `#exec cmd=` directive spawns a child process
and follows the same essential operations as [Procedure A]. Other SSI directives
(`#include`, `#echo`) are handled internally by `ssinc.dll` without passing
through a scripting engine. Although these operate in-process, they do not map
to [Procedure B] because `ssinc.dll` performs predefined operations with
attacker-controlled parameters - it does not interpret or execute
attacker-authored code. [Procedure B] requires arbitrary code execution through
a scripting engine within `w3wp.exe`.

For a web shell to execute, its file extension must match a handler mapping that
routes the request to an executable handler rather than serving it as static
content. The requirement that a request match a handler mapping is an essential
operation in the pipeline - it cannot be skipped. However, the mappings
themselves are configurable. When an attacker modifies handler mappings through
`web.config` to route additional extensions through executable handlers, the
essential operations change - this is covered in [Procedure C].

### ASP vs. ASP.NET Execution

Classic ASP files (`.asp`) are interpreted directly by `asp.dll` inside
`w3wp.exe`. No additional artifacts are produced on disk.

ASP.NET files (`.aspx`) undergo a compilation step. On first request, the
ASP.NET engine compiles the source into a .NET assembly (DLL) stored in
`C:\Windows\Microsoft.NET\Framework64\<version>\Temporary ASP.NET Files\`. On
.NET Framework 4.8, this compilation spawns `csc.exe` as a child process of
`w3wp.exe`.

The compilation produces several artifacts in `Temporary ASP.NET Files`: a
`.compiled` metadata file, the compiled assembly (`.dll`), intermediate C#
source files (`.cs`), and compiler I/O files. The `.compiled` file's name
preserves the original source extension - e.g., `shell.aspx.cdcab7d2.compiled`
or `readme.txt.cdcab7d2.compiled` if a `.txt` file has been configured for
ASP.NET execution via handler manipulation (see [Procedure C]).

### The Web Root and Virtual Directories

Every IIS site maps to a physical directory (default: `C:\inetpub\wwwroot\`).
Virtual directories can extend the web-accessible area to other paths. For a web
shell to be reachable via HTTP, the shell file must reside within a
web-accessible path.

### `web.config` and Handler Manipulation

IIS configuration can be modified at the directory level through `web.config`
files. A `web.config` placed in any web-accessible directory overrides IIS
settings for that directory and its subdirectories.

An attacker who can write a `web.config` can manipulate handler mappings in two
ways. First, they can add a custom handler mapping that routes a normally static
extension (`.jpg`, `.txt`, `.png`) through the ASP.NET engine, then place a web
shell with that extension. Second, they can define an inline `IHttpHandler`
within the `web.config` itself - no separate script file needed.

IIS application pools operate in one of two managed pipeline modes: Integrated
or Classic. Integrated mode is the default since IIS 7 and merges the ASP.NET
and IIS request pipelines into a single unified pipeline. Classic mode preserves
the IIS 6 behavior where ASP.NET runs as a separate ISAPI extension. The
pipeline mode determines which configuration section governs handler mappings:
Integrated mode reads from `system.webServer/handlers`, while Classic mode reads
from `system.web/httpHandlers` and ignores `system.webServer/handlers`. In
Integrated mode, entries in `system.web/httpHandlers` are not processed and
generate a migration error unless `validateIntegratedModeConfiguration` is set
to `false` in the application's `web.config`.

The custom handler mapping variant requires two configuration elements: a
`<handlers>` entry routing the extension to `PageHandlerFactory`, and a
`<buildProviders>` entry registering `PageBuildProvider` for the extension.
Without both, ASP.NET fails with a compilation error.

In Integrated mode, the attacker must target `system.webServer/handlers`, which
is locked by default (`overrideModeDefault="Deny"` in `applicationHost.config`).
Subdirectory `web.config` files cannot add handler entries to this section
unless an administrator has unlocked it or the attacker has sufficient access to
modify `applicationHost.config` directly. In Classic mode, the attacker targets
`system.web/httpHandlers`, which is not locked by default - but the application
pool must be running in Classic mode rather than the default Integrated mode.

The `<buildProviders>` element can only be defined at the IIS Application level
- ASP.NET returns a configuration error if it appears below the application
root. This means the custom handler variant requires either that the target
directory is already an IIS Application, the attacker can modify the site root's
`web.config`, or the attacker can modify `machine.config` (requires `SYSTEM`
access).

When a `web.config` is placed in a subdirectory, IIS dynamically reloads that
directory's configuration without a server restart.

A third handler manipulation path exists: deploying a pre-compiled
`IHttpHandler` DLL to the application's `bin/` directory with a matching
`web.config` handler registration. Because the assembly is already compiled,
ASP.NET does not invoke `csc.exe` and does not produce the `App_Web_*.dll` or
`.compiled` artifacts in `Temporary ASP.NET Files` that characterize the other
variants. However, the CLR shadow-copies the DLL from `bin/` into `Temporary
ASP.NET Files\<app>\<hash>\assembly\dl3\` at load time, which is a file creation
event. This variant requires both a `web.config` handler entry and write access
to the `bin/` directory.

### IIS Application Initialization

IIS Application Initialization can be configured through `web.config` to send
internal warmup requests to specified pages on app pool start, recycle, or
reboot. If an attacker designates a web shell as a preload page, IIS will
automatically trigger it on every lifecycle event - transforming the shell from
a passive backdoor into one that auto-executes without an attacker-initiated
request.

## Procedures

| ID | Title | Tactic |
|----|-------|--------|
| TRR0000.WIN.A | Web Shell with OS Command Execution | Persistence |
| TRR0000.WIN.B | Web Shell with In-Process Execution | Persistence |
| TRR0000.WIN.C | Web Shell via `web.config` Manipulation | Persistence |

### Procedure A: Web Shell with OS Command Execution

This procedure covers all execution paths where a request processed by
`w3wp.exe` results in a child process being spawned. The Process Spawn operation
is the defining characteristic that distinguishes this procedure from [Procedure
B]. The delivery method for placing the malicious file on disk is tangential;
the essential prerequisite is that the file exists in a web-accessible path.

Three variants share this defining operation but differ in their handler path,
prerequisites, and upstream artifacts.

In the ASP.NET variant, a malicious `.aspx`, `.ashx`, or `.asmx` file is
processed by the ASP.NET engine, which requires the ASP.NET role service. On
first request under .NET Framework 4.8, the engine compiles the source into an
assembly, spawning `csc.exe` as a child process of `w3wp.exe`. This compilation
produces artifacts in `Temporary ASP.NET Files` - a `.compiled` metadata file,
the compiled assembly (`.dll`), intermediate C# source files (`.cs`), and
compiler I/O files. After compilation, the web shell's code executes and spawns
a command interpreter such as `cmd.exe` or `powershell.exe` with
attacker-supplied arguments.

In the Classic ASP variant, a malicious `.asp` file is interpreted by `asp.dll`
inside `w3wp.exe`. The Classic ASP role service is not installed by default and
is separate from the ASP.NET role service. No compilation step occurs and no
artifacts are produced on disk from interpretation. The web shell spawns a child
process through the same mechanism as the ASP.NET variant.

In the SSI variant, a file with a `.shtml`, `.stm`, or `.shtm` extension
containing an `#exec cmd=` directive is parsed by `ssinc.dll`. The Server Side
Includes role service must be installed. No scripting engine is involved -
`ssinc.dll` processes the directive directly and spawns a child process to
execute the command string. Attacker control is limited to the command string
within the directive.

All three variants converge at the same essential operation: the child process
spawned by `w3wp.exe` executes the command and output is returned in the HTTP
response.

#### Detection Data Model

![DDM - Web Shell with OS Command Execution](ddms/trr0000_win_a.png)

File prerequisites feed into the shared pipeline (Route Request, Match Handler,
Execute Code). Execute Code represents the handler processing the request within
`w3wp.exe` - through a scripting engine for the ASP.NET and Classic ASP
variants, and through `ssinc.dll` directive processing for the SSI variant. The
distinguishing operation is Process Spawn from `w3wp.exe`, shared across all
three variants. Compile ASPX is a sub-operation of Execute Code, relevant only
to the ASP.NET variant.

### Procedure B: Web Shell with In-Process Execution

This procedure shares the same prerequisites and pipeline as [Procedure A]
through Execute Code. The difference is that the web shell never spawns a child
process - all operations occur within the `w3wp.exe` process. Examples include
.NET framework APIs such as `System.IO.File.ReadAllText()` or
`System.Net.WebClient`, and COM objects used for in-process operations such as
`ADODB.Connection` or `Scripting.FileSystemObject`.

The invocation method does not determine the procedure. COM objects that spawn
child processes - such as `WScript.Shell.Run()` or `WScript.Shell.Exec()` - fall
under [Procedure A] regardless of how they are called, because Process Spawn is
the defining essential operation. The specific APIs or COM objects used are
attacker-controlled and tangential. The side effects of those calls may produce
telemetry depending on the action taken.

SSI directives such as `#include` and `#echo` also operate without spawning a
child process, but they do not map to this procedure. These directives perform
predefined I/O operations within `ssinc.dll` - they do not execute
attacker-authored code and do not reach the Process Spawn or Call .NET API
operations in the pipeline.

#### Detection Data Model

![DDM - Web Shell with In-Process Execution](ddms/trr0000_win_b.png)

Identical to [Procedure A] through Execute Code. Diverges at the final step:
Call .NET API instead of Process Spawn. The Call .NET API operation has no
direct telemetry - only its side effects may be observable.

### Procedure C: Web Shell via `web.config` Manipulation

This procedure introduces Write Config as an essential operation not present in
[Procedure A] or [Procedure B]. Write Config changes the essential operation
chain in two ways: it enables non-standard file extensions to be routed through
an executable handler, and in the inline `IHttpHandler` variant, it eliminates
the separate script file prerequisite entirely.

Three variants exist. In the custom handler mapping variant, the attacker writes
a `web.config` with both a handler mapping and build provider registration, then
places a shell with a normally static extension. The build provider must be
defined at the IIS Application level. In the inline handler variant, the
attacker defines an `IHttpHandler` directly in the `web.config` - no separate
file needed. In the pre-compiled DLL variant, the attacker places a compiled
`IHttpHandler` assembly in the application's `bin/` directory with a matching
`web.config` handler registration; this bypasses `csc.exe` and standard
compilation artifacts, though the CLR shadow copy into `Temporary ASP.NET
Files\assembly\dl3\` still produces a file creation event.

The write location prerequisite differs across variants. The custom handler
mapping variant requires `web.config` at the IIS Application root because the
`<buildProviders>` element can only be defined at the Application level - a
subdirectory `web.config` is insufficient. The inline handler variant can
operate from a subdirectory `web.config`, subject to the handler section locking
constraints and pipeline mode behavior documented in [Technical Background]. The
pre-compiled DLL variant requires both a `web.config` with handler registration
- which can be at subdirectory level, subject to the same locking and pipeline
mode constraints - and write access to the application's `bin/` directory. The
downstream pipeline operates the same as [Procedure A] and [Procedure B];
post-execution behavior depends on the shell's code.

Application Initialization can further enhance persistence by configuring IIS to
auto-trigger the shell on app pool lifecycle events (see [Technical
Background]).

When ASP.NET compiles a non-standard extension (custom handler variant), the
`.compiled` metadata file preserves the original extension in its filename
(e.g., `readme.txt.cdcab7d2.compiled`).

#### Detection Data Model

![DDM - Web Shell via web.config Manipulation](ddms/trr0000_win_c.png)

Write Config feeds into Match Handler, reflecting its modification of handler
matching. In the inline variant, Write Config is the sole prerequisite. In the
custom handler mapping and pre-compiled DLL variants, it is accompanied by a
file operation. The downstream pipeline and post-execution branches remain the
same as [Procedure A] and [Procedure B].

## Available Emulation Tests

| ID             | Link                |
|----------------|---------------------|
| TRR0000.WIN.A  | [Atomic Test T1505.003-1], [Atomic Test T1505.003-2] |
| TRR0000.WIN.B  |                     |
| TRR0000.WIN.C  |                     |

## References

- [IIS Architecture Overview - Microsoft Learn]
- [Handler Mappings in IIS - Microsoft Learn]
- [Application Pools in IIS - Microsoft Learn]
- [ASP.NET Compilation Overview - Microsoft Learn]
- [ASP.NET Dynamic Compilation - Microsoft Learn]
- [Virtual Directories in IIS - Microsoft Learn]
- [web.config Reference - Microsoft Learn]
- [IIS Application Initialization - Microsoft Learn]
- [Server-Side Includes in IIS - Microsoft Learn]
- [IHttpHandler Interface - Microsoft Learn]
- [IIS Integrated Pipeline - Microsoft Learn]
- [IIS Validation Configuration - Microsoft Learn]
- [Detect and Prevent Web Shell Malware - NSA/CISA]
- [Web Shell Attacks Continue to Rise - Microsoft Security Blog]
- [Ghost in the Shell - Microsoft Security Blog]
- [Web Shell Detection - Elastic Security]
- [Mo' Shells Mo' Problems: Deep Panda Web Shells - CrowdStrike]
- [T1505.003 - MITRE ATT&CK]

[Technical Background]: #technical-background
[Procedure A]: #procedure-a-web-shell-with-os-command-execution
[Procedure B]: #procedure-b-web-shell-with-in-process-execution
[Procedure C]: #procedure-c-web-shell-via-webconfig-manipulation
[T1505.003]: https://attack.mitre.org/techniques/T1505/003/
[IIS Architecture Overview - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis/introduction-to-iis-architecture
[Handler Mappings in IIS - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/configuration/system.webserver/handlers/
[Application Pools in IIS - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/
[ASP.NET Compilation Overview - Microsoft Learn]:
    https://learn.microsoft.com/en-us/previous-versions/aspnet/ms178466(v=vs.100)
[ASP.NET Dynamic Compilation - Microsoft Learn]:
    https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723(v=vs.100)
[Virtual Directories in IIS - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/application/virtualdirectory
[web.config Reference - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/configuration/
[IIS Application Initialization - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/configuration/system.webserver/applicationinitialization/
[Server-Side Includes in IIS - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/configuration/system.webserver/serversideinclude
[IHttpHandler Interface - Microsoft Learn]:
    https://learn.microsoft.com/en-us/dotnet/api/system.web.ihttphandler
[IIS Integrated Pipeline - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/application-frameworks/building-and-running-aspnet-applications/how-to-take-advantage-of-the-iis-integrated-pipeline
[IIS Validation Configuration - Microsoft Learn]:
    https://learn.microsoft.com/en-us/iis/configuration/system.webserver/validation
[Detect and Prevent Web Shell Malware - NSA/CISA]:
    https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF
[Web Shell Attacks Continue to Rise - Microsoft Security Blog]:
    https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/
[Ghost in the Shell - Microsoft Security Blog]:
    https://www.microsoft.com/en-us/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/
[Web Shell Detection - Elastic Security]:
    https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/persistence_webshell_detection
[Mo' Shells Mo' Problems: Deep Panda Web Shells - CrowdStrike]:
    https://www.crowdstrike.com/en-us/blog/mo-shells-mo-problems-deep-panda-web-shells/
[T1505.003 - MITRE ATT&CK]: https://attack.mitre.org/techniques/T1505/003/
[Atomic Test T1505.003-1]:
    https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md#atomic-test-1---deploy-asp-webshell
[Atomic Test T1505.003-2]:
    https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md#atomic-test-2---deploy-aspx-webshell
