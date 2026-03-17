# Research: T1505.003 Web Shell — Windows/IIS Technical Deep Dive

## Technique Summary

Web shells are server-side scripts placed on web servers to provide persistent remote access and command execution. On Windows/IIS, web shells exploit the IIS request processing pipeline to execute attacker-controlled code within the w3wp.exe worker process context. The technique encompasses multiple execution models (Classic ASP, ASP.NET WebForms, generic handlers, web.config abuse) that share the common requirement of placing executable content in the IIS content path and triggering it via HTTP request.

## Technical Background

### 1. IIS Request Pipeline Architecture

The IIS request processing chain from HTTP request to code execution follows a specific, well-documented path:

**HTTP.sys (Kernel-Mode Driver)**
- HTTP.sys is a kernel-mode device driver that listens for HTTP/HTTPS requests on configured ports (typically 80/443). It replaced the user-mode Winsock approach from pre-IIS 6.0.
- HTTP.sys provides kernel-mode caching, kernel-mode request queuing, request pre-processing, and security filtering.
- When a request arrives, HTTP.sys intercepts it and contacts WAS (Windows Process Activation Service) to obtain configuration from applicationHost.config.
- HTTP.sys routes requests to the appropriate application pool's kernel-mode request queue based on URL prefix registrations.
- Source: https://learn.microsoft.com/iis/get-started/introduction-to-iis/introduction-to-iis-architecture

**Windows Process Activation Service (WAS)**
- WAS manages application pool configuration and worker process lifecycle (start, stop, recycle).
- On startup, WAS reads applicationHost.config and passes configuration to listener adapters.
- When a request enters a queue for an application pool with no running worker process, WAS starts a new w3wp.exe process.
- WAS replaced the process management role previously held by WWW Service (W3SVC) in IIS 6.0.

**WWW Publishing Service (W3SVC)**
- In IIS 7+, W3SVC acts as the listener adapter for HTTP.sys (not the process manager).
- Responsible for configuring HTTP.sys with URL registrations, notifying WAS when requests arrive, and collecting performance counters.
- Runs as LocalSystem in the same Svchost.exe process as WAS.

**w3wp.exe (Worker Process)**
- The IIS worker process that actually processes HTTP requests.
- Each application pool has one or more w3wp.exe instances (configurable via web garden settings).
- Worker processes run under the application pool identity (default: ApplicationPoolIdentity, a virtual account per-pool).
- Inside w3wp.exe, the Web Server Core processes requests through an ordered pipeline of events, with native and managed modules responding at each stage.
- Source: https://learn.microsoft.com/iis/get-started/introduction-to-iis/introduction-to-iis-architecture

**Integrated vs. Classic Pipeline Mode**
- **Integrated Mode** (default since IIS 7): Native IIS and ASP.NET pipelines are unified. All file types can use managed modules (e.g., Forms authentication on static files). Managed handlers are invoked directly by the IIS pipeline via the ManagedEngine module (webengine.dll).
- **Classic Mode**: ASP.NET requests are routed to aspnet_isapi.dll as an ISAPI extension, then processed in a separate ASP.NET pipeline. Only requests mapped to aspnet_isapi.dll via handler mappings are processed by ASP.NET.
- Mode is set per-application-pool, allowing both modes to coexist on the same server.
- Source: https://learn.microsoft.com/iis/get-started/introduction-to-iis/introduction-to-iis-architecture

### 2. Handler Mapping Resolution

Handler mappings determine how IIS decides what processes a file. This is the mechanism that makes web shells executable.

**Resolution Order**
1. IIS processes the `<handlers>` list top-to-bottom (first match wins).
2. Handlers defined in applicationHost.config form the base list.
3. web.config entries are appended after inherited entries (unless `<clear/>` is used, which removes all inherited mappings).
4. For each handler, IIS checks the **path** (file extension/wildcard), **verb** (GET/POST/*), and **preconditions** (classicMode/integratedMode, runtimeVersion, bitness).
5. Handlers whose preconditions do not match the current app pool are skipped.
6. The StaticFile handler at the bottom catches everything not matched above.

**Default Handler Mappings for Web Shell-Relevant Extensions**
- `.aspx` -> `System.Web.UI.PageHandlerFactory` (Integrated) or `aspnet_isapi.dll` via `IsapiModule` (Classic)
- `.asp` -> `asp.dll` via `IsapiModule` (processes VBScript/JScript)
- `.ashx` -> `System.Web.UI.SimpleHandlerFactory` (generic handlers)
- `.asmx` -> `System.Web.Services.Protocols.WebServiceHandlerFactory`
- `.shtml`/`.stm`/`.shtm` -> `ServerSideIncludeModule` (Iis_ssi.dll)

**Key Point**: Any file with an extension that has a registered handler mapping will be executed by IIS when requested. An attacker placing a file with a mapped extension (e.g., .aspx, .asp, .ashx) in an IIS content path has the file processed automatically on the next HTTP request -- no additional configuration needed.

**Handler Configuration Locations**
- Global: `%SystemRoot%\System32\inetsrv\config\applicationHost.config` (under `<system.webServer><handlers>`)
- Per-site/application: `web.config` (under `<system.webServer><handlers>`)
- Legacy ASP.NET: `web.config` (under `<system.web><httpHandlers>`) -- only for Classic mode

Source: https://learn.microsoft.com/iis/configuration/system.webserver/handlers/

### 3. Execution Models: Classic ASP vs. ASP.NET

#### Classic ASP (asp.dll)
- **Execution model**: Interpreted. VBScript/JScript code is parsed and interpreted by the ASP scripting engine at runtime. ASP does NOT compile to .NET assemblies or disk-backed DLLs.
- **Script caching**: ASP employs a multi-level cache: Template Cache (in-memory compiled templates) and Script Engine Cache (pre-parsed bytecode). This avoids re-parsing on every request but is NOT disk-backed compilation.
- **Disk cache**: The `diskTemplateCacheDirectory` setting (default: `%windir%\system32\inetsrv\ASP Compiled Templates`) stores overflow templates, but these are internal to asp.dll and are not standard .NET assemblies.
- **Process model**: asp.dll is an ISAPI extension loaded by IsapiModule into w3wp.exe. All ASP execution occurs in-process within w3wp.exe.
- **Command execution**: Classic ASP web shells use `Server.CreateObject("WScript.Shell")` followed by `.Run` or `.Exec` methods, or `Server.CreateObject("Scripting.FileSystemObject")` for file operations. The `CreateObject` call instantiates a COM object within the w3wp.exe process context. When `.Run` or `.Exec` is called with a command, it spawns cmd.exe (or the specified executable) as a child process of w3wp.exe.
- **No compilation artifacts**: Classic ASP produces NO .NET compilation artifacts (no csc.exe invocation, no Temporary ASP.NET Files entries, no .dll/.compiled files).
- Source: https://learn.microsoft.com/windows/win32/com/using-com-objects-in-active-server-pages, https://learn.microsoft.com/iis/configuration/system.webserver/asp/cache

#### ASP.NET (.aspx, .ashx, .asmx)
- **Execution model**: Compiled. When an .aspx/.ashx/.asmx file is first requested, ASP.NET dynamically compiles the source into a .NET assembly (DLL).
- **Compilation process**: w3wp.exe invokes csc.exe (C# compiler) or vbc.exe (VB.NET compiler) as a child process to compile the web page code. The compiler reads a `.cmdline` file containing compilation parameters.
- **Compiler locations**:
  - .NET 4.x (legacy CodeDom): `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe` (64-bit) or `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe` (32-bit)
  - Roslyn (post-.NET 4.5, if DotNetCompilerPlatform NuGet is installed): `<app>\bin\roslyn\csc.exe`
- **Output location**: Compiled assemblies stored in `%WINDIR%\Microsoft.NET\Framework[64]\v4.0.30319\Temporary ASP.NET Files\<app>\<hash1>\<hash2>\`
  - Customizable via `<compilation tempDirectory="..." />` in web.config
- **Compilation artifacts**:
  - `.dll` files (e.g., `App_Web_z01dtudd.dll`) -- the compiled assembly
  - `.compiled` files (e.g., `cmd.aspx.cdcab7d2.compiled`) -- metadata mapping source files to assemblies
  - `.cmdline` files -- compiler invocation parameters
  - `.out` files -- compiler output log
  - `.cs` or `.vb` intermediate source files (generated from .aspx markup)
- **Subsequent requests**: After initial compilation, the cached DLL is used directly. Recompilation occurs only when the source file changes.
- Source: https://learn.microsoft.com/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/precompiling-your-website-cs, https://swolfsec.github.io/2023-10-29-Webshell-Compilation-Artifacts/

#### .ashx (Generic Handlers) vs .aspx
- Both are compiled on-demand (JIT) when first requested.
- .ashx files implement `IHttpHandler` directly (lighter weight, no page lifecycle overhead).
- .ashx files use `@WebHandler` directive instead of `@Page`.
- Both produce identical compilation artifacts in Temporary ASP.NET Files.
- From a web shell perspective, .ashx and .aspx are functionally equivalent -- both auto-compile and execute without additional configuration.
- Source: https://www.dotnetperls.com/ashx, https://learn.microsoft.com/en-us/previous-versions/aspnet/bb398986(v=vs.100)

### 4. API-Level Behavior

#### Process Spawning (Command Execution Web Shells)
The primary .NET API for spawning external processes:
- `System.Diagnostics.Process.Start()` with `ProcessStartInfo`
  - Common pattern: `FileName = "cmd.exe"`, `Arguments = "/c " + command`
  - `UseShellExecute = false`, `RedirectStandardOutput = true` to capture output
  - This results in w3wp.exe spawning cmd.exe (or powershell.exe, etc.) as a child process

#### In-Process Operations (No Child Process)
Sophisticated web shells avoid process creation entirely by using .NET framework APIs directly within w3wp.exe:
- **File operations**: `System.IO.File.ReadAllText()`, `System.IO.File.WriteAllBytes()`, `System.IO.Directory.GetFiles()`
- **Network operations**: `System.Net.WebClient.DownloadFile()`, `System.Net.Sockets.TcpClient`
- **Registry access**: `Microsoft.Win32.Registry` namespace
- **Active Directory**: `System.DirectoryServices` namespace
- **PowerShell in-process**: `System.Management.Automation.PowerShell` class (loads PowerShell SDK without spawning powershell.exe)
- **Reflection/Assembly loading**: `System.Reflection.Assembly.Load(byte[])` for loading additional assemblies without disk writes
- **Shellcode execution**: Via P/Invoke to `VirtualAlloc`/`CreateThread` Win32 APIs from within managed code

#### COM Object Invocation (Classic ASP)
- `Server.CreateObject("WScript.Shell")` -- instantiates Windows Script Host Shell object
  - `.Run(command)` -- executes command, returns exit code
  - `.Exec(command)` -- executes command, returns object with StdOut/StdErr streams
- `Server.CreateObject("Scripting.FileSystemObject")` -- file system operations
- `Server.CreateObject("ADODB.Connection")` -- database access
- COM objects run in-process within w3wp.exe (in-proc COM servers) or out-of-process (out-of-proc COM servers)
- The application pool identity (IUSR, IWAM, or AppPoolIdentity) must have DCOM launch/access permissions for the COM class

Source: https://learn.microsoft.com/windows/win32/com/using-com-objects-in-active-server-pages

### 5. web.config Manipulation Techniques

#### Handler Mapping Modification via web.config
A web.config file in an application directory can register new handler mappings:

```xml
<configuration>
  <system.webServer>
    <handlers>
      <add name="MyHandler" path="*.xyz" verb="*"
           type="MyNamespace.MyHandler, MyAssembly" />
    </handlers>
  </system.webServer>
</configuration>
```

This maps a custom extension to a managed handler class. The assembly must be in the application's `bin` directory or registered in the GAC.

#### web.config as a Web Shell (Soroush Dalili Research)
The most significant web.config abuse technique uses `buildProviders` and `httpHandlers` to make the web.config file itself executable:

**Required sections:**
1. `<system.web><compilation><buildProviders>`: Register `PageBuildProvider` for the `.config` extension
2. `<system.web><httpHandlers>`: Map `.config` extension to `PageHandlerFactory`
3. `<system.webServer><security><requestFiltering>`: Remove the `.config` file extension block and `web.config` hidden segment restriction

**Critical constraint**: `buildProviders` can ONLY be defined at the application root level (`allowDefinition='MachineToApplication'`). This means the web.config web shell technique works only when placed in the root directory of an IIS application, NOT in subdirectories (unless the subdirectory is itself configured as a separate IIS application).

**IIS hot-reload**: Yes, IIS monitors web.config for changes. When web.config is modified, the application domain is recycled and the new configuration takes effect. This means writing a malicious web.config triggers automatic reloading without requiring IIS restart.

Source: https://soroush.me/blog/2019/08/uploading-web-config-for-fun-and-profit-2/

### 6. Compilation Artifacts Deep Dive

#### ASP.NET Dynamic Compilation
When an .aspx/.ashx file is first requested:

1. w3wp.exe detects the file has changed or has no cached assembly
2. ASP.NET runtime generates intermediate C#/VB.NET source from the .aspx markup
3. w3wp.exe spawns csc.exe/vbc.exe as a child process
4. Compiler reads parameters from a `.cmdline` file in Temporary ASP.NET Files
5. Compiler produces a DLL in Temporary ASP.NET Files
6. A `.compiled` metadata file maps the source .aspx to the compiled DLL
7. A `.out` file logs compiler output

**Exact process chain for compilation**:
```
w3wp.exe -> csc.exe /noconfig /fullpaths @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\<hash1>\<hash2>\<random>.cmdline"
```

**Temporary ASP.NET Files directory structure**:
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\
  <application_name>\
    <hash1>\
      <hash2>\
        App_Web_<random>.dll          <- compiled assembly
        cmd.aspx.<hash>.compiled      <- metadata/mapping file
        <random>.cmdline              <- compiler arguments
        <random>.out                  <- compiler output
        <random>.0.cs                 <- intermediate C# source (generated from .aspx)
```

**Forensic significance**: The `.compiled` file contains a timestamp indicating when compilation occurred. The `.out` file shows the exact compilation command. The DLL can be decompiled with dnSpy/ILSpy to reveal web shell functionality.

**Classic ASP**: Produces NO compilation artifacts in Temporary ASP.NET Files. Classic ASP templates may be cached in `%windir%\system32\inetsrv\ASP Compiled Templates` but these are internal to asp.dll, not .NET assemblies.

Source: https://swolfsec.github.io/2023-10-29-Webshell-Compilation-Artifacts/, https://learn.microsoft.com/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/precompiling-your-website-cs

### 7. Server-Side Includes (SSI) via ssinc.dll

- SSI is handled by `ServerSideIncludeModule` (Iis_ssi.dll) for `.shtml`, `.stm`, `.shtm` extensions.
- The `#exec cmd` directive is **disabled by default in IIS 7+**. Attempting to use it returns: "The CMD option is not enabled for #EXEC calls."
- The `#exec cgi` directive is still available and can execute CGI executables: `<!--#exec cgi="/path/to/executable.exe"-->`
- SSI requires the Server Side Includes role service to be installed (not installed by default).
- The `ssiExecDisable` attribute in `<system.webServer><serverSideInclude>` controls whether `#exec` is allowed (default: false, meaning exec is enabled, but `#exec cmd` is specifically disabled regardless).
- **Verdict**: SSI is a limited web shell vector. `#exec cmd` is disabled by default. `#exec cgi` requires a pre-existing CGI executable on disk. SSI is rarely installed on modern IIS servers.

Source: https://learn.microsoft.com/iis/configuration/system.webserver/serversideinclude

## Essential Operations Identified

### Op 1: Write File to IIS Content Path — Write WebShellFile
- **Tag**: [EIO]
- **Essential**: Yes -- the web shell must exist as a file in the IIS-accessible content path for file-based web shells. Without the file, there is nothing for IIS to process.
- **Immutable**: Yes -- IIS handler mapping resolution requires a file (or virtual path mapping) to exist at the requested URL path. The attacker cannot avoid placing content in the IIS content directory tree. (The specific path and filename are attacker-controlled, but the requirement to write to an IIS-served directory is immutable.)
- **Observable**: Yes -- Sysmon 11 (FileCreate) captures file creation events with `TargetFilename` path. The process performing the write may vary (w3wp.exe for upload-based delivery, cmd.exe/powershell.exe for interactive placement, or any process with write access to the webroot).
- **Description**: A file with a handler-mapped extension (.aspx, .asp, .ashx, .asmx, .php, or .config) is written to a directory served by IIS. The file contains server-side code that IIS will execute upon request.
- **Notes**: The write mechanism is tangential -- it could be via file upload functionality, RDP session, SMB share access, exploit chain, or any other file delivery method. What matters is that a file with executable content arrives in an IIS content path.

### Op 2: HTTP Request to Web Shell — Request WebShellURL
- **Tag**: [EIO]
- **Essential**: Yes -- the web shell code does not execute until an HTTP request triggers IIS to process the file through its handler mapping pipeline. Without an inbound HTTP request matching the web shell's URL, no code execution occurs.
- **Immutable**: Yes -- IIS processes files via HTTP requests through HTTP.sys -> WAS -> w3wp.exe. There is no alternative trigger for file-based web shell execution on IIS.
- **Observable**: Yes -- IIS W3C logs (cs-uri-stem, cs-method, c-ip, sc-status fields). Also observable via HTTP.sys ETW provider (Microsoft-Windows-HttpService) and IIS ETW provider (Microsoft-Windows-IIS-Logging). The HTTP.sys kernel-mode driver logs requests before they reach w3wp.exe.
- **Description**: An HTTP request (typically GET or POST) arrives at the IIS server targeting the URL path of the deployed web shell file. HTTP.sys receives the request, routes it to the appropriate application pool's request queue, and w3wp.exe picks it up for processing.
- **Notes**: The specific URL path, query parameters, POST body content, and HTTP method are all attacker-controlled (tangential). The fact that an HTTP request must reach IIS targeting the web shell path is immutable.

### Op 3: IIS Handler Mapping Resolution — Resolve HandlerMapping
- **Tag**: [EIO]
- **Essential**: Yes -- IIS must resolve the requested URL to a handler that can process the file. Without a matching handler mapping, IIS returns a 404.3 error or serves the file as static content (no execution).
- **Immutable**: Yes -- handler mapping resolution is a fixed part of the IIS pipeline architecture. The server MUST match the request to a handler before any code execution occurs. Default handler mappings for .aspx, .asp, .ashx are present in a standard IIS installation.
- **Observable**: Yes -- IIS Failed Request Tracing (FREB) logs the handler resolution process. The handler name appears in IIS W3C extended logs if the `s-handler` field is enabled. IIS ETW tracing also captures handler selection.
- **Description**: The IIS pipeline evaluates the ordered `<handlers>` list (top to bottom, first match wins) against the request URL path and verb. Preconditions (integratedMode/classicMode, runtime version, bitness) are checked. The first matching handler processes the request.
- **Notes**: For default extensions (.aspx, .asp, .ashx), handler mappings exist in the default applicationHost.config. For non-standard extensions, the attacker must either use a default-mapped extension or modify web.config to add a handler mapping.

### Op 4: Code Execution Within w3wp.exe — Execute WebShellCode
- **Tag**: [EIO]
- **Essential**: Yes -- this IS the technique. The web shell code executes within the w3wp.exe process context. Without code execution, the web shell provides no capability.
- **Immutable**: Yes -- once a handler processes a request for a server-side script, the code within that script executes inside the w3wp.exe worker process. This is the fundamental behavior of server-side scripting on IIS.
- **Observable**: Partially. In-process code execution within w3wp.exe has limited direct telemetry:
  - ETW: Microsoft-Windows-DotNETRuntime (AssemblyLoad events for .NET) -- fires for assembly loads
  - Sysmon 7 (ImageLoad) -- fires for disk-backed assembly loads into w3wp.exe
  - No direct telemetry for Classic ASP script interpretation (no assembly load)
  - Process-level: w3wp.exe CPU/memory changes are indirect indicators only
- **Description**: The handler (asp.dll for Classic ASP, ASP.NET pipeline for .aspx/.ashx) parses and executes the server-side code. For ASP.NET, this involves loading the compiled assembly and invoking the handler's ProcessRequest method. For Classic ASP, the VBScript/JScript engine interprets the script.
- **Notes**: The code executed is entirely attacker-controlled (tangential). The fact that code executes within w3wp.exe is immutable.

### Op 5: ASP.NET Dynamic Compilation — Compile WebShellAssembly
- **Tag**: [EIO] (conditional -- ASP.NET path only)
- **Essential**: Yes, for ASP.NET web shells that have not been pre-compiled. The ASP.NET runtime MUST compile .aspx/.ashx source into a .NET assembly before execution. Cannot be skipped.
- **Immutable**: Yes -- ASP.NET's dynamic compilation is a fixed requirement of the runtime. The source code must be compiled to IL before the CLR can execute it. The compiler (csc.exe/vbc.exe) must be invoked.
- **Observable**: Yes -- multiple telemetry sources:
  - Sysmon 1 (ProcessCreate): w3wp.exe spawns csc.exe or vbc.exe
  - Windows Security 4688 (Process Creation): same process chain with command line if auditing enabled
  - Sysmon 11 (FileCreate): .dll, .compiled, .cmdline, .out files created in Temporary ASP.NET Files
  - ETW: Microsoft-Windows-DotNETRuntime AssemblyLoad_V1 (EID 154) when the compiled assembly is loaded
- **Description**: On first request (or after source modification), ASP.NET invokes csc.exe (C#) or vbc.exe (VB.NET) to compile the web shell source into a DLL assembly. The compiler reads a .cmdline parameter file and writes output to Temporary ASP.NET Files. The resulting DLL is then loaded into w3wp.exe.
- **Notes**: Pre-compiled web shells (deployed as DLLs in the bin directory) skip this step entirely. Classic ASP web shells also skip this -- asp.dll interprets VBScript/JScript directly without .NET compilation. This operation is essential only for the ASP.NET dynamic compilation path.

### Op 6: Process Spawning for Command Execution — Spawn ChildProcess
- **Tag**: [TANGENTIAL] / [OPTIONAL] -- depends on web shell type
- The decision to spawn cmd.exe/powershell.exe or perform operations in-process is entirely attacker-controlled. Sophisticated web shells perform all operations within w3wp.exe using .NET framework APIs, never spawning a child process. Simple web shells use System.Diagnostics.Process.Start() or WScript.Shell.Exec() to run OS commands. This operation fails the immutability test (attacker chooses whether to spawn processes) and the essentiality test (web shells can accomplish their objectives without spawning child processes).

### Op 7: Web Shell File Extension — Use MappedExtension
- **Tag**: [TANGENTIAL]
- The specific file extension (.aspx, .asp, .ashx, .asmx, .php, etc.) is attacker-controlled. What is immutable is that the extension must have a handler mapping in IIS. The available mapped extensions depend on what role services are installed (ASP.NET, Classic ASP, PHP via FastCGI, etc.).

### Op 8: Specific .NET APIs Used Within Web Shell — Use SpecificAPI
- **Tag**: [TANGENTIAL]
- The specific APIs called (System.Diagnostics.Process.Start, System.IO.File, System.Net.WebClient, etc.) are entirely attacker-chosen implementation details. The web shell could use any .NET API available within the w3wp.exe process context.

### Op 9: web.config Modification for Handler Abuse — Modify WebConfig
- **Tag**: [OPTIONAL] for standard web shells; [EIO] for web.config-as-web-shell technique
- Standard web shells (.aspx, .asp) do not require web.config modification since their extensions have default handler mappings. web.config modification is required ONLY when: (a) using a non-standard extension that needs a new handler mapping, or (b) using the web.config-as-web-shell technique with buildProviders + PageBuildProvider. For case (b), this becomes essential and immutable.

## Execution Paths Found

### Path 1: ASP.NET File-Based Web Shell (.aspx/.ashx)
**Essential operations**: Write WebShellFile -> Request WebShellURL -> Resolve HandlerMapping -> Compile WebShellAssembly -> Execute WebShellCode

This is the most common web shell deployment path on modern Windows/IIS servers. An .aspx or .ashx file containing C# or VB.NET code is written to the IIS content directory. On first HTTP request, ASP.NET dynamically compiles the source to a DLL (w3wp.exe spawns csc.exe/vbc.exe), producing compilation artifacts in Temporary ASP.NET Files. The compiled assembly is loaded and its ProcessRequest method is invoked. Subsequent requests use the cached DLL without recompilation.

**Distinguishing characteristic**: The compilation step (Op 5) is unique to this path and produces distinctive telemetry (csc.exe child process, file artifacts).

### Path 2: Classic ASP File-Based Web Shell (.asp)
**Essential operations**: Write WebShellFile -> Request WebShellURL -> Resolve HandlerMapping -> Execute WebShellCode

Classic ASP scripts are interpreted by asp.dll (VBScript/JScript engine), NOT compiled to .NET assemblies. There is no csc.exe invocation and no Temporary ASP.NET Files artifacts. The scripting engine parses and executes the code in-process within w3wp.exe via asp.dll (loaded by IsapiModule).

**Distinguishing characteristic**: No compilation step. No .NET-related telemetry. Command execution uses COM objects (WScript.Shell) rather than .NET APIs (System.Diagnostics.Process).

### Path 3: web.config as Web Shell
**Essential operations**: Write WebShellFile (web.config) -> Request WebShellURL -> Resolve HandlerMapping (via modified buildProviders + httpHandlers) -> Compile WebShellAssembly -> Execute WebShellCode

This path abuses ASP.NET's build provider and handler mapping system to make web.config itself executable. Requires three specific web.config sections: buildProviders (register PageBuildProvider for .config), httpHandlers (map .config to PageHandlerFactory), and requestFiltering (remove .config extension block and web.config hidden segment).

**Distinguishing characteristic**: The web shell file IS the configuration file. buildProviders section can only be defined at application root level. web.config modification triggers IIS application domain recycling. After recycling, requesting the web.config URL triggers ASP.NET compilation and execution of inline code.

**Critical constraint**: buildProviders requires allowDefinition='MachineToApplication'. This technique only works at the application root, not in subdirectories (unless the subdirectory is configured as a separate IIS application).

### Path 4: Pre-Compiled Web Shell (DLL in bin directory)
**Essential operations**: Write WebShellFile (DLL to bin + handler registration) -> Request WebShellURL -> Resolve HandlerMapping -> Execute WebShellCode

A pre-compiled .NET assembly implementing IHttpHandler is placed in the application's `bin` directory. A web.config handler mapping points a URL/extension to the handler class. No runtime compilation occurs -- the DLL is loaded directly.

**Distinguishing characteristic**: No csc.exe invocation. No Temporary ASP.NET Files artifacts. But does require web.config modification to register the handler and a DLL write to the bin directory. Observable via Sysmon 7 (ImageLoad) when w3wp.exe loads the DLL.

### Rejected Paths (Same Procedure)

- **.asmx web shells**: Same essential operations as Path 1 (.ashx/.aspx). ASMX files use the WebServiceHandlerFactory, but the compilation and execution chain is identical to .aspx.
- **Different file delivery mechanisms (upload vs. RDP vs. exploit)**: The write operation is the same essential operation regardless of how the file arrives. These are different instances (tangential delivery methods), not different procedures.
- **cmd.aspx vs. antak.aspx vs. SharPyShell**: Different tools implementing the same Path 1 procedure. The web shell's internal functionality (command execution vs. file browser vs. shellcode runner) is tangential -- the IIS pipeline processing chain is identical.
- **PHP web shells on IIS with PHP/FastCGI**: While technically possible, PHP on IIS uses FastCgiModule (not the ASP.NET pipeline). The essential operations are the same (file write, HTTP request, handler resolution, code execution), but the handler mapping resolves to FastCgiModule instead of ASP.NET/asp.dll. This could be argued as a variant of Path 2 (interpreted, no .NET compilation).

## Telemetry Sources

### Sysmon Events
| Event ID | Name | Relevance |
|---|---|---|
| 1 | ProcessCreate | w3wp.exe spawning csc.exe/vbc.exe (compilation), cmd.exe/powershell.exe (command execution) |
| 7 | ImageLoad | DLL loads into w3wp.exe (compiled assemblies, pre-compiled handlers) |
| 11 | FileCreate | Web shell file creation in IIS content path; compilation artifacts in Temporary ASP.NET Files |
| 22 | DNSQuery | DNS resolution if web shell makes outbound network connections |
| 3 | NetworkConnect | Outbound connections from w3wp.exe (disabled by default, very noisy) |

### Windows Security Events
| Event ID | Description | Requirements |
|---|---|---|
| 4688 | Process Creation | Audit Process Creation policy must be enabled; command line logging requires separate GPO |
| 4663 | Object Access | Requires SACL on specific files/directories; not broadly deployed |

### IIS Logging
- **W3C Extended Log Format**: Records cs-uri-stem (requested URL), cs-method (HTTP method), c-ip (client IP), sc-status (response code), cs-uri-query (query string), cs(User-Agent), s-handler (handler name, if field enabled).
- **Default location**: `%SystemDrive%\inetpub\logs\LogFiles\W3SVC<SiteID>\`
- **Limitation**: W3C logs do NOT capture POST body content by default. Most web shells receive commands via POST body. Only the URL and query string are logged.
- **Failed Request Tracing (FREB)**: Detailed per-request diagnostics including handler resolution. Not enabled by default; generates XML trace files.

### ETW Providers
| Provider | GUID | Relevance |
|---|---|---|
| Microsoft-Windows-IIS-Logging | {7e8ad27f-b271-4ea2-a783-a47bde29143b} | Real-time W3C log equivalent (IIS 8.5+) |
| IIS: WWW Server | {3A2A4E84-4C21-4981-AE10-3FDA0D9B0F83} | Request-based tracing events |
| IIS: Active Server Pages (ASP) | {06b94d9a-b15e-456e-a4ef-37c984a2cb4b} | Classic ASP execution events |
| Microsoft-Windows-DotNETRuntime | {e13c0d23-ccbc-4e12-931b-d9cc2eee27e4} | AssemblyLoad_V1 (EID 154) for .NET assembly loads |
| Microsoft-Windows-HttpService | {dd5ef90a-6398-47a4-ad34-4dcecdef795f} | HTTP.sys kernel-level request logging |

### File Integrity Monitoring (FIM)
- Critical for detecting web shell file writes to IIS content directories.
- Should monitor `%SystemDrive%\inetpub\wwwroot\` and all configured IIS application physical paths.
- Also monitor `web.config` files for unauthorized modification.
- Not a native Windows capability -- requires third-party tools or Windows Defender for Endpoint.

### Commonly Missed Telemetry Sources
1. **IIS W3C extended field `s-handler`**: Not enabled by default but identifies which handler processed each request (e.g., "System.Web.UI.PageHandlerFactory" vs "StaticFile"). Useful for identifying requests processed by ASP.NET handlers in unexpected directories.
2. **ETW Microsoft-Windows-DotNETRuntime AssemblyLoad events**: Fires for all assembly loads including dynamically compiled web shell assemblies. Not commonly collected.
3. **Compilation artifact monitoring**: Files in Temporary ASP.NET Files directories are rarely monitored. New DLLs appearing here correlate 1:1 with ASP.NET page compilations.
4. **web.config change detection**: While web.config is "just a file," modifications trigger application domain recycling, which can be observed via w3wp.exe recycling behavior and Windows event logs (Application pool recycle events).

## Edge Cases and Variants

### Server-Side Includes (SSI) via ssinc.dll
- `#exec cmd` directive is **disabled by default** in IIS 7+. This is NOT a viable web shell vector on modern IIS without explicit reconfiguration.
- `#exec cgi` is available but requires a pre-existing CGI executable on disk, making it impractical for standalone web shell use.
- SSI role service (`Web-Includes`) is not installed by default.
- **Verdict**: Minimal web shell relevance on modern IIS (7+). Could be scoped out for a modern-focused TRR.

### ISAPI Filters/Extensions as Web Shell Vectors
- ISAPI extensions (.dll loaded by IsapiModule) can serve as persistent backdoors but overlap more with T1505.004 (IIS Components) than T1505.003 (Web Shell).
- ISAPI filters (loaded by IsapiFilterModule) intercept all requests and can inject responses, but again fall under T1505.004.
- **Scoping note**: Custom ISAPI extensions are more accurately categorized as IIS modules/components (T1505.004), not file-based web shells (T1505.003).

### .ashx / .asmx Handlers
- .ashx files are generic handlers implementing IHttpHandler. They compile and execute identically to .aspx but are lighter weight (no page lifecycle).
- .asmx files are legacy SOAP web services. They also auto-compile when requested.
- Both are valid web shell carriers and follow the same execution path as .aspx (Path 1).
- **Key insight**: Any ASP.NET handler-mapped extension that triggers dynamic compilation is a valid web shell delivery extension. The specific extension is tangential.

### web.config Without Separate File
- Yes, web.config CAN serve as a standalone web shell via the buildProviders/httpHandlers abuse technique (Path 3 above).
- The inline code (implementing IHttpHandler with ProcessRequest method) is embedded within the web.config XML.
- **Constraint**: buildProviders must be at application root level.
- **Constraint**: Default IIS requestFiltering blocks direct access to .config files and the web.config hidden segment. Both restrictions must be removed in the web.config itself.
- This makes web.config a self-modifying configuration that enables its own execution.
- Source: https://soroush.me/blog/2019/08/uploading-web-config-for-fun-and-profit-2/

### In-Memory / Fileless Variants (Scope Boundary)
- MDSec research describes virtual path providers that serve web shell responses from memory (no disk-backed .aspx file).
- SharPyShell uses runtime C# compilation via Reflection to execute code without standard compilation artifacts.
- These approaches blur the line between T1505.003 (Web Shell) and T1620 (Reflective Code Loading).
- **Scoping note**: File-based web shells are core T1505.003 scope. In-memory-only execution without a file on disk may be better categorized under T1620 or T1505.004.

## Scoping Recommendations

### In Scope
- File-based web shells on Windows/IIS using default handler mappings (.aspx, .asp, .ashx, .asmx)
- web.config manipulation for handler mapping or self-execution (buildProviders technique)
- Pre-compiled web shell DLLs deployed to bin directory with handler registration
- The IIS request pipeline from HTTP.sys through w3wp.exe code execution
- Compilation artifacts and telemetry for ASP.NET dynamic compilation path
- Classic ASP interpreted execution path

### Exclusion Table
| Excluded Item | Rationale |
|---|---|
| T1505.004 IIS Components (native modules, ISAPI filters) | Different sub-technique with different essential operations (RegisterModule, applicationHost.config modification) |
| PHP/FastCGI web shells | Different handler module (FastCgiModule), different process model; could be separate procedure if included |
| SSI #exec directives | Disabled by default on IIS 7+; SSI role service not installed by default; negligible real-world prevalence |
| In-memory-only virtual path web shells | No file on disk; overlaps T1620 Reflective Code Loading |
| Linux/Apache/Nginx web shells | Platform scope boundary (Windows/IIS only) |
| Web shell C2 protocols and post-exploitation capabilities | Post-execution attacker behavior; outside the scope of the file-to-execution chain |

## Sources

### Microsoft Documentation (Authoritative)
- IIS Architecture: https://learn.microsoft.com/iis/get-started/introduction-to-iis/introduction-to-iis-architecture
- IIS Handlers Configuration: https://learn.microsoft.com/iis/configuration/system.webserver/handlers/
- IIS Handler Add Element: https://learn.microsoft.com/iis/configuration/system.webserver/handlers/add
- SSI Configuration: https://learn.microsoft.com/iis/configuration/system.webserver/serversideinclude
- ASP Cache Configuration: https://learn.microsoft.com/iis/configuration/system.webserver/asp/cache
- ASP.NET Compilation Overview: https://learn.microsoft.com/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/precompiling-your-website-cs
- ASP.NET HTTP Modules and Handlers: https://learn.microsoft.com/troubleshoot/developer/webapps/aspnet/development/http-modules-handlers
- COM Objects in ASP: https://learn.microsoft.com/windows/win32/com/using-com-objects-in-active-server-pages
- IHttpHandler Interface: https://learn.microsoft.com/dotnet/api/system.web.ihttphandler?view=netframework-4.8.1
- Developing IIS Modules and Handlers: https://learn.microsoft.com/iis/develop/runtime-extensibility/developing-iis-modules-and-handlers-with-the-net-framework
- IIS ETW Logging: https://learn.microsoft.com/iis/get-started/whats-new-in-iis-85/logging-to-etw-in-iis-85
- Windows Security Event 4688: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- Wildcard Script Mapping: https://learn.microsoft.com/iis/application-frameworks/building-and-running-aspnet-applications/wildcard-script-mapping-and-iis-integrated-pipeline
- ASP.NET Temp File Path Customization: https://techcommunity.microsoft.com/blog/iis-support-blog/customizing-temporary-file-paths-in-asp-net-applications/4411172

### MITRE ATT&CK
- T1505.003 Web Shell: queried via MCP get_technique_by_id (STIX data)

### Security Research
- Webshell Compilation Artifacts: https://swolfsec.github.io/2023-10-29-Webshell-Compilation-Artifacts/ (forensic analysis of compilation artifacts)
- Soroush Dalili - web.config for Fun and Profit 2: https://soroush.me/blog/2019/08/uploading-web-config-for-fun-and-profit-2/ (web.config as web shell technique)
- MDSec - Covert Web Shells in .NET: https://www.mdsec.co.uk/2020/10/covert-web-shells-in-net-with-read-only-web-paths/ (virtual path providers, in-memory web shells)
- Microsoft Security Blog - IIS Modules Evolution: https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/ (in-process execution, avoiding child processes)
- SharPyShell: https://github.com/antonioCoco/SharPyShell (in-process C# web shell framework)

### Atomic Red Team
- T1505.003 Test: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.yaml
- Single test: "Web Shell Written to Disk" -- copies cmd.aspx/b.jsp/tests.jsp to C:\inetpub\wwwroot. Windows only. Tests file placement only, not execution.

### Telemetry Documentation
- Sysmon Event ID 11: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011
- IIS Logging Configuration: https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis
- W3C Logging Format: https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging

## Intelligence Gaps

1. **[?] Exact ETW events for Classic ASP script execution**: The IIS: Active Server Pages ETW provider (GUID {06b94d9a-b15e-456e-a4ef-37c984a2cb4b}) should emit events when asp.dll processes scripts, but specific event IDs and field content for web shell-relevant operations (CreateObject calls, script errors) are not documented in the sources consulted. Lab testing with ETW tracing would resolve this.

2. **[?] Sysmon 7 behavior for ASP.NET dynamically compiled assemblies**: It is confirmed that Sysmon 7 fires for disk-backed assemblies loaded via CLR. Since dynamically compiled web shell DLLs ARE disk-backed (in Temporary ASP.NET Files), Sysmon 7 should fire when w3wp.exe loads them. This needs lab confirmation to verify the Image field shows the Temporary ASP.NET Files DLL path.

3. **[?] Roslyn vs. legacy CodeDom compiler path on Server 2019/2022**: Whether modern Windows Server versions default to the Roslyn compiler (bin\roslyn\csc.exe) or the Framework CodeDom compiler (Framework64\v4.0.30319\csc.exe) for dynamic ASP.NET compilation depends on whether DotNetCompilerPlatform NuGet is installed. The default IIS installation (no custom packages) should use the Framework compiler. Needs lab verification.

4. **[?] web.config web shell compilation process**: When web.config is registered as a buildProvider target and PageHandlerFactory processes it, does csc.exe still get spawned for compilation? The inline code must be compiled, so logically yes, but this needs verification -- it is possible ASP.NET handles this differently for .config files.

5. **[?] IIS application pool recycle event telemetry**: When web.config is modified, the application domain recycles. What specific Windows event log entries (Application log, System log) record this recycling event? This would be relevant telemetry for detecting web.config manipulation.
