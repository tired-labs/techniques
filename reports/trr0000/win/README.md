# TRR0000: Execute Malicious VM on Host

## Metadata

| Key | Value |
| - | - |
| ID | TRR0000 |
| External IDs | [T1564.006][ref-1] |
| Tactics | Defense Evasion |
| Platforms | Windows |
| Contributors | Jordan Anderson ([keepwatch][ref-2]) |

## Technique Overview

This technique involves adversaries running malicious code inside a virtual
machine (VM) on a compromised host. The primary goal is to isolate their malware
or malicious action from the host operating system, thereby blinding host-based security tools to
the details of the malicious activity (which could include encrypting shared
disks, establishing C2, local reconnaissance, etc.). Because these VMs can bridge network connections to the host, they can also be used to exfiltrate data from the host to the internet, run port scans, or conduct other malicious activity that would otherwise be caught by host-based security tools. They can also be used to bypass application allowlisting, as the malicious code is running in a different operating system than the host. Finally, they can provide access to the host filesystem, which can be used to steal sensitive data or conduct encryption for impact.

Note that this ATT&CK technique contains multiple procedures without common
operations/chokepoints. As a result, this TRR includes two known procedures
(focused on native Windows features). Third-party and portable hypervisors
(such as VirtualBox or VMware Player) represent additional out-of-scope
procedures not covered here.

## Technical Background

### Hypervisor Isolation

A hypervisor abstracts host hardware and provides an isolated execution
environment for a guest operating system. Security tools installed on the host
cannot inspect guest memory, enumerate guest processes, or monitor guest file
system activity. This isolation is the core property adversaries exploit: any
code running inside the guest is invisible to host-based endpoint detection and
response (EDR) products.

On Windows, two categories of hypervisor are relevant:

- **Native (Type 1)**: Hyper-V operates as a Type 1 hypervisor integrated into
  the Windows kernel. Once enabled, the host OS itself runs as a privileged
  partition managed by the Hyper-V hypervisor. Windows Sandbox also uses Hyper-V
  technology under the hood.
- **Third-party (Type 2)**: Products like Oracle VirtualBox and VMware
  Workstation/Player install as applications on the host OS and load kernel-mode
  drivers to manage virtual machines.

This TRR focuses on Type 1 hypervisors on Windows, specifically Hyper-V and Windows Sandbox.

### Type 1 Hypervisors

This is a key point to establish before going further. Type 1 hypervisors run directly on the host hardware, below the host operating system. This means that the host operating system is running as a guest of the hypervisor, and the hypervisor has full control over the host hardware. This is in contrast to Type 2 hypervisors, which run as applications on top of the host operating system. 

The use of these features produces many forensic and detection artifacts.

### Hyper-V

Hyper-V is available on Windows 10/11 Pro, Enterprise, Education editions and
Windows Server.

#### Enable Hyper-V

This feature is not enabled by default on Windows, so if you expect it to not be enabled, there's a potential detection opportunity here. There are two documented ways to enable Hyper-V, but the key is that they both
require service changes, per [Microsoft's documentation][ref-3]:

- Requires a reboot:
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
  ```
- Does not require a reboot:
  ```cmd
  DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V
  ```

Event ID 7045 is a log entry that indicates a new service has been installed on
the system [^ref-4].

#### Import VM to Hyper-V

One way to abuse Hyper-V is to import a pre-built malicious VM into Hyper-V[^ref-22]. This can be done via the Hyper-V Manager GUI or via PowerShell. The below PowerShell command will import a VM from a given path:

```powershell
Import-VM -Path "C:\Path\To\VM" -Copy -GenerateNewId
```

Unlike a service, a Hyper-V virtual machine's primary configuration is not
stored in the registry, so there aren't many good indicators for a new
VM being added to Hyper-V. Even if there were, the data available is sparse (VM name, VM filesystem path, etc.) and difficult to use for detection (similar to the challenges with scheduled tasks).

More importantly, while threat actors have imported malicious VMs previously, the attack can also work if attackers create a new VM and then conduct malicious operations within. Going forward, we'll focus on the elements that are essential for a given procedure.

#### Start VM

Unlike importing a VM, starting a VM is essential to the procedure. When a Hyper-V VM starts, the Virtual Machine Management Service (`vmms.exe`) coordinates with the Hyper-V Compute Service (`vmcompute.exe`) to
launch a Virtual Machine Worker Process (`vmwp.exe`) for each running VM. The
`vmwp.exe` process is the host-side representation of the running guest and is
responsible for device emulation and I/O.

VM starts can occur through the Hyper-V Manager GUI, PowerShell, or programmatically via the Hyper-V WMI provider. 

Several built-in Windows events can be used to collect data about VM starts (as long as
defenders are logging them):

| Event ID | Description | Source | Sample message | Details |
| - | - | - | - | - |
| 18500 | VM started successfully | Microsoft-Windows-Hyper-V-Worker-Admin | 'VM-SRV-001' started successfully. (Virtual machine ID D8EB8812-63FE-468A-9545-1E2028EC1F5F) | Per [MyEventlog - 18500][ref-5] |
| 15130 | VM failed to start | Microsoft-Windows-Hyper-V-VMMS-Admin | 'VM_Name' failed to start. (Virtual machine ID XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX) | Per [Unable to start LOCAL Hyper-V VM...][ref-6] |
| 1 | Process create | Sysmon | Specifically look for the `vmwp.exe` process, and the username (as well as CommandLine) will contain the GUID of the VM | Per [How to Stop/Kill a Hung Virtual Machine...][ref-7] |

Note that 18500 and 15130 are not part of the traditional Windows event logs
(System, Application, Security), but found in a different part of the event log
system (and likely will require explicit collection decisions). The full path to
these logs is: Applications and Services Logs > Microsoft > Windows >
Hyper-V-Worker > Admin, or on-disk:
```text
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Hyper-V-Worker%4Admin.evtx
```
(the `%4` replaces the `/`, which is not a valid Windows file path).

#### Connect VM to the network

This is not strictly required for malicious activity (a Hyper-V VM can be used for file system evasion only), but it is required for command and control (C2) traffic to be effective, or can be used as a
proxy for VM start if other logs are unavailable.

Network traffic from the guest is routed through a Hyper-V virtual switch; when using the Default Switch, traffic is NATed through the host's network stack, causing outbound connections to
appear as originating from the host's IP address. 

##### Monitor VM connection via Registry artifacts

"When a Hyper-V VM is started, the extensible switch interface creates a port
before the virtual machine (VM) network adapter is exposed within the guest
operating system" [^ref-8]. The technical artifact of that change is Virtual Machine Management Service (VMMS)
creates new GUID-labeled Registry keys under the switch for each "port" in use
(by default one) [^ref-9], and deletes the ports when the VM stops
[^ref-10]. Therefore, a network-enabled VM starting will create a Registry
key underneath one of the switch ports (either the default switch, or a custom
switch) - the advantage for us is we can merely monitor at the appropriate
depth:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSMP\Parameters\SwitchList\* (single level)\(new key created here)
```

The Hyper-V Virtual Switch Management Protocol (VMSMP) stores the configuration
for its virtual switches and all the ports connected to them underneath a
registry key:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSMP\Parameters\SwitchList
```

```text
...SwitchList\
│
└───{GUID-for-Default-Switch}  <-- This is your "Default Switch"
│   │   FriendlyName: "Default Switch"
│   │   ...other config values
|
└───{GUID-for-External-Switch}
    │
    ├───{GUID-for-VM1-vNIC-Port}   <-- Port for "VM 1"
    │   │   FriendlyName: "VM 1 - Network Adapter"
    │
    ├───{GUID-for-VM2-vNIC-Port}   <-- Port for "VM 2"
    │
    └───{GUID-for-Host-Adapter-Port} <-- Port for the Host OS
```

There is a "Default Switch" which is automatically enabled when you enable the
service on Windows 10 and 11 [^ref-11]. On Windows Server, this must be
enabled manually [^ref-12]. These registry keys can be used to determine
if network connectivity is possible from Hyper-V VMs.

##### Monitor VM connection via Event logs

Event ID 232 captures the "network connection" event [^ref-13] (equivalent
to plugging an Ethernet cable into a device, but virtually here). The below is a
sample event, derived from [this troubleshooting article][ref-14] (search for
232).

```text
NIC C0470977-2D74-4F23-B695-B60A74E5100A (Friendly Name: MyTestVM_Network_Adapter) successfully connected to port 608710AB-5CDD-449D-B3DE-801891384C7E on switch FF9A59EE-0D6C-468D-98B0-DE0008045F13(Friendly Name: Default_vSwitch).
```

#### Mapping Hyper-V VM GUID to friendly name

- Option 1: `Get-VM -Id "<guid>"`
- Option 2 (use VMCX config file)
  - Navigate to `C:\ProgramData\Microsoft\Windows\Hyper-V\Virtual Machines\`
  - This contains XML-formatted files with names like `<guid>.vmcx`
  - Open this file to find the `name` attribute

### Windows Sandbox

Windows Sandbox is a lightweight, disposable desktop environment built on
Hyper-V container technology. It is available on Windows 10/11 Pro and
Enterprise. When launched, it creates a temporary Windows instance that is
destroyed when closed.

Using Windows Sandbox requires Hyper-V to be enabled on the host OS (see previous section), as well as the Windows Sandbox feature to be enabled.

Sandbox can be launched via `WindowsSandbox.exe`, either with no arguments (for
a default configuration) or with a `.wsb` configuration file that specifies
options such as mapped host folders, networking settings, and logon commands. A
`.wsb` file is not required — the sandbox can be opened with default settings and
malicious activity conducted interactively or through other means.

#### VM Execution Identification

The execution of the sandbox is distinct from how standard Hyper-V VMs are started.

**Process Execution**

The primary indicator is the execution of the manager process:

- `WindowsSandbox.exe`: The main entry point application
- `CmProxy.exe` / `CmProxyD.exe`: Container Manager Proxy, often seen handling
  RDP connections to the sandbox

**Command-line interface** (optional) [^ref-15]

`wsb start` with configuration: 

  ```text
  wsb start --config "<Configuration><Networking>Disabled</Networking></Configuration>"
  ```

`wsb share`:

  ```text
  wsb share --id 12345678-1234-1234-1234-1234567890AB -f C:\host\folder -s C:\sandbox\folder --allow-write
  ```

`wsb exec`:

  ```text
  wsb exec –-id 12345678-1234-1234-1234-1234567890AB -c app.exe -r System
  ```

**Event Logs** [^ref-16]

- Windows Sandbox session start: `Event ID 39` in the `AppModel-Runtime` channel
- Windows Sandbox session end: `Event ID 41` in the `AppModel-Runtime` channel

> [!NOTE]
> Other Hyper-V VMs on the system can trigger these events - look specifically
> for the keyword `CmProxyD` in the event details.

#### Feature Enablement (Setup)

Like Hyper-V, this feature must be enabled if not already present.

**Commands** [^ref-17]

- PowerShell:

  ```powershell
  Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
  ```

- DISM:

  ```cmd
  Dism /online /Enable-Feature /FeatureName:"Containers-DisposableClientVM" /All
  ```

**Forensic Artifacts of Enablement:**

- **Registry Keys**
  - Keys created when the package is installed:

    ```text
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Containers-DisposableClientVM*
    ```

  - `HKLM\SYSTEM\CurrentControlSet\Services\CmService`: The *Container Manager
    Service* which is required for Sandbox execution. [^ref-18]
- **Services**
  - `CmService` (Container Manager Service): This service manages the lifecycle
    of containers and is essential for Windows Sandbox. Its startup type may
    change to specific/automatic when the feature is enabled. [^ref-18]
- **Events**
  - `Event ID 9` in the `Setup` log fires when the feature has been enabled (and
    the PC has restarted) [^ref-16]

#### Configuration Files (.wsb)

Windows Sandbox can be customized using `.wsb` files (XML format). These files
are critical forensic artifacts because they define mapped folders
(host-to-guest), logon commands (what runs on start), and network settings
[^ref-19]. Technically, the sandbox can be configured with the `wsb` CLI
as well, so these files are not mandatory (but can be very informative if present)!

- **Extension:** `*.wsb`
- **Suspicious Content:**
  - `<MappedFolder>`: Maps a host folder to the sandbox. This is the primary way
    to smuggle malware *into* the sandbox.
  - `<LogonCommand>`: Commands to execute automatically when the sandbox starts.
  - `<Networking>Enable</Networking>`: Explicitly enabling networking (though it
    is on by default).

**Example Malicious WSB**

```xml
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Users\Public\Payloads</HostFolder>
      <SandboxFolder>C:\Payloads</SandboxFolder> 
      <ReadOnly>true</ReadOnly> 
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\Payloads\malware.exe</Command>
  </LogonCommand>
</Configuration>
```

## Procedures

| ID | Title | Tactic |
| - | - | - |
| TRR0000.WIN.A | Execute VM via Hyper-V | Defense Evasion |
| TRR0000.WIN.B | Execute VM via Windows Sandbox | Defense Evasion |

### Procedure A: Execute VM via Hyper-V

There are very useful Hyper-V logs that can give you a lot of data about the VMs
being started in your environment. However, almost all of the detail available
can be changed by the attacker (such as VM name), so the best defense is to
monitor for Hyper-V being **used** on systems, ideally by looking for the Hyper-V
process executing. Since the primary detection signal is execution, expected Hyper-V usage in a given environment will determine whether this technique should be detected or yielded[^ref-23] for that environment.

#### Detection Data Model - Procedure A

![Procedure A DDM](ddms/execute-malicious-vm-on-host_procedure-a_ddm.png)

The most durable detection signal is `vmwp.exe` process execution — VM name
and configuration details can be changed by an attacker, but a Hyper-V VM
cannot execute without spawning this process. Event ID 18500 provides
higher-fidelity confirmation of VM start but requires explicitly collecting
from the non-default `Microsoft-Windows-Hyper-V-Worker-Admin` channel. Service
creation events (7045/4697) could be used for partial coverage, but technically an attacker can abuse an already-enabled Hyper-V feature, so process execution is more durable.

### Procedure B: Execute VM via Windows Sandbox

#### Detection Data Model - Procedure B

![Procedure B DDM](ddms/execute-malicious-vm-on-host_procedure-b_ddm.png)

Similar to Hyper-V, the most durable detection signal is process execution. The `WindowsSandbox.exe` process must always run for Windows Sandbox to operate. Event ID 39 provides higher-fidelity confirmation of sandbox start but requires explicitly collecting from the non-default `AppModel-Runtime` channel. Service creation events (7045/4697) could be used for partial coverage, but technically an attacker can abuse an already-enabled Windows Sandbox feature, so process execution is more durable.

## Available Emulation Tests

| ID | Link |
| - | - |
| TRR0000.WIN.A | [Atomic Red Team: Create and Start Hyper-V Virtual Machine][ref-21] |
| TRR0000.WIN.B | None |

## References

[^ref-4]: [Splunk: Event ID 7045][ref-4]
[^ref-8]: [Microsoft Learn: Overview of Hyper-V Extensible Switch Ports][ref-8]
[^ref-9]: [Rlevchenko: Hyper-V 3.0 interaction with registry][ref-9]
[^ref-10]: [Kickthatcomputer: Hyper-V failed to update configuration for port][ref-10]
[^ref-11]: [YouTube: How to set up Default Switch in Hyper-V][ref-11]
[^ref-12]: [YouTube: How to Enable Default Switch in Hyper-V Server][ref-12]
[^ref-13]: [Hatena Blog: Event ID 232][ref-13]
[^ref-15]: [Microsoft Learn: Windows Sandbox configuration][ref-15]
[^ref-16]: [HackTheBox: Windows Sandbox Data Exfiltration Attack Forensics][ref-16]
[^ref-17]: [Microsoft Learn: Windows Sandbox overview][ref-17]
[^ref-18]: [Check Point Research: Playing in the Windows Sandbox][ref-18]
[^ref-19]: [Microsoft Learn: Windows Sandbox configuration file][ref-19]
[^ref-22]: [Sophos: Ragnar Locker Ransomware Deploys Virtual Machine to Dodge Security][ref-22]
[^ref-23]: [Thriving Defense: Some Techniques Should Only Be Detected Opportunistically][ref-23]

[ref-1]: https://attack.mitre.org/techniques/T1564/006/
[ref-2]: https://github.com/keepwatch
[ref-3]: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/Install-Hyper-V?tabs=powershell&pivots=windows
[ref-4]: https://research.splunk.com/sources/614dedc8-8a14-4393-ba9b-6f093cbcd293/
[ref-5]: https://www.myeventlog.com/search/show/788
[ref-6]: https://learn.microsoft.com/en-us/answers/questions/1418975/unable-to-start-local-hyper-v-vm-on-stopped-window
[ref-7]: https://woshub.com/how-to-stop-a-hung-virtual-machine-on-hyper-v-2016/#:~:text=The%20only%20way%20to%20force,(Virtual%20Machine%20Worker%20Process).
[ref-8]: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/overview-of-hyper-v-extensible-switch-ports
[ref-9]: https://rlevchenko.com/2014/07/28/hyper-v-3-0-interaction-with-registry-and-how-it-was-in-2008-r2/
[ref-10]: https://kickthatcomputer.wordpress.com/2013/03/09/hyper-vfailed-to-update-configuration-for-port/#:~:text=In%20the%20Virtual%20Machine%20Settings,additional%20sub%2Dkeys%20still%20present.
[ref-11]: https://www.youtube.com/watch?v=33bBVFobTGY
[ref-12]: https://youtu.be/jdk6xCNmydU?si=b6JXpzFLPNjNuMPk&t=990
[ref-13]: https://cdn-ak.f.st-hatena.com/images/fotolife/i/ici-blog/20250205/20250205212242.png
[ref-14]: https://clustering201.rssing.com/chan-5788003/all_p296.html
[ref-15]: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli
[ref-16]: https://www.hackthebox.com/blog/windows-sandbox-data-exfiltration-attack-forensics#the_attack_
[ref-17]: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview
[ref-18]: https://research.checkpoint.com/2021/playing-in-the-windows-sandbox/
[ref-19]: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file
[ref-20]: https://sigmahq.io/docs/digging-deeper/pipelines.html#query-expression-placeholders
[ref-21]: https://www.atomicredteam.io/atomic-red-team/atomics/T1564.006#atomic-test-3---create-and-start-hyper-v-virtual-machine
[ref-22]: https://www.sophos.com/en-us/blog/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security
[ref-23]: https://thrivingdefense.com/principles/some-techniques-should-only-be-detected-opportunistically