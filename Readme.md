<img src="https://raw.githubusercontent.com/Aldaviva/Fail2Ban4Win/master/Fail2Ban4Win/pifmgr_37.ico" height="32" alt="Fail2Ban4Win logo" /> Fail2Ban4Win
===

![price: free](https://img.shields.io/badge/price-free-brightgreen) [![Build status](https://img.shields.io/github/actions/workflow/status/Aldaviva/Fail2Ban4Win/dotnetframework.yml?branch=master&logo=github)](https://github.com/Aldaviva/Fail2Ban4Win/actions/workflows/dotnetframework.yml) [![Test status](https://img.shields.io/testspace/tests/Aldaviva/Aldaviva:Fail2Ban4Win/master?passed_label=passing&failed_label=failing&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA4NTkgODYxIj48cGF0aCBkPSJtNTk4IDUxMy05NCA5NCAyOCAyNyA5NC05NC0yOC0yN3pNMzA2IDIyNmwtOTQgOTQgMjggMjggOTQtOTQtMjgtMjh6bS00NiAyODctMjcgMjcgOTQgOTQgMjctMjctOTQtOTR6bTI5My0yODctMjcgMjggOTQgOTQgMjctMjgtOTQtOTR6TTQzMiA4NjFjNDEuMzMgMCA3Ni44My0xNC42NyAxMDYuNS00NFM1ODMgNzUyIDU4MyA3MTBjMC00MS4zMy0xNC44My03Ni44My00NC41LTEwNi41UzQ3My4zMyA1NTkgNDMyIDU1OWMtNDIgMC03Ny42NyAxNC44My0xMDcgNDQuNXMtNDQgNjUuMTctNDQgMTA2LjVjMCA0MiAxNC42NyA3Ny42NyA0NCAxMDdzNjUgNDQgMTA3IDQ0em0wLTU1OWM0MS4zMyAwIDc2LjgzLTE0LjgzIDEwNi41LTQ0LjVTNTgzIDE5Mi4zMyA1ODMgMTUxYzAtNDItMTQuODMtNzcuNjctNDQuNS0xMDdTNDczLjMzIDAgNDMyIDBjLTQyIDAtNzcuNjcgMTQuNjctMTA3IDQ0cy00NCA2NS00NCAxMDdjMCA0MS4zMyAxNC42NyA3Ni44MyA0NCAxMDYuNVMzOTAgMzAyIDQzMiAzMDJ6bTI3NiAyODJjNDIgMCA3Ny42Ny0xNC44MyAxMDctNDQuNXM0NC02NS4xNyA0NC0xMDYuNWMwLTQyLTE0LjY3LTc3LjY3LTQ0LTEwN3MtNjUtNDQtMTA3LTQ0Yy00MS4zMyAwLTc2LjY3IDE0LjY3LTEwNiA0NHMtNDQgNjUtNDQgMTA3YzAgNDEuMzMgMTQuNjcgNzYuODMgNDQgMTA2LjVTNjY2LjY3IDU4NCA3MDggNTg0em0tNTU3IDBjNDIgMCA3Ny42Ny0xNC44MyAxMDctNDQuNXM0NC02NS4xNyA0NC0xMDYuNWMwLTQyLTE0LjY3LTc3LjY3LTQ0LTEwN3MtNjUtNDQtMTA3LTQ0Yy00MS4zMyAwLTc2LjgzIDE0LjY3LTEwNi41IDQ0UzAgMzkxIDAgNDMzYzAgNDEuMzMgMTQuODMgNzYuODMgNDQuNSAxMDYuNVMxMDkuNjcgNTg0IDE1MSA1ODR6IiBmaWxsPSIjZmZmIi8%2BPC9zdmc%2B)](https://aldaviva.testspace.com/spaces/194263) [![Coverage status](https://img.shields.io/coveralls/github/Aldaviva/Fail2Ban4Win?logo=coveralls)](https://coveralls.io/github/Aldaviva/Fail2Ban4Win?branch=master)

Fail2Ban4Win is a background service that temporarily blocks IP ranges in Windows Firewall when enough authentication errors appear in Event Log in a given time period for those IP ranges.

You can customize the duration of the ban, the type of Event Log events to detect, and other options. The example configuration file will set Fail2Ban4Win to ban a /24 subnet for 24 hours after 10 failures to authenticate to either Remote Desktop Services or sshd.

<!-- MarkdownTOC autolink="true" bracket="round" autoanchor="false" levels="1,2,3" style="ordered" -->

1. [Behavior](#behavior)
1. [Requirements](#requirements)
1. [Installation](#installation)
    1. [Upgrade](#upgrade)
1. [Configuration](#configuration)
    1. [Logging](#logging)
    1. [Handling a new event](#handling-a-new-event)
1. [Running](#running)
1. [Monitoring](#monitoring)
1. [Acknowledgments](#acknowledgments)

<!-- /MarkdownTOC -->

## Behavior

1. Fail2Ban4Win runs in the background as a Windows Service.
1. Configuration comes from a JSON file in the installation directory.
1. Fail2Ban4Win listens for Event Log events from various logs and event IDs.
1. When a matching event is created, Fail2Ban4Win extracts the client's IP address from the event data. The IP address is aggregated into a /24 subnet IP range.
1. Fail2Ban4Win keeps track of how many times each subnet (not each IP address) has triggered auth failures over the last 24 hours.
1. When a given subnet has failed to authenticate 10 times in the last 24 hours across all Event Log selectors, a Windows Firewall rule is created to block incoming traffic from that subnet on all ports.
1. After being banned for 1 day, the firewall rule is deleted and the subnet is allowed to fail 10 more times before being banned a second time.
1. Each time a subnet is repeatedly banned, the ban duration increases by 1 day, up to a maximum of a 4 day ban, after which each subsequent ban will always be 4 days.
1. When Fail2Ban4Win restarts, it deletes all firewall rules it created and starts from scratch. This allows it to fail open.

You can [customize](#configuration) most of the above specifics to suit your banning needs.

## Requirements
- Windows 7 SP1, Windows Server 2008 R2 SP1, or later
- [.NET Framework 4.7.2](https://dotnet.microsoft.com/download/dotnet-framework) or later, which are included in Windows 10 1803 (April 2018 Update), Windows Server 2019, and later
- Use Windows Firewall, as opposed to a third-party firewall solution

## Installation
1. Download the [latest release](https://github.com/Aldaviva/Fail2Ban4Win/releases/latest). You have artifact options to choose from:
    - [**`Fail2Ban4Win.zip`**](https://github.com/Aldaviva/Fail2Ban4Win/releases/latest/download/Fail2Ban4Win.zip) — Single big EXE file
    - [**`Fail2Ban4Win-unpacked.zip`**](https://github.com/Aldaviva/Fail2Ban4Win/releases/latest/download/Fail2Ban4Win-unpacked.zip) — Folder full of DLLs, which may reduce antivirus false positives
    <div>The file structure is the only difference. Both artifacts are otherwise equivalent and have the same behavior, features, and bugs.</div>
1. Extract the contents of the ZIP file to a directory like `C:\Program Files (x86)\Fail2Ban4Win\`.
1. Open an elevated PowerShell window (run it as administrator).
1. Allow PowerShell scripts to run until you close the window.
    ```ps1
    Set-ExecutionPolicy RemoteSigned -Scope Process -Force
    ```
1. Register Fail2Ban4Win as a service.
    ```ps1
    & 'C:\Program Files (x86)\Fail2Ban4Win\Install service.ps1'
    ```
1. Configure the service in the next section before starting it.

### Upgrade
1. Download the [latest release](https://github.com/Aldaviva/Fail2Ban4Win/releases/latest), as [described above](#installation).
2. Extract the ZIP file to the installation directory.
> [!CAUTION]
> Don't overwrite config files like `configuration.json` or `NLog.config`.
3. Restart the service using `services.msc` (GUI), `Restart-Service Fail2Ban4Win` (PowerShell), or `net stop Fail2Ban4Win & net start Fail2Ban4Win` (Command Prompt).

## Configuration
The provided example configuration file has selectors for [Remote Desktop Services](https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-portal), [Cygwin OpenSSH sshd](https://cygwin.com/packages/summary/openssh.html) (updated in [1.3.1](https://github.com/Aldaviva/Fail2Ban4Win/releases/tag/1.3.1)), and [Windows OpenSSH sshd](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview) (updated in [1.3.1](https://github.com/Aldaviva/Fail2Ban4Win/releases/tag/1.3.1)). It also has some example values for `neverBanSubnets` and other properties that you can replace with your own values.

> [!IMPORTANT]  
> Be aware that `isDryRun` is set to `true` in the example configuration to avoid accidentally blocking traffic until you're ready.

1. Open the `configuration.json` file from the Fail2Ban4Win installation directory in a text editor. (You may need to start the editor elevated depending on your file permissions.)
1. Set any of the following properties. 
    |Property name|Default when omitted|Description|
    |---|---|---|
    |`isDryRun`|`false`|Firewall rules will only be created or deleted when this is `false`.|
    |`maxAllowedFailures`|`9`|If an IP range (of size `banSubnetBits`) exceeds this number of failures during the `failureWindow`, it will be banned. By default, the **10**<sup>th</sup> failure is a ban.|
    |`failureWindow`|`1.00:00:00` (1 day)|How long to consider auth failures. By default, 10 failures in **1 day** results in a ban. The format is `d.hh:mm:ss`.|
    |`banPeriod`|`1.00:00:00` (1 day)|After enough failures, the IP range will be banned by adding a Windows Firewall block rule, which will be removed after this period of time. The format is `d.hh:mm:ss`. By default, a ban lasts **1 day**.|
    |`banSubnetBits`|`0`|Optional CIDR subnet aggregation size when both counting failures and blocking traffic. The example value of `8` bits blocks the /24 subnet, or 255.255.255.0. You can restrict blocking only to the exact IP address by setting this to **`0`**, which is equivalent to /32.|
    |`banRepeatedOffenseCoefficient`|`0.0`|How much of the `banPeriod` to add on subsequent offenses (optional). The default `banPeriod` of 1 day and example coefficient of `1.0` results in a 1 day ban for first offenders, 2 days for 2<sup>nd</sup> offenders, 3 days for 3<sup>rd</sup> offenders, and 4 days for 4<sup>th</sup> offenders or greater. Changing this coefficient from 1.0 to 2.0 would result in successive ban durations of 1 day, 3 days, 5 days, and 7 days instead. Defaults to all subsequent bans having the same duration as initial bans.|
    |`banRepeatedOffenseMax`|`4`|An optional limit on how many repeated offenses can be used to calculate ban duration. By default, the 5<sup>th</sup> offense and subsequent bans will be capped at the same duration as the **4**<sup>th</sup> offense ban, which is 4 days.|
    |`neverBanSubnets`|`[]`|Optional whitelist of IP ranges that should never be banned, regardless of how many auth failures they generate. Each item can be a single IP address, like `67.210.32.33`, or a range, like `67.210.32.0/24`.|
    |`neverBanReservedSubnets`|`true`|By default, IP addresses in the reserved blocks `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` will not be banned, to avoid unintentionally blocking LAN access. To allow all three ranges to be banned, change this to `false`. To then selectively prevent some of those ranges from getting banned, you may add them to the `neverBanSubnets` list above. The loopback addresses 127.0.0.0/8 will never be banned, regardless of this setting.|
    |`unbanAllOnStartup`|`true`|Whether Fail2Ban4Win should, when it launches, delete all of its existing firewall rules which it previously created. This is **`true`** by default, to fail open. To preserve existing bans, _e.g._ after a computer reboot, set this to `false`. When resuming existing unban timers, the duration is corrected for the time Fail2Ban4Win wasn't running. Unrelated firewall rules (Windows defaults, your custom rules) are never touched, regardless of this setting.|
    |`eventLogSelectors`|`[]`|Required list of events to listen for in Event Log. Each object in the list can have the following properties.<ul><li>`logName`: required, which log in Event Viewer contains the events, _e.g._ `Application`, `Security`, `OpenSSH/Operational`.</li><li>`eventId`: required, numeric ID of event logged on auth failure, _e.g._ `4625` for RDP auth errors.</li><li>`source`: optional Source, AKA Provider Name, of events, _e.g._ `sshd-session` for Cygwin OpenSSH sshd. If omitted, events will not be filtered by Source.</li><li>`ipAddressEventDataName`: optional, the `Name` of the `Data` element in the event XML's `EventData` in which to search for the client IP address of the auth request, _e.g._ `IpAddress` for RDP. If omitted, the first `Data` element will be searched instead.</li><li>`ipAddressEventDataIndex`: optional, the 0-indexed offset of the `Data` element in the XML's `EventData` in which to search for the client IP address, _e.g._ `3` to search for IP addresses in the fourth `Data` element in `EventData`. Useful if `EventData` has multiple `Data` children, but none of them have a `Name` attribute to specify in `ipAddressEventDataName`, and the IP address doesn't appear in the first one. This offset is applied after any `Name` attribute filtering, and applies whether or not `ipAddressEventDataName` is specified. If omitted, defaults to `0`.</li><li>`ipAddressPattern`: optional, regular expression pattern string that matches the IP address in the `Data` element specified above. Useful if you want to filter out some events from the log with the desired ID and source but that don't describe an auth failure (_e.g._ sshd's disconnect events). If omitted, searches for all IPv4 addresses in the `Data` element's text content. To set [options like case-insensitivity](https://docs.microsoft.com/en-us/dotnet/standard/base-types/miscellaneous-constructs-in-regular-expressions), put `(?i)` at the start of the pattern. Patterns are not anchored to the entire input string unless you surround them with `^` and `$`. If you specify a pattern, ensure the desired IPv4 capture group in your pattern has the name `ipAddress`, _e.g._ <pre lang="regex">Failed: (?&lt;ipAddress&gt;(?:\d{1,3}\\.){3}\d{1,3})</pre></li><li>`eventPredicate`: optional, XPath 1.0 query fragment to filter events based on arbitrary elements, matched against the `<Event>` element. Useful if not all events with the given `logName`, `eventId`, and `source` should trigger bans, like IIS HTTP 200 responses, _e.g._ `[EventData/Data[@Name='sc-status']=403]`. Most XPath functions are not supported by Windows ETW.</li></ul>See [Handling a new event](#handling-a-new-event) below for a tutorial on creating this object.|
1. After saving the configuration file, restart the Fail2Ban4Win service using `services.msc` (GUI), `Restart-Service Fail2Ban4Win` (PowerShell), or `net stop Fail2Ban4Win & net start Fail2Ban4Win` (Command Prompt) for your changes to take effect. Note that the service will clear existing bans when it starts (unless you changed `unbanAllOnStartup` to `false`).

### Logging
Fail2Ban4Win uses [NLog](https://nlog-project.org) to log messages. By default, it logs messages of Info severity and above to `logs\Fail2Ban4Win.log` in the installation directory.

You can configure this logging by editing `NLog.config` in the Fail2Ban4Win installation directory. See NLog documentation for this [XML config file](https://github.com/nlog/NLog/wiki/Configuration-file), the [format of log messages](https://nlog-project.org/config/?tab=layout-renderers), [file handling](https://github.com/nlog/NLog/wiki/File-target), and [other places to write logs besides a local file](https://nlog-project.org/config/?tab=targets).

### Handling a new event
In this example, we will go through the process of creating an event for Windows OpenSSH sshd. This event is already supported in the example configuration file, but the following process covers all of the necessary steps to add any other event.

1. Ensure OpenSSH Server is installed and running in Windows.
    - Install the [latest sshd version from Microsoft's PowerShell/Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/releases), which has important security fixes that are often missing from the older built-in version below (for Terrapin, VerifyHostKeyDNS, and DoS attacks).
    - Otherwise, install OpenSSH Server in the Windows Settings app (`explorer.exe ms-settings:optionalfeatures`):
        - **Windows 10**: System › Optional features › Add a feature › OpenSSH Server
        - **Windows 11**: System › Optional features › View features › See available features › OpenSSH server
        - **Windows Server 2019**: Apps › Apps & features › Manage optional features › Add a feature › OpenSSH Server
        - **Windows Server 2022**: Apps › Apps & features › Optional features › Add a feature › OpenSSH Server
        - **Windows Server 2025**: OpenSSH Server is preinstalled, so start the `sshd` service and set its startup type to Automatic
1. Open Event Viewer (`eventvwr.msc`).
1. Find an instance of the event you want. If one doesn't exist, start an SSH client like [ssh](https://linux.die.net/man/1/ssh) or [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) and fail to authenticate on purpose.
    ![Event Viewer with OpenSSH failure event, General tab](https://i.imgur.com/YZsr8H5.png)
1. The `logName` value of the event log selector object comes from the **Log Name** shown here, in this case, `OpenSSH/Operational`.
1. The optional `source` value comes from the **Source** shown here, in this case, `OpenSSH`. You can also omit `source` in this case because all events in this log have the same Source.
1. The `eventId` value comes from the **Event ID** shown here, in this case, `4`.
1. Switch to the Details (XML View) of the event to determine how the IP address is represented in the `<EventData>`.
    ![Event Viewer with OpenSSH failure event, Details tab](https://i.imgur.com/RKQio4P.png)
1. The IP address is found in the following element.
    ```xml
    <Data Name="payload">Failed password for invalid user foo bar from 192.168.1.7 port 49721 ssh2</Data>
    ```
1. The `ipAddressEventDataName` value comes from the `Name` attribute value of the `<Data>` element which contains the IP address in its text content, in this case, `payload`.
    - If there were just one `<Data>` element with no `Name` attribute, you would omit the `ipAddressEventDataName` property from the event log selector object.
    - If there were multiple `<Data>` elements with no `Name` attributes, you would omit the `ipAddressEventDataName` property and set `ipAddressEventDataIndex` to the position of the desired `Data` element (where the first `Data` child of the `EventData` element would have index 0).
1. The `ipAddressPattern` helps narrow down which events represent auth failures. Some events in this log with ID 4 are caused by successful auth attempts or disconnections, which should not trigger firewall bans. By matching the text of an auth failure, only the correct events will be processed. The [following pattern](https://regex101.com/r/ZdJqcT/5) matches only auth failures and captures the IP address in a named group for processing.
    ```regex
    ^Failed password for(?: invalid user)? .+ from (?<ipAddress>(?:\d{1,3}\.){3}\d{1,3}) port \d{1,5} ssh\d?$
    ```
1. Here is the resulting event log selector object from all of the above properties.
    ```json
    {
        "logName": "OpenSSH/Operational",
        "source": "OpenSSH",
        "eventId": 4,
        "ipAddressEventDataName": "payload",
        "ipAddressPattern": "^Failed password for(?: invalid user)? .+ from (?<ipAddress>(?:\\d{1,3}\\.){3}\\d{1,3}) port \\d{1,5} ssh\\d?$"
    }
    ```
1. You can add this selector object to `configuration.json` by appending it to the `eventLogSelectors` array.

## Running
Do any of the following.
- Start the `Fail2Ban4Win` service from the `services.msc` GUI.
- Start the service from PowerShell using `Start-Service Fail2Ban4Win`.
- Start the service from Command Prompt using `net start Fail2Ban4Win`.
- Run the service in the foreground by starting `Fail2Ban4Win.exe` in a console window. This is useful for looking at the log output and verifying your configuration, especially when `isDryRun` is true. You can stop the process using `Ctrl`+`C`.

## Monitoring
You can see the block rules created by Fail2Ban4Win in Windows Firewall.
1. Start Windows Firewall with Advanced Security (`wf.msc`).
1. Go to `Inbound Rules`.
1. To only show rules created by Fail2Ban4Win, select Action › Filter by Group › Filter by Fail2Ban4Win.
    - If Fail2Ban4Win has not created any rules yet (for example, if it started running recently), the Filter by Fail2Ban4Win option will not appear in the Filter by Group menu. Click Refresh to update the collection of rules and groups.
1. To sort by creation time, select View › Add/Remove Columns and Add the Description column, then click the Description column header.

![Windows Firewall with Advanced Security filtering by Fail2Ban4Win rules](https://i.imgur.com/pW12vKL.png)

## Acknowledgments
- My parents for free Windows Server hosting with a static IP address for anyone to connect to.
- A vague awareness of the existence of [`fail2ban`](https://www.fail2ban.org) that convinced me that non-stop RDP and SSH login attempts might have a solution.
- [`wail2ban` by Katie McLaughlin (`glasnt`)](https://github.com/glasnt/wail2ban) for being archived and motivating me to create my own non-archived implementation.
- [`win2ban`](https://itefix.net/win2ban) for charging twenty-nine American dollars for some cobbled together free open-source projects that made me indignant enough to create my own free, open-source, clean-room implementation.
- [Soroush (`falahati`)](https://github.com/falahati/WindowsFirewallHelper) for the excellent .NET wrapper for the Windows Firewall COM API.
- [Robert Mustacchi (`rmustacc`)](https://github.com/rmustacc) for talking me out of trying to implement a wait-free list to store failure times and instead continuing to lock array lists.
