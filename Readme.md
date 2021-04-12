Fail2Ban4Win
===

Fail2Ban4Win is a background service that temporarily blocks IP ranges in Windows Firewall when enough authentication errors appear in Event Log in a given time period for those IP ranges.

You can customize the duration of the ban, the type of Event Log events to detect, and other options. The example configuration file will set Fail2Ban4Win to ban a /24 subnet for 24 hours after 10 failures to authenticate to either Remote Desktop Services or sshd.

<!-- MarkdownTOC autolink="true" bracket="round" autoanchor="true" levels="1,2,3" style="ordered" -->

1. [Behavior](#behavior)
1. [Requirements](#requirements)
1. [Installation](#installation)
    1. [New installation](#new-installation)
    1. [Upgrade](#upgrade)
1. [Configuration](#configuration)
    1. [Handling a new event](#handling-a-new-event)
1. [Running](#running)
1. [Monitoring](#monitoring)
1. [Acknowledgments](#acknowledgments)
1. [Contributor Code of Conduct](#contributor-code-of-conduct)

<!-- /MarkdownTOC -->

<a id="behavior"></a>
## Behavior

1. Fail2Ban4Win runs in the background as a Windows service.
1. Configuration comes from a JSON file in the installation directory.
1. Fail2Ban4Win listens for Event Log events from various logs and event IDs.
1. When a matching event is created, Fail2Ban4Win extracts the client's IP address from the event data. The IP address is aggregated into a /24 subnet IP range.
1. Fail2Ban4Win keeps track of how many times each subnet has triggered auth failures over the last 24 hours.
1. When a given subnet has failed to authenticate 10 times in the last 24 hours, a Windows Firewall rule is created to block incoming traffic from that subnet on all ports.
1. After being banned for 1 day, the firewall rule is deleted and the subnet is allowed to fail 10 more times before being banned a second time.
1. Each time a subnet is repeatedly banned, the ban duration increases by 1 day, up to a maximum of a four day ban, after which each subsequent ban will always be 4 days.
1. When Fail2Ban4Win restarts, it deletes all firewall rules it created and starts from scratch. This allows it to fail open and avoids persisting the failure history.

You can [customize](#configuration) most of the above specifics.

<a id="requirements"></a>
## Requirements
- Windows 7 or later, or Windows Server 2008 R2 or later
- [.NET Framework 4.8](https://dotnet.microsoft.com/download/dotnet-framework)
- Use Windows Firewall, as opposed to a third-party firewall solution

<a id="installation"></a>
## Installation
<a id="new-installation"></a>
### New installation
1. Download the [latest release](https://github.com/Aldaviva/Fail2Ban4Win/releases) ZIP file (`Fail2Ban4Win-x.x.x.zip`).
1. Extract the contents of the ZIP file to a directory like `C:\Program Files (x86)\Fail2Ban4Win\`.
1. Open an elevated PowerShell window (run it as administrator).
1. Allow PowerShell scripts to run until you close the window.
    ```ps1
    Set-ExecutionPolicy RemoteSigned -Scope Process -Force
    ```
1. Register Fail2Ban4Win as a service.
    ```ps1
    & 'C:\Program Files (x86)\Fail2Ban4Win\Install Service.ps1'
    ```
1. Configure the service in the next section before starting it.

<a id="upgrade"></a>
### Upgrade
1. Download the [latest release](https://github.com/Aldaviva/Fail2Ban4Win/releases) ZIP file (`Fail2Ban4Win-x.x.x.zip`).
1. Extract `Fail2Ban4Win.exe` from the ZIP file to the installation directory.
1. Restart the service using `services.msc`, `Restart-Service Fail2Ban4Win`, or `net stop Fail2Ban4Win & net start Fail2Ban4Win`.

<a id="configuration"></a>
## Configuration
The provided example configuration file has selectors for [Remote Desktop Services](https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-portal), [Cygwin OpenSSH sshd](https://cygwin.com/packages/summary/openssh.html), and [Windows OpenSSH sshd](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview). It also has some example values for `neverBanSubnets` and other properties that you can replace with your own values.

Be aware that `isDryRun` defaults to `true` to avoid accidentally blocking traffic until you're ready.

1. Open the `configuration.json` file from the Fail2Ban4Win installation directory in a text editor. (You may need to start it elevated depending on your file permissions.)
1. Set any of the following properties. 
    |Property name|Default|Description|
    |---|---|---|
    |`isDryRun`|`true`|Firewall rules will only be created or deleted when this is `false`.|
    |`maxAllowedFailures`|`9`|If an IP range (of size `banSubnetBits`) exceeds this number of failures during the `failureWindow`, it will be banned.|
    |`failureWindow`|`1.00:00:00` (1 day)|How long to consider auth failures. By default, 10 failures in 1 day results in a ban. The format is `d.hh:mm:ss`.|
    |`banPeriod`|`1.00:00:00` (1 day)|After enough failures, the IP range will be banned by adding a Windows Firewall block rule, which will be removed after this period of time. The format is `d.hh:mm:ss`.|
    |`banSubnetBits`|`0`|Optional CIDR subnet aggregation size when counting failures and blocking traffic. The example value of `8` bits blocks the /24 subnet, or 255.255.255.0. You can restrict blocking only to the exact IP address by setting this to `0`, which is equivalent to /32.|
    |`banRepeatedOffenseCoefficient`|`0`|How much of the `banPeriod` to add on subsequent offenses (optional). The default `banPeriod` of 1 day and example coefficient of `1` results in a 1 day ban for first offenders, 2 days for 2nd offenders, 3 days for 3rd offenders, and 4 days for 4th offenders or greater. Changing this coefficient from 1 to 2 would result in successive ban durations of 1 day, 3 days, 5 days, and 7 days instead.|
    |`banRepeatedOffenseMax`|`4`|An optional limit on how many repeated offenses can be used to calculate ban duration. By default, the 5th offense and subsequent bans will be capped at same duration as the 4th offense ban, which is 4 days.|
    |`logLevel`|`Info`|Optionally adjust the logging verbosity of Fail2Ban4Win. Valid values are `Trace` (most verbose), `Debug`, `Info`, `Warn`, `Error`, and `Fatal` (least verbose). All messages at the given level will be logged, as well as all messages at less verbose levels, _i.e._ `Warn` will also log `Error` and `Fatal` messages. To see the log output, you must run `Fail2Ban4Win.exe` in a console like Command Prompt or PowerShell.|
    |`neverBanSubnets`|`[]`|Optional whitelist of IP ranges that should never be banned, regardless of how many auth failures they generate. Each item can be a single IP address, like `67.210.32.33`, or a range, like `67.210.32.0/24`.|
    |`eventLogSelectors`|`[]`|Required list of events to listen for in Event Log. Each object in the list can have the following properties.<ul><li>`logName`: required, which log in Event Viewer contains the events, _e.g._ `Application`, `Security`, `OpenSSH/Operational`.</li><li>`eventId`: required, numeric ID of event logged on auth failure, _e.g._ `4625` for RDP auth errors.</li><li>`source`: optional Source, AKA Provider Name, of events, _e.g._ `sshd` for Cygwin OpenSSH sshd. If omitted, events will not be filtered by Source.</li><li>`ipAddressEventDataName`: optional, the `Name` of the `Data` element in the event XML's `EventData` in which to search for the client IP address of the auth request, _e.g._ `IpAddress` for RDP. If omitted, the first `Data` element will be searched instead.</li><li>`ipAddressPattern`: optional, regular expression pattern string that matches the IP address in the `Data` element specified above. Useful if you want to filter out some events from the log with the desired ID and source but that don't describe an auth failure (_e.g._ sshd's disconnect events). If omitted, searches for all IPv4 addresses in the `Data` element's text content. To set [options like case-insensitivity](https://docs.microsoft.com/en-us/dotnet/standard/base-types/miscellaneous-constructs-in-regular-expressions), put `(?i)` at the start of the pattern. Patterns are not anchored to the entire input string unless you surround them with `^` and `$`. If you specify a pattern, ensure the desired IPv4 capture group in your pattern has the name `ipAddress`, _e.g._ <pre lang="regex">Auth failed: (?&lt;ipAddress&gt;(?:\d{1,3}\\.){3}\d{1,3})</pre></li></ul>See [Handling a new event](#handling-a-new-event) below for a tutorial on creating this object.|
1. After saving the configuration file, restart the Fail2Ban4Win service for your changes to take effect. Note that the service will clear existing bans when it starts.

<a id="handling-a-new-event"></a>
### Handling a new event
In this example, we will go through the process of creating an event for Windows OpenSSH sshd. This event is already supported in the example configuration file, but the following process covers all of the necessary steps to add any other event.

1. Ensure OpenSSH Server is installed and running in Windows.
    1. Run `explorer.exe ms-settings:optionalfeatures` or go to Settings › Apps › Apps & features › Manage optional features.
    1. Select Add a feature.
    1. Install OpenSSH Server.
1. Open Event Viewer (`eventvwr.msc`).
1. Find an instance of the event you want. If one doesn't exist, start an SSH client like [ssh](https://linux.die.net/man/1/ssh) or [KiTTY](http://www.9bis.net/kitty/) and fail to authenticate on purpose.
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
1. The `ipAddressEventDataName` value comes from the `<Data>` element that contains the IP address in its text content. In this case, that element has the `Name` attribute value of **`payload`**.
    - If there were just one `<Data>` element with no `Name` attribute, you would omit the `ipAddressEventDataName` property from the event log selector object.
1. The `ipAddressPattern` helps narrow down which events represent auth failures. Some events in this log with ID 4 are caused by successful auth attempts or disconnections, which should not trigger firewall bans. By matching the text of an auth failure, the correct events will be processed. The [following pattern](https://regex101.com/r/ZdJqcT/1) matches only auth failures and captures the IP address in a named group for processing.
    ```regex
    ^Failed password for(?: invalid user)? .+ from (?<ipAddress>(?:\d{1,3}\.){3}\d{1,3}) port \d{1,5} ssh\d?$
    ```
1. Here is the resulting event log selector from all of the above properties.
    ```json
    {
        "logName": "OpenSSH/Operational",
        "source": "OpenSSH",
        "eventId": 4,
        "ipAddressEventDataName": "payload",
        "ipAddressPattern": "^Failed password for(?: invalid user)? .+ from (?<ipAddress>(?:\\d{1,3}\\.){3}\\d{1,3}) port \\d{1,5} ssh\\d?$"
    }
    ```
1. You can add this object to `configuration.json` by appending it to the `eventLogSelectors` array.


<a id="running"></a>
## Running
Do any of the following.
- Start the `Fail2Ban4Win` service from `services.msc`.
- Start the service from PowerShell using `Start-Service Fail2Ban4Win`.
- Start the service from Command Prompt using `net start Fail2Ban4Win`.
- Run the service in the foreground by starting `Fail2Ban4Win.exe` in a console window. This is useful for looking at the log output and verifying your configuration, especially when `isDryRun` is true. You can stop the process using `Ctrl`+`C`.

<a id="monitoring"></a>
## Monitoring
You can see the block rules created by Fail2Ban4Win in Windows Firewall.
1. Start Windows Firewall with Advanced Security (`wf.msc`).
1. Go to `Inbound Rules`.
1. To only show rules created by Fail2Ban4Win, select Action › Filter by Group › Filter by Fail2Ban4Win.
1. To sort by creation time, select View › Add/Remove Columns and Add the Description column, then click the Description column header.

![Windows Firewall with Advanced Security filtering by Fail2Ban4Win rules](https://i.imgur.com/pW12vKL.png)

<a id="acknowledgments"></a>
## Acknowledgments
- My parents for free Windows Server hosting with a static IP address for anyone to connect to.
- A vague awareness of the existence of [`fail2ban`](https://www.fail2ban.org) that convinced me that non-stop RDP and SSH login attempts might have a solution.
- [`wail2ban` by Katie McLaughlin (`glasnt`)](https://github.com/glasnt/wail2ban) for being archived and motivating me to creating my own non-archived implementation.
- [`win2ban`](https://itefix.net/win2ban) for charging twenty-nine American dollars for some cobbled together free open-source projects that made me indignant enough to create my own free, open-source, clean-room implementation.
- [Robert Mustacchi (`rmustacc`)](https://github.com/rmustacc) for talking me out of trying to implement a wait-free list to store failure times and instead continuing to lock array lists.

<a id="contributor-code-of-conduct"></a>
## Contributor Code of Conduct
- Please be nice to me.