# windows-dfir-lab71-data-collection-usb-activity-investigation
## Overview
A common DFIR scenario is discovering that a user or process collected or staged files shortly before USB activity.

The important investigative question is not simply:

“Was a USB device connected?”

Instead:

“What data was collected or staged before the USB activity, who collected it, and what evidence connects the collection activity to the later removable-media event?”

An attacker may first gather documents, credentials, reports, archives, or other sensitive files into a temporary directory. Only afterward might they connect a USB device and copy the staged data.

The strongest finding is not:

“Several files existed in a staging directory.”

It is:

“User X, using Process Y, created or copied specific files into a staging location during a defined time window, creating a dataset that could subsequently be transferred to removable media.”

This lab simulates a Windows DFIR investigation where an analyst discovers that files may have been collected and staged on a workstation before potential removable-media activity. The objective is to reconstruct the local collection and staging activity using Windows file-system artifacts, PowerShell, Sysmon, SHA256 hashing, archive analysis, and Wazuh telemetry.

The investigation focuses on determining what data was collected, where it was staged, when the activity occurred, which processes were involved, and whether the available evidence supports a connection to later USB-based data transfer.


## Scenario

A Windows workstation is suspected of having files collected and staged before possible USB-based transfer. The analyst investigates the local activity to determine what was collected, when it was staged, and which processes were involved.

In this controlled lab, files are copied from a source directory into a staging location, validated using SHA256 hashes, and compressed into an archive. Sysmon and Wazuh telemetry are reviewed to reconstruct the activity.

- Identify the collected and staged files.
- Correlate file and process activity.
- Validate files using SHA256.
- Investigate archive creation.
- Separate confirmed evidence from assumptions.

USB transfer or exfiltration is not assumed without supporting evidence.

## Objectives

- Identify files collected and staged on the Windows workstation.
- Establish a baseline using file timestamps and SHA256 hashes.
- Investigate file creation activity using Sysmon Event ID 11.
- Correlate file activity with PowerShell and process telemetry.
- Validate staged files against the original hashes.
- Investigate the creation of the compressed archive.
- Review relevant telemetry in Wazuh Discover.
- Build a timeline of the collection and staging activity.
- Distinguish confirmed evidence from assumptions about USB transfer or exfiltration.

## Lab Environment

| Component | Value |
|---|---|
| Hostname | `DESKTOP-9MMM37V` |
| User | `desktop-9mmm37v\dell` |
| PowerShell | `7.6.6` |
| Operating System | Windows |
| Sysmon | Installed |
| Wazuh Agent | `4.12.0` |
| SIEM | Wazuh |
| Primary telemetry | Sysmon Operational Log |
| Hash algorithm | SHA256 |

## Lab Directory Structure

```text
C:\DataCollectionUSBLab\
├── Archive\
├── Evidence\
├── SourceData\
└── Staging\
```

### Source Data

The controlled source dataset contains:

```text
Application-Inventory.txt
Employee-Onboarding.txt
IR-Contacts.txt
Security-Review.txt
```

The files were created under:

```text
C:\DataCollectionUSBLab\SourceData
```

Their original SHA256 hashes were recorded before staging.

## Investigation Workflow

### 1. Establish Host Context

The hostname, user account, date/time, and PowerShell version were recorded before beginning the investigation.

```powershell
hostname
whoami
Get-Date
$PSVersionTable.PSVersion
```

This establishes the environment in which the controlled activity occurred.

### 2. Create the Source Dataset

The benign files were created inside:

```text
C:\DataCollectionUSBLab\SourceData
```

The files were then reviewed using PowerShell to document their size and timestamps.

### 3. Hash the Original Files

SHA256 hashes were generated for the source files.

```powershell
Get-ChildItem "$Lab\SourceData" -File |
    Get-FileHash -Algorithm SHA256
```

The resulting hashes were stored in:

```text
C:\DataCollectionUSBLab\Evidence\source-hashes.txt
```

### 4. Stage the Files

The source files were copied into:

```text
C:\DataCollectionUSBLab\Staging
```

The staged files retained the same SHA256 values as the originals.

This demonstrates that the same file content existed in both the source and staging locations.

### 5. Investigate File Creation

Sysmon Event ID 11 was reviewed to identify file creation activity.

Example telemetry included:

```text
Event ID: 11
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Windows\SystemTemp\_PSScriptPolicyTest_0bquwsf24.om1.ps1
User: NT AUTHORITY\SYSTEM
```

These PowerShell policy-test files were treated as telemetry noise rather than evidence of malicious collection.

The important investigative point is that Event ID 11 identifies file creation activity but does not, by itself, prove that a file was copied or exfiltrated.

### 6. Correlate Process Activity

Where available, Sysmon Event ID 1 can be correlated with Event ID 11 using fields such as:

- Process ID
- Process GUID
- Timestamp
- Image
- Command line

This provides stronger evidence about which process generated the file activity.

### 7. Validate the Staged Files

The source and staging hashes were compared.

The hashes matched for all four controlled files:

| File | Source SHA256 | Staging SHA256 |
|---|---|---|
| Application-Inventory.txt | `603D6D4887EFCD814E4CCA83436C173F69CF61AA0348C0C7934715F4C4E6B339` | Match |
| Employee-Onboarding.txt | `5B883AAA9E6F77DCB105686BCFE4142CB4C2215B07F50ADDE8E0F6A84EBD887B` | Match |
| IR-Contacts.txt | `F3CBEDCB169FC765050DD870CF60E7AD365C161DEE773DABAB905E6B8EBB9E2F` | Match |
| Security-Review.txt | `DBEF917FE1C48C58540F20342E40B4E3C4AF7326715BAFD312C9BAD0166479A3` | Match |

The matching hashes provide strong evidence that the staged files contained the same content as the original source files.

### 8. Create the Archive

The staged files were compressed using PowerShell:

```powershell
Compress-Archive `
    -Path "$Lab\Staging\*" `
    -DestinationPath "$Lab\Archive\collected-data.zip" `
    -Force
```

The resulting archive was:

```text
C:\DataCollectionUSBLab\Archive\collected-data.zip
```

Recorded archive SHA256:

```text
EADD931C305972290CB8E8C799C47D0E2721E305BAAEC52A784F36EA1C8C1BA5
```

### 9. Review Wazuh Telemetry

Wazuh Discover was used to review archived Windows and Sysmon telemetry.

Relevant fields included:

```text
data.win.eventdata.utcTime
data.win.system.channel
data.win.system.computer
data.win.system.eventID
data.win.system.eventRecordID
data.win.eventdata.processId
data.win.eventdata.processGuid
data.win.eventdata.image
data.win.eventdata.targetFilename
```

This allowed the analyst to examine file activity and distinguish controlled lab activity from unrelated Windows background activity.

## ATT&CK Considerations

The observed behavior can be mapped conceptually to:

- **T1005 — Data from Local System**
- **T1074 — Data Staged**
- **T1074.001 — Local Data Staging**

These references describe behavioral categories relevant to the investigation. They should not be interpreted as proof that an adversary performed the activity.

