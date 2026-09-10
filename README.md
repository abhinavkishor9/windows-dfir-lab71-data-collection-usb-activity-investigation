# Windows DFIR Lab 71 — Data Collection Before USB Activity Investigation

## Overview

This lab simulates a Windows DFIR investigation where an analyst discovers that files may have been collected and staged on a workstation before potential removable-media activity. The objective is to reconstruct the local collection and staging activity using Windows file-system artifacts, PowerShell, Sysmon, SHA256 hashing, archive analysis, and Wazuh telemetry.

The investigation focuses on determining what data was collected, where it was staged, when the activity occurred, which processes were involved, and whether the available evidence supports a connection to later USB-based data transfer.

> **Investigation principle:** Follow the evidence, not the assumption.

## Scenario

A Windows workstation is suspected of having data prepared for possible removal through a USB device. Before investigating removable-media activity, the analyst examines the workstation for evidence of local data collection and staging.

A controlled dataset is created under `C:\DataCollectionUSBLab\SourceData` and then copied into a staging directory. The staged files are subsequently compressed into an archive. The investigation uses file metadata, SHA256 hashes, Sysmon telemetry, PowerShell activity, and Wazuh events to reconstruct this activity.

The lab intentionally stops at the staging and archive-preparation phase. No USB transfer or exfiltration is performed or claimed.

## Objectives

- Establish the Windows host and user context.
- Create and document a controlled dataset.
- Establish SHA256 hashes for the original files.
- Identify the local staging directory.
- Examine file creation and modification activity.
- Use Sysmon Event ID 11 to investigate file creation.
- Correlate file activity with process telemetry where available.
- Validate staged files using SHA256 hashes.
- Create and investigate a compressed archive.
- Review relevant telemetry in Wazuh Discover.
- Build a chronological investigation timeline.
- Separate confirmed evidence from assumptions.
- Identify telemetry gaps and investigative limitations.

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

## Evidence Assessment

### Confirmed

- A controlled dataset was created on the workstation.
- The files were copied into a local staging directory.
- Source and staged file hashes matched.
- A compressed archive was created from the staged files.
- Sysmon and Wazuh provided Windows file/process telemetry.
- PowerShell was used during the controlled collection and archive workflow.

### Plausible

- The staging directory represents a dataset prepared for subsequent handling or transfer.
- The archive could be suitable for later transfer to removable media.

### Not Established

- A USB device was connected.
- The archive was copied to a USB device.
- Data was successfully exfiltrated.
- The activity was malicious.
- The user intended to steal or exfiltrate the data.

## ATT&CK Considerations

The observed behavior can be mapped conceptually to:

- **T1005 — Data from Local System**
- **T1074 — Data Staged**
- **T1074.001 — Local Data Staging**

These references describe behavioral categories relevant to the investigation. They should not be interpreted as proof that an adversary performed the activity.

## Telemetry Limitations

This lab demonstrates why individual events should not be interpreted in isolation.

Sysmon Event ID 11 provides file creation telemetry, but it does not automatically establish:

- the reason a file was created,
- whether it was copied from another location,
- whether it was transferred externally,
- whether the user acted maliciously.

Process correlation, file hashes, timestamps, command lines, archive metadata, USB connection artifacts, and additional endpoint telemetry would be required for a stronger conclusion.

## Investigation Conclusion

The investigation successfully confirmed a local collection and staging sequence followed by archive preparation. The controlled files were staged and their SHA256 hashes matched the originals, while PowerShell was used during the workflow. However, the available evidence does not establish USB transfer, exfiltration, or malicious intent. The correct DFIR conclusion is therefore that **local data staging and archive preparation were observed, while subsequent removable-media transfer remains unconfirmed**.
