# Investigation Notes — Data Collection Before USB Activity

## Investigation Overview

This investigation examines a controlled Windows scenario in which several files are collected into a local staging directory before being compressed into an archive. The objective is to determine what data was staged, when the activity occurred, how the files were handled, and what endpoint telemetry can support the sequence.

The investigation deliberately avoids assuming that staging resulted in USB transfer or exfiltration.

## Host Context

```text
Hostname: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
PowerShell: 7.6.6
```

The environment was verified before beginning the controlled activity.

## Investigation Question

The primary question is:

> What data was collected or staged before potential USB activity, who collected it, and what evidence connects the collection activity to later removable-media activity?

The available lab evidence can answer the first part of this question but cannot establish the final USB transfer.

## Source Dataset

The controlled source files were stored in:

```text
C:\DataCollectionUSBLab\SourceData
```

Files:

```text
Security-Review.txt
Employee-Onboarding.txt
IR-Contacts.txt
Application-Inventory.txt
```

Their recorded sizes were:

```text
Security-Review.txt        88 bytes
Employee-Onboarding.txt    66 bytes
IR-Contacts.txt            67 bytes
Application-Inventory.txt  58 bytes
```

The files had a LastWriteTime of:

```text
10-09-2026 08:27:16
```

## Source Hashes

SHA256 values were recorded before staging.

```text
Application-Inventory.txt
603D6D4887EFCD814E4CCA83436C173F69CF61AA0348C0C7934715F4C4E6B339

Employee-Onboarding.txt
5B883AAA9E6F77DCB105686BCFE4142CB4C2215B07F50ADDE8E0F6A84EBD887B

IR-Contacts.txt
F3CBEDCB169FC765050DD870CF60E7AD365C161DEE773DABAB905E6B8EBB9E2F

Security-Review.txt
DBEF917FE1C48C58540F20342E40B4E3C4AF7326715BAFD312C9BAD0166479A3
```

The hashes were stored in:

```text
C:\DataCollectionUSBLab\Evidence\source-hashes.txt
```

## Staging Activity

The source files were copied into:

```text
C:\DataCollectionUSBLab\Staging
```

The staged files showed:

```text
CreationTime: 10-09-2026 08:29:40
LastWriteTime: 10-09-2026 08:27:16
```

The difference between CreationTime and LastWriteTime is consistent with the files being created in the source location first and subsequently copied into the staging directory.

This supports the staging sequence, although timestamps alone should not be treated as proof of malicious intent.

## Hash Validation

The SHA256 values of the staged files were compared with the original source hashes.

All four files matched.

This establishes that the staged copies contained the same content as the original controlled dataset.

Hash equality is stronger evidence than filename comparison because it demonstrates content equivalence.

## Sysmon File Creation Evidence

Sysmon Event ID 11 was reviewed for file creation activity.

An example event showed:

```text
Event ID: 11
UtcTime: 2026-09-10 03:22:05.236
ProcessId: 3148
ProcessGuid: {6a3a75f0-225d-6aa2-ea2e-000000000900}
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Windows\SystemTemp\_PSScriptPolicyTest_0bquwsf24.om1.ps1
User: NT AUTHORITY\SYSTEM
```

This event was not treated as evidence of the controlled data collection.

The filename and location are consistent with PowerShell policy-test activity. This demonstrates an important DFIR issue: a high-volume file creation feed can contain legitimate operating-system and application activity.

## Wazuh Evidence

Wazuh telemetry was reviewed using Sysmon and Windows event fields.

Another Event ID 11 record showed:

```text
UtcTime: 2026-09-10 04:39:00.589
Channel: Microsoft-Windows-Sysmon/Operational
Computer: DESKTOP-9MMM37V
Event ID: 11
EventRecordID: 181435
ProcessId: 21832
Image: PowerShell
TargetFilename: C:\Windows\SystemTemp\__PSScriptPolicyTest_sccyllgi.h3i.ps1
```

This was also treated as background PowerShell policy-test activity rather than evidence of malicious staging.

The example demonstrates why analysts should correlate:

- process identity,
- file path,
- timestamps,
- process GUID,
- command line,
- user,
- surrounding events.

## Archive Creation

The staged files were compressed into:

```text
C:\DataCollectionUSBLab\Archive\collected-data.zip
```

The archive size was:

```text
764 bytes
```

SHA256:

```text
EADD931C305972290CB8E8C799C47D0E2721E305BAAEC52A784F36EA1C8C1BA5
```

The archive provides an additional artifact showing that the staged dataset was packaged.

However, archive creation does not prove that the archive was transferred anywhere.

## Evidence Interpretation

### Confirmed Evidence

1. Four controlled files were created.
2. Their original hashes were documented.
3. The files were copied into a local staging directory.
4. The staged files matched the original hashes.
5. The staged dataset was compressed into a ZIP archive.
6. PowerShell was used during the lab workflow.
7. Sysmon and Wazuh captured Windows file/process telemetry.

### Interpretation

The sequence is consistent with:

```text
Source Data
    |
    v
Local Staging
    |
    v
Hash Validation
    |
    v
Archive Creation
```

This represents a complete local preparation sequence.

### Not Confirmed

The following were not established:

```text
USB Device Connection
        |
        v
USB File Transfer
        |
        v
External Exfiltration
```

No evidence in the controlled lab establishes these steps.

## Strongest Investigative Finding

The strongest finding is not simply that several files existed inside a staging directory.

The stronger finding is:

> A controlled dataset was created on the Windows workstation, subsequently copied into a dedicated local staging directory, verified through matching SHA256 hashes, and packaged into an archive using PowerShell.

This provides a defensible description of the observed activity without extending the evidence into an unsupported claim of exfiltration.

## Telemetry Gaps

The investigation would require additional evidence to determine whether the staged archive was later transferred.

Useful additional telemetry would include:

- USB device connection events.
- Windows Kernel-PnP events.
- USBSTOR registry artifacts.
- ShellBags or other relevant filesystem artifacts.
- File creation events on removable volumes.
- Process creation around the suspected USB connection.
- Wazuh events associated with removable storage.
- Prefetch or other execution artifacts where applicable.
- Endpoint detection telemetry.
- Network telemetry if external transfer occurred.

## Final Assessment

The lab confirms local data collection, staging, hash validation, and archive preparation.

The evidence does not establish USB transfer, successful exfiltration, or malicious intent.

The appropriate DFIR verdict is:

```text
CONFIRMED:
Local data staging and archive preparation.

NOT ESTABLISHED:
USB transfer, exfiltration, or malicious intent.
```
