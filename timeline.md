# Investigation Timeline — Data Collection Before USB Activity

## Timeline

| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| 08:25:39 | Host environment verified | PowerShell `Get-Date`, hostname, user, PowerShell version | Confirmed |
| 08:26 | Lab directory structure established | `C:\DataCollectionUSBLab\` | Confirmed |
| 08:27:16 | Source dataset files created/available | Four files under `SourceData` with recorded LastWriteTime | Confirmed |
| 08:27 | Original file hashes recorded | `Evidence\source-hashes.txt` | Confirmed |
| 08:29:40 | Staged files show new CreationTime | Files under `Staging` | Consistent with local staging |
| 09:48:36 | ZIP archive created | `Archive\collected-data.zip` | Confirmed |
| 09:48+ | Archive SHA256 recorded | `EADD931C305972290CB8E8C799C47D0E2721E305BAAEC52A784F36EA1C8C1BA5` | Confirmed |
| 09:54 | Archive-related investigation/review performed | PowerShell/Sysmon review | Confirmed |
| 08:52:05 | PowerShell policy-test file observed in Sysmon | Event ID 11 | Background telemetry |
| 10:09:00.589 | PowerShell policy-test file observed in Wazuh | Sysmon Event ID 11 | Background telemetry |

## Detailed Timeline

### 08:25:39 — Environment Verification

The analyst verified the workstation context.

```text
Hostname: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
PowerShell: 7.6.6
```

This establishes the environment in which the controlled investigation was performed.

### 08:26 — Lab Structure

The investigation directories were established:

```text
C:\DataCollectionUSBLab\
├── Archive\
├── Evidence\
├── SourceData\
└── Staging\
```

### 08:27:16 — Source Dataset

Four controlled files were present in:

```text
C:\DataCollectionUSBLab\SourceData
```

Their recorded LastWriteTime was:

```text
10-09-2026 08:27:16
```

### 08:27 — Baseline Hashing

SHA256 hashes were generated for the four source files and saved to:

```text
C:\DataCollectionUSBLab\Evidence\source-hashes.txt
```

This established a baseline for later comparison.

### 08:29:40 — Local Staging

The files appeared in:

```text
C:\DataCollectionUSBLab\Staging
```

with CreationTime:

```text
10-09-2026 08:29:40
```

The staged files retained the source LastWriteTime.

The source and staging hashes subsequently matched.

### 09:48:36 — Archive Creation

PowerShell created:

```text
C:\DataCollectionUSBLab\Archive\collected-data.zip
```

Archive size:

```text
764 bytes
```

Archive SHA256:

```text
EADD931C305972290CB8E8C799C47D0E2721E305BAAEC52A784F36EA1C8C1BA5
```

This confirms the staged dataset was packaged into an archive.

### 09:54 — Archive Investigation

The archive and associated telemetry were reviewed using PowerShell and Sysmon-related investigation steps.

This represents analyst investigation activity rather than a separate confirmed collection event.

### 08:52:05 — Background PowerShell Policy-Test Event

Sysmon Event ID 11 recorded a PowerShell-created file:

```text
C:\Windows\SystemTemp\_PSScriptPolicyTest_0bquwsf24.om1.ps1
```

The event was treated as unrelated background PowerShell policy-test activity.

### 10:09:00.589 — Wazuh Background Telemetry

Wazuh showed another Sysmon Event ID 11 record at:

```text
2026-09-10 04:39:00.589 UTC
```

The target file was:

```text
C:\Windows\SystemTemp\__PSScriptPolicyTest_sccyllgi.h3i.ps1
```

This was also treated as background PowerShell policy-test activity and was not connected to the controlled staging sequence.

## Investigative Sequence

The core evidence chain is:

```text
Controlled Source Files
        |
        v
Source SHA256 Baseline
        |
        v
Local Staging Directory
        |
        v
Matching SHA256 Hashes
        |
        v
Archive Creation
        |
        v
Archive SHA256
```

## Final Timeline Assessment

The timeline supports a confirmed sequence of:

```text
Data Creation
    ->
Local Staging
    ->
Hash Validation
    ->
Archive Preparation
```

The timeline does not contain sufficient evidence to extend the sequence to:

```text
USB Connection
    ->
USB Transfer
    ->
Exfiltration
```

Those events remain unconfirmed.
