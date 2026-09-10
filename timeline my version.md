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

