# Troubleshooting Notes

## 1. Large Number of Sysmon Event ID 1 Results

### Observation

The unfiltered Sysmon Event ID 1 query returned many process-creation events.

### Explanation

Sysmon Event ID 1 records process creation across the system, so a large number of results is expected on an active Windows workstation.

### Approach

A targeted search was then performed using:

`Compress-Archive|powershell.exe|staged-data.zip`

This reduced the investigation to events that contained the relevant search terms.

### DFIR Lesson

Do not rely on an unfiltered process-creation list. Use timestamps, process names, command lines, users, and parent processes to narrow the investigation.

---

## 2. Targeted Sysmon Event ID 1 Results Did Not Show Full Event Details

### Observation

The targeted query returned entries such as:

`Process Create:...`

instead of displaying the complete message.

### Explanation

The screenshot captured the query output in a truncated form.

### Investigation Impact

The result confirms that matching process-creation events were returned, but the available screenshot does not provide enough information to verify the exact command line, parent process, or process ID for each result.

### DFIR Lesson

Do not overstate truncated evidence. Record exactly what the available telemetry proves.

---

## 3. Sysmon Event ID 11 Targeted Search Returned No Result

### Observation

The targeted query searched for:

- `staged-data.zip`
- `SuspiciousCompressionLab`

No matching result was displayed.

### Explanation

The filesystem confirmed that the archive existed, but the provided Sysmon query output did not show a corresponding Event ID 11 record.

### Conclusion

The archive was confirmed through direct filesystem inspection, but Sysmon Event ID 11 evidence for the archive was not established.

### DFIR Lesson

A file can be confirmed without a corresponding telemetry event. The telemetry gap should be documented rather than converted into a claim that the file was never monitored.

---

## 4. PowerShell Event ID 4104 Search Returned No Result

### Observation

The query searched for:

`Compress-Archive|staged-data.zip|SuspiciousCompressionLab`

No result was displayed.

### Explanation

The query did not identify a matching Script Block Logging event in the returned results.

### Conclusion

No matching 4104 event was established from the screenshot.

This does not prove that PowerShell was not used.

---

## 5. Security Event ID 4688 Search Returned No Result

### Observation

The query searched for:

`powershell.exe|Compress-Archive`

No matching event was displayed.

### Conclusion

Security 4688 did not provide supporting evidence in the provided screenshot set.

### DFIR Lesson

Different telemetry sources provide different visibility. The absence of an event in one source does not automatically invalidate evidence collected elsewhere.

---

## 6. Many Sysmon Event ID 3 Network Connections

### Observation

The Sysmon Event ID 3 query returned numerous network connection events.

### Problem

The output did not provide sufficient process-level details to associate the displayed network traffic with the archive.

### Correct Interpretation

The host generated network activity during the investigation period.

The screenshots do not establish:

- Archive transfer.
- Destination of the archive.
- Process responsible for the transfer.
- Exfiltration.

### DFIR Lesson

Network activity must be correlated with the responsible process and destination before it can be associated with suspected data staging or exfiltration.

---

## 7. Archive Size Was Smaller Than the Combined Source Files

### Observation

The source files totaled:

26 + 26 + 24 = 76 bytes

The resulting ZIP archive was:

430 bytes

### Explanation

A ZIP archive contains archive structure and metadata in addition to the compressed file contents. Small input files may therefore produce an archive that is larger than their combined raw size.

### DFIR Lesson

Archive size alone should not be used to determine whether compression occurred successfully or whether an archive is suspicious.

---

## 8. Archive Validation

### Observation

The archive was extracted successfully using `Expand-Archive`.

### Result

The expected three files appeared in the extraction directory.

### Conclusion

The archive contents were validated successfully.

### DFIR Lesson

When investigating an archive, inspect the actual contents rather than inferring them from the filename.

---

## 9. Cleanup

The lab was removed with:

`Remove-Item "C:\SuspiciousCompressionLab" -Recurse -Force`

The cleanup was verified using:

`Test-Path "C:\SuspiciousCompressionLab"`

Result:

`False`

This confirms that the controlled test environment was removed after the investigation.

---

