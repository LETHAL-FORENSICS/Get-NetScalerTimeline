# DuckDB Queries

Threat hunting queries for the DuckDB database created by Get-NetScalerTimeline.ps1.

```sql
-- Title: Bodyfile (All Entries)
-- Description: Lists all entries of the bodyfile (table NetScaler): one row per file, directory, symbolic link, deleted file and orphan file of /flash and /var, incl. file type, status, timestamps (UTC) and hashes (if -Hash was used). Sorted by change time (ctime), newest first.
-- Id: 824b7127-f7d4-4fe8-bc9e-83a49ac1cdf0
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT * FROM NetScaler
```

```sql
-- Title: Total Records
-- Description: Counts all entries of the bodyfile (table NetScaler): files, directories, symbolic links, deleted and orphan files of /flash and /var. Should match the "Total Rows" output of Get-NetScalerTimeline.ps1.
-- Id: 938c8004-bac4-4e7f-82a5-5145c0a9a70c
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT COUNT(*) AS Total FROM NetScaler;
```

```sql
-- Title: All file system events between two timestamps (UTC)
-- Description: Lists all file system events within a time window (UTC). Set ts_start and ts_end (exclusive) to the window of interest. Result 1: All events from the Timeline view (Accessed, Modified, Changed, Birth), one row per timestamp. Result 2: All files and directories with a change time (ctime) in the window, one row per file. ctime cannot be set from user space (e.g. touch) and is therefore the most reliable timestamp.
-- Id: 45275f4f-ff3d-40ae-8ca1-88dc389228f5
-- Author: Martin Willing
-- Date: 2026-10-04
SET VARIABLE ts_start = TIMESTAMP '2026-09-20 00:00:00';
SET VARIABLE ts_end   = TIMESTAMP '2026-09-22 00:00:00';  -- exclusive

SELECT *
FROM Timeline
WHERE Timestamp >= getvariable('ts_start')
  AND Timestamp <  getvariable('ts_end')
ORDER BY Timestamp;

SELECT *
FROM NetScaler
WHERE LastChangeTime >= getvariable('ts_start')
  AND LastChangeTime <  getvariable('ts_end')
ORDER BY LastChangeTime;
```

```sql
-- Title: Timestamp Mismatch (ctime vs. mtime)
-- Description: Lists regular files whose inode change time (ctime) is more than one day later than their modification time (mtime). Indicates files that were placed on disk long after their content date (e.g. timestomping, archives extracted with preserved timestamps, copied files). Note: Firmware upgrades cause large clusters of benign hits.
-- Id: 051b3e21-ca78-4629-8ba7-2afeebea33df
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT Path, LastModificationTime, LastChangeTime,
       date_diff('day', LastModificationTime, LastChangeTime) AS Days_Diff
FROM NetScaler
WHERE Type = 'Regular File'
  AND LastChangeTime - LastModificationTime > INTERVAL 1 DAY
ORDER BY LastChangeTime DESC;
```

```sql
-- Title: Changed Files (ctime): Last 24h
-- Description: Lists all files and directories with a change time (ctime) within the last 24 hours before the last activity on the image (not before now, so it also works on images acquired days later). ctime is updated on every content or metadata change (write, chmod, chown, rename) and cannot be set from user space (e.g. touch). Reads (atime) are not included, use the Timeline view for those. Result 1 shows the computed window (sanity check), result 2 the changed files. Note: /var/log and /var/nslog change constantly and dominate the results.
-- Id: c61caccd-f6d8-4c15-a949-14b98762a39d
-- Author: Martin Willing
-- Date: 2026-10-04
SET VARIABLE ts_end   = (SELECT MAX(LastChangeTime) FROM NetScaler);
SET VARIABLE ts_start = getvariable('ts_end') - INTERVAL 24 HOUR;

-- Sanity check: confirm the computed window before trusting the result set below
SELECT getvariable('ts_start') AS WindowStart, getvariable('ts_end') AS WindowEnd;

SELECT *
FROM NetScaler
WHERE LastChangeTime BETWEEN getvariable('ts_start') AND getvariable('ts_end')
ORDER BY LastChangeTime;
```

```sql
-- Title: All Events (incl. Reads): Last 24h
-- Description: Lists all file system events (Accessed, Modified, Changed, Birth) within the last 24 hours before the last activity on the image (not before now, so it also works on images acquired days later). Unlike the ctime query, this includes reads (atime), e.g. an attacker reading ns.conf or private keys in /flash/nsconfig/ssl. The window end is anchored to the latest ctime, because mtime and atime can be set from user space (e.g. touch) and a single forged timestamp would shift the window. Result 1 shows the computed window (sanity check), result 2 the events from the Timeline view (one row per timestamp). Note: /var/log and /var/nslog change constantly and dominate the results.
-- Id: 147c754f-3110-4e2e-90aa-d45a9c79e450
-- Author: Martin Willing
-- Date: 2026-10-04
SET VARIABLE ts_end   = (SELECT MAX(LastChangeTime) FROM NetScaler);
SET VARIABLE ts_start = getvariable('ts_end') - INTERVAL 24 HOUR;

-- Sanity check: confirm the computed window before trusting the result set below
SELECT getvariable('ts_start') AS WindowStart, getvariable('ts_end') AS WindowEnd;

SELECT *
FROM Timeline
WHERE Timestamp BETWEEN getvariable('ts_start') AND getvariable('ts_end')
ORDER BY Timestamp;
```

```sql
-- Title: Web Shell Persistence (/var/netscaler/gui/vpn/scripts/linux)
-- Description: Lists all events for /var/netscaler/gui/vpn/scripts/linux and its contents (Newest First). This directory is served via the URL /vpn/scripts/linux (Alias in httpd.conf) and normally holds the NetScaler Gateway client packages for Linux (.deb). In the CVE-2026-88771/88772 campaign (Sep 2026), web shells were staged here as .deb files with names that mimic legitimate client packages (e.g. nsgclient18.deb, nsg64.deb). Check new or changed .deb files (ctime) outside firmware upgrades, files owned by nobody (UID 65534) and compare hashes (-Hash) against the IOCs. Includes the directory itself: its mtime/ctime changes when files are added, deleted or renamed.
-- Id: e355eff1-3506-462f-a2cb-b21ed2743b21
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT Timestamp, Timestamp_Info, Status, Path, Type, Bytes, FileSize, Mode, UID, GID, Inode
FROM Timeline
WHERE Path = '/var/netscaler/gui/vpn/scripts/linux'
   OR starts_with(Path, '/var/netscaler/gui/vpn/scripts/linux/')
ORDER BY Timestamp DESC;
```

```sql
-- Title: Trojanized Client Installers (/var/netscaler/gui/vpns/scripts/vista)
-- Description: Lists all events for /var/netscaler/gui/vpns/scripts/vista and its contents (Newest First). This directory holds the NetScaler Gateway VPN client installers for Windows. httpd.conf only exposes three files via the URL /vpns/scripts/vista/ (nsvpnc_setup64.exe, nsvpnc_setup.exe, AGEE_setup.exe), so other files placed here are not reachable without a modified httpd.conf. The main risk is a replaced installer that infects every user who downloads the VPN client. Check changed .exe files (ctime) outside firmware upgrades, files owned by nobody (UID 65534) and compare hashes (-Hash) with the installer of the same firmware build (e.g. under /var/nsinstall). Includes the directory itself: its mtime/ctime changes when files are added, deleted or renamed.
-- Id: 6cb70fad-ae25-45f0-aef2-d7d2eeec80d5
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT Timestamp, Timestamp_Info, Status, Path, Type, Bytes, FileSize, Mode, UID, GID, Inode
FROM Timeline
WHERE Path = '/var/netscaler/gui/vpns/scripts/vista'
   OR starts_with(Path, '/var/netscaler/gui/vpns/scripts/vista/')
ORDER BY Timestamp DESC;
```

```sql
-- Title: Trojanized Client Installers (/var/netscaler/gui/vpns/scripts/mac)
-- Description: Lists all events for /var/netscaler/gui/vpns/scripts/mac and its contents (Newest First). This directory holds the NetScaler Gateway VPN client for macOS (Citrix_Access_Gateway.dmg). Unlike scripts/vista, httpd.conf exposes the whole directory via the URL /vpns/scripts/mac, so any file placed here is downloadable. PHP is disabled in the VPN virtual host, so a PHP web shell here only executes with a modified httpd.conf (RAM disk, not part of the image). Main risks: a replaced installer that infects every user who downloads the VPN client, and attacker files hosted for download. Check new or changed files (ctime) outside firmware upgrades, files owned by nobody (UID 65534) and compare hashes (-Hash) with the installer of the same firmware build. Includes the directory itself: its mtime/ctime changes when files are added, deleted or renamed.
-- Id: 3097a60b-856d-4825-a7a7-12db261c5f5f
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT Timestamp, Timestamp_Info, Status, Path, Type, Bytes, FileSize, Mode, UID, GID, Inode
FROM Timeline
WHERE Path = '/var/netscaler/gui/vpns/scripts/mac'
   OR starts_with(Path, '/var/netscaler/gui/vpns/scripts/mac/')
ORDER BY Timestamp DESC;
```

```sql
-- Title: Web Shell Persistence (/var/vpn/theme and /var/vpn/themes)
-- Description: Lists all events for the VPN portal theme directories /var/vpn/theme and /var/vpn/themes and their contents (Newest First). Both are internet-facing: httpd.conf exposes them via the URLs /vpn/theme, /vpns/theme, /vpn/themes and /vpns/themes. They normally contain theme assets only (e.g. css, js, images, fonts). Check server-side scripts (e.g. .php, .pl, .sh), unexpected file types, hidden files, files owned by nobody (UID 65534, i.e. most likely written via HTTP) and new or changed files (ctime) outside theme changes or firmware upgrades. Includes the directories themselves: their mtime/ctime changes when files are added, deleted or renamed.
-- Id: dc8eed93-cbb0-41be-813a-080cf8edc8ad
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT Timestamp, Timestamp_Info, Status, Path, Type, Bytes, FileSize, Mode, UID, GID, Inode
FROM Timeline
WHERE Path = '/var/vpn/theme'
   OR starts_with(Path, '/var/vpn/theme/')
ORDER BY Timestamp DESC;
```

```sql
-- Title: Web Shell Persistence (/var/netscaler/logon/LogonPoint/custom)
-- Description: Lists all events for /var/netscaler/logon/LogonPoint/custom and its contents (Newest First). This directory holds the customizations of the Gateway login page (e.g. css, js, images) and is internet-facing via the URL /logon/LogonPoint/custom. In the CVE-2026-88771 campaign (Sep 2026), a hidden PHP web shell was placed here as .ctxs.receiver and served via a modified httpd.conf as /logon/LogonPoint/custom/receiver.min.css (Unit 42). Check hidden files (names starting with a dot), server-side scripts, files owned by nobody (UID 65534) and new or changed files (ctime). Note: At every Apache start, NetScaler touches files under /var/netscaler/logon that are older than 34 days, so clusters of identical timestamps are expected and an old web shell may show a recent mtime/ctime. Includes the directory itself: its mtime/ctime changes when files are added, deleted or renamed.
-- Id: 118cb5dd-22f4-4cc9-b741-e204b5fe154b
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT Timestamp, Timestamp_Info, Status, Path, Type, Bytes, FileSize, Mode, UID, GID, Inode
FROM Timeline
WHERE Path = '/var/netscaler/logon/LogonPoint/custom'
   OR starts_with(Path, '/var/netscaler/logon/LogonPoint/custom/')
ORDER BY Timestamp DESC;
```

```sql
-- Title: RAM Disk Coverage Check
-- Description: Checks whether paths of the NetScaler root file system (RAM disk) exist in the image. The root file system (e.g. /etc, /netscaler, /bin) is rebuilt from the firmware at every boot and is not part of the VMDK, so all counts are expected to be 0. Artifacts like /etc/httpd.conf or web shells under /netscaler/ns_gui must be collected from the live system (e.g. UAC). A count greater than 0 means the image contains more than /flash and /var (e.g. a different disk layout), so check the partitions found by the script.
-- Id: 37f09a48-9423-403c-9fb7-552beff3a191
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT p AS Path, COUNT(n.Path) AS Entries
FROM (VALUES ('/netscaler/'),
             ('/etc/'),
             ('/bin/'),
             ('/sbin/'),
             ('/usr/')) AS t(p)
LEFT JOIN NetScaler n ON starts_with(n.Path, t.p)
GROUP BY p
ORDER BY p;
```

```sql
-- Title: NetScaler Boot Persistence (Startup Scripts)
-- Description: Lists all events for the NetScaler startup scripts rc.netscaler, nsbefore.sh and nsafter.sh under /flash/nsconfig (Newest First). These scripts run at every boot and are the main way to restore RAM disk changes after a reboot (e.g. web shells under /netscaler/ns_gui, a modified /etc/httpd.conf, a SUID /bin/sh). They often do not exist at all, so their presence alone is worth a closer look. Check new or changed scripts (ctime) and extract them for review (icat, offset of /flash, Inode). An empty result means none of the scripts exist (also not as deleted entries).
-- Id: 67bac5ad-48b8-43d9-8989-b01fe018e44c
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT Timestamp, Timestamp_Info, Status, Path, Bytes, Mode, UID, GID
FROM Timeline
WHERE starts_with(Path, '/flash/nsconfig/')
  AND FileName IN ('rc.netscaler', 'nsbefore.sh', 'nsafter.sh')
ORDER BY Timestamp DESC;
```

```sql
-- Title: Web Shell Persistence (VPN and Web GUI Paths)
-- Description: Lists all events for the critical internet-facing VPN and Web GUI paths on persistent storage (/var) in one result (Newest First): /var/netscaler/gui/vpn/scripts/linux, /var/netscaler/gui/vpns/scripts/vista, /var/netscaler/gui/vpns/scripts/mac, /var/vpn/theme, /var/vpn/themes and /var/netscaler/logon/LogonPoint/custom. Overview of the individual Web Shell Persistence queries. Check hidden files, server-side scripts, .deb/.sig files, files owned by nobody (UID 65534) and new or changed files (ctime) outside firmware upgrades. Includes the directories themselves: their mtime/ctime changes when files are added, deleted or renamed. Note: /netscaler/ns_gui is RAM disk only and NOT part of the image.
-- Id: 3c6fdbe4-3ebc-43da-8de6-1b3c2211b5fd
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT Timestamp, Timestamp_Info, Status, Path, Type, Bytes, FileSize, Mode, UID, GID, Inode
FROM Timeline
WHERE Path IN ('/var/netscaler/gui/vpn/scripts/linux',
               '/var/netscaler/gui/vpns/scripts/vista',
               '/var/netscaler/gui/vpns/scripts/mac',
               '/var/vpn/theme',
               '/var/netscaler/logon/LogonPoint/custom')
   OR starts_with(Path, '/var/netscaler/gui/vpn/scripts/linux/')
   OR starts_with(Path, '/var/netscaler/gui/vpns/scripts/vista/')
   OR starts_with(Path, '/var/netscaler/gui/vpns/scripts/mac/')
   OR starts_with(Path, '/var/vpn/theme/')
   OR starts_with(Path, '/var/netscaler/logon/LogonPoint/custom/')
ORDER BY Timestamp DESC;
```

```sql
-- Title: Web Shell Path Coverage
-- Description: Shows which critical internet-facing VPN and Web GUI paths (/var) exist in this image and how many entries each contains. Covers the same paths as the query Web Shell Persistence (VPN and Web GUI Paths). Paths with 0 entries are either missing on this firmware or were never used, so they cannot hold a web shell in this image.
-- Id: 38a0502c-2af1-4d96-b3cd-35ae0ce4f9ed
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT p AS Path, COUNT(n.Path) AS Entries
FROM (VALUES ('/var/netscaler/gui/vpn/scripts/linux/'),
             ('/var/netscaler/gui/vpns/scripts/vista/'),
             ('/var/netscaler/gui/vpns/scripts/mac/'),
             ('/var/vpn/theme/'),
             ('/var/vpn/themes/'),
             ('/var/netscaler/logon/LogonPoint/custom/')) AS t(p)
LEFT JOIN NetScaler n ON starts_with(n.Path, t.p)
GROUP BY p
ORDER BY p;
```

```sql
-- Title: Staging Directory (/var/tmp)
-- Description: Lists all events for /var/tmp and its contents (Newest First). /var/tmp is persistent and world-writable, a common staging area for tools, scripts and archives (e.g. web shells, reverse shells, exfiltration archives). Includes the directory itself: its mtime/ctime changes when files are added, deleted or renamed. The Indicator column flags typical attacker file types for review, it does not filter anything out. Files owned by nobody (UID 65534) were most likely written via the web server. Note: /var/tmp also holds benign NetScaler files (e.g. support bundles, upgrade files). /var/tmp/netscaler/portal/templates/*.xml was an IOC for CVE-2019-19781. These template cache files are deleted at every Apache start, so look for deleted entries there as well.
-- Id: dbd054d6-346c-4fd1-99a8-e14b31f91282
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    Timestamp,
    Timestamp_Info,
    Status,
    Path,
    Type,
    Bytes,
    FileSize,
    Mode,
    UID,
    GID,
    Inode,
    CASE
        WHEN Extension IN ('php', 'phtml', 'php5', 'pl', 'py', 'sh', 'cgi', 'xml', 'js')        THEN 'Script'
        WHEN Extension IN ('tar', 'tgz', 'gz', 'zip', '7z', 'bz2', 'xz', 'rar')                 THEN 'Archive'
        WHEN Extension IN ('so', 'elf', 'bin', 'out')                                           THEN 'Binary'
        WHEN Extension IN ('deb', 'sig')                                                        THEN 'Package (staged script?)'
        WHEN FileName LIKE '.%' AND Type = 'Regular File'                                       THEN 'Hidden File'
        WHEN Type = 'Regular File' AND Extension IS NULL AND Bytes > 0                          THEN 'No Extension'
        ELSE NULL
    END AS Indicator
FROM Timeline
WHERE Path = '/var/tmp'
   OR starts_with(Path, '/var/tmp/')
ORDER BY Timestamp DESC;
```

```sql
-- Title: NetScaler Configuration and Boot Persistence (/flash/nsconfig)
-- Description: Lists all events for /flash/nsconfig and its contents (Newest First). /flash/nsconfig (/nsconfig on the live system) holds the persistent configuration, boot hooks, certificates and keys. Boot hooks (rc.netscaler, nsbefore.sh, nsafter.sh) are the main way to restore RAM disk web shells after a reboot. Reads (atime) of private keys in ssl/ can indicate key theft, but reads at boot time are normal. ns.conf changes with every "save config", so the timing matters more than the change itself; compare it with the backups (ns.conf.N). Added keys in ssh/ give persistent access. The Category column groups the files for review, it does not filter anything out. Includes the directory itself.
-- Id: f0cdca4e-e6e6-4729-ad1c-6c70efbc65fc
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    Timestamp,
    Timestamp_Info,
    Status,
    Path,
    Type,
    Bytes,
    FileSize,
    Mode,
    UID,
    GID,
    Inode,
    CASE
        WHEN FileName IN ('rc.netscaler', 'nsbefore.sh', 'nsafter.sh')                 THEN 'Boot Hook'
        WHEN regexp_matches(FileName, '^ns\.conf(\.\d+)?$')                             THEN 'Configuration'
        WHEN starts_with(Path, '/flash/nsconfig/ssl/')
             AND Extension IN ('key', 'pem', 'pfx', 'p12')                              THEN 'Certificate / Key'
        WHEN starts_with(Path, '/flash/nsconfig/ssl/')                                  THEN 'SSL'
        WHEN starts_with(Path, '/flash/nsconfig/ssh/')                                  THEN 'SSH'
        WHEN starts_with(Path, '/flash/nsconfig/monitors/')                             THEN 'Monitor Script'
        WHEN starts_with(Path, '/flash/nsconfig/license/')                              THEN 'License'
        WHEN Extension IN ('php', 'phtml', 'pl', 'py', 'sh', 'cgi', 'deb', 'sig')       THEN 'Script'
        ELSE NULL
    END AS Category
FROM Timeline
WHERE Path = '/flash/nsconfig'
   OR starts_with(Path, '/flash/nsconfig/')
ORDER BY Timestamp DESC;
```

```sql
-- Title: Crash Dumps per Day (Exploitation Traces)
-- Description: Number of crash dumps per day under /var/core and /var/crash, incl. the crashed processes. Several crashes on one day, or crashes shortly before suspicious file system activity, can indicate exploitation attempts. Several different processes crashing at nearly the same time point to a system-wide event (hang, watchdog reboot, upgrade) rather than a targeted exploit. The counter file bounds is excluded. Note: A manually generated NSPPE core dump during evidence collection also shows up here.
-- Id: f8d50110-99b3-467e-844a-93557b424e7f
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    CAST(LastModificationTime AS DATE)                                       AS Crash_Date,
    COUNT(*)                                                                 AS Crash_Dumps,
    string_agg(DISTINCT regexp_extract(FileName, '^(.+)-(\d+)\.gz$', 1), ', ') AS Processes,
    MIN(LastModificationTime)                                                AS First_Crash,
    MAX(LastModificationTime)                                                AS Last_Crash
FROM NetScaler
WHERE (starts_with(Path, '/var/core/') OR starts_with(Path, '/var/crash/'))
  AND Type = 'Regular File'
  AND FileName <> 'bounds'
GROUP BY ALL
ORDER BY Crash_Date DESC;
```

```sql
-- Title: Crash Dumps (Exploitation Traces)
-- Description: Lists crash dumps under /var/core and /var/crash (Newest First). NetScaler writes process core dumps to /var/core/<N>/<process>-<pid>.gz (one numbered folder per dump set, bounds is the counter for the next set number). Memory-corruption exploits (e.g. CVE-2023-3519, CVE-2026-88772) often crash the packet engine (NSPPE) or exposed daemons such as nsaaad (AAA/authentication) and leave core dumps. The dump time marks a possible exploitation attempt, which can be correlated with httpaccess*.log, httperror*.log and ns.log. Note: Dumps can also be caused by bugs, hangs, reboots or a manually generated NSPPE core dump during evidence collection, so look at timing, clusters and correlation with other events.
-- Id: 08aef940-93ae-413a-97d1-75492e9e9b9c
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    LastModificationTime                                   AS Crash_Time,     -- When the dump was written
    LastChangeTime,
    Status,
    Path,
    regexp_extract(Path, '^/var/core/(\d+)/', 1)           AS Dump_Set,
    regexp_extract(FileName, '^(.+)-(\d+)\.gz$', 1)        AS Process,
    TRY_CAST(regexp_extract(FileName, '^(.+)-(\d+)\.gz$', 2) AS BIGINT) AS PID,
    Type,
    Bytes,
    FileSize,
    Inode,
    CASE
        WHEN FileName ILIKE 'nsppe%'                      THEN 'Packet Engine (NSPPE)'
        WHEN FileName ILIKE 'nsaaad-%'                    THEN 'AAA Daemon (Authentication)'
        WHEN FileName ILIKE 'pitboss-%'                   THEN 'Process Monitor (pitboss)'
        WHEN regexp_matches(FileName, '^.+-\d+\.gz$')     THEN 'Daemon Core Dump'
        WHEN FileName = 'bounds'                          THEN 'Dump Counter (bounds)'
        WHEN regexp_matches(FileName, '^vmcore\.\d+')     THEN 'Kernel Crash Dump'
        WHEN Type = 'Directory'                           THEN 'Directory'
        ELSE 'Other'
    END AS Category
FROM NetScaler
WHERE Path IN ('/var/core', '/var/crash')
   OR starts_with(Path, '/var/core/')
   OR starts_with(Path, '/var/crash/')
ORDER BY Crash_Time DESC NULLS LAST;
-- Investigation Tips
-- NSPPE dumps: most relevant. Note the crash time and check the minutes before it in httperror*.log/httpaccess*.log, then look at the Timeline view for files created right after it, such as a web shell under /var/netscaler/logon or /var/vpn.
-- Several daemons in one dump set with nearly the same Crash_Time: probably a system-wide event (hang, watchdog reboot, upgrade) rather than a targeted exploit. A single nsaaad dump is more interesting (authentication daemon behind the Gateway login).
-- pitboss: the log poisoning of CVE-2026-88771 imitates pitboss messages. A pitboss dump inside the exploitation window deserves a closer look.
-- Deleted dumps: Status = 'Deleted' is interesting in itself. Attackers sometimes remove crash dumps to hide failed exploit attempts.
-- No hits at all: this doesn't rule out exploitation. Successful exploits often don't crash, and old dumps may have been cleaned up.
```

```sql
-- Title: Log Tampering (/var/log and /var/nslog)
-- Description: Checks log files under /var/log and /var/nslog for signs of tampering based on file system metadata: deleted logs, empty (truncated) logs, metadata changes without a write (ctime much later than mtime, e.g. chmod/touch/timestomping) and stale active logs (no write for more than 24 hours before the last activity on the image, e.g. logging stopped). Rotated archives are excluded from the ctime/stale checks, because rotation (rename) updates ctime. Rows with an indicator are listed first. Note: Metadata cannot show which entries were removed from a log. Confirm findings by checking the extracted logs (table Logs) for gaps in the log entries. Deleted logs whose directory entry is gone only appear under $OrphanFiles without a name and are not covered by this query. The 10 minute and 24 hour thresholds are starting points: some logs are quiet by nature.
-- Id: 69133298-064f-46bd-994d-d200602ada84
-- Author: Martin Willing
-- Date: 2026-10-04
SET VARIABLE ts_end = (SELECT MAX(LastChangeTime) FROM NetScaler);

WITH LogFiles AS (
    SELECT
        *,
        -- Active log = not a rotated archive (e.g. ns.log.0.gz, newnslog.13.tar.gz, messages.1)
        Type = 'Regular File'
        AND NOT regexp_matches(FileName, '\.\d+(\.tar)?(\.gz|\.bz2|\.xz)?$')
        AND coalesce(Extension, '') NOT IN ('gz', 'bz2', 'xz', 'tgz', 'zip')      AS Is_Active
    FROM NetScaler
    WHERE starts_with(Path, '/var/log/')
       OR starts_with(Path, '/var/nslog/')
)
SELECT
    LastModificationTime,
    LastChangeTime,
    LastAccessTime,
    Status,
    Path,
    Type,
    Bytes,
    FileSize,
    Mode,
    UID,
    Inode,
    Is_Active,
    concat_ws(' | ',
        CASE WHEN Status <> 'Allocated'                                          THEN 'Deleted' END,
        CASE WHEN Type = 'Regular File' AND Bytes = 0                            THEN 'Empty (Truncated?)' END,
        CASE WHEN Is_Active
              AND LastChangeTime - LastModificationTime > INTERVAL 10 MINUTE     THEN 'Metadata Change w/o Write (ctime >> mtime)' END,
        CASE WHEN Is_Active
              AND getvariable('ts_end') - LastModificationTime > INTERVAL 24 HOUR THEN 'Stale (No Write > 24h)' END
    ) AS Indicator
FROM LogFiles
WHERE Type <> 'Directory'
ORDER BY (Indicator = '') ASC, LastModificationTime DESC NULLS LAST;
```

```sql
-- Title: Web Shell Hunting (/var/netscaler/logon)
-- Description: Lists all events for /var/netscaler/logon and its contents (Newest First). This persistent, internet-facing directory holds the Gateway login pages (LogonPoint, themes). Known location for web shells and modified login pages (credential harvesting), e.g. the hidden PHP web shell .ctxs.receiver of the CVE-2026-88771 campaign (Sep 2026). The Indicator column flags server-side scripts, files owned by the web server user nobody (UID 65534, i.e. most likely written via HTTP), hidden files and unexpected file types (incl. files without extension). Rows with an indicator are listed first. Modified login pages (.html/.js) are not flagged, so check single changed files outside upgrades or theme changes. Note: At every Apache start, NetScaler touches files under /var/netscaler/logon that are older than 34 days, so clusters of identical timestamps are expected. Includes the directory itself.
-- Id: 755e25c7-6faf-489e-8777-4145ff47344a
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    Timestamp,
    Timestamp_Info,
    Status,
    Path,
    Type,
    Bytes,
    FileSize,
    Mode,
    UID,
    GID,
    Inode,
    concat_ws(' | ',
        CASE WHEN Extension IN ('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'pl', 'py', 'sh', 'cgi', 'jsp', 'asp', 'aspx')
             THEN 'Server-Side Script' END,
        CASE WHEN UID = 65534
             THEN 'Owned by nobody (Web Server)' END,
        CASE WHEN FileName LIKE '.%' AND Type = 'Regular File'
             THEN 'Hidden File' END,
        CASE WHEN Type = 'Regular File'
              AND coalesce(Extension, '') NOT IN ('css', 'js', 'html', 'htm', 'xml', 'json', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'map', 'txt')
              AND coalesce(Extension, '') NOT IN ('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'pl', 'py', 'sh', 'cgi', 'jsp', 'asp', 'aspx')
             THEN 'Unexpected File Type' END
    ) AS Indicator
FROM Timeline
WHERE Path = '/var/netscaler/logon'
   OR starts_with(Path, '/var/netscaler/logon/')
ORDER BY (Indicator = '') ASC, Timestamp DESC;
```

```sql
-- Title: Web Shell Hunting (/var/vpn)
-- Description: Lists all events for /var/vpn and its contents (Newest First). This persistent, internet-facing directory holds VPN portal content (e.g. theme, themes, bookmark). The Indicator column flags server-side scripts, files owned by the web server user nobody (UID 65534, i.e. most likely written via HTTP), hidden files, unexpected file types (incl. files without extension) and XML files in bookmark/ (IOC for the CVE-2019-19781 template injection). Rows with an indicator are listed first. Note: Users can create bookmarks legitimately, so a Bookmark XML hit alone is not proof of compromise. Check its content (icat), especially in combination with Owned by nobody. Includes the directory itself.
-- Id: c9f4aa80-e7a9-40aa-8503-cbf69abaa936
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    Timestamp,
    Timestamp_Info,
    Status,
    Path,
    Type,
    Bytes,
    FileSize,
    Mode,
    UID,
    GID,
    Inode,
    concat_ws(' | ',
        CASE WHEN Extension IN ('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'pl', 'py', 'sh', 'cgi', 'jsp', 'asp', 'aspx')
             THEN 'Server-Side Script' END,
        CASE WHEN starts_with(Path, '/var/vpn/bookmark/') AND Extension = 'xml'
             THEN 'Bookmark XML (CVE-2019-19781 IOC)' END,
        CASE WHEN UID = 65534
             THEN 'Owned by nobody (Web Server)' END,
        CASE WHEN FileName LIKE '.%' AND Type = 'Regular File'
             THEN 'Hidden File' END,
        CASE WHEN Type = 'Regular File'
              AND coalesce(Extension, '') NOT IN ('css', 'js', 'html', 'htm', 'xml', 'json', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'map', 'txt')
              AND coalesce(Extension, '') NOT IN ('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'pl', 'py', 'sh', 'cgi', 'jsp', 'asp', 'aspx')
             THEN 'Unexpected File Type' END
    ) AS Indicator
FROM Timeline
WHERE Path = '/var/vpn'
   OR starts_with(Path, '/var/vpn/')
ORDER BY (Indicator = '') ASC, Timestamp DESC;
```

```sql
-- Title: CVE-2026-88771/88772 Known File IOCs
-- Description: Searches the whole image (incl. deleted entries) for file names and hashes published by Unit 42 for the exploitation of CVE-2026-88771 and CVE-2026-88772 (Sep 2026): PHP web shell .ctxs.receiver, .deb web shells (names mimic legitimate client packages) and the SUID binary .ns_suidcmd. The SHA256 match (nsg64.deb) also finds renamed copies, but requires -Hash. Hits on .ctxs.receiver, the .deb names or the hash are strong indicators of compromise. For .ns_suidcmd, check whether it is part of the firmware on a clean appliance of the same build before rating a hit. Source: Unit 42 Threat Brief (updated 2026-09-30). Note: IOC lists are not exhaustive, so no hits does not prove the appliance was not compromised.
-- Id: 4d1fd6d4-9434-452a-a8d5-4704a073244e
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    LastModificationTime,
    LastChangeTime,
    LastAccessTime,
    Status,
    Path,
    Type,
    Bytes,
    FileSize,
    Mode,
    UID,
    GID,
    Inode,
    MD5,
    SHA256
FROM NetScaler
WHERE FileName IN ('.ctxs.receiver', '.ns_suidcmd',
                   'nsgclient18.deb', 'nsgser18.deb', 'nsgpackage64.deb',
                   'nsgbuild.deb', 'nsgsupport.deb', 'nsg64.deb')
   OR SHA256 IN ('ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec') -- nsg64.deb (Unit 42)
ORDER BY LastChangeTime DESC NULLS LAST;
```

```sql
-- Title: CVE-2026-88771/88772 Web Shell Patterns
-- Description: Hidden files and .deb/.sig files (incl. deleted entries) in the internet-facing directories /var/netscaler/logon, /var/netscaler/gui and /var/vpn. Matches the web shell patterns from the Sep 2026 NetScaler zero-day campaign (e.g. .ctxs.receiver, nsg*.deb) regardless of the actual file name. Note: /var/netscaler/gui/vpn/scripts/linux legitimately holds the Gateway client packages for Linux (.deb), so .deb hits there are expected. Check their ctime (outside firmware upgrades?), owner (nobody, UID 65534?) and hashes (-Hash) against the IOCs and the packages of the same firmware build.
-- Id: d1bdd522-b3b1-4f31-9dfe-19749156b27d
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    LastModificationTime,
    LastChangeTime,
    Status,
    Path,
    Type,
    Bytes,
    FileSize,
    Mode,
    UID,
    Inode,
    SHA256,
    CASE
        WHEN FileName LIKE '.%'            THEN 'Hidden File'
        WHEN Extension IN ('deb', 'sig')   THEN 'Package Extension (.deb/.sig)'
    END AS Indicator
FROM NetScaler
WHERE (starts_with(Path, '/var/netscaler/logon/')
    OR starts_with(Path, '/var/netscaler/gui/')
    OR starts_with(Path, '/var/vpn/'))
  AND Type = 'Regular File'
  AND (FileName LIKE '.%' OR Extension IN ('deb', 'sig'))
ORDER BY LastChangeTime DESC NULLS LAST;
```

```sql
-- Title: CVE-2026-88771/88772 Exploitation Window Activity
-- Description: Lists all writes and metadata changes (Modified, Changed; no reads) in the internet-facing and persistence-relevant directories /var/netscaler, /var/vpn, /var/tmp, /var/core and /flash/nsconfig between the start of the reported pre-disclosure exploitation (2026-08-21, Unit 42) and the last activity on the image. Logs (/var/log, /var/nslog) are not included. Use to spot web shell drops, staged tools, crash dumps and boot hook changes during the zero-day window. Note: Benign clusters are expected: Apache restarts touch files under /var/netscaler/logon and /var/netscaler/gui/admin_ui, and a firmware upgrade (e.g. the patch for CVE-2026-88771/88772, see /var/nsinstall) changes many files at once. Identify these clusters first, then look at single files outside them.
-- Id: 41b6cfe1-64d9-433b-82bd-f7df6fc919b8
-- Author: Martin Willing
-- Date: 2026-10-04
SET VARIABLE ts_start = TIMESTAMP '2026-08-21 00:00:00';
SET VARIABLE ts_end   = (SELECT MAX(LastChangeTime) FROM NetScaler);

SELECT Timestamp, Timestamp_Info, Status, Path, Type, Bytes, FileSize, UID, Inode
FROM Timeline
WHERE Timestamp BETWEEN getvariable('ts_start') AND getvariable('ts_end')
  AND Timestamp_Info IN ('Modified', 'Changed')
  AND (starts_with(Path, '/var/netscaler/')
    OR starts_with(Path, '/var/vpn/')
    OR starts_with(Path, '/var/tmp/')
    OR starts_with(Path, '/var/core/')
    OR starts_with(Path, '/flash/nsconfig/'))
ORDER BY Timestamp;
```

```sql
-- Title: NetScaler Firmware Version
-- Description: Lists the NetScaler kernel images under /flash (file name contains the firmware version, e.g. ns-14.1-73.37.gz) and the firmware upgrade packages under /var/nsinstall (e.g. build-13.1-64.24_nc_64) with their timestamps. Shows whether a version fixing CVE-2026-88771/88772 (14.1-73.37 / 13.1-64.23 or later) was installed, and when (ctime), which is relevant to whether the appliance was exposed during the exploitation window (2026-08-21 to 2026-09-24, Unit 42). Note: Several kernel images and build packages may remain on disk after upgrades, so the newest one is not necessarily the running version. The active kernel is defined in the boot loader configuration under /flash/boot.
-- Id: 3e1492b9-8d96-42e6-a866-06358c961974
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT 'Kernel Image' AS Source, LastModificationTime, LastChangeTime, Status, Path, FileSize
FROM NetScaler
WHERE starts_with(Path, '/flash/')
  AND regexp_matches(FileName, '^ns-\d+\.\d+-[\d.]+.*\.gz$')
UNION ALL
SELECT 'Upgrade Package' AS Source, LastModificationTime, LastChangeTime, Status, Path, FileSize
FROM NetScaler
WHERE regexp_matches(Path, '^/var/nsinstall/[^/]+$')
  AND Type = 'Directory'
ORDER BY LastChangeTime DESC;
```

```sql
-- Title: Log Poisoning (CVE-2026-88771)
-- Description: Searches the extracted NetScaler logs (table Logs: ns.log, httpaccess*.log, httperror*.log, incl. rotated archives) for log poisoning, Stage 1 and 2 of the CVE-2026-88771 exploitation chain (Unit 42): fake pitboss messages ("PPE unexpectedly died", "PPE missed too many heartbeats") followed by "NSPPE" and a shell operator (;, $(, &&, ||). In HTTP logs, pitboss/heartbeat text never occurs legitimately, so any occurrence there is flagged as well. Same logic as the view LogPoisoning. Note: The local logs only cover a short period (see the log coverage in the transcript), older events may only be available in SIEM/Syslog.
-- Id: ff780f83-fa0c-48b3-94cf-ff1caa20ea52
-- Author: Martin Willing
-- Date: 2026-10-04
SELECT
    LogFile,
    LineNumber,
    CASE
        WHEN regexp_matches(Line, '(?i)pitboss.{0,100}PPE.{0,150}(unexpectedly died|missed too many heartbeats).{0,150}NSPPE.{0,50}(;|[$][(]|&&|[|][|])')
            THEN 'Log Poisoning Pattern (pitboss + Shell Operator)'
        ELSE 'pitboss/Heartbeat Text in HTTP Log'
    END AS Indicator,
    Line
FROM Logs
WHERE regexp_matches(Line, '(?i)pitboss.{0,100}PPE.{0,150}(unexpectedly died|missed too many heartbeats).{0,150}NSPPE.{0,50}(;|[$][(]|&&|[|][|])')
   OR (LogFile ILIKE 'http%' AND (Line ILIKE '%pitboss%' OR Line ILIKE '%heartbeat%' OR Line ILIKE '%NSPPE%'))
ORDER BY LogFile, LineNumber;
```

```sql
-- Title: Log Poisoning Pivot (SIEM Anchor)
-- Description: Lists all writes and metadata changes (Modified, Changed; no reads) from 1 hour before to 24 hours after a log poisoning event confirmed in SIEM/Syslog (CVE-2026-88771). Stage 3 of the exploitation chain should leave traces shortly afterwards (e.g. web shell, .deb files, .ns_suidcmd, crash dumps, boot hook changes). Use when the local logs no longer cover the event. Set ts_anchor to the SIEM event time and convert it to UTC first, because SIEMs often display local time. Logs (/var/log, /var/nslog) are excluded because they change constantly.
-- Id: 21536b3f-8d8d-4a41-be25-8c6aca1ecdf0
-- Author: Martin Willing
-- Date: 2026-10-04
SET VARIABLE ts_anchor = TIMESTAMP '2026-01-01 00:00:00';  -- SIEM event time (UTC!)

SELECT Timestamp, Timestamp_Info, Status, Path, Type, Bytes, FileSize, UID, Inode
FROM Timeline
WHERE Timestamp BETWEEN getvariable('ts_anchor') - INTERVAL 1 HOUR
                    AND getvariable('ts_anchor') + INTERVAL 24 HOUR
  AND Timestamp_Info IN ('Modified', 'Changed')
  AND NOT starts_with(Path, '/var/log/')
  AND NOT starts_with(Path, '/var/nslog/')
ORDER BY Timestamp;
```

```sql
-- Title: Known Malicious File Hashes (CVE-2026-88771/88772)
-- Description: Matches the SHA256 hashes of all allocated regular files against published IOCs. Also finds renamed or moved copies. Requires -Hash, otherwise no hashes exist and the result is always empty. Check the column Hashed_Files: if it is 0, the image was not hashed and the result is NOT clean. Extend the IOC list with new hashes (SHA256, name, source). nsg64.deb: Unit 42 Threat Brief (updated 2026-09-30).
-- Id: c8d28d74-58e0-4714-b1e3-f9729d6cc019
-- Author: Martin Willing
-- Date: 2026-10-04
WITH IOCs (SHA256, IOC_Name, Source) AS (
    VALUES
        ('ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec', 'nsg64.deb', 'Unit 42 (2026-09-30)')
)
SELECT
    (SELECT COUNT(SHA256) FROM NetScaler) AS Hashed_Files,
    i.IOC_Name,
    i.Source,
    n.Path,
    n.Status,
    n.FileSize,
    n.LastModificationTime,
    n.LastChangeTime,
    n.MD5,
    n.SHA256
FROM IOCs i
LEFT JOIN NetScaler n ON n.SHA256 = i.SHA256
ORDER BY n.LastChangeTime DESC NULLS LAST;
```
