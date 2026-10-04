-- Title: Filesystem Timeline Creation
-- Description: Imports a Sleuthkit/TSK bodyfile into DuckDB.
-- Id: def85148-9d46-4372-8323-14dce576fc0c
-- Author: Martin Willing
-- Date: 2026-10-04
--
-- Bodyfile Format (TSK 3.x+):
-- MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
--
-- Notes:
-- - File names are NOT escaped, i.e. a '|' in a file name creates additional fields. Each line is therefore read as a whole
--   and split from both ends: the first field is the MD5, the last 9 fields are fixed, everything in between is the file name.
-- - Mode: TSK writes '<name type>/<meta type><permissions>' (e.g. r/rrw-r--r--), UAC writes '<type><permissions>' (e.g. -rw-r--r--).
-- - TSK appends ' (deleted)' or ' (deleted-realloc)' to deleted entries and ' -> <target>' to symbolic links.
-- - Timestamps: epoch_ms() returns a TIMESTAMP in UTC. Do NOT use CAST(to_timestamp(...) AS TIMESTAMP), which converts to the
--   session time zone (local time by default).
-- - UFS2: TSK 4.14 does not parse the birth time --> CreationTime is NULL for NetScaler images.
-- - MD5 and SHA256 are the last two columns. They are filled by Hashes.sql when the script is run with -Hash.

CREATE OR REPLACE TABLE NetScaler AS
WITH Lines AS (
    SELECT string_split(rtrim(line, chr(13)), '|') AS f
    FROM read_csv(
        getenv('BODYFILE'),
        columns     = {'line': 'VARCHAR'},
        delim       = chr(31),                 -- Unit Separator (does not occur in bodyfiles) --> one column per line
        header      = false,
        quote       = '',
        escape      = '',
        auto_detect = false
    )
),

Fields AS (
    SELECT
        NULLIF(f[1], '0')                      AS MD5,          -- fls -m writes 0 (no hash)
        array_to_string(f[2:len(f) - 9], '|')  AS Name,
        f[len(f) - 8]                          AS Inode,        -- kept as text (NTFS entries like "60129-128-4")
        f[len(f) - 7]                          AS Mode,
        TRY_CAST(f[len(f) - 6] AS BIGINT)      AS UID,
        TRY_CAST(f[len(f) - 5] AS BIGINT)      AS GID,
        TRY_CAST(f[len(f) - 4] AS BIGINT)      AS Bytes,
        TRY_CAST(f[len(f) - 3] AS DOUBLE)      AS Atime,        -- DOUBLE: some collectors write fractional seconds
        TRY_CAST(f[len(f) - 2] AS DOUBLE)      AS Mtime,
        TRY_CAST(f[len(f) - 1] AS DOUBLE)      AS Ctime,
        TRY_CAST(f[len(f)]     AS DOUBLE)      AS Crtime
    FROM Lines
    WHERE len(f) >= 11
),

Parsed AS (
    SELECT
        *,

        -- File type character: TSK --> meta type (falls back to name type if unknown), UAC --> first character
        CASE
            WHEN Mode LIKE '_/%' AND substr(Mode, 3, 1) <> '-' THEN substr(Mode, 3, 1)
            ELSE substr(Mode, 1, 1)
        END                                    AS TypeChar,
        Mode LIKE '_/%'                        AS IsTSK,

        CASE
            WHEN Name LIKE '% (deleted-realloc)' THEN 'Deleted (Reallocated)'
            WHEN Name LIKE '% (deleted)'         THEN 'Deleted'
            ELSE 'Allocated'
        END                                    AS Status,

        regexp_replace(Name, ' \((deleted|deleted-realloc)\)$', '') AS CleanName
    FROM Fields
),

Paths AS (
    SELECT
        *,
        CASE WHEN TypeChar = 'l' AND strpos(CleanName, ' -> ') > 0
             THEN substr(CleanName, 1, strpos(CleanName, ' -> ') - 1)
             ELSE CleanName END                AS Path,
        CASE WHEN TypeChar = 'l' AND strpos(CleanName, ' -> ') > 0
             THEN substr(CleanName, strpos(CleanName, ' -> ') + 4)
             ELSE NULL END                     AS LinkTarget
    FROM Parsed
),

Names AS (
    SELECT *, regexp_extract(Path, '[^/]+$') AS FileName
    FROM Paths
)

SELECT
    Path,
    FileName,

    CASE
        WHEN TypeChar = 'd'                        THEN NULL
        WHEN NOT regexp_matches(FileName, '\.')    THEN NULL
        WHEN regexp_matches(FileName, '^\.[^.]*$') THEN NULL   -- Dotfiles (e.g. .profile)
        ELSE lower(regexp_extract(FileName, '\.([^.]+)$', 1))
    END                                        AS Extension,

    LinkTarget,
    Status,
    Path LIKE '%/$OrphanFiles/%'               AS Orphan,
    Inode,
    Mode,

    -- File type (standard Unix/TSK file type indicator letters)
    CASE
        WHEN Mode IS NULL OR Mode = ''   THEN 'Unknown'
        WHEN TypeChar = 'r'              THEN 'Regular File'
        WHEN TypeChar = '-' AND IsTSK    THEN 'Unknown'        -- TSK: unknown type (e.g. Orphan Files)
        WHEN TypeChar = '-'              THEN 'Regular File'   -- UAC: '-' = regular file
        WHEN TypeChar = 'd'              THEN 'Directory'
        WHEN TypeChar = 'l'              THEN 'Symbolic Link'
        WHEN TypeChar = 'p'              THEN 'Named Pipe (FIFO)'
        WHEN TypeChar = 's'              THEN 'Socket'
        WHEN TypeChar = 'b'              THEN 'Block Special'
        WHEN TypeChar = 'c'              THEN 'Character Special'
        WHEN TypeChar = 'h'              THEN 'Shadow Inode'
        WHEN TypeChar = 'w'              THEN 'Whiteout'       -- UFS/BSD
        WHEN TypeChar = 'v'              THEN 'Virtual File'   -- TSK
        WHEN TypeChar = 'V'              THEN 'Virtual Directory'
        ELSE 'Unknown'
    END                                        AS Type,

    UID,
    GID,
    Bytes,

    -- Human-readable file size
    CASE
        WHEN Bytes IS NULL           THEN NULL
        WHEN Bytes > 1099511627776   THEN printf('%.2f TB', Bytes / 1099511627776.0)
        WHEN Bytes > 1073741824      THEN printf('%.2f GB', Bytes / 1073741824.0)
        WHEN Bytes > 1048576         THEN printf('%.2f MB', Bytes / 1048576.0)
        WHEN Bytes > 1024            THEN printf('%.2f KB', Bytes / 1024.0)
        WHEN Bytes > 0               THEN printf('%.2f Bytes', Bytes::DOUBLE)
        ELSE ''
    END                                        AS FileSize,

    -- Raw epoch values (handy for sorting / min-max / re-deriving dates)
    CAST(floor(Atime)  AS BIGINT)              AS Atime_Epoch,
    CAST(floor(Mtime)  AS BIGINT)              AS Mtime_Epoch,
    CAST(floor(Ctime)  AS BIGINT)              AS Ctime_Epoch,
    CAST(floor(Crtime) AS BIGINT)              AS Crtime_Epoch,

    -- Human-readable UTC timestamps. An epoch of 0 (or anything unparsable) is treated as "no timestamp" and mapped to NULL.
    CASE WHEN Atime  > 0 THEN epoch_ms(CAST(round(Atime  * 1000) AS BIGINT)) END AS LastAccessTime,
    CASE WHEN Mtime  > 0 THEN epoch_ms(CAST(round(Mtime  * 1000) AS BIGINT)) END AS LastModificationTime,
    CASE WHEN Ctime  > 0 THEN epoch_ms(CAST(round(Ctime  * 1000) AS BIGINT)) END AS LastChangeTime,
    CASE WHEN Crtime > 0 THEN epoch_ms(CAST(round(Crtime * 1000) AS BIGINT)) END AS CreationTime,

    -- File hashes (filled by Hashes.sql when -Hash is used)
    MD5,
    CAST(NULL AS VARCHAR)                      AS SHA256

FROM Names
ORDER BY LastModificationTime DESC NULLS LAST;

CREATE OR REPLACE VIEW Timeline AS
    SELECT LastAccessTime       AS Timestamp, 'Accessed' AS Timestamp_Info, Path, FileName, Extension, LinkTarget, Status, Orphan, Inode, Mode, Type, UID, GID, Bytes, FileSize, MD5, SHA256 FROM NetScaler WHERE LastAccessTime IS NOT NULL
    UNION ALL
    SELECT LastModificationTime AS Timestamp, 'Modified' AS Timestamp_Info, Path, FileName, Extension, LinkTarget, Status, Orphan, Inode, Mode, Type, UID, GID, Bytes, FileSize, MD5, SHA256 FROM NetScaler WHERE LastModificationTime IS NOT NULL
    UNION ALL
    SELECT LastChangeTime       AS Timestamp, 'Changed'  AS Timestamp_Info, Path, FileName, Extension, LinkTarget, Status, Orphan, Inode, Mode, Type, UID, GID, Bytes, FileSize, MD5, SHA256 FROM NetScaler WHERE LastChangeTime IS NOT NULL
    UNION ALL
    SELECT CreationTime         AS Timestamp, 'Birth'    AS Timestamp_Info, Path, FileName, Extension, LinkTarget, Status, Orphan, Inode, Mode, Type, UID, GID, Bytes, FileSize, MD5, SHA256 FROM NetScaler WHERE CreationTime IS NOT NULL
    ORDER BY Timestamp;
