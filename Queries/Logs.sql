-- Title: Log Import (ns.log, httpaccess-vpn.log)
-- Description: Imports the extracted NetScaler logs (decompressed, UTF-8) line by line with file name and line number. Creates the view LogPoisoning: fake pitboss heartbeat messages with additional text after "NSPPE;" (log poisoning, Stage 2 of the CVE-2026-88771 exploitation chain, Unit 42).
-- Id: 13d83fe4-2129-41f7-bdb2-ef50f49630b3
-- Author: Martin Willing
-- Date: 2026-10-04

CREATE OR REPLACE TABLE Logs AS
WITH Files AS (
    SELECT
        regexp_extract(filename, '[^/\\]+$')   AS LogFile,
        string_split(content, chr(10))         AS Lines
    FROM read_text(getenv('LOGFILES'))
)
SELECT
    LogFile,
    unnest(generate_series(1, len(Lines)))     AS LineNumber,
    unnest(Lines)                              AS Line
FROM Files;

CREATE OR REPLACE VIEW LogPoisoning AS
WITH Classified AS (
    SELECT
        LogFile,
        LineNumber,
        Line,
        CASE
            -- Log poisoning pattern (SIEM rule, CVE-2026-88771): fake pitboss message followed by shell operators
            WHEN regexp_matches(Line, '(?i)pitboss.{0,100}PPE.{0,150}(unexpectedly died|missed too many heartbeats).{0,150}NSPPE.{0,50}(;|[$][(]|&&|[|][|])')
                THEN 'Log Poisoning Pattern (pitboss + Shell Operator)'
            -- HTTP logs: pitboss/heartbeat text never occurs legitimately (broader fallback)
            WHEN LogFile ILIKE 'http%'
             AND (Line ILIKE '%pitboss%' OR Line ILIKE '%heartbeat%' OR Line ILIKE '%NSPPE%')
                THEN 'pitboss/Heartbeat Text in HTTP Log'
        END AS Indicator
    FROM Logs
)
SELECT *
FROM Classified
WHERE Indicator IS NOT NULL
ORDER BY LogFile, LineNumber;