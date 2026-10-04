-- Title: File Hashes (MD5, SHA256)
-- Description: Adds the MD5 and SHA256 hashes of all allocated regular files (calculated from the image via icat) to the table NetScaler. Join key: Path + Inode (inode numbers are only unique per file system). Deleted files are not hashed, because their data blocks may already be reallocated.
-- Id: dc339067-18e7-423c-87b1-720235092043
-- Author: Martin Willing
-- Date: 2026-10-04

ALTER TABLE NetScaler ADD COLUMN IF NOT EXISTS SHA256 VARCHAR;

UPDATE NetScaler AS n
SET MD5    = h.MD5,
    SHA256 = h.SHA256
FROM read_csv(getenv('HASHFILE'), header = true, all_varchar = true) AS h
WHERE n.Path  = h.Path
  AND n.Inode = h.Inode;