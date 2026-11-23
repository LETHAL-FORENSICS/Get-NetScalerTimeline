# Changelog  

All notable changes to Get-NetScalerTimeline will be documented in this file.  

## [0.2.0] - 2026-11-23
### Added
- Support for RAW file system images without partition table (`*.img`, `*.raw`, `*.dd`, `*.bin`), e.g. a dd image of the NetScaler RAM disk `/dev/md0` (incl. `/etc` and `/netscaler`)
- Warning if the image size is not a multiple of 512 bytes (e.g. additional bytes of the SSH session in a dd image acquired via SSH)
- Check whether the DuckDB UI extension is available before launching the DuckDB UI (warning if offline or not yet published for the bundled DuckDB version)

### Fixed
- Undated `...b` rows (`0000-00-00`) are removed from the CSV/XLSX timeline, because the UFS2 creation time is not available (`crtime` = 0)
- `Export-Csv -NoTypeInformation` is only used in Windows PowerShell 5.1 (obsolete warning in PowerShell 7.6)
- Output directory: timestamped subdirectory (UTC) per run (`Get-NetScalerTimeline\<yyyy-MM-ddTHHmmssZ>`), previous results are no longer deleted

### Changed
- DuckDB CLI v2.0.0 (bundled in `Tools\DuckDB\duckdb.exe`)
- README: `/netscaler/ns_gui` is a symbolic link to `/var/netscaler/gui` (persistent, part of the VMDK)
- README: Contributing section completed

## [0.1.0] - 2026-10-04
### Added
- Initial Release
- Automatic detection of the FreeBSD Slice (0xa5) and all UFS partitions in its BSD Disk Label (e.g. `/flash`, `/var`)
- VMDK support: flat extent (`*-flat.vmdk`) or descriptor file (`*.vmdk`), incl. split images
- File system timeline (fls, mactime) in UTC as CSV and XLSX, optionally limited to a date range (`-StartDate`, `-EndDate`)
- DuckDB database (table `NetScaler`, view `Timeline`) and DuckDB UI
- Log extraction (`ns.log`, `httpaccess*.log`, `httperror*.log`) incl. rotated archives, with SHA256 hashes of the evidence copies
- Log poisoning detection (CVE-2026-88771) and log coverage report
- Optional MD5 and SHA256 file hashing (`-Hash`)
- Threat hunting queries (see [Queries.md](Queries.md))