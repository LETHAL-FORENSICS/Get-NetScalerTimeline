# Changelog  

All notable changes to Get-NetScalerTimeline will be documented in this file.  

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