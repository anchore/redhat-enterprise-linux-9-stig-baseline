# Changelog

All notable changes to this InSpec profile are documented here.

---

## [2.7.0] - 2026-05-11

### Aligned to DISA STIG RHEL 9 V2R7 (Benchmark Date: 05 Jan 2026)

#### Updated (146 controls)
- Revised rule revision numbers (`rid` tags) for 116 controls updated in V2R7
- Updated fix procedure text and `fix_id` tags for 61 controls with revised remediation guidance
- Removed redundant `CCI-000366` mapping from 46 controls and other stale CCI entries per DISA cleanup in V2R7

#### Added
- **SV-279936** (`RHEL-09-654097`) — New control requiring RHEL 9 to audit any script or executable called by cron as root or by any privileged user (CCI-000172 / AU-12 c / medium)

#### Fixed
- Added missing `tag 'host'` to 9 controls that lacked host/container applicability tags:
  `SV-257936`, `SV-270174`, `SV-270175`, `SV-270176`, `SV-270177`, `SV-270178`, `SV-270180`, `SV-272488`, `SV-272496`

#### Unchanged
- 299 controls with no V2R7 metadata changes were left untouched
- 7 supplementary controls not present in the official XCCDF (`SV-257987`, `SV-257988`, `SV-258062`, `SV-258076`, `SV-258172`, `SV-258226`, `SV-258237`) retained as-is
- All InSpec test logic (describe blocks, only_if guards, input references) preserved across all files

---

## [2.4.0] - (previous release)

Aligned to DISA STIG RHEL 9 V2R4.
