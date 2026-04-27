# 🔍 Chrome SNSS Parser - Windows Browser Forensic Extractor. #Chrome-History-SNSS-Parser
Chrome SNSS parser and history extractor for Windows - parses Chrome session files, browsing history, cookies, downloads and browser artifacts from Live machines and forensic images into a timestamped CSV. DFIR/Brwoser forensic tool.

---

## Overview

`SNSS-parser-win_v1.py` is a Python-based forensic tool that extracts and correlates artefacts from Google Chrome (and Chromium) profiles on Windows. It handles locked files (browser open), multiple profiles, multiple users, and multiple Chrome variants in a single run. All output is written to a timestamped CSV and an error/skipped log — no third-party dependencies required.

---

## Requirements

- Python 3.8+
- Windows (live machine or mounted forensic image)
- No external libraries — standard library only

---

## Usage

```bash
# Auto-detect all Chrome profiles on the current machine
py SNSS-parser-win_v1.py

# Scan a specific user
py SNSS-parser-win_v1.py C:\Users\JohnDoe

# Scan a mounted forensic image
py SNSS-parser-win_v1.py D:\Users\
```

### Output Files

Both files are saved in the same folder as the script, named with a UTC timestamp:

| File | Contents |
|---|---|
| `chrome_forensic_YYYYMMDD_HHMMSS.csv` | All extracted artefacts |
| `chrome_forensic_YYYYMMDD_HHMMSS_skipped.log` | Permission errors, locked files, parse warnings |

### CSV Columns

```
#  |  Source  |  Date Time (UTC)  |  URL  |  Title  |  Comments  |  User
```

---

## Supported Browsers

| Browser | Path Scanned |
|---|---|
| Google Chrome (Stable) | `AppData\Local\Google\Chrome\User Data` |
| Google Chrome Beta | `AppData\Local\Google\Chrome Beta\User Data` |
| Google Chrome SxS (Canary) | `AppData\Local\Google\Chrome SxS\User Data` |
| Chromium | `AppData\Local\Chromium\User Data` |

> Microsoft Edge is **not** included — it has its own separate tooling.

---

## What It Extracts

| Source Type | File | Description |
|---|---|---|
| `SESSION` | `Sessions/`, `Current Session`, `Last Session` | Open and restored tabs parsed from SNSS binary format. Covers Chrome 91+ (SNSS v3) and legacy (SNSS v1). |
| `HISTORY` | `History` | Full browsing history with visit counts and timestamps. |
| `DOWNLOAD` | `History` | Downloaded files — original URL, save path, status (complete/cancelled/interrupted), file size. |
| `SEARCH` | `History` | Keyword search terms entered in the address bar, linked to the search URL and timestamp. |
| `TYPED_URL` | `History` | URLs the user manually typed (not clicked), with typed count. |
| `HIDDEN_URL` | `History` | Redirect chain hops and subframe navigations (`hidden=1` in Chrome's urls table). These are suppressed from the omnibox but recorded — useful for uncovering ad-tracking redirects and URL shortener chains. |
| `CLEARED_GAP` | `History` | Gaps in visit ID sequence indicating deleted history records. Reports the ID range, count of deleted visits, and the time window. |
| `FAVICON_ONLY` | `Favicons` | Sites that have a favicon cached but no corresponding History entry — strong indicator that history was cleared after visiting. |
| `COOKIE` | `Network/Cookies` | Cookie name, host, creation time, expiry, secure flag, httponly flag. |
| `BOOKMARK` | `Bookmarks` | All bookmarks with folder path and date added. |
| `TOP_SITE` | `Top Sites` | Most-visited sites stored for the New Tab thumbnail grid. |
| `PASSWORD` | `Login Data` | Saved login usernames and associated URLs. Passwords remain encrypted (DPAPI) and are not decrypted. |
| `AUTOFILL` | `Web Data` | Form field autofill values (names, emails, phone numbers etc.) with usage count and timestamps. |
| `ADDRESS` | `Web Data` | Saved address profiles — full name, email, phone, street address, city, state, zip, country. |
| `GOOGLE_ACCT` | `Preferences`, `Local State` | Signed-in Google account email and display name. |
| `CLEAR_EVENT` | `Preferences` | Timestamp of the last "Clear Browsing Data" action executed by the user. |
| `EXTENSION` | `Secure Preferences` | Installed extensions — name, version, extension ID, enabled/disabled state, install time. |
| `BOTH` | `History` + `Sessions` | Deduplicated entry present in both History and an open Session — merged into a single row with the earliest timestamp. |

---

## Key Forensic Features

**Handles locked files** — Chrome holds write locks on SQLite databases while running. The script catches `PermissionError` on every file copy, logs the failure to the skipped log, and continues parsing everything else. Close Chrome before running for full coverage.

**Deleted history detection** — `CLEARED_GAP` entries identify gaps in Chrome's internal visit ID sequence. A gap of N means N visit records were deleted. The timestamp range shows when the deletion likely occurred.

**Multi-profile, multi-user** — Automatically discovers all Chrome profiles across all Windows user accounts under the scanned path. Each entry is tagged with the Windows username.

**SNSS session parsing** — Parses Chrome's proprietary binary SNSS format to recover open and recently closed tab URLs, titles, and navigation history — including tabs the user never converted to bookmarks.

---

## What Is Not Yet Covered

| Artefact | File | Notes |
|---|---|---|
| Media history | `Media History` | Videos and audio played — site, watch duration, last watch time |
| Network activity predictor | `Network Action Predictor` | URLs Chrome pre-fetched or pre-connected to, even if never fully loaded |
| Push notification permissions | `Platform Notifications` | Sites granted notification permission; individual notification records |
| Visited Links | `Visited Links` | Binary hash table (pre-Chrome 126) or SQLite (Chrome 126+) — survives history clearing |
| Permission grants | `Preferences` → `content_settings` | Sites granted camera, microphone, location access |
| Site engagement scores | `Preferences` → `profile.site_engagement` | Chrome's internal time-on-site scoring |
| Sync metadata | `Sync Data` | Activity synced to a Google account — links behaviour across devices |
| Local Storage / IndexedDB | `Local Storage/`, `IndexedDB/` | Per-site stored data — can contain session tokens, chat logs, user data |
| Chrome cache | `Cache/` | Recently fetched resources — images, scripts, pages |
| Decrypted passwords | `Login Data` | Requires DPAPI decryption using the logged-in user's credentials |

---

## Notes

- All timestamps are **UTC**.
- The CSV uses **UTF-8 with BOM** (`utf-8-sig`) so Excel opens it correctly without garbled characters.
- `AUTOFILL` and `ADDRESS` timestamps use plain Unix epoch — other Chrome tables use Windows FILETIME microseconds.
- Encrypted SNSS versions (v2, v4) are detected and skipped with a warning — they were never shipped in public Chrome builds.

---

## License

MIT
