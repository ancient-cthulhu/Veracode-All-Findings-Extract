# Veracode Findings API Export

Exports Veracode findings for all scan types (SAST, DAST, SCA and SCA Agent, Manual Pen Test, IaC/Container Security) into one CSV.

## Features

- **Concurrent:** thread pool with a bounded window, so memory stays flat on any tenant size
- **Rate limited:** shared token bucket. A 429 on any thread pauses all threads
- **Retries:** exponential backoff with jitter, honours `Retry-After`, on 429/5xx/timeouts
- **Completeness checks:** every run ends `COMPLETE` or `INCOMPLETE` and exits non-zero if data is missing
- **Reconciliation CSV:** expected vs retrieved count per app/context/scan type
- **Safe output:** atomic write, deterministic row order, a malformed finding never kills the export
- **Finding UID:** tenant-wide unique, stable ID per finding
- **Filters:** app, scan type, severity, CWE, status, policy, sandboxes

## Prerequisites

**Credentials** (one of):
- API Service Account with **Results API** role (recommended, org-wide)
- User Account with **Reviewer** or **Security Lead** role (assigned teams only)

```ini
# Mac/Linux: ~/.veracode/credentials   Windows: C:\Users\<username>\.veracode\credentials
[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

**Python packages:**
```bash
pip install requests veracode-api-signing veracode-api-py
```

## Quick Start

```bash
python script.py                                              # everything (policy scans + IaC)
python script.py --app-name "App1,App2"                       # specific apps
python script.py --include-sandbox                            # add sandbox findings
python script.py --severity-gte 4 --status OPEN               # open High/Very High only
python script.py --scan-type IAC                              # one scan type
python script.py --scan-type STATIC,DYNAMIC,MANUAL,SCA        # exclude IaC
python script.py --max-apps 5 --output test.csv               # quick connectivity test
python script.py --include-sandbox --output full-export.csv   # full tenant audit
echo "Exit code: $?"                                          # 0 = complete, 1 = incomplete
```

After any run, check the reconciliation CSV for rows where Status is not `OK`.

## Arguments

### Scope and Filtering

|Argument           |Default |Description                                          |
|-------------------|--------|-----------------------------------------------------|
|`--output`         |`veracode_findings_api.csv`|Output CSV filename               |
|`--app-name`       |None    |Comma-separated app names (exact match)              |
|`--app-guid`       |None    |Single application GUID                              |
|`--scan-type`      |All     |STATIC, DYNAMIC, MANUAL, SCA, IAC (comma-separated)  |
|`--severity`       |None    |Exact severity (0-5)                                 |
|`--severity-gte`   |None    |Minimum severity (0-5)                               |
|`--cwe`            |None    |CWE ID(s), comma-separated                           |
|`--status`         |None    |OPEN or CLOSED (applied client-side)                 |
|`--violates-policy`|False   |Only findings that fail policy                       |
|`--include-sandbox`|False   |Include sandbox findings                             |
|`--max-apps`       |None    |Limit apps processed (testing)                       |

### Output

|Argument           |Default |Description                                          |
|-------------------|--------|-----------------------------------------------------|
|`--excel-bom`      |False   |UTF-8 BOM for Excel. Do not use if a script reads the CSV|
|`--raw-json`       |False   |Also write raw API JSON Lines (large on big tenants) |
|`--dedup`          |False   |Drop duplicate findings (always reported either way) |
|`--no-annotations` |False   |Skip annotations (Mitigation Comments will be blank) |

### Performance and Reliability

|Argument           |Default |Description                                          |
|-------------------|--------|-----------------------------------------------------|
|`--rate-limit`     |3.5     |Requests/sec (210/min, under Veracode's 250/min)     |
|`--max-workers`    |5       |Concurrent threads                                   |
|`--page-size`      |500     |Records per page                                     |
|`--max-attempts`   |6       |Retries per request                                  |
|`--sleep`          |0.0     |Extra delay between pages (rarely needed)            |
|`--combine-scan-types`|False|One call for STATIC,DYNAMIC,MANUAL. Undocumented by Veracode, verify counts|
|`--ignore-failures`|False   |Exit 0 even on failures (not recommended)            |
|`--ca-cert`        |None    |CA bundle (.pem) for SSL inspection (e.g. Zscaler)   |

## Severity Mapping

|Numeric|5        |4   |3     |2  |1       |0            |
|-------|---------|----|------|---|--------|-------------|
|Label  |Very High|High|Medium|Low|Very Low|Informational|

IaC: critical=5, high=4, medium=3, low=2, negligible=1, unknown=0.

## Exit Codes

|Code|Meaning                                                          |
|----|-----------------------------------------------------------------|
|0   |Complete: all requests succeeded and all findings are in the CSV |
|1   |Incomplete: check the reconciliation CSV. Do not treat as authoritative|
|2   |Invalid arguments                                                |
|130 |Interrupted: previous output file left untouched                 |

Use the exit code to gate pipelines. Auth failures (401/403) are fatal, never retried, and never produce an empty CSV marked as success.

## IaC (Container Security)

Fetched on every run unless excluded with `--scan-type`. No browser cookies needed: the script exchanges your HMAC credentials for a short-lived token (`/api/authn/v2/principal`) and refreshes it automatically if it expires mid-run. IaC assets are matched to applications by name (case-insensitive). Unmatched assets are still exported under a placeholder app entry.

## Output Files

|File                                        |Contents                                       |
|--------------------------------------------|-----------------------------------------------|
|`<output>.csv`                              |One row per finding, sorted deterministically so runs can be diffed. Written atomically, so a failed run never leaves a partial file|
|`<output>_reconciliation_<timestamp>.csv`   |Per app/context/scan type: expected vs retrieved count, Status `OK`/`MISMATCH`/`FAILED`. Any non-OK row means that context is incomplete|
|`veracode_findings_api_raw_<timestamp>.jsonl`|Only with `--raw-json`. Full API response per finding|

## CSV Columns

|Column              |Description                                                      |
|--------------------|-----------------------------------------------------------------|
|Application Name / ID|App name and GUID                                               |
|Sandbox Name        |Blank for policy scans and IaC                                   |
|Custom Severity Name|Very High, High, Medium, Low, Very Low, Informational            |
|Severity            |5 to 0, matching the above. IaC: mapped from critical/high/medium/low/negligible/unknown|
|CVE ID              |SCA and IaC vulnerabilities                                      |
|Description         |HTML stripped                                                    |
|Vulnerability Title |SCA: CVE or flaw name. IaC: finding type                         |
|CWE ID              |CWE number. IaC: rule ID (e.g. CIS-DI-0001)                      |
|Flaw Name           |CWE name or category. IaC: finding ID or title                   |
|First Found Date    |ISO 8601. IaC: scan date                                         |
|Filename/Class      |File (STATIC), URL (DYNAMIC), component (SCA), file and lines (IaC)|
|Finding Status      |OPEN or CLOSED. IaC: always OPEN                                 |
|Fixed Date / Days to Resolve|Only when CLOSED or FIXED                                |
|Team Name           |Business unit or first team                                      |
|Scan Type           |STATIC, DAST, Dynamic Analysis, MANUAL, SCA, SCA Agent, IAC      |
|CVSS                |Prefers v3                                                       |
|Resolution Status / Resolution|Platform mitigation state (e.g. APPROVED, FALSE POSITIVE)|
|Mitigation Comments |Annotation comments. IaC: suggested fix                          |
|Veracode Link       |Deep link to the finding or scan                                 |
|IAC File Path / Start Line / End Line|IaC only (blank for other scan types)           |
|Issue ID            |Veracode finding ID. Only unique per app and context, use Finding UID as a key|
|Violates Policy     |Fails assigned policy                                            |
|Export Notes        |Set only when a row could not be fully parsed (row kept, reason given)|

### Finding Identity and Location (appended at the end, existing column positions unchanged)

|Column              |Description                                                      |
|--------------------|-----------------------------------------------------------------|
|Finding UID         |Unique, stable ID, e.g. `SAST-3f9a1c2b7d4e8a10`. **Use as primary key**|
|Finding Key         |Readable form of what the UID is built from                      |
|Module              |STATIC, MANUAL                                                   |
|Line Number         |STATIC, IaC (start line)                                         |
|Procedure           |STATIC                                                           |
|Vulnerable Parameter|DYNAMIC                                                          |
|Component ID        |SCA                                                              |
|Location Detail     |e.g. `app.war \| src/UserDao.java:42 \| in findUser`, `https://host/search \| param=q`|

**How the UID is built:** `<prefix>-` + first 16 hex chars of SHA-256 over:

```
Application GUID | POLICY or Sandbox GUID | Scan Type | Issue ID
```

- **Application GUID:** Issue ID is only unique within one app.
- **Context:** the same Issue ID appears in the policy scan and each sandbox. GUID is used, not name, so renaming a sandbox does not change it.
- **Scan Type:** raw API value (STATIC, DYNAMIC, MANUAL, SCA), so display labels like "SCA Agent" never affect it.
- **Issue ID:** Veracode keeps it across rescans, so the UID is stable between exports and safe to upsert on.
- **IaC:** has no Issue ID, so it uses `file path(s) ~ start-end line ~ rule ID ~ finding ID ~ type`. Scan ID is excluded to keep it stable. Unmatched IaC assets use `iac-asset:<name>` as the app part.
- **Prefix:** SAST, DAST, MPT, SCA or IAC.

Rows sharing a UID are listed in the run summary: API duplicates (remove with `--dedup`) or one IaC finding repeated across scans.

**Columns that are blank by design:** CVE ID (SCA/IaC only), Sandbox Name (sandbox rows only), Fixed Date and Days to Resolve (CLOSED/FIXED only), CVSS (mostly SCA), Resolution fields (not for IaC).

## How It Works

1. **Setup:** validates credentials, creates pooled HTTP sessions, starts the rate limiter.
2. **Lookups:** fetches all application profiles (paginated), SCA workspace/project mappings and Dynamic Analysis mappings (both used for deep links only, never for which findings are retrieved). Applies `--app-name` / `--app-guid`.
3. **Findings per app (concurrent):**
   - Policy scan: one request per scan type (STATIC, DYNAMIC, MANUAL). Single values are the only documented form.
   - SCA: always a separate request (Veracode does not support combining it).
   - With `--include-sandbox`: repeats both for every sandbox (paginated).
   - `--status` is filtered client-side because it is not a documented API parameter.
   - Pagination continues while `_links.next`, `total_pages` or `total_elements` says more data exists, with a hard page cap that is reported if hit.
4. **IaC:** gets the principal token, lists IaC scans, fetches findings per scan, matches assets to apps.
5. **Output:** normalises each row on its own (a bad record becomes a salvage row with `Export Notes`), strips HTML, computes derived fields, deep links and Finding UID, streams rows per app to a temp file, then publishes atomically and prints the completeness summary.

## Performance

Veracode's guidance is under 250 requests/min. Default `--rate-limit 3.5` is 210/min. Above about 4/s causes 429s and slows the run.

- Default works for any tenant size: `--max-workers 5 --rate-limit 3.5`
- MISMATCH or FAILED in reconciliation: `--max-workers 3 --rate-limit 2`
- Slow run: the rate limit is the bottleneck, raising it past ~4/s makes it slower
- Fewer calls: `--combine-scan-types`. Veracode documents only single scan types, so a partially honoured combined value could silently drop a scan type. Verify counts first

## API Limitations

These are Veracode behaviours and cause legitimate differences against the platform:

- Only the **latest policy scan** is returned.
- **Sandbox-only apps** return nothing without `--include-sandbox`.
- **SCA Agent** findings appear only if the project is linked to an app profile. Often the largest gap.
- **Mitigated findings** come back as OPEN with a resolution status, so counts can exceed the UI.

For a full tenant extract including closed and mitigated findings, consider the Reporting API (FINDINGS report). Max six months per call, must be enabled by Veracode support.

## Troubleshooting

|Problem                     |Check                                                            |
|----------------------------|-----------------------------------------------------------------|
|401/403                     |Credentials file location and format, account role (see Prerequisites)|
|IaC auth failed             |Account has Container Security access, `veracode-api-py` installed. Token comes from `/api/authn/v2/principal` and auto-refreshes|
|0 applications              |User accounts only see their teams' apps (service accounts see all). Check API region (US/EU). Test with `--max-apps 5`|
|429s persist                |Lower `--rate-limit` and `--max-workers`, no parallel runs on the same account|
|Run INCOMPLETE              |Filter reconciliation CSV: `FAILED` = request failed after all retries, `MISMATCH` = API total differs from retrieved (data changed mid-run or throttling). Re-run with lower rate|
|Fewer findings than platform|`--include-sandbox`, reconciliation failures, API Limitations above|
|Blank fields                |Many columns apply to specific scan types only (expected)        |
|Mitigation Comments blank   |Remove `--no-annotations`                                        |
|First header wrong in a script|Remove `--excel-bom`                                           |
|404 on an app               |No scans yet, no permission, or app deleted                      |
|No sandboxes                |Use `--include-sandbox`, check sandbox permissions. Some apps have none|
|SCA Agent links generic     |Workspace mapping failed. Links only, findings are unaffected    |

## API References

- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro)
- [Applications REST API](https://docs.veracode.com/r/c_apps_intro)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)

*Community tool, not officially supported by Veracode.*
