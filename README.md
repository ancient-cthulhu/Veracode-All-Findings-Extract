# Veracode Findings API Export

Exports Veracode findings for all scan types (SAST, DAST, SCA and SCA Agent, Manual Pen Test, IaC/Container Security) into one CSV.

## Features

- **Concurrent:** thread pool with a bounded window, so memory stays flat on any tenant size
- **Rate limited:** shared token bucket. A 429 on any thread pauses all threads
- **Retries:** exponential backoff with jitter, honours `Retry-After` (up to 300 s; a longer one fails the request), on 429/5xx/timeouts. TLS, URL and header errors fail at once
- **Completeness checks:** every run ends `COMPLETE` or `INCOMPLETE` and exits non-zero if data is missing, including repeated or duplicated API pages and pages that come back empty while the API says more exist
- **Reconciliation CSV:** expected vs retrieved count per app/context/scan type and per IaC scan
- **Safe output:** atomic write, deterministic row order, a malformed finding never kills the export, spreadsheet formulas in cells are neutralised
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

Or set environment variables `VERACODE_API_ID` and `VERACODE_API_KEY` (the older `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET` names also work).

**Region:** detected from the API ID (US `api.veracode.com`, EU `api.veracode.eu`, FedRAMP `api.veracode.us`). Override with `VERACODE_API_BASE`.

**Python packages:**
```bash
pip install --no-deps -r requirements.txt
```
`requirements.txt` lists every package the script imports, with minimum versions. `--no-deps` stops `veracode-api-signing` from pulling in `httpie` (and its dependencies), which the script never imports.

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

After any run, check the reconciliation CSV for rows where Status is `MISMATCH` or `FAILED`.

## Arguments

### Scope and Filtering

|Argument           |Default |Description                                          |
|-------------------|--------|-----------------------------------------------------|
|`--output`         |`veracode_findings_api.csv`|Output CSV filename               |
|`--app-name`       |None    |Comma-separated app names (exact match)              |
|`--app-guid`       |None    |Single application GUID (IaC limited to that app)    |
|`--scan-type`      |All     |STATIC, DYNAMIC, MANUAL, SCA, IAC (comma-separated)  |
|`--severity`       |None    |Exact severity (0-5)                                 |
|`--severity-gte`   |None    |Minimum severity (0-5)                               |
|`--cwe`            |None    |CWE ID(s), comma-separated                           |
|`--status`         |None    |OPEN or CLOSED (applied client-side)                 |
|`--violates-policy`|False   |Only findings that fail policy (SCA: filtered client-side, the parameter is not valid for SCA)|
|`--include-sandbox`|False   |Include sandbox findings                             |
|`--max-apps`       |None    |Limit apps processed (testing). Must be 1 or more    |
|`--iac-all-scans`  |False   |IaC: export every historical scan per asset (default: latest scan only)|

### Output

|Argument           |Default |Description                                          |
|-------------------|--------|-----------------------------------------------------|
|`--excel-bom`      |False   |UTF-8 BOM for Excel. Do not use if a script reads the CSV|
|`--raw-json`       |False   |Also write raw API JSON Lines next to `--output` (large on big tenants)|
|`--raw-cells`      |False   |Write cells verbatim. By default a text cell starting with `=` `+` `-` `@`, tab or CR gets a leading `'` so spreadsheets do not run it as a formula. Use for machine consumers and vulnerability-management imports|
|`--dedup`          |False   |Drop duplicate findings (always reported either way; kept duplicates make the run INCOMPLETE)|
|`--no-annotations` |False   |Skip annotations (Mitigation Comments will be blank) |

### Performance and Reliability

|Argument           |Default |Description                                          |
|-------------------|--------|-----------------------------------------------------|
|`--rate-limit`     |3.5     |Requests/sec (210/min, under Veracode's 250/min)     |
|`--max-workers`    |8       |Concurrent threads. The rate limit still caps requests/sec; 8 keeps 3.5 req/s saturated up to ~2.3 s per page|
|`--page-size`      |500     |Records per page (1-500)                             |
|`--max-attempts`   |6       |Attempts per request (1 or more)                     |
|`--sleep`          |0.0     |Extra delay between pages (rarely needed)            |
|`--combine-scan-types`|False|One call for STATIC,DYNAMIC,MANUAL. Undocumented by Veracode, verify counts|
|`--request-all-scan-types`|False|Request policy DYNAMIC/MANUAL findings for every app. By default they are requested only when the app's `scans` list has that scan type (see How It Works)|
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
|1   |Incomplete: check the reconciliation CSV. Do not treat as authoritative. Also used when the finished CSV could not replace a locked file (the temp file path is printed)|
|2   |Invalid arguments                                                |
|130 |Interrupted: previous output file left untouched                 |

Use the exit code to gate pipelines. Auth failures (401/403) are fatal, never retried, and never produce an empty CSV marked as success.

## IaC (Container Security)

Fetched on every run unless excluded with `--scan-type`. No browser cookies needed: the script exchanges your HMAC credentials for a short-lived token (`/api/authn/v2/principal`) and refreshes it automatically if it expires mid-run. IaC assets are matched to applications by name (case-insensitive). Unmatched assets are still exported under a placeholder app entry.

The scan list is the full scan history, so by default only the latest scan per asset (asset ID or name, asset type, scan type, by `scanned_at`) is exported; older scans would repeat every finding as OPEN. `--iac-all-scans` keeps the history. Each IaC scan gets a reconciliation row (`Context` = `iac-scan:<scan id>`, expected = `pagination.total_elements` when the API reports it). IaC rows are ordered by asset name and scan ID.

## Output Files

|File                                        |Contents                                       |
|--------------------------------------------|-----------------------------------------------|
|`<output>.csv`                              |One row per finding, sorted deterministically so runs can be diffed. Written to a private temp file (`mkstemp`, mode 0600) in the same folder and moved into place atomically, so a failed run never leaves a partial file. If the destination is locked (open in Excel) the move is retried a few times, then the run exits 1 and prints the temp file path|
|`<output>_reconciliation_<timestamp>.csv`   |Per app/context/scan type and per IaC scan: expected vs retrieved count, Status `OK`/`MISMATCH`/`FAILED`/`SKIPPED`. `SKIPPED` = request not sent because it could only be empty (reason in Detail). Any `MISMATCH` or `FAILED` row means that context is incomplete|
|`<output>_raw_<timestamp>.jsonl`            |Only with `--raw-json`, next to `--output`. Full API response per finding|

Text cells starting with `=`, `+`, `-`, `@`, tab or CR are prefixed with `'` (CSV formula injection); numbers are never changed. Pass `--raw-cells` when a program, not a spreadsheet, reads the CSV.

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
|Fixed Date / Days to Resolve|Last seen date of a closed, fixed finding (CLOSED with resolution UNRESOLVED or blank). The API has no fix date, so this is the last scan in which the flaw was still present. Blank for mitigated and false-positive closures|
|Team Name           |All teams the application belongs to, joined with `; `           |
|Scan Type           |STATIC, DAST, Dynamic Analysis, MANUAL, SCA, SCA Agent, IAC      |
|CVSS                |Prefers v3                                                       |
|Resolution Status / Resolution|Platform mitigation state (e.g. APPROVED, FALSE POSITIVE)|
|Mitigation Comments |Annotation comments. IaC: suggested fix                          |
|Veracode Link       |Deep link to the finding or scan. Sandbox findings link to the application's module / SCA page (the build links describe policy scans only)|
|IAC File Path / Start Line / End Line|IaC only (blank for other scan types)           |
|Issue ID            |Veracode finding ID. Only unique per app and context, use Finding UID as a key|
|Violates Policy     |Fails assigned policy                                            |
|Export Notes        |Set only when a row could not be fully parsed or enriched (row kept, reason given)|

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
|Business Unit       |Application business unit (blank when Not Specified)            |
|Last Seen Date      |`last_seen_date` from the API for every finding. IaC: scan date  |

**How the UID is built:** `<prefix>-` + first 16 hex chars of SHA-256 over:

```
Application GUID | POLICY or Sandbox GUID | Scan Type | Issue ID
```

- **Application GUID:** Issue ID is only unique within one app.
- **Context:** the same Issue ID appears in the policy scan and each sandbox. GUID is used, not name, so renaming a sandbox does not change it.
- **Scan Type:** raw API value (STATIC, DYNAMIC, MANUAL, SCA), so display labels like "SCA Agent" never affect it.
- **Issue ID:** Veracode keeps it across rescans, so the UID is stable between exports and safe to upsert on.
- **SCA:** uses `component ID ~ CVE` (CWE ID when there is no CVE) instead of the Issue ID, which SCA findings often lack. The component path is not used because upload scans embed a per-upload file ID in it. The path is used only when there is no component ID. **SCA UIDs changed once in this version**: re-key stored SCA rows after the first export.
- **IaC:** has no Issue ID, so it uses `file path(s) ~ start-end line ~ rule ID ~ finding ID ~ type`. Scan ID is excluded to keep it stable. Unmatched IaC assets use `iac-asset:<name>` as the app part.
- **Prefix:** SAST, DAST, MPT, SCA or IAC.

Rows sharing a UID are listed in the run summary. API duplicates that end up in the CSV make the run INCOMPLETE; `--dedup` removes them (a repeated API page already fails its context, so `--dedup` only cleans the output). With `--iac-all-scans`, one IaC finding repeated across scans also shares a UID.

**Columns that are blank by design:** CVE ID (SCA/IaC only), Sandbox Name (sandbox rows only), Fixed Date and Days to Resolve (closed, fixed findings only), CVSS (mostly SCA), Resolution fields (not for IaC).

## How It Works

1. **Setup:** validates credentials, creates pooled HTTP sessions, starts the rate limiter.
2. **Lookups:** fetches all application profiles (paginated; a 404 on the list is fatal, never an empty export), SCA workspace/project mappings and Dynamic Analysis mappings (both used for deep links only, never for which findings are retrieved, and skipped when `--scan-type` excludes SCA / DYNAMIC; Dynamic Analysis pages use size 100, the service maximum; the per-workspace and per-analysis walks run on `--max-workers` threads under the shared rate limit and are merged in list order). Applies `--app-name` / `--app-guid`.
3. **Findings per app (concurrent):**
   - Policy scan: one request per scan type (STATIC, DYNAMIC, MANUAL). Single values are the only documented form. DYNAMIC and MANUAL are requested only when the app's `scans` list from the Applications API has a scan of that type (no scan means the request can only be empty); each skipped request is a `SKIPPED` row in the reconciliation CSV. STATIC and SCA are always requested, and nothing is skipped when the `scans` list is missing or malformed. `--request-all-scan-types` turns the skipping off.
   - SCA: always a separate request (Veracode does not support combining it). Parameters the spec marks invalid for SCA (`include_annot`, `violates_policy`, `finding_category`, `mitigated_after`) are not sent; `--violates-policy` is applied to SCA rows client-side.
   - With `--include-sandbox`: repeats both for every sandbox (paginated). Sandboxes always get every scan type: the Veracode docs describe sandboxes as Static Analysis / SCA ([Scan code in a sandbox](https://docs.veracode.com/r/c_about_sandbox)) but do not state that they cannot hold Dynamic or Manual results, and the sandbox list carries no per-type scan data.
   - `--status` is filtered client-side because it is not a documented API parameter.
   - Pagination continues while `_links.next`, `total_pages` or `total_elements` says more data exists, with a hard page cap that is reported if hit. A context fails (reconciliation `FAILED`) when a page repeats records already seen, when pages come back empty while the API still advertises more, or when a response is not a JSON object.
4. **IaC:** gets the principal token, lists IaC scans, keeps the latest scan per asset, fetches findings per scan, matches assets to apps.
5. **Output:** normalises each row on its own (a bad record becomes a row with `Export Notes`, the rest of the app is kept), strips HTML, computes derived fields, deep links and Finding UID, streams rows per app to a temp file, then publishes atomically and prints the completeness summary. Normalisation runs in the worker thread right after each scan-type request, so the raw API records of a context are freed before the next one is fetched; row order is unchanged.

## Performance

Veracode's guidance is under 250 requests/min. Default `--rate-limit 3.5` is 210/min. Above about 4/s causes 429s and slows the run.

- Default works for any tenant size: `--max-workers 8 --rate-limit 3.5`
- MISMATCH or FAILED in reconciliation: `--max-workers 3 --rate-limit 2`
- Slow run: the rate limit is the bottleneck, raising it past ~4/s makes it slower
- Fewer calls: `--combine-scan-types`. Veracode documents only single scan types, so a partially honoured combined value could silently drop a scan type. Verify counts first
- Proxy and CA settings (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, Windows proxy settings) are read once per host per session instead of on every request, with the same precedence as `requests` (an env CA bundle still overrides `--ca-cert`). `~/.netrc` is not used

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
|IaC auth failed             |Account has Container Security access. Token comes from `/api/authn/v2/principal` and auto-refreshes|
|0 applications              |User accounts only see their teams' apps (service accounts see all). Check the `API Base` line in the banner matches your region (set `VERACODE_API_BASE` if not). A 404 on the application list stops the run (exit 1). Test with `--max-apps 5`|
|429s persist                |Lower `--rate-limit` and `--max-workers`, no parallel runs on the same account. A `Retry-After` above 300 s fails the request instead of waiting|
|Run INCOMPLETE              |Filter reconciliation CSV: `FAILED` = request failed after all retries or the API returned inconsistent pages (repeated records, empty pages while more was advertised), `MISMATCH` = API total differs from retrieved (data changed mid-run or throttling). Re-run with lower rate|
|"could not be published"    |The output CSV was open (e.g. in Excel). Close it, then rename the printed temp file or re-run|
|Cells start with `'`        |Formula neutralisation. Use `--raw-cells` for programmatic imports|
|Fewer findings than platform|`--include-sandbox`, reconciliation failures, API Limitations above|
|Blank fields                |Many columns apply to specific scan types only (expected)        |
|Mitigation Comments blank   |Remove `--no-annotations`. SCA rows never have them (annotations are not available for SCA in the Findings API)|
|First header wrong in a script|Remove `--excel-bom`                                           |
|404 on an app               |No scans yet, no permission, or app deleted                      |
|No sandboxes                |Use `--include-sandbox`, check sandbox permissions. Some apps have none|
|SCA Agent links generic     |Workspace mapping failed. Links only, findings are unaffected    |

## API References

- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro)
- [Applications REST API](https://docs.veracode.com/r/c_apps_intro)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)

*Community tool, not officially supported by Veracode.*
