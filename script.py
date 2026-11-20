#!/usr/bin/env python3
"""Export vulnerability findings from Veracode across all scan types into a single CSV.

Covers SAST, DAST, SCA, Manual, and IaC scan types with concurrent API processing,
rate limiting, and optional sandbox inclusion.

"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import functools
import hashlib
import html
import json
import os
import random
import re
import itertools
import sys
import tempfile
import threading
import time
from collections import Counter as CollCounter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Region-dependent URLs. These are the US defaults; configure_api_base()
# rebinds all of them at startup for EU / FedRAMP tenants.
BASE_URL = "https://api.veracode.com"
APPLICATIONS_URL = f"{BASE_URL}/appsec/v1/applications"
SANDBOXES_URL_TEMPLATE = f"{BASE_URL}/appsec/v1/applications/{{app_guid}}/sandboxes"
FINDINGS_URL_TEMPLATE = f"{BASE_URL}/appsec/v2/applications/{{app_guid}}/findings"
SCA_API_BASE = f"{BASE_URL}/srcclr/v3"
DYNAMIC_ANALYSES_URL = f"{BASE_URL}/was/configservice/v1/analyses"
PRINCIPAL_URL = f"{BASE_URL}/api/authn/v2/principal"
ANALYSIS_CENTER_BASE = "https://analysiscenter.veracode.com/auth/index.jsp"
WEB_UI_BASE = "https://web.analysiscenter.veracode.com"
SCA_UI_BASE = "https://sca.analysiscenter.veracode.com"

# API host per region character (7th char of the API ID prefix, e.g. vera01ei-).
REGION_API_BASES: dict[str, str] = {
    "e": "https://api.veracode.eu",
    "f": "https://api.veracode.us",
    "g": "https://api.veracode.com",
}

# 500 is the documented maximum page size for the Findings API.
DEFAULT_PAGE_SIZE = 500
MAX_PAGE_SIZE = 500
# (connect, read) seconds. A short connect timeout fails fast on an
# unreachable host or proxy; the read timeout covers slow large pages.
CONNECT_TIMEOUT = 10
DEFAULT_REQUEST_TIMEOUT = (CONNECT_TIMEOUT, 120)
NON_SCA_SCAN_TYPES = ("STATIC", "DYNAMIC", "MANUAL")
# Policy-context scan types requested only when the application's scans list
# (Applications API, scan_type enum STATIC/DYNAMIC/MANUAL/SCA) contains them.
POLICY_SKIPPABLE_SCAN_TYPES = frozenset({"DYNAMIC", "MANUAL"})
# Reconciliation statuses that do not make an application incomplete.
RECON_OK_STATUSES = frozenset({"OK", "SKIPPED"})
MAX_ERROR_BODY_LOG = 500

# Findings API query parameters the spec marks "Not valid for the SCA scan
# type" / "Does not apply to the SCA scan type". They are never sent on a
# scan_type=SCA request; --violates-policy is applied client-side instead.
SCA_INVALID_PARAMS = frozenset({
    "include_annot", "violates_policy", "finding_category", "mitigated_after",
})

# Dynamic Analysis configuration service: "The maximum is 100".
DA_PAGE_SIZE = 100

# FindingStatus.resolution: the Findings v2.1 spec types it as a plain string
# with no enum (its example is UNRESOLVED); the platform reports approved
# mitigations as MITIGATED and false positives as POTENTIAL_FALSE_POSITIVE.
# Fixed Date is filled only for CLOSED findings whose resolution is blank or
# UNRESOLVED (an allow-list), so a mitigation, a false positive or any
# unknown future value is never reported as a code fix.
FIXED_RESOLUTIONS = frozenset({"", "UNRESOLVED"})

# Retry policy
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
DEFAULT_MAX_ATTEMPTS = 6
DEFAULT_BASE_BACKOFF = 1.5
MAX_BACKOFF = 90.0
# A server-supplied Retry-After above this is not slept through: the request
# fails as a FetchError instead of stalling every worker for hours.
MAX_RETRY_AFTER = 300.0

# Request errors that will not succeed on retry (bad TLS trust / --ca-cert,
# malformed URL or header). Retrying them only burns the backoff budget.
# SSLError subclasses ConnectionError, so it must be checked first.
PERMANENT_REQUEST_ERRORS: tuple[type[BaseException], ...] = (
    requests.exceptions.SSLError,
    requests.exceptions.InvalidURL,
    requests.exceptions.MissingSchema,
    requests.exceptions.InvalidSchema,
    requests.exceptions.InvalidHeader,
)

# Veracode documents a 250 request/minute guidance. Warn above this.
SAFE_RPS = 4.0

# Hard backstop against an endpoint that advertises a next page forever.
# At the default page size this is 5,000,000 records in one context, far
# beyond any real application, so hitting it means something is wrong.
MAX_PAGES_SAFETY_CAP = 10_000

# IaC / Container Security API (uses principal token auth, not HMAC)
IAC_API_BASE = "https://ui.analysiscenter.veracode.com/container-scan-query/v1"
IAC_SCANS_URL = f"{IAC_API_BASE}/scans"
IAC_FINDINGS_URL_TEMPLATE = f"{IAC_API_BASE}/scans/{{scan_id}}/findings"
IAC_AUTH_TOKEN_PREFIX = "VERACODE-TOKEN vsid="
IAC_MAX_RECORDS = 5000

# Pre-compiled regexes for the hot-path in strip_html_tags
_RE_HTML_TAG = re.compile(r"<[^>]+>")
_RE_WHITESPACE = re.compile(r"\s+")

SEVERITY_LABEL: dict[int, str] = {
    5: "Very High",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Very Low",
    0: "Informational",
}

IAC_SEVERITY_MAP: dict[str, tuple[int, str]] = {
    "critical": (5, "Very High"),
    "high": (4, "High"),
    "medium": (3, "Medium"),
    "low": (2, "Low"),
    "negligible": (1, "Very Low"),
    "unknown": (0, "Informational"),
}

CSV_FIELDNAMES: list[str] = [
    "Application Name",
    "Application ID",
    "Sandbox Name",
    "Custom Severity Name",
    "CVE ID",
    "Description",
    "Vulnerability Title",
    "CWE ID",
    "Flaw Name",
    "First Found Date",
    "Filename/Class",
    "Finding Status",
    "Fixed Date",
    "Team Name",
    "Days to Resolve",
    "Scan Type",
    "CVSS",
    "Severity",
    "Resolution Status",
    "Resolution",
    "Mitigation Comments",
    "Veracode Link",
    "IAC File Path",
    "IAC Start Line",
    "IAC End Line",
    "Issue ID",
    "Violates Policy",
    "Export Notes",
    # --- Finding identity and location (appended so existing column
    # positions are unchanged for consumers that read by position) ---
    "Finding UID",
    "Finding Key",
    "Module",
    "Line Number",
    "Procedure",
    "Vulnerable Parameter",
    "Component ID",
    "Location Detail",
    "Business Unit",
    # Appended last so every earlier column keeps its position.
    "Last Seen Date",
]

# Finding identity
# ----------------
# Veracode's issue_id is only unique inside one application, and the same
# issue_id is reported once per context (policy and each sandbox). A key
# that is unique across the whole tenant therefore needs all four of:
#   application GUID | context (POLICY or sandbox GUID) | scan type | issue_id
# The sandbox GUID is used rather than its name because names can be renamed.
# The raw API scan_type (STATIC, DYNAMIC, MANUAL, SCA) is used rather than the
# display label ("SCA Agent", "Dynamic Analysis") so the key does not change
# if a display rule changes.
CONTEXT_POLICY = "POLICY"
CONTEXT_IAC = "IAC"
UID_HEX_LEN = 16  # 64 bits: ~3e-6 collision odds at 10 million rows
UID_PREFIX: dict[str, str] = {
    "STATIC": "SAST",
    "DYNAMIC": "DAST",
    "MANUAL": "MPT",
    "SCA": "SCA",
    "IAC": "IAC",
}

RECON_FIELDNAMES: list[str] = [
    "Application Name",
    "Application GUID",
    "Context",
    "Scan Type Requested",
    "Expected (API total_elements)",
    "Retrieved",
    "Pages Fetched",
    "Status",
    "Detail",
]

VALID_SCAN_TYPES = frozenset({"STATIC", "DYNAMIC", "MANUAL", "SCA", "IAC"})
API_SCAN_TYPES = frozenset({"STATIC", "DYNAMIC", "MANUAL", "SCA"})


def _parse_requested_scan_types(scan_type_str: Optional[str]) -> list[str]:
    """Parse a comma-separated scan-type string into an uppercase list."""
    if not scan_type_str:
        return []
    return [s.strip().upper() for s in scan_type_str.split(",") if s.strip()]


# ---------------------------------------------------------------------------
# Credentials and Region
# ---------------------------------------------------------------------------

def apply_credential_aliases() -> None:
    """Copy VERACODE_API_ID / VERACODE_API_KEY onto the names the signing
    library reads, without overwriting values that are already set."""
    for src, dst in (("VERACODE_API_ID", "VERACODE_API_KEY_ID"),
                     ("VERACODE_API_KEY", "VERACODE_API_KEY_SECRET")):
        if os.environ.get(src) and not os.environ.get(dst):
            os.environ[dst] = os.environ[src]


def api_base_for_key_id(api_key_id: Optional[str]) -> str:
    """Pick the API host from the 7th character of the API ID prefix."""
    if api_key_id and "-" in api_key_id:
        prefix = api_key_id.split("-", 1)[0]
        if len(prefix) >= 7:
            return REGION_API_BASES.get(prefix[6].lower(), REGION_API_BASES["g"])
    return REGION_API_BASES["g"]


def resolve_api_base() -> str:
    """VERACODE_API_BASE wins; otherwise derive the region from the API ID
    (environment first, then ~/.veracode/credentials). Never logs the ID."""
    override = os.environ.get("VERACODE_API_BASE", "").strip().rstrip("/")
    if override:
        return override if "://" in override else f"https://{override}"
    key_id = os.environ.get("VERACODE_API_KEY_ID")
    if not key_id:
        try:
            from veracode_api_signing.credentials import get_credentials
            key_id = get_credentials()[0]
        except Exception:  # noqa: BLE001 - best effort; signing reports the real error later
            key_id = None
    return api_base_for_key_id(key_id)


def configure_api_base(api_base: str) -> None:
    """Rebind every region-dependent URL for *api_base*.

    The UI hosts share the API host's top-level domain (com / eu / us).
    """
    global BASE_URL, APPLICATIONS_URL, SANDBOXES_URL_TEMPLATE
    global FINDINGS_URL_TEMPLATE, SCA_API_BASE, DYNAMIC_ANALYSES_URL
    global PRINCIPAL_URL, ANALYSIS_CENTER_BASE, WEB_UI_BASE, SCA_UI_BASE
    global IAC_API_BASE, IAC_SCANS_URL, IAC_FINDINGS_URL_TEMPLATE

    BASE_URL = api_base.rstrip("/")
    APPLICATIONS_URL = f"{BASE_URL}/appsec/v1/applications"
    SANDBOXES_URL_TEMPLATE = f"{BASE_URL}/appsec/v1/applications/{{app_guid}}/sandboxes"
    FINDINGS_URL_TEMPLATE = f"{BASE_URL}/appsec/v2/applications/{{app_guid}}/findings"
    SCA_API_BASE = f"{BASE_URL}/srcclr/v3"
    DYNAMIC_ANALYSES_URL = f"{BASE_URL}/was/configservice/v1/analyses"
    PRINCIPAL_URL = f"{BASE_URL}/api/authn/v2/principal"

    host = BASE_URL.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    tld = host.rsplit(".", 1)[-1].lower()
    if tld not in ("com", "eu", "us"):
        tld = "com"
    ANALYSIS_CENTER_BASE = f"https://analysiscenter.veracode.{tld}/auth/index.jsp"
    WEB_UI_BASE = f"https://web.analysiscenter.veracode.{tld}"
    SCA_UI_BASE = f"https://sca.analysiscenter.veracode.{tld}"
    IAC_API_BASE = f"https://ui.analysiscenter.veracode.{tld}/container-scan-query/v1"
    IAC_SCANS_URL = f"{IAC_API_BASE}/scans"
    IAC_FINDINGS_URL_TEMPLATE = f"{IAC_API_BASE}/scans/{{scan_id}}/findings"


# ---------------------------------------------------------------------------
# Failure Tracking
# ---------------------------------------------------------------------------

class FetchError(Exception):
    """Raised when a request could not be completed after all retries."""


class FailureTracker:
    """Thread-safe register of irrecoverable failures and count mismatches.

    The original script printed errors and carried on, so a run that lost
    half its data still ended with 'EXPORT COMPLETED'. Everything recorded
    here is surfaced in the final summary and drives the process exit code.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.failures: list[dict[str, str]] = []
        self.mismatches: list[dict[str, str]] = []
        self.retries = 0
        self.rate_limit_hits = 0
        self.pages_ok = 0
        self.pages_failed = 0

    def record_failure(self, scope: str, detail: str) -> None:
        with self._lock:
            self.failures.append({"scope": scope, "detail": detail})

    def record_mismatch(self, scope: str, expected: int, retrieved: int) -> None:
        with self._lock:
            self.mismatches.append({
                "scope": scope,
                "detail": f"expected {expected}, retrieved {retrieved}",
            })

    def record_page(self, ok: bool) -> None:
        with self._lock:
            if ok:
                self.pages_ok += 1
            else:
                self.pages_failed += 1

    def record_retry(self, was_rate_limit: bool) -> None:
        with self._lock:
            self.retries += 1
            if was_rate_limit:
                self.rate_limit_hits += 1

    @property
    def clean(self) -> bool:
        return not self.failures and not self.mismatches


# ---------------------------------------------------------------------------
# Session Factory
# ---------------------------------------------------------------------------

class ResolvedEnvSession(requests.Session):
    """Session that reads proxy and CA-bundle settings once per host.

    With ``trust_env`` on, requests re-reads HTTP(S)_PROXY / ALL_PROXY /
    NO_PROXY, REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE and, on Windows, the
    registry proxy settings on every request (3.9 s of 4.4 s spent in
    Session.request in a 10k-finding profile). Here ``trust_env`` is off and
    the same lookups run once per scheme+host, then are merged exactly as
    requests merges them: per-host NO_PROXY bypass, and an env CA bundle
    still overrides Session.verify (--ca-cert) unless a request passes its
    own ``verify``. A side effect of trust_env=False: ~/.netrc credentials
    are no longer added to unauthenticated (IaC token) requests.
    """

    def __init__(self) -> None:
        super().__init__()
        self.trust_env = False
        self._env_by_origin: dict[tuple[str, str], tuple[dict[str, str], Optional[str]]] = {}

    def _environment_for(self, url: str) -> tuple[dict[str, str], Optional[str]]:
        parts = urlsplit(url)
        key = (parts.scheme.lower(), parts.netloc.lower())
        hit = self._env_by_origin.get(key)
        if hit is None:
            proxies = requests.utils.get_environ_proxies(url, no_proxy=None)
            bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE")
            hit = self._env_by_origin[key] = (proxies, bundle)
        return hit

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        proxies = {} if proxies is None else proxies
        if proxies.get("no_proxy") is not None:
            # A per-request no_proxy changes the bypass decision; not cached.
            env_proxies = requests.utils.get_environ_proxies(url, no_proxy=proxies["no_proxy"])
            bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE")
        else:
            env_proxies, bundle = self._environment_for(url)
        for k, v in env_proxies.items():
            proxies.setdefault(k, v)
        if verify is True or verify is None:
            verify = bundle or verify
        return super().merge_environment_settings(url, proxies, stream, verify, cert)


def create_session(ca_cert: Optional[str] = None, use_hmac: bool = True) -> requests.Session:
    """Create an HTTP session with connection pooling and optional custom CA cert.

    Note: no urllib3-level retries are configured. urllib3's default Retry has
    an empty status_forcelist, so it would not retry 429/5xx anyway. Retries
    are handled explicitly in request_with_retry so that Retry-After is
    honoured and failures are recorded.
    """
    if ca_cert and not os.path.isfile(ca_cert):
        raise FileNotFoundError(
            f"CA certificate file not found: {ca_cert}\n"
            "If DER-encoded (.cer), convert first: "
            "openssl x509 -inform DER -in corp-ca.cer -out corp-ca.pem"
        )

    session = ResolvedEnvSession()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=50,
        max_retries=0,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if ca_cert:
        session.verify = ca_cert
    if use_hmac:
        session.auth = RequestsAuthPluginVeracodeHMAC()
    return session


_THREAD_LOCAL = threading.local()


def _thread_session(ca_cert: Optional[str] = None, use_hmac: bool = True) -> requests.Session:
    """Return a Session owned by the calling thread, creating it once.

    requests.Session is not documented as thread-safe, so each worker gets
    its own; reusing it across applications keeps the TLS connection alive
    instead of opening a new one per app.
    """
    cache = getattr(_THREAD_LOCAL, "sessions", None)
    if cache is None:
        cache = _THREAD_LOCAL.sessions = {}
    key = (ca_cert, use_hmac)
    session = cache.get(key)
    if session is None:
        session = cache[key] = create_session(ca_cert=ca_cert, use_hmac=use_hmac)
    return session


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe token-bucket rate limiter with global cooperative backoff.

    Key design choices:
    - ``time.sleep()`` is called **outside** the lock so sleeping threads do
      not prevent others from acquiring tokens that have become available.
    - Uses ``time.monotonic()`` to be immune to NTP / wall-clock adjustments.
    - ``pause()`` lets one thread that received a 429 stall every other
      thread. Without this, ten workers keep hammering a throttled endpoint
      and every one of them burns its retry budget.
    """

    def __init__(self, requests_per_second: float = 3.5) -> None:
        self._rps = requests_per_second
        self._tokens = float(requests_per_second)
        self._max_tokens = float(requests_per_second)
        self._last_update = time.monotonic()
        self._pause_until = 0.0
        self._lock = threading.Lock()

    def pause(self, seconds: float) -> None:
        """Stall all callers for at least *seconds* (global backoff).

        Capped at MAX_RETRY_AFTER so one hostile or buggy Retry-After cannot
        freeze every worker for a day.
        """
        seconds = min(max(0.0, seconds), MAX_RETRY_AFTER)
        with self._lock:
            target = time.monotonic() + seconds
            if target > self._pause_until:
                self._pause_until = target

    def acquire(self) -> None:
        """Block until a token is available, then consume it."""
        while True:
            with self._lock:
                now = time.monotonic()

                if now < self._pause_until:
                    sleep_needed = self._pause_until - now
                else:
                    elapsed = now - self._last_update
                    self._tokens = min(
                        self._max_tokens,
                        self._tokens + elapsed * self._rps,
                    )
                    self._last_update = now

                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return  # token acquired, lock released
                    sleep_needed = (1.0 - self._tokens) / self._rps

            # Sleep WITHOUT holding the lock
            time.sleep(sleep_needed)


# ---------------------------------------------------------------------------
# Request Layer (retry + backoff + failure recording)
# ---------------------------------------------------------------------------

def _retry_after_seconds(resp: requests.Response) -> Optional[float]:
    """Parse the Retry-After header (seconds form or HTTP-date form)."""
    raw = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        pass
    try:
        when = dt.datetime.strptime(raw, "%a, %d %b %Y %H:%M:%S %Z")
        # utcnow() is deprecated from Python 3.12; use an aware UTC clock and
        # attach UTC to the parsed value, which %Z leaves naive.
        now = dt.datetime.now(dt.timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        return max(0.0, (when - now).total_seconds())
    except (TypeError, ValueError):
        return None


def request_with_retry(
    session: requests.Session,
    url: str,
    *,
    scope: str,
    rate_limiter: Optional[RateLimiter] = None,
    tracker: Optional[FailureTracker] = None,
    max_attempts: Optional[int] = None,
    ok_statuses: tuple[int, ...] = (200,),
    passthrough_statuses: tuple[int, ...] = (404,),
    auth_refresh: Optional[Any] = None,
    **kwargs: Any,
) -> requests.Response:
    """GET *url* with rate limiting and retries.

    Retries on connection errors, timeouts and RETRYABLE_STATUS codes,
    honouring Retry-After when present. Raises FetchError when the request
    cannot be completed. Statuses in *passthrough_statuses* are returned to
    the caller as-is so it can decide (404 usually means 'no data here').

    *auth_refresh*, when supplied, is called once on a 401 to mint a fresh
    credential and returns replacement headers. This exists for the IaC
    principal token, which is obtained once and can expire part-way through
    a long run. Without it an expiry turns every remaining IaC request into
    a hard failure.
    """
    last_detail = "unknown"
    auth_refreshed = False
    # Resolved here rather than as a default argument, because default
    # arguments bind once at definition time and would ignore --max-attempts.
    if max_attempts is None:
        max_attempts = DEFAULT_MAX_ATTEMPTS
    max_attempts = max(1, max_attempts)
    # requests has no default timeout; a stalled socket would hang a worker.
    # A bare number is the read timeout; the connect timeout is added.
    timeout = kwargs.get("timeout", DEFAULT_REQUEST_TIMEOUT)
    if isinstance(timeout, (int, float)) and not isinstance(timeout, bool):
        timeout = (CONNECT_TIMEOUT, timeout)
    kwargs["timeout"] = timeout

    for attempt in range(1, max_attempts + 1):
        if rate_limiter:
            rate_limiter.acquire()

        retry_after: Optional[float] = None
        try:
            resp = session.get(url, **kwargs)
        except PERMANENT_REQUEST_ERRORS as exc:
            raise FetchError(
                f"{scope}: {type(exc).__name__} (not retried): {str(exc)[:200]}"
            ) from exc
        except requests.RequestException as exc:
            last_detail = f"{type(exc).__name__}: {str(exc)[:200]}"
        else:
            if resp.status_code in ok_statuses:
                return resp
            if resp.status_code in passthrough_statuses:
                return resp
            if resp.status_code == 401 and auth_refresh and not auth_refreshed:
                # Credential expired mid-run. Mint a new one and retry this
                # exact request once before giving up.
                auth_refreshed = True
                try:
                    new_headers = auth_refresh()
                except Exception as exc:
                    raise FetchError(
                        f"{scope}: HTTP 401 and credential refresh failed: {exc}"
                    ) from exc
                if new_headers:
                    kwargs["headers"] = {**(kwargs.get("headers") or {}), **new_headers}
                print(f"    AUTH refreshed after 401 [{scope}]; retrying")
                continue
            if resp.status_code not in RETRYABLE_STATUS:
                body = resp.text[:MAX_ERROR_BODY_LOG] if resp.text else ""
                raise FetchError(
                    f"{scope}: non-retryable HTTP {resp.status_code}. {body}"
                )
            last_detail = f"HTTP {resp.status_code}"
            retry_after = _retry_after_seconds(resp)
            if resp.status_code == 429 and rate_limiter:
                # Stall every worker, not just this one (pause() is capped).
                rate_limiter.pause(retry_after if retry_after is not None else 30.0)
            if retry_after is not None and retry_after > MAX_RETRY_AFTER:
                raise FetchError(
                    f"{scope}: HTTP {resp.status_code} with Retry-After "
                    f"{retry_after:.0f}s, above the {MAX_RETRY_AFTER:.0f}s cap; "
                    f"not waiting")

        if tracker:
            tracker.record_retry(was_rate_limit=last_detail == "HTTP 429")

        if attempt == max_attempts:
            break

        if retry_after is not None:
            delay = retry_after
        else:
            delay = min(MAX_BACKOFF, DEFAULT_BASE_BACKOFF * (2 ** (attempt - 1)))
        delay += random.uniform(0.0, 0.3 * max(delay, 0.5))  # jitter
        print(f"    RETRY {attempt}/{max_attempts - 1} [{scope}] after {last_detail}; "
              f"sleeping {delay:.1f}s")
        time.sleep(delay)

    raise FetchError(f"{scope}: exhausted {max_attempts} attempts. Last error: {last_detail}")


# ---------------------------------------------------------------------------
# HAL Helpers
# ---------------------------------------------------------------------------

def _get_embedded(data: dict, key: str) -> list[dict]:
    """Safely extract ``data["_embedded"][key]``, defaulting to ``[]``."""
    return (data.get("_embedded") or {}).get(key, []) or []


def _page_meta(data: dict) -> tuple[Optional[int], Optional[int]]:
    """Return ``(total_pages, total_elements)`` from a HAL page block."""
    page = data.get("page") or {}
    tp = page.get("total_pages")
    te = page.get("total_elements")
    return (
        int(tp) if isinstance(tp, (int, float)) else None,
        int(te) if isinstance(te, (int, float)) else None,
    )


def _has_next(data: dict) -> bool:
    return bool((data.get("_links") or {}).get("next"))


def _record_identity(record: Any) -> Any:
    """Identity used to spot a record served twice during one walk.

    Findings carry ``issue_id`` (unique per scan type within one context);
    anything else (applications, sandboxes, SCA findings without an
    issue_id) is identified by a stable hash of the whole record.
    """
    if isinstance(record, dict) and not _blank(record.get("issue_id")):
        return ("issue", _s(record.get("scan_type")), _s(record.get("issue_id")))
    blob = json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)
    return ("hash", hashlib.sha256(blob.encode("utf-8")).hexdigest())


def _json_object(resp: requests.Response, where: str) -> dict:
    """Decode a JSON object body or raise FetchError.

    A 200 carrying ``null``, a list or a scalar used to escape as an
    AttributeError, bypassing the failure accounting and the FATAL path.
    """
    try:
        data = resp.json()
    except ValueError as exc:
        raise FetchError(f"{where}: invalid JSON response ({exc})") from exc
    if not isinstance(data, dict):
        raise FetchError(
            f"{where}: expected a JSON object, got {type(data).__name__}")
    return data


def paginate(
    session: requests.Session,
    url: str,
    embedded_key: str,
    *,
    scope: str,
    rate_limiter: Optional[RateLimiter],
    tracker: Optional[FailureTracker],
    params: Optional[dict[str, Any]] = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    timeout: int = 120,
    sleep_time: float = 0.0,
    max_pages: int = MAX_PAGES_SAFETY_CAP,
    on_page: Optional[Any] = None,
    empty_on_404: bool = True,
) -> tuple[list[dict], Optional[int], int]:
    """Walk every page of a Veracode HAL collection.

    Stop conditions, in order of safety:

    - The walk continues while EITHER ``_links.next`` is present OR
      ``page.total_pages`` says more pages remain. Trusting ``total_pages``
      alone is unsafe: on a large tenant the count can be stale or computed
      against a snapshot taken before the walk finished, and believing it
      truncates the walk exactly like the bug this script exists to fix.
      Only when both signals agree there is no more data do we stop.
    - An empty page ends the walk only when no next link is advertised, so a
      single sparse page cannot end it early. Two consecutive empty pages
      while ``_links.next`` or ``total_pages`` still says more exists is a
      FetchError (the result would be silently truncated otherwise).
    - A page whose records were all seen earlier in the walk (a repeated
      page from a cache, proxy or unstable sort), or any record served
      twice, is a FetchError: the count may still match ``total_elements``
      while real records were never fetched.
    - ``max_pages`` is a hard backstop against an API that advertises a next
      link forever. Hitting it is recorded as a failure, never silently.

    A 404 on page 0 means "no data" unless *empty_on_404* is False, in which
    case it is a FetchError (used for the application list, where a 404 means
    a wrong base URL or path rather than an empty tenant).

    Returns ``(records, total_elements_reported, pages_fetched)``.
    Raises FetchError if any page could not be retrieved or is inconsistent.
    """
    base_params = dict(params or {})
    base_params["size"] = page_size

    records: list[dict] = []
    seen_ids: set = set()
    total_elements: Optional[int] = None
    total_pages: Optional[int] = None
    page = 0
    pages_fetched = 0
    empty_streak = 0

    while True:
        req_params = dict(base_params)
        req_params["page"] = page

        resp = request_with_retry(
            session, url,
            scope=f"{scope} page {page}",
            rate_limiter=rate_limiter,
            tracker=tracker,
            params=req_params,
            timeout=timeout,
        )
        if resp.status_code == 404:
            if page > 0:
                # A later page vanishing is not 'no data': the earlier pages
                # said more existed. Fail the context instead of truncating.
                raise FetchError(
                    f"{scope} page {page}: HTTP 404 mid-walk after "
                    f"{len(records)} records")
            if not empty_on_404:
                raise FetchError(f"{scope} page 0: HTTP 404 (endpoint not found)")
            break

        data = _json_object(resp, f"{scope} page {page}")

        pages_fetched += 1
        if tracker:
            tracker.record_page(ok=True)
        batch = _get_embedded(data, embedded_key)
        tp, te = _page_meta(data)
        if te is not None:
            total_elements = te
        if tp is not None:
            total_pages = tp

        if batch:
            ids = [_record_identity(r) for r in batch]
            repeats = sum(1 for i in ids if i in seen_ids)
            if repeats == len(ids):
                raise FetchError(
                    f"{scope} page {page}: repeated page (all {len(ids)} records "
                    f"were already returned by an earlier page)")
            if repeats or len(set(ids)) != len(ids):
                raise FetchError(
                    f"{scope} page {page}: {repeats or len(ids) - len(set(ids))} "
                    f"duplicate record(s) across pages; total_elements="
                    f"{total_elements}, unique so far {len(seen_ids)}")
            seen_ids.update(ids)
            records.extend(batch)
            empty_streak = 0
            if on_page:
                on_page(page, batch, len(records), total_elements)
        else:
            empty_streak += 1

        # --- Stop logic -------------------------------------------------
        # Each signal may independently claim there is more data. Only stop
        # when none of them does.
        next_link = _has_next(data)
        meta_says_more = total_pages is not None and page < total_pages - 1
        count_says_more = (
            total_elements is not None and len(records) < total_elements
        )

        if not (next_link or meta_says_more or count_says_more):
            break

        # An API that advertises more but keeps returning nothing would spin
        # forever. Two consecutive empty pages end the walk; if a next link or
        # total_pages still promised more, that is a truncation, not the end.
        # (A short count alone is left to the caller's total_elements check,
        # which reports it as a MISMATCH.)
        if empty_streak >= 2:
            if next_link or meta_says_more:
                raise FetchError(
                    f"{scope} page {page}: {empty_streak} consecutive empty pages "
                    f"while the API still advertises more data "
                    f"(next link={next_link}, total_pages={total_pages}); "
                    f"stopped after {len(records)} records")
            break

        page += 1

        if page >= max_pages:
            detail = (
                f"{scope}: hit the {max_pages}-page safety cap after "
                f"{len(records)} records. The walk was stopped, so this "
                f"result set may be incomplete."
            )
            if tracker:
                tracker.record_failure(scope, detail)
            print(f"    ! {detail}")
            break

        if sleep_time > 0:
            time.sleep(sleep_time)

    return records, total_elements, pages_fetched


# ---------------------------------------------------------------------------
# Text Utilities
# ---------------------------------------------------------------------------

def strip_html_tags(text: Optional[str]) -> Optional[str]:
    """Remove HTML tags, decode entities, and normalise whitespace.

    Also attempts base64 decoding for payloads that look like encoded HTML.
    """
    if not text:
        return text

    # Heuristic: long, space-free ASCII means likely base64-encoded HTML.
    if len(text) > 100 and " " not in text and text.isascii():
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="ignore")
            if "<" in decoded and ">" in decoded:
                text = decoded
        except Exception:
            pass

    text = _RE_HTML_TAG.sub("", text)
    text = html.unescape(text)
    text = _RE_WHITESPACE.sub(" ", text).strip()
    return text


def _extract_team_name(app_profile: dict[str, Any]) -> Optional[str]:
    """All teams the application belongs to, sorted and joined with '; '."""
    teams = app_profile.get("teams") or []
    names = sorted({str(t.get("team_name")).strip() for t in teams
                    if isinstance(t, dict) and t.get("team_name")})
    return "; ".join(names) or None


def _extract_business_unit(app_profile: dict[str, Any]) -> Optional[str]:
    """Business unit name, blank when unset ('Not Specified')."""
    bu = app_profile.get("business_unit")
    name = bu.get("name") if isinstance(bu, dict) else None
    return name if name and name != "Not Specified" else None


# ---------------------------------------------------------------------------
# Finding Field Extractors
# ---------------------------------------------------------------------------

def _extract_cwe_id(details: dict[str, Any]) -> Optional[int]:
    cwe = details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("id")
    if isinstance(cwe, (int, float)):
        return int(cwe)
    return None


def _extract_cwe_name(details: dict[str, Any]) -> Optional[str]:
    cwe = details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("name")
    return details.get("finding_category") or details.get("flaw_name")


def _extract_cve_id(details: dict[str, Any]) -> Optional[str]:
    cve = details.get("cve")
    if isinstance(cve, dict):
        return cve.get("name")
    if isinstance(cve, str):
        return cve
    return None


def _extract_cvss(details: dict[str, Any]) -> Optional[float]:
    cve = details.get("cve")
    if isinstance(cve, dict):
        cvss3 = cve.get("cvss3")
        if isinstance(cvss3, dict):
            score = cvss3.get("score")
            if score is not None:
                return score
        return cve.get("cvss")
    return details.get("cvss")


_FILENAME_KEYS: dict[str, tuple[str, ...]] = {
    "STATIC": ("file_name", "file_path"),
    "DYNAMIC": ("path", "URL"),
    "MANUAL": ("location", "module"),
    "SCA": ("component_filename", "version"),
}


def _extract_filename(details: dict[str, Any], scan_type: str) -> Optional[str]:
    for key in _FILENAME_KEYS.get(scan_type, ()):
        val = details.get(key)
        if val:
            return val
    return None


def _extract_mitigation_comments(finding: dict[str, Any]) -> Optional[str]:
    """Build a pipe-delimited string from annotation comments.

    Requires include_annot=TRUE on the findings request, which this version
    sends by default. Without it the annotations node is absent and this
    always returned None.
    """
    annotations = finding.get("annotations") or []
    parts: list[str] = []
    for ann in annotations if isinstance(annotations, list) else []:
        if not isinstance(ann, dict):
            continue
        comment = ann.get("comment")
        if comment:
            action = ann.get("action", "")
            parts.append(f"[{action}] {comment}" if action else comment)
    return " | ".join(parts) if parts else None


# ---------------------------------------------------------------------------
# Finding Identity and Location
# ---------------------------------------------------------------------------

def _s(value: Any) -> str:
    """Stringify for keys: None becomes '', whitespace is trimmed."""
    return "" if value is None else str(value).strip()


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def build_finding_identity(
    app_key: Any, context: Any, scan_type: Any, identity: Any,
) -> tuple[str, str]:
    """Return ``(finding_uid, finding_key)`` for one finding.

    finding_key is the readable form, e.g.
    ``<app-guid>|POLICY|STATIC|1042``. finding_uid is a short, fixed-length
    digest of the same parts with a scan-type prefix, e.g.
    ``SAST-3f9a1c2b7d4e8a10``, which is easier to filter on in Excel and to
    use as a primary key downstream.

    The digest is taken over a JSON array of the parts, not the joined
    string, so a '|' inside a component (a file path, say) cannot make two
    different findings hash to the same value.
    """
    parts = [_s(app_key), _s(context) or CONTEXT_POLICY,
             _s(scan_type).upper() or "UNKNOWN", _s(identity)]
    key = "|".join(parts)
    digest = hashlib.sha256(
        json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:UID_HEX_LEN]
    prefix = UID_PREFIX.get(parts[2], "UNK")
    return f"{prefix}-{digest}", key


def _sca_component_path(details: dict[str, Any]) -> Optional[str]:
    """Flatten SCA component_path, which may be a list of dicts or strings."""
    raw = details.get("component_path")
    if not raw:
        return None
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        paths = []
        for item in raw:
            if isinstance(item, dict):
                p = item.get("path")
                if p:
                    paths.append(str(p))
            elif item:
                paths.append(str(item))
        return ", ".join(paths) or None
    return None


def extract_location(details: dict[str, Any], scan_type: Optional[str]) -> dict[str, Any]:
    """Pull the fields that tell two otherwise identical-looking findings apart.

    SAST rows with the same CWE in the same file previously looked
    identical in the CSV because only file_name was exported. Line number,
    module, full path and procedure are what differ between them. Every key
    is read with .get(), so a field the API omits leaves the cell blank
    rather than failing the row.
    """
    out: dict[str, Any] = {
        "Module": None,
        "Line Number": None,
        "Procedure": None,
        "Vulnerable Parameter": None,
        "Component ID": None,
        "Location Detail": None,
    }
    parts: list[str] = []

    if scan_type == "STATIC":
        module = details.get("module")
        path = details.get("file_path") or details.get("file_name")
        line = details.get("file_line_number")
        proc = details.get("procedure")
        out["Module"] = module or None
        out["Line Number"] = None if _blank(line) else line
        out["Procedure"] = proc or None
        if module:
            parts.append(str(module))
        if path:
            parts.append(f"{path}:{line}" if not _blank(line) else str(path))
        if proc:
            parts.append(f"in {proc}")

    elif scan_type == "DYNAMIC":
        url = details.get("URL") or details.get("url")
        if not url:
            host = details.get("hostname")
            port = details.get("port")
            path = details.get("path")
            if host:
                url = f"{host}:{port}" if port else str(host)
                if path:
                    url += path if str(path).startswith("/") else f"/{path}"
            elif path:
                url = str(path)
        param = details.get("vulnerable_parameter")
        out["Vulnerable Parameter"] = param or None
        if url:
            parts.append(str(url))
        if param:
            parts.append(f"param={param}")

    elif scan_type == "MANUAL":
        module = details.get("module")
        location = details.get("location")
        vector = details.get("input_vector")
        out["Module"] = module or None
        for v in (module, location):
            if v:
                parts.append(str(v))
        if vector:
            parts.append(f"vector={vector}")

    elif scan_type == "SCA":
        comp_id = details.get("component_id")
        fname = details.get("component_filename")
        version = details.get("version")
        cpath = _sca_component_path(details)
        out["Component ID"] = comp_id or None
        if fname:
            parts.append(f"{fname} {version}" if version else str(fname))
        elif version:
            parts.append(str(version))
        if cpath:
            parts.append(f"path={cpath}")

    out["Location Detail"] = " | ".join(parts) or None
    return out


def _content_identity(details: dict[str, Any], scan_type: Optional[str]) -> str:
    """Fallback identity when a finding arrives without an issue_id.

    Not expected for Findings API data, but a blank issue_id would otherwise
    collapse every such finding in an app onto one UID.
    """
    loc = extract_location(details, scan_type)
    bits = [
        _s(_extract_cwe_id(details)),
        _s(_extract_cve_id(details)),
        _s(loc.get("Component ID")),
        _s(loc.get("Location Detail")),
    ]
    return "content:" + "~".join(bits)


# ---------------------------------------------------------------------------
# Date Helpers
# ---------------------------------------------------------------------------

def _days_between(start_iso: Optional[str], end_iso: Optional[str]) -> Optional[int]:
    """Return the number of days between two ISO-8601 date strings, or None."""
    if not start_iso or not end_iso:
        return None
    try:
        s = dt.datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        e = dt.datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
        # Mixed offset-aware / naive values cannot be subtracted; treat a
        # missing offset as UTC instead of silently returning None.
        if s.tzinfo is None:
            s = s.replace(tzinfo=dt.timezone.utc)
        if e.tzinfo is None:
            e = e.replace(tzinfo=dt.timezone.utc)
        return (e - s).days
    except (ValueError, TypeError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Scan-URL Parsing
# ---------------------------------------------------------------------------

def _parse_scan_url_params(scan_url: str) -> Optional[tuple[int, str]]:
    """Parse ``'Prefix:a:b:12345:extra'`` into ``(12345, '12345:extra')``."""
    parts = scan_url.split(":")
    if len(parts) >= 4:
        try:
            build_id = int(parts[3])
            return build_id, ":".join(parts[3:])
        except (ValueError, IndexError):
            pass
    return None


# ---------------------------------------------------------------------------
# Veracode Deep-Link Generation
# ---------------------------------------------------------------------------

def _link_suffix(primary: str, secondary: Optional[str]) -> str:
    return f"{primary}:{secondary}" if secondary else f"{primary}:"


def _generate_veracode_link(
    app_guid: str,
    scan_type: str,
    details: Optional[dict[str, Any]],
    sandbox_guid: Optional[str] = None,
    finding_obj: Optional[dict[str, Any]] = None,
    app_id: Optional[str] = None,
    app_oid: Optional[str] = None,
) -> Optional[str]:
    """Build a platform deep-link appropriate for the scan type."""
    if not app_guid:
        return None
    base = ANALYSIS_CENTER_BASE

    if scan_type == "STATIC":
        return _link_static(base, app_guid, app_id, app_oid, sandbox_guid, finding_obj, details)
    if scan_type == "DYNAMIC":
        return _link_dynamic(base, app_guid, sandbox_guid, finding_obj)
    if scan_type == "MANUAL":
        return f"{base}#AnalyzeAppManualList:{_link_suffix(app_guid, sandbox_guid)}"
    if scan_type == "SCA":
        return _link_sca(base, app_guid, app_id, app_oid, sandbox_guid, finding_obj, details)
    return f"{base}#AnalyzeAppModuleList:{app_guid}:"


def _link_static(
    base: str, app_guid: str, app_id: Optional[str], app_oid: Optional[str],
    sandbox_guid: Optional[str], finding_obj: Optional[dict], details: Optional[dict],
) -> str:
    # The scan-url params and the app's build list describe POLICY scans
    # only, so a sandbox finding would deep-link to the policy build. Sandbox
    # findings get the application-level module list instead.
    if sandbox_guid:
        if app_oid and app_id:
            return f"{base}#AnalyzeAppModuleList:{app_oid}:{app_id}:"
        return f"{base}#AnalyzeAppModuleList:{_link_suffix(app_guid, sandbox_guid)}"

    scan_params = None
    if finding_obj:
        # Prefer the params for the build the finding actually came from.
        scan_params = (
            finding_obj.get("_finding_scan_params")
            or finding_obj.get("_latest_scan_params")
        )
    if scan_params and app_oid and app_id:
        return f"{base}#ReviewResultsAllFlaws:{app_oid}:{app_id}:{scan_params}"

    build_id = (finding_obj or {}).get("build_id") or (details or {}).get("build_id")
    if build_id and app_oid and app_id:
        return f"{base}#ReviewResultsAllFlaws:{app_oid}:{app_id}:{build_id}"
    if app_oid and app_id:
        return f"{base}#AnalyzeAppModuleList:{app_oid}:{app_id}:"
    return f"{base}#AnalyzeAppModuleList:{_link_suffix(app_guid, sandbox_guid)}"


def _link_dynamic(
    base: str, app_guid: str, sandbox_guid: Optional[str], finding_obj: Optional[dict],
) -> str:
    if finding_obj:
        da_id = finding_obj.get("_dynamic_analysis_id")
        if da_id:
            return f"{WEB_UI_BASE}/was/#/analysis/{da_id}/scans"
        dast_url = finding_obj.get("_dast_scan_url")
        if dast_url:
            return f"{base}#{dast_url}"
    return f"{base}#AnalyzeAppDynamicList:{_link_suffix(app_guid, sandbox_guid)}"


def _link_sca(
    base: str, app_guid: str, app_id: Optional[str], app_oid: Optional[str],
    sandbox_guid: Optional[str], finding_obj: Optional[dict], details: Optional[dict],
) -> str:
    if details:
        metadata = _sca_metadata(details)
        if str(metadata.get("sca_scan_mode", "")).upper() == "AGENT":
            ws = (
                details.get("workspace_guid") or details.get("workspace_id")
                or metadata.get("workspace_guid") or metadata.get("workspace_id")
            )
            pid = details.get("project_id") or metadata.get("project_id")
            if finding_obj:
                ws = ws or finding_obj.get("_sca_workspace_guid") or finding_obj.get("workspace_guid")
                pid = pid or finding_obj.get("_sca_project_id") or finding_obj.get("project_id")
            if ws and pid:
                return f"{SCA_UI_BASE}/workspaces/{ws}/projects/{pid}/issues"
            return f"{SCA_UI_BASE}/workspaces"

    # Policy-scan params only; a sandbox finding gets the app-level page.
    scan_params = None if sandbox_guid else (finding_obj or {}).get("_latest_scan_params")
    if scan_params and app_oid and app_id:
        return f"{base}#ReviewResultsSCA:{app_oid}:{app_id}:{scan_params}"
    if app_oid and app_id:
        return f"{base}#AnalyzeAppSourceComposition:{app_oid}:{app_id}:"
    return f"{base}#AnalyzeAppSourceComposition:{_link_suffix(app_guid, sandbox_guid)}"


# ---------------------------------------------------------------------------
# Finding Normalisation
# ---------------------------------------------------------------------------

def _sca_metadata(details: Any) -> dict[str, Any]:
    """finding_details.metadata as a dict.

    The Findings spec declares ``metadata`` a string while its example shows
    an object; anything that is not an object is treated as absent.
    """
    meta = details.get("metadata") if isinstance(details, dict) else None
    return meta if isinstance(meta, dict) else {}


def _sca_identity(details: dict[str, Any]) -> Optional[str]:
    """Stable identity for an SCA finding, or None without a component_id.

    component_id names the library version and the CVE (or, without one, the
    CWE) names the vulnerability, so together they survive rescans.
    component_path is not used: upload-scan paths embed a per-upload file
    id (``file330108_1682024184933_html/...``) that changes on every scan.
    """
    comp = _s(details.get("component_id"))
    if not comp:
        return None
    vuln = _s(_extract_cve_id(details))
    if not vuln:
        cwe = _s(_extract_cwe_id(details))
        vuln = f"cwe:{cwe}" if cwe else ""
    return f"sca:{comp}~{vuln}"


def normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalise a raw API finding record into the common CSV schema."""
    app_profile = finding.get("_app_profile") or {}
    scan_type = finding.get("scan_type")
    original_scan_type = scan_type
    details = finding.get("finding_details") or {}

    # Refine scan-type label for display
    if scan_type == "SCA":
        if _sca_metadata(details).get("sca_scan_mode") == "AGENT":
            scan_type = "SCA Agent"
    elif scan_type == "DYNAMIC":
        if finding.get("_dynamic_analysis_id"):
            scan_type = "Dynamic Analysis"
        elif finding.get("_dast_scan_url"):
            scan_type = "DAST"

    status_obj = finding.get("finding_status") or {}
    first_found = status_obj.get("first_found_date")
    last_seen = status_obj.get("last_seen_date")
    status = status_obj.get("status")
    resolution_status = status_obj.get("resolution_status")
    resolution = status_obj.get("resolution")

    # The Findings API has no fix date (FindingStatus has no resolution_date).
    # For a CLOSED finding that was fixed (not mitigated, not a false
    # positive) the best available value is last_seen_date: the last scan in
    # which the flaw was still present. A mitigated finding is never "fixed".
    fixed_date = None
    if (str(status or "").upper() == "CLOSED"
            and _s(resolution).upper() in FIXED_RESOLUTIONS):
        fixed_date = last_seen

    cve_id = _extract_cve_id(details)
    flaw_name = _extract_cwe_name(details)
    severity = details.get("severity")

    vuln_title = None
    if scan_type in ("SCA", "SCA Agent"):
        vuln_title = cve_id or flaw_name

    app_guid = finding.get("_app_guid")
    app_id = finding.get("_app_id")
    app_oid = finding.get("_app_oid")

    issue_id = finding.get("issue_id")
    identity = _sca_identity(details) if original_scan_type == "SCA" else None
    if identity is None:
        identity = (issue_id if not _blank(issue_id)
                    else _content_identity(details, original_scan_type))
    finding_uid, finding_key = build_finding_identity(
        app_guid,
        finding.get("_sandbox_guid") or CONTEXT_POLICY,
        original_scan_type,
        identity,
    )
    location = extract_location(details, original_scan_type)

    return {
        **location,
        "Finding UID": finding_uid,
        "Finding Key": finding_key,
        "Application Name": finding.get("_app_name"),
        "Application ID": app_guid,
        "Sandbox Name": finding.get("_sandbox_name"),
        "Custom Severity Name": SEVERITY_LABEL.get(severity) if severity is not None else None,
        "CVE ID": cve_id,
        "Description": strip_html_tags(finding.get("description")),
        "Vulnerability Title": vuln_title,
        "CWE ID": _extract_cwe_id(details),
        "Flaw Name": flaw_name,
        "First Found Date": first_found,
        "Filename/Class": _extract_filename(details, original_scan_type),
        "Finding Status": status,
        "Fixed Date": fixed_date,
        "Team Name": _extract_team_name(app_profile),
        "Business Unit": _extract_business_unit(app_profile),
        "Days to Resolve": _days_between(first_found, fixed_date),
        "Scan Type": scan_type,
        "CVSS": _extract_cvss(details),
        "Severity": severity,
        "Resolution Status": resolution_status,
        "Resolution": resolution,
        "Veracode Link": _generate_veracode_link(
            app_guid, original_scan_type, details,
            finding.get("_sandbox_guid"), finding, app_id, app_oid,
        ),
        "Mitigation Comments": _extract_mitigation_comments(finding),
        "Issue ID": finding.get("issue_id"),
        "Violates Policy": finding.get("violates_policy"),
        "Last Seen Date": last_seen,
        # Set when per-finding enrichment failed (row kept, links degraded).
        "Export Notes": finding.get("_export_note"),
    }


def normalize_iac_finding(
    finding: dict[str, Any],
    iac_record: dict[str, Any],
    app_name: str,
    app_guid: str,
    app_profile: Optional[dict[str, Any]],
    app_key: Optional[str] = None,
) -> dict[str, Any]:
    """Normalise a detailed IaC finding into the common CSV schema.

    *app_key* is the application component of the Finding UID. For an IaC
    asset matched to an application profile it is the application GUID. For
    an unmatched asset the caller passes ``iac-asset:<name>`` because the
    placeholder Application ID is the scan_id, which changes every scan and
    would make the UID unstable.
    """
    sev_str = str(finding.get("severity", "unknown")).lower()
    sev_level, sev_label = IAC_SEVERITY_MAP.get(sev_str, (0, "Informational"))

    finding_id = finding.get("id", "")
    finding_type = finding.get("finding_type", "")
    title = strip_html_tags(finding.get("title", "") or finding.get("description", "IaC Misconfiguration"))
    description = strip_html_tags(finding.get("description", ""))
    suggested_fix = strip_html_tags(finding.get("suggested_fix", ""))
    rule_id = finding.get("rule_id", "")
    cvss = finding.get("cvss", "")

    raw_path = finding.get("filepath", [])
    file_path = raw_path[0] if isinstance(raw_path, list) and raw_path else (raw_path or "")
    start_line = finding.get("start_line", "")
    end_line = finding.get("end_line", "")

    full_desc = description or title
    if finding_id:
        full_desc = f"{finding_id}: {full_desc}"

    location = file_path
    if start_line and end_line:
        location += f" (Lines {start_line}-{end_line})"
    elif start_line:
        location += f" (Line {start_line})"

    scan_id = iac_record.get("scan_id", "")

    # IaC has no platform issue_id. The exported "Issue ID" is the rule or
    # CVE id, which repeats across files and scans. Identity is therefore
    # built from what makes the finding distinct: every file path, the line
    # span, rule id, finding id and type. scan_id is deliberately excluded
    # so the same finding keeps the same UID from one scan to the next.
    all_paths = (
        ";".join(str(p) for p in raw_path) if isinstance(raw_path, list) else _s(raw_path)
    )
    iac_identity = "~".join([
        all_paths, f"{_s(start_line)}-{_s(end_line)}",
        _s(rule_id), _s(finding_id), _s(finding_type).lower(),
    ])
    finding_uid, finding_key = build_finding_identity(
        app_key or app_guid, CONTEXT_IAC, "IAC", iac_identity,
    )

    return {
        "Finding UID": finding_uid,
        "Finding Key": finding_key,
        "Module": None,
        "Line Number": start_line or None,
        "Procedure": None,
        "Vulnerable Parameter": None,
        "Component ID": None,
        "Location Detail": location or None,
        "Application Name": app_name,
        "Application ID": app_guid,
        "Sandbox Name": None,
        "Custom Severity Name": sev_label,
        "CVE ID": finding_id if finding_type == "vulnerability" else None,
        "Description": full_desc,
        "Vulnerability Title": finding_type.title() if finding_type else None,
        "CWE ID": rule_id or None,
        "Flaw Name": finding_id or title,
        "First Found Date": iac_record.get("scanned_at"),
        "Filename/Class": location or None,
        "Finding Status": "OPEN",
        "Fixed Date": None,
        "Team Name": _extract_team_name(app_profile) if app_profile else None,
        "Business Unit": _extract_business_unit(app_profile) if app_profile else None,
        "Days to Resolve": None,
        "Scan Type": "IAC",
        "CVSS": cvss or None,
        "Severity": sev_level,
        "Resolution Status": None,
        "Resolution": None,
        "Veracode Link": (
            f"{WEB_UI_BASE}/app/container-iac-scans/{scan_id}/summary"
            if scan_id else None
        ),
        "Mitigation Comments": suggested_fix or None,
        "IAC File Path": file_path,
        "IAC Start Line": start_line or None,
        "IAC End Line": end_line or None,
        "Issue ID": finding_id or None,
        "Violates Policy": None,
        "Last Seen Date": iac_record.get("scanned_at"),
    }


# ---------------------------------------------------------------------------
# API Fetchers
# ---------------------------------------------------------------------------

def get_applications(
    session: requests.Session,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
) -> list[dict[str, Any]]:
    """Fetch all applications via pagination.

    A failure here is fatal: a short application list silently drops every
    finding for every missing app, which was the single worst failure mode
    in the original script.
    """
    print("\n" + "=" * 70)
    print("  FETCHING APPLICATIONS")
    print("=" * 70)

    def _progress(page: int, batch: list, running: int, expected: Optional[int]) -> None:
        if page == 0 or (page + 1) % 5 == 0:
            exp = f"/{expected}" if expected else ""
            print(f"  Retrieved {running}{exp} applications so far...")

    apps, expected, pages = paginate(
        session, APPLICATIONS_URL, "applications",
        scope="applications",
        rate_limiter=rate_limiter,
        tracker=tracker,
        page_size=DEFAULT_PAGE_SIZE,
        timeout=60,
        on_page=_progress,
        # A 404 here is a wrong VERACODE_API_BASE, proxy rewrite or path
        # change, never an empty tenant; exporting zero apps as COMPLETE
        # would be a silent total loss.
        empty_on_404=False,
    )

    if expected is not None and expected != len(apps):
        tracker.record_mismatch("applications", expected, len(apps))
        print(f"  ! COUNT MISMATCH: API reported {expected}, retrieved {len(apps)}")

    print(f"\n  Total applications found: {len(apps)} "
          f"(expected {expected if expected is not None else 'unreported'}, "
          f"{pages} pages)\n")
    return apps


def get_sandboxes(
    session: requests.Session,
    app_guid: str,
    app_name: str,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
) -> list[dict[str, Any]]:
    """Return development sandboxes for an application.

    Now paginated. The original made a single unparameterised GET, so any
    application with more sandboxes than one default page lost the rest,
    and with them every finding in those sandboxes.
    """
    url = SANDBOXES_URL_TEMPLATE.format(app_guid=app_guid)
    try:
        sandboxes, expected, _ = paginate(
            session, url, "sandboxes",
            scope=f"sandboxes[{app_name}]",
            rate_limiter=rate_limiter,
            tracker=tracker,
            page_size=DEFAULT_PAGE_SIZE,
            timeout=60,
        )
    except FetchError as exc:
        tracker.record_failure(f"sandboxes[{app_name}]", str(exc))
        print(f"    FAILED to fetch sandboxes for {app_name}: {exc}")
        return []

    if expected is not None and expected != len(sandboxes):
        tracker.record_mismatch(f"sandboxes[{app_name}]", expected, len(sandboxes))
    return sandboxes


def _map_in_order(fn: Any, items: list[Any], max_workers: int) -> list[Any]:
    """``[fn(x) for x in items]``, run on a pool when max_workers > 1.

    Results come back in input order whatever order the calls finish in, so
    callers merge them exactly as the sequential loop did.
    """
    if max_workers <= 1 or len(items) <= 1:
        return [fn(x) for x in items]
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as pool:
        return list(pool.map(fn, items))


def get_sca_workspaces(
    session: requests.Session,
    sleep_time: float,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    max_workers: int = 1,
    ca_cert: Optional[str] = None,
) -> dict[str, dict[str, str]]:
    """Fetch SCA workspaces/projects.

    Returns a lookup keyed by lower-cased project name and 'guid:<app_guid>'.
    This map only drives deep-link construction; it never affects which
    findings are retrieved. With max_workers > 1 the per-workspace project
    walks run on a pool (one session per thread, shared rate limiter) and
    are merged in workspace order, so the map is the same as a serial run.
    """
    ws_map: dict[str, dict[str, str]] = {}
    try:
        all_ws, _, _ = paginate(
            session, f"{SCA_API_BASE}/workspaces", "workspaces",
            scope="sca-workspaces",
            rate_limiter=rate_limiter,
            tracker=tracker,
            page_size=DEFAULT_PAGE_SIZE,
            timeout=60,
            sleep_time=sleep_time,
        )
    except FetchError as exc:
        tracker.record_failure("sca-workspaces", str(exc))
        print(f"    FAILED to fetch SCA workspaces: {exc}")
        return ws_map

    print(f"  Fetched {len(all_ws)} SCA workspaces")

    def fetch_projects(ws_id: str) -> Any:
        sess = session if max_workers <= 1 else _thread_session(ca_cert=ca_cert)
        try:
            projects, _, _ = paginate(
                sess, f"{SCA_API_BASE}/workspaces/{ws_id}/projects", "projects",
                scope=f"sca-projects[{ws_id}]",
                rate_limiter=rate_limiter,
                tracker=tracker,
                page_size=DEFAULT_PAGE_SIZE,
                timeout=60,
                sleep_time=sleep_time,
            )
            return projects
        except FetchError as exc:
            return exc

    with_id = [w for w in all_ws if w.get("id")]
    results = _map_in_order(fetch_projects, [w.get("id") for w in with_id], max_workers)

    total_proj = 0
    name_collisions = 0
    for workspace, projects in zip(with_id, results):
        ws_id = workspace.get("id")
        ws_site = workspace.get("site_id")
        if isinstance(projects, FetchError):
            tracker.record_failure(f"sca-projects[{ws_id}]", str(projects))
            print(f"    FAILED to fetch SCA projects for workspace {ws_id}: {projects}")
            continue

        for proj in projects:
            ps = proj.get("site_id")
            pn = proj.get("name", "")
            lg = (proj.get("linked_application") or {}).get("guid")
            if ps and ws_site:
                mapping = {"workspace_guid": ws_site, "project_id": ps, "project_name": pn}
                key = pn.lower()
                if key in ws_map and ws_map[key] != mapping:
                    name_collisions += 1
                ws_map[key] = mapping
                if lg:
                    ws_map[f"guid:{lg}"] = mapping
                total_proj += 1

    print(f"  Fetched {total_proj} total SCA projects across all workspaces")
    if name_collisions:
        print(f"  Note: {name_collisions} duplicate project names across workspaces "
              f"(affects SCA deep links only, not finding counts)")
    return ws_map


def get_dynamic_analyses(
    session: requests.Session,
    sleep_time: float,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    max_workers: int = 1,
    ca_cert: Optional[str] = None,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch Dynamic Analysis metadata keyed by linked application GUID.

    Both the analyses list and each analysis's scan list are now paginated.
    With max_workers > 1 the per-analysis scan walks run on a pool and are
    merged in analysis order, so each app's list order matches a serial run.
    """
    da_map: dict[str, list[dict]] = {}
    try:
        analyses, _, _ = paginate(
            session, DYNAMIC_ANALYSES_URL, "analyses",
            scope="dynamic-analyses",
            rate_limiter=rate_limiter,
            tracker=tracker,
            page_size=DA_PAGE_SIZE,
            timeout=60,
            sleep_time=sleep_time,
        )
    except FetchError as exc:
        tracker.record_failure("dynamic-analyses", str(exc))
        print(f"    FAILED to fetch Dynamic Analyses: {exc}")
        return da_map

    def fetch_scans(a_id: str) -> Any:
        sess = session if max_workers <= 1 else _thread_session(ca_cert=ca_cert)
        try:
            scans, _, _ = paginate(
                sess, f"{DYNAMIC_ANALYSES_URL}/{a_id}/scans", "scans",
                scope=f"dynamic-analysis-scans[{a_id}]",
                rate_limiter=rate_limiter,
                tracker=tracker,
                page_size=DA_PAGE_SIZE,
                timeout=60,
                sleep_time=sleep_time,
            )
            return scans
        except FetchError as exc:
            return exc

    with_id = [a for a in analyses if a.get("analysis_id")]
    results = _map_in_order(fetch_scans, [a.get("analysis_id") for a in with_id],
                            max_workers)

    for analysis, scans in zip(with_id, results):
        a_id = analysis.get("analysis_id")
        if isinstance(scans, FetchError):
            tracker.record_failure(f"dynamic-analysis-scans[{a_id}]", str(scans))
            continue

        for scan in scans:
            guid = scan.get("linked_platform_app_uuid")
            if guid:
                da_map.setdefault(guid, []).append({
                    "analysis_id": a_id,
                    "analysis_name": analysis.get("name"),
                })
    return da_map


# ---------------------------------------------------------------------------
# Findings Fetchers
# ---------------------------------------------------------------------------

def _fetch_findings_context(
    session: requests.Session,
    app_guid: str,
    app_name: str,
    app_profile: dict[str, Any],
    scan_type: Optional[str],
    filters: dict[str, Any],
    sleep_time: float,
    sandbox_guid: Optional[str],
    sandbox_name: Optional[str],
    app_id: Optional[str],
    app_oid: Optional[str],
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    page_size: int,
    include_annotations: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Paginate all findings for one app / sandbox / scan-type combination.

    Returns ``(findings, reconciliation_row)``. Unlike the original, a mid-walk
    failure is recorded and surfaced rather than silently truncating the walk
    and returning as if the app were fully processed.
    """
    url = FINDINGS_URL_TEMPLATE.format(app_guid=app_guid)

    params: dict[str, Any] = {}
    if sandbox_guid:
        params["context"] = sandbox_guid
    if scan_type:
        params["scan_type"] = scan_type
    if filters.get("cwe"):
        params["cwe"] = filters["cwe"]
    for key in ("severity", "severity_gte"):
        if filters.get(key) is not None:
            params[key] = filters[key]
    if filters.get("violates_policy"):
        params["violates_policy"] = "TRUE"
    if include_annotations:
        # Without this the annotations node is absent and Mitigation Comments
        # is always blank.
        params["include_annot"] = "TRUE"

    # NOTE: 'status' is deliberately NOT sent. It is not a documented Findings
    # API query parameter; sending it silently returns unfiltered data. The
    # filter is applied client-side by the caller instead.

    # The spec marks these "Not valid for the SCA scan type". If the server
    # ignored violates_policy, --violates-policy would return every SCA
    # finding; if it rejected either, every SCA context would fail.
    sca_policy_filter = False
    if scan_type == "SCA":
        sca_policy_filter = bool(filters.get("violates_policy"))
        for key in SCA_INVALID_PARAMS:
            params.pop(key, None)

    context_label = f"sandbox:{sandbox_name}" if sandbox_guid else "policy"
    scope = f"findings[{app_name}|{context_label}|{scan_type or 'ALL'}]"

    recon: dict[str, Any] = {
        "Application Name": app_name,
        "Application GUID": app_guid,
        "Context": context_label,
        "Scan Type Requested": scan_type or "ALL",
        "Expected (API total_elements)": "",
        "Retrieved": 0,
        "Pages Fetched": 0,
        "Status": "OK",
        "Detail": "",
    }

    try:
        findings, expected, pages = paginate(
            session, url, "findings",
            scope=scope,
            rate_limiter=rate_limiter,
            tracker=tracker,
            params=params,
            page_size=page_size,
            timeout=180,
            sleep_time=sleep_time,
        )
    except FetchError as exc:
        tracker.record_failure(scope, str(exc))
        tracker.record_page(ok=False)
        recon["Status"] = "FAILED"
        recon["Detail"] = str(exc)[:300]
        print(f"    FAILED {scope}: {exc}")
        return [], recon

    for finding in findings:
        finding["_app_name"] = app_name
        finding["_app_guid"] = app_guid
        finding["_app_profile"] = app_profile
        finding["_sandbox_name"] = sandbox_name if sandbox_guid else None
        finding["_sandbox_guid"] = sandbox_guid
        finding["_app_id"] = app_id
        finding["_app_oid"] = app_oid

    recon["Expected (API total_elements)"] = "" if expected is None else expected
    recon["Retrieved"] = len(findings)
    recon["Pages Fetched"] = pages

    if expected is not None and expected != len(findings):
        tracker.record_mismatch(scope, expected, len(findings))
        recon["Status"] = "MISMATCH"
        recon["Detail"] = f"API reported {expected}, retrieved {len(findings)}"
        print(f"    ! MISMATCH {scope}: expected {expected}, got {len(findings)}")

    if sca_policy_filter:
        # Reconciliation compares the unfiltered walk with total_elements;
        # the policy filter is applied afterwards, like --status.
        kept = [f for f in findings if f.get("violates_policy") is True]
        note = (f"--violates-policy applied client-side: kept {len(kept)} "
                f"of {len(findings)}")
        recon["Detail"] = f"{recon['Detail']}; {note}" if recon["Detail"] else note
        findings = kept

    if findings:
        print(f"    [{context_label}|{scan_type or 'ALL'}] {len(findings)} findings "
              f"across {pages} page(s)")

    return findings, recon


def _skipped_recon(app_name: str, app_guid: str, scan_type: str) -> dict[str, Any]:
    """Reconciliation row for a policy request that was not sent."""
    return {
        "Application Name": app_name,
        "Application GUID": app_guid,
        "Context": "policy",
        "Scan Type Requested": scan_type,
        "Expected (API total_elements)": "",
        "Retrieved": 0,
        "Pages Fetched": 0,
        "Status": "SKIPPED",
        "Detail": (f"no {scan_type} scan in the application's scans list "
                   "(Applications API), so the request can only be empty; "
                   "pass --request-all-scan-types to send it anyway"),
    }


def _get_all_findings_for_app(
    session: requests.Session,
    app_guid: str,
    app_name: str,
    app_profile: dict[str, Any],
    filters: dict[str, Any],
    sleep_time: float,
    include_sandboxes: bool,
    app_id: Optional[str],
    app_oid: Optional[str],
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    page_size: int,
    include_annotations: bool,
    combine_scan_types: bool,
    app_scan_types: Optional[frozenset[str]] = None,
    sink: Optional[Callable[[list[dict[str, Any]]], None]] = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch findings for the policy scan plus, optionally, every sandbox.

    SCA must be requested on its own: Veracode documents that combining SCA
    with other scan types is not supported.

    *app_scan_types* is the set of scan types in the Applications API
    ``scans`` list (None = unknown). In the policy context, DYNAMIC and
    MANUAL are only requested when listed there; skipped requests get a
    SKIPPED reconciliation row. Sandbox contexts always request every type.

    With *sink*, each context's findings are handed to ``sink(list)`` as
    soon as they are fetched and released before the next request (the
    returned findings list is then empty).
    """
    all_findings: list[dict] = []
    recon_rows: list[dict] = []

    # dict.fromkeys de-duplicates while keeping order: "STATIC,STATIC" must
    # not fetch (and export) the same context twice.
    requested = list(dict.fromkeys(_parse_requested_scan_types(filters.get("scan_type"))))
    non_sca: list[str]
    if requested:
        fetch_sca = "SCA" in requested
        non_sca = [t for t in requested if t in NON_SCA_SCAN_TYPES]
    else:
        fetch_sca = True
        non_sca = list(NON_SCA_SCAN_TYPES)

    # Only single scan_type values are documented. Requesting them one at a
    # time is a few extra calls per app but removes the risk that a
    # comma-joined value is partially honoured or ignored outright.
    def batches(types: list[str]) -> list[str]:
        if combine_scan_types:
            return [",".join(types)] if types else []
        return list(types)

    # Policy context: a DYNAMIC or MANUAL request for an app whose scans list
    # has no scan of that type can only return an empty page (39% of all
    # calls on a benchmark tenant). STATIC and SCA are always requested.
    policy_skipped: list[str] = []
    if app_scan_types is not None:
        policy_skipped = [t for t in non_sca
                          if t in POLICY_SKIPPABLE_SCAN_TYPES and t not in app_scan_types]
    policy_non_sca = [t for t in non_sca if t not in policy_skipped]

    contexts: list[tuple[Optional[str], Optional[str]]] = [(None, None)]

    if include_sandboxes:
        sbs = get_sandboxes(session, app_guid, app_name, rate_limiter, tracker)
        if sbs:
            print(f"    Found {len(sbs)} sandbox(es)")
        for sb in sbs:
            sg = sb.get("guid")
            if sg:
                contexts.append((sg, sb.get("name", sg)))

    for ctx_guid, ctx_name in contexts:
        # (scan_type value, skip?) in request order.
        if ctx_guid is not None:
            todo = [(b, False) for b in batches(non_sca)]
        elif combine_scan_types:
            todo = ([(t, True) for t in policy_skipped]
                    + [(b, False) for b in batches(policy_non_sca)])
        else:
            todo = [(t, t in policy_skipped) for t in non_sca]
        if fetch_sca:
            todo.append(("SCA", False))

        for st, skip in todo:
            if skip:
                recon_rows.append(_skipped_recon(app_name, app_guid, st))
                continue
            findings, recon = _fetch_findings_context(
                session, app_guid, app_name, app_profile, st, filters,
                sleep_time, ctx_guid, ctx_name, app_id, app_oid,
                rate_limiter, tracker, page_size, include_annotations,
            )
            recon_rows.append(recon)
            if sink is not None:
                sink(findings)
            else:
                all_findings.extend(findings)
            del findings  # do not hold this context while fetching the next

    return all_findings, recon_rows


# ---------------------------------------------------------------------------
# Per-Application Worker (thread pool)
# ---------------------------------------------------------------------------

def _enrich_finding(
    finding: dict[str, Any],
    app_guid: Optional[str],
    app_name: str,
    latest_scan_params: Optional[str],
    static_params_by_build: dict[int, str],
    dast_url_by_build: dict[int, str],
    da_map: dict[str, list[dict[str, Any]]],
    sca_map: dict[str, dict[str, str]],
) -> None:
    """Attach link-building hints to one finding (may raise; caller guards)."""
    finding["_latest_scan_params"] = latest_scan_params
    ftype = finding.get("scan_type")
    build_id = finding.get("build_id")

    if ftype == "STATIC" and build_id and build_id in static_params_by_build:
        finding["_finding_scan_params"] = static_params_by_build[build_id]

    elif ftype == "DYNAMIC":
        if build_id and build_id in dast_url_by_build:
            finding["_dast_scan_url"] = dast_url_by_build[build_id]
        da_list = da_map.get(app_guid) if app_guid else None
        if da_list:
            finding["_dynamic_analysis_id"] = da_list[0].get("analysis_id")

    elif ftype == "SCA":
        if _sca_metadata(finding.get("finding_details")).get("sca_scan_mode") == "AGENT":
            mapping = sca_map.get(f"guid:{app_guid}") or sca_map.get(app_name.lower())
            if mapping:
                finding["_sca_workspace_guid"] = mapping["workspace_guid"]
                finding["_sca_project_id"] = mapping["project_id"]


def _listed_scan_types(app: dict[str, Any]) -> Optional[frozenset[str]]:
    """Scan types in the Applications API ``scans`` list, or None if unknown.

    None (request every type) when the list is missing or holds anything
    that is not an object, so a malformed record never hides findings.
    """
    scans = app.get("scans")
    if not isinstance(scans, list) or not all(isinstance(s, dict) for s in scans):
        return None
    return frozenset(str(s.get("scan_type") or "").upper() for s in scans)


def _process_application(
    app: dict[str, Any],
    idx: int,
    total: int,
    filters: dict[str, Any],
    sleep_time: float,
    include_sandboxes: bool,
    sca_map: dict[str, dict[str, str]],
    da_map: dict[str, list[dict[str, Any]]],
    rate_limiter: RateLimiter,
    tracker: FailureTracker,
    page_size: int,
    include_annotations: bool,
    combine_scan_types: bool,
    ca_cert: Optional[str] = None,
    request_all_scan_types: bool = False,
    prepare: Optional[Callable[[], PreparedBatch]] = None,
) -> tuple[Any, list[dict[str, Any]]]:
    """Fetch and enrich findings for one application (thread worker).

    Returns the raw findings list, or, with *prepare* (a factory such as
    StreamingExporter.new_batch), a PreparedBatch normalised per context.
    """
    session = _thread_session(ca_cert=ca_cert)
    profile = app.get("profile") or {}
    app_guid = app.get("guid")
    app_name = profile.get("name", "Unknown")

    try:
        app_id = app.get("id")
        app_oid = app.get("oid") or app.get("alt_org_id")
        app_scan_types = None if request_all_scan_types else _listed_scan_types(app)

        # ---- Single-pass scan-URL parsing ----
        static_params_by_build: dict[int, str] = {}
        dast_url_by_build: dict[int, str] = {}
        latest_scan_params: Optional[str] = None

        for scan in app.get("scans") or []:
            if not isinstance(scan, dict):
                continue
            scan_url = scan.get("scan_url", "")
            if not scan_url:
                continue
            stype = scan.get("scan_type")
            if stype == "STATIC":
                parsed = _parse_scan_url_params(scan_url)
                if parsed:
                    static_params_by_build[parsed[0]] = parsed[1]
                    if latest_scan_params is None:  # first entry is latest
                        latest_scan_params = parsed[1]
            elif stype == "DYNAMIC" and scan_url.startswith("DynamicParamsView:"):
                parsed = _parse_scan_url_params(scan_url)
                if parsed:
                    dast_url_by_build[parsed[0]] = scan_url

        print(f"  [{idx}/{total}] {app_name} ({app_guid})")

        # ---- Enrich findings ----
        # Each finding is enriched on its own: one malformed record (for
        # example finding_details.metadata arriving as a string) used to
        # raise out of this loop and discard every finding of the app.
        def enrich(found: list[dict[str, Any]]) -> None:
            for finding in found:
                try:
                    _enrich_finding(finding, app_guid, app_name, latest_scan_params,
                                    static_params_by_build, dast_url_by_build,
                                    da_map, sca_map)
                except Exception as exc:
                    detail = f"{type(exc).__name__}: {exc}"
                    issue = finding.get("issue_id", "?") if isinstance(finding, dict) else "?"
                    tracker.record_failure(f"enrich[{app_name}]", f"issue_id={issue}: {detail}")
                    if isinstance(finding, dict):
                        finding["_export_note"] = f"ENRICHMENT_FAILED: {detail}"[:400]

        result: Any
        if prepare is None:
            findings, recon_rows = _get_all_findings_for_app(
                session, app_guid, app_name, profile, filters,
                sleep_time, include_sandboxes, app_id, app_oid, rate_limiter,
                tracker, page_size, include_annotations, combine_scan_types,
                app_scan_types=app_scan_types,
            )
            enrich(findings)
            result = findings
        else:
            # Enrich and normalise each context here, in the worker, so its
            # raw dicts are freed before the next context is fetched.
            batch = prepare()

            def sink(found: list[dict[str, Any]]) -> None:
                enrich(found)
                batch.add(found)

            _, recon_rows = _get_all_findings_for_app(
                session, app_guid, app_name, profile, filters,
                sleep_time, include_sandboxes, app_id, app_oid, rate_limiter,
                tracker, page_size, include_annotations, combine_scan_types,
                app_scan_types=app_scan_types, sink=sink,
            )
            result = batch

        print(f"    Total for {app_name}: {len(result)}\n")
        return result, recon_rows

    except Exception as exc:
        # Anything reaching here is unexpected; record it so the run cannot
        # report success.
        tracker.record_failure(f"application[{app_name}]", f"{type(exc).__name__}: {exc}")
        print(f"    UNEXPECTED ERROR processing {app_name}: {exc}\n")
        return [], [{
            "Application Name": app_name,
            "Application GUID": app_guid,
            "Context": "n/a",
            "Scan Type Requested": "n/a",
            "Expected (API total_elements)": "",
            "Retrieved": 0,
            "Pages Fetched": 0,
            "Status": "FAILED",
            "Detail": f"{type(exc).__name__}: {exc}"[:300],
        }]


# ---------------------------------------------------------------------------
# IaC Live Fetching (principal token auth)
# ---------------------------------------------------------------------------

def _get_principal_token(ca_cert: Optional[str] = None) -> str:
    """Get a session token via an HMAC-signed principal API call.

    Uses this script's own session so the call honours --ca-cert, the
    resolved region, the request timeout and the retry policy.
    """
    session = create_session(ca_cert=ca_cert)
    try:
        resp = request_with_retry(
            session, PRINCIPAL_URL, scope="principal",
            passthrough_statuses=(), timeout=60,
        )
        principal = resp.json()
    except (FetchError, ValueError) as exc:
        raise RuntimeError(f"Failed to retrieve principal token: {exc}") from exc
    finally:
        session.close()

    if not isinstance(principal, dict) or not principal.get("token"):
        raise RuntimeError(
            f"Unexpected principal response type: {type(principal).__name__}"
        )
    return principal["token"]


def _iac_auth_header(token: str) -> dict[str, str]:
    """Build the Authorization header for IaC/Container Security API calls."""
    return {"Authorization": f"{IAC_AUTH_TOKEN_PREFIX}{token}"}


class IacTokenProvider:
    """Holds the IaC principal token and re-mints it on demand.

    The token was previously fetched once and reused for the whole IaC
    phase, which begins only after the findings phase. On a large tenant
    that can be hours later, so expiry is expected rather than exceptional.
    Refresh is serialised and de-duplicated: concurrent workers hitting 401
    at the same time trigger exactly one refresh between them.
    """

    def __init__(self, ca_cert: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._ca_cert = ca_cert
        self.refreshes = 0

    def get(self) -> str:
        with self._lock:
            if self._token is None:
                self._token = _get_principal_token(self._ca_cert)
            return self._token

    def headers(self) -> dict[str, str]:
        return _iac_auth_header(self.get())

    def refresh(self, stale_headers: Optional[dict[str, str]] = None) -> dict[str, str]:
        """Mint a new token and return replacement headers.

        *stale_headers* are the headers the failed request used. If the
        current token already differs, another thread refreshed while this
        one waited, so its token is reused instead of minting again.
        """
        with self._lock:
            if (stale_headers is not None and self._token is not None
                    and stale_headers != _iac_auth_header(self._token)):
                return _iac_auth_header(self._token)
            self._token = _get_principal_token(self._ca_cert)
            self.refreshes += 1
            return _iac_auth_header(self._token)


def _paginate_iac(
    session: requests.Session,
    url: str,
    tokens: "IacTokenProvider",
    records_key: str,
    *,
    scope: str,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    extra_params: Optional[dict[str, Any]] = None,
    stats: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Paginate an IaC/Container Security collection with retries.

    This API uses ``pagination.total_pages`` / ``total_elements`` and a
    ``limit`` parameter rather than the HAL shape used elsewhere.

    - Empty pages while ``total_pages`` says more remain are a FetchError.
    - Without a ``pagination`` block a full page (``== limit``) means more
      may follow, so the walk continues until a short or empty page.
    - A page identical to the previous one is a FetchError.

    When *stats* is given it is filled with ``pages`` (fetched) and
    ``expected`` (``pagination.total_elements`` or None) for reconciliation.
    """
    all_records: list[dict] = []
    page = 0
    empty_streak = 0
    prev_batch: Optional[list] = None
    expected: Optional[int] = None
    pages = 0

    while True:
        params = dict(extra_params or {})
        params.update({"page": page, "limit": IAC_MAX_RECORDS})

        headers = tokens.headers()
        resp = request_with_retry(
            session, url,
            scope=f"{scope} page {page}",
            rate_limiter=rate_limiter,
            tracker=tracker,
            headers=headers,
            params=params,
            timeout=90,
            passthrough_statuses=(404,),
            # Pass the headers this request used so concurrent 401s share
            # one refresh instead of each minting a new token.
            auth_refresh=functools.partial(tokens.refresh, headers),
        )
        if resp.status_code == 404:
            if page > 0:
                raise FetchError(
                    f"{scope} page {page}: HTTP 404 mid-walk after "
                    f"{len(all_records)} records")
            break

        data = _json_object(resp, f"{scope} page {page}")
        pages += 1

        records = data.get(records_key, []) or []
        if not isinstance(records, list):
            raise FetchError(f"{scope} page {page}: '{records_key}' is not a list")
        if page > 0 and records and records == prev_batch:
            raise FetchError(
                f"{scope} page {page}: repeated page (identical to page {page - 1})")
        prev_batch = records
        all_records.extend(records)
        empty_streak = 0 if records else empty_streak + 1

        pagination = data.get("pagination")
        pagination = pagination if isinstance(pagination, dict) else {}
        te = pagination.get("total_elements")
        if isinstance(te, (int, float)) and not isinstance(te, bool):
            expected = int(te)
        tp = pagination.get("total_pages")
        if isinstance(tp, (int, float)) and not isinstance(tp, bool):
            total_pages = int(tp)
            if page >= total_pages - 1:
                break
            if not records:
                # total_pages promises more but the API returned nothing.
                raise FetchError(
                    f"{scope} page {page}: empty page while total_pages="
                    f"{total_pages}; stopped after {len(all_records)} records")
        elif len(records) < IAC_MAX_RECORDS or empty_streak:
            # No pagination block: only a full page can have a successor.
            break

        page += 1
        if page >= MAX_PAGES_SAFETY_CAP:
            detail = (f"{scope}: hit the {MAX_PAGES_SAFETY_CAP}-page safety cap "
                      f"after {len(all_records)} records; result may be incomplete.")
            tracker.record_failure(scope, detail)
            print(f"    ! {detail}")
            break

    if stats is not None:
        stats["pages"] = pages
        stats["expected"] = expected
    return all_records


def _fetch_iac_scans(
    session: requests.Session,
    tokens: "IacTokenProvider",
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    filter_apps: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    """Fetch the IaC scan list using principal token auth."""
    print("  Fetching IaC scan list...")
    try:
        all_records = _paginate_iac(
            session, IAC_SCANS_URL, tokens, "records",
            scope="iac-scans",
            rate_limiter=rate_limiter,
            tracker=tracker,
        )
    except FetchError as exc:
        tracker.record_failure("iac-scans", str(exc))
        print(f"  FAILED to fetch IaC scans: {exc}")
        return []

    if filter_apps:
        filter_lc = {n.lower() for n in filter_apps}
        all_records = [
            r for r in all_records
            if str(r.get("asset_name", "")).lower() in filter_lc
        ]
        print(f"  Filtered to {len(all_records)} scans matching specified apps")

    print(f"  Found {len(all_records)} IaC scans\n")
    return all_records


def _iac_recon_row(
    asset_name: str, scan_id: Any, expected: Optional[int], retrieved: int,
    pages: int, status: str = "OK", detail: str = "",
) -> dict[str, Any]:
    """Reconciliation row for one IaC scan's findings walk."""
    return {
        "Application Name": asset_name,
        "Application GUID": "",
        "Context": f"iac-scan:{scan_id}",
        "Scan Type Requested": "IAC",
        "Expected (API total_elements)": "" if expected is None else expected,
        "Retrieved": retrieved,
        "Pages Fetched": pages,
        "Status": status,
        "Detail": detail[:300],
    }


def _parse_when(value: Any) -> Optional[dt.datetime]:
    """Parse ISO 8601 or epoch (s / ms) into an aware UTC datetime."""
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            n = float(value)
            return dt.datetime.fromtimestamp(n / 1000 if n > 1e11 else n, dt.timezone.utc)
        s = str(value).strip().replace("Z", "+00:00")
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # trim nanoseconds
        d = dt.datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def latest_iac_scans(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only the newest scan per (asset, asset type, scan type).

    The scan list is the full scan history. Exporting every record repeated
    each finding once per historical scan, all as OPEN, including findings
    a later scan had already fixed. The asset is identified by asset_id when
    present (survives renames), else by its name, case-insensitively.
    Mirrors ``latest_scan_ids`` in Veracode-IaC-Extract.
    """
    floor = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    best: dict[tuple, tuple[dt.datetime, int]] = {}
    for idx, s in enumerate(scans):
        key = (_s(s.get("asset_id") or s.get("asset_name")).lower(),
               _s(s.get("asset_type")).lower(), _s(s.get("scan_type")).lower())
        when = _parse_when(s.get("scanned_at")) or floor
        if key not in best or when > best[key][0]:
            best[key] = (when, idx)
    keep = {idx for _, idx in best.values()}
    return [s for i, s in enumerate(scans) if i in keep]


def _process_iac_scan(
    record: dict[str, Any],
    idx: int,
    total: int,
    tokens: "IacTokenProvider",
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    ca_cert: Optional[str] = None,
) -> dict[str, Any]:
    """Fetch detailed findings for one IaC scan (thread worker).

    The returned record carries a ``_recon`` reconciliation row.
    """
    asset_name = record.get("asset_name", "Unknown")
    scan_id = record.get("scan_id")

    if not scan_id:
        tracker.record_failure(f"iac-scan[{asset_name}]", "record has no scan_id")
        out = record.copy()
        out["_recon"] = _iac_recon_row(asset_name, "", None, 0, 0, "FAILED",
                                       "record has no scan_id")
        return out

    scope = f"iac-findings[{asset_name}:{scan_id}]"
    session = _thread_session(ca_cert=ca_cert, use_hmac=False)
    stats: dict[str, Any] = {}
    try:
        findings = _paginate_iac(
            session, IAC_FINDINGS_URL_TEMPLATE.format(scan_id=scan_id), tokens, "findings",
            scope=scope,
            rate_limiter=rate_limiter,
            tracker=tracker,
            extra_params={"sort": "severity", "direction": "desc"},
            stats=stats,
        )
    except FetchError as exc:
        tracker.record_failure(scope, str(exc))
        tracker.record_page(ok=False)
        print(f"    FAILED IaC findings for {asset_name} (scan {scan_id}): {exc}")
        findings = []
        recon = _iac_recon_row(asset_name, scan_id, None, 0, 0, "FAILED", str(exc))
    else:
        expected = stats.get("expected")
        recon = _iac_recon_row(asset_name, scan_id, expected, len(findings),
                               stats.get("pages", 0))
        if expected is not None and expected != len(findings):
            tracker.record_mismatch(scope, expected, len(findings))
            recon["Status"] = "MISMATCH"
            recon["Detail"] = f"API reported {expected}, retrieved {len(findings)}"
            print(f"    ! MISMATCH {scope}: expected {expected}, got {len(findings)}")

    detailed_record = record.copy()
    detailed_record["detailed_findings"] = findings
    detailed_record["_recon"] = recon
    print(f"    [{idx}/{total}] {asset_name} (scan {scan_id}): {len(findings)} findings")
    return detailed_record


def _fetch_iac_data_live(
    rate_limiter: RateLimiter,
    tracker: FailureTracker,
    max_workers: int = 5,
    filter_apps: Optional[set[str]] = None,
    ca_cert: Optional[str] = None,
    all_scans: bool = False,
) -> list[dict[str, Any]]:
    """Fetch IaC scan data live via principal token auth.

    By default only the latest scan per asset is fetched (see
    latest_iac_scans); *all_scans* keeps the full history. Records are
    returned sorted by asset name and scan id so output order does not
    depend on thread completion.
    """
    print("  Obtaining principal token via HMAC auth...")
    tokens = IacTokenProvider(ca_cert=ca_cert)
    try:
        tokens.get()
        print("  Principal token obtained (auto-refreshes on 401)\n")
    except RuntimeError as exc:
        tracker.record_failure("iac-principal-token", str(exc))
        print(f"  {exc}")
        return []

    session = create_session(ca_cert=ca_cert, use_hmac=False)
    try:
        records = _fetch_iac_scans(session, tokens, rate_limiter, tracker, filter_apps)
    finally:
        session.close()

    if not records:
        return []

    if not all_scans:
        latest = latest_iac_scans(records)
        if len(latest) != len(records):
            print(f"  Keeping the latest scan per asset: {len(records)} -> {len(latest)} "
                  f"scans (pass --iac-all-scans to export the history)")
        records = latest

    print(f"  Fetching detailed findings for {len(records)} scans...\n")
    detailed_records: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_record = {
            executor.submit(
                _process_iac_scan,
                record=rec, idx=idx, total=len(records),
                tokens=tokens, rate_limiter=rate_limiter, tracker=tracker,
                ca_cert=ca_cert,
            ): rec
            for idx, rec in enumerate(records, 1)
        }
        for future in as_completed(future_to_record):
            rec = future_to_record[future]
            try:
                detailed_records.append(future.result())
            except Exception as exc:
                name = rec.get("asset_name", "Unknown")
                tracker.record_failure(f"iac-scan[{name}]", f"{type(exc).__name__}: {exc}")
                print(f"    ERROR processing {name}: {exc}")
                detailed_records.append({
                    **rec, "detailed_findings": [],
                    "_recon": _iac_recon_row(name, rec.get("scan_id", ""), None, 0, 0,
                                             "FAILED", f"{type(exc).__name__}: {exc}"),
                })

    # as_completed yields in thread-completion order; sort so the IaC block
    # of the CSV is reproducible run to run.
    detailed_records.sort(key=lambda r: (_s(r.get("asset_name")).lower(),
                                         _s(r.get("asset_name")), _s(r.get("scan_id"))))

    total_findings = sum(len(r.get("detailed_findings", [])) for r in detailed_records)
    print(f"\n  Fetched {len(detailed_records)} IaC scans with {total_findings} total findings")
    return detailed_records


# ---------------------------------------------------------------------------
# Post-processing
# ---------------------------------------------------------------------------

def _finding_key(row: dict[str, Any]) -> tuple:
    """Identity key for duplicate detection.

    A finding is uniquely identified by its issue ID within an application
    and context. Two different sandboxes legitimately report the same issue
    ID, so the context is part of the key.
    """
    return (
        row.get("_app_guid"),
        row.get("_sandbox_guid"),
        row.get("scan_type"),
        row.get("issue_id"),
    )


def _row_passes_status(row: dict, status: Optional[str]) -> bool:
    """Apply the --status filter to one normalised row.

    'status' is not a documented Findings API query parameter, so the
    filter is applied client-side.
    """
    if not status:
        return True
    return str(row.get("Finding Status", "")).upper() == status.upper()


def safe_normalize(
    finding: dict[str, Any],
    tracker: FailureTracker,
) -> dict[str, Any]:
    """Normalise one finding, never raising.

    The previous implementation normalised inside a list comprehension, so a
    single API shape drift (for example ``finding_status`` arriving as a
    string instead of an object) raised and destroyed the ENTIRE export -
    every finding lost, no CSV written at all. Across hundreds of thousands
    of records the chance of zero anomalies is not a safe bet.

    A finding that cannot be normalised is never silently dropped. A salvage
    row is emitted carrying whatever identifying fields can be read directly,
    with the reason in ``Export Notes``, and the failure is registered so the
    run reports INCOMPLETE.
    """
    if "Application Name" in finding:
        return finding  # already-normalised (IaC) row
    try:
        return normalize_finding(finding)
    except Exception as exc:
        scope = f"normalize[{finding.get('_app_name', '?')}]"
        detail = f"issue_id={finding.get('issue_id', '?')}: {type(exc).__name__}: {exc}"
        tracker.record_failure(scope, detail)

        salvage = {k: None for k in CSV_FIELDNAMES}
        for key, src in (
            ("Application Name", "_app_name"), ("Application ID", "_app_guid"),
            ("Sandbox Name", "_sandbox_name"), ("Issue ID", "issue_id"),
            ("Scan Type", "scan_type"), ("Violates Policy", "violates_policy"),
        ):
            try:
                salvage[key] = finding.get(src)
            except Exception:
                pass
        try:
            salvage["Finding UID"], salvage["Finding Key"] = build_finding_identity(
                finding.get("_app_guid"),
                finding.get("_sandbox_guid") or CONTEXT_POLICY,
                finding.get("scan_type"),
                finding.get("issue_id"),
            )
        except Exception:
            pass
        salvage["Export Notes"] = f"NORMALIZATION_FAILED: {type(exc).__name__}: {exc}"[:400]
        return salvage


# Characters that make Excel / LibreOffice / Sheets treat a cell as a formula
# (OWASP CSV injection). Tab and CR are included because some importers
# strip them and then evaluate what follows.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", chr(13))

# os.replace on Windows fails with PermissionError while the destination is
# open in Excel (no FILE_SHARE_DELETE). Retry a few times, then give up.
PUBLISH_ATTEMPTS = 5
PUBLISH_RETRY_DELAY = 2.0


class PublishError(Exception):
    """Raised when finished temp files could not be moved into place."""


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in one CSV cell.

    Descriptions, file names, procedures, comments and app names come from
    scanned code or tenant users, so a cell such as ``=HYPERLINK(...)`` would
    run when the CSV is opened in a spreadsheet. A string starting with
    = + - @ tab or CR is prefixed with a single quote. Non-strings (numbers,
    booleans, None) and strings that are plain numbers ("-1.5") are left
    unchanged. Disabled with --raw-cells.
    """
    if not isinstance(value, str) or not value.startswith(_FORMULA_PREFIXES):
        return value
    try:
        float(value)
        return value
    except ValueError:
        return "'" + value


def _csv_safe_row(row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    return {k: _csv_safe(row.get(k)) for k in fields}


def _sort_key(row: dict[str, Any]) -> tuple:
    """Deterministic ordering key.

    Without this, ``as_completed`` produced a different row order on every
    run, so two exports of an unchanged tenant could not be diffed.
    """
    def s(v: Any) -> str:
        return "" if v is None else str(v)
    # Finding UID is the final tie-breaker. IaC rows share Issue IDs (rule
    # or CVE id), so without it their relative order was not deterministic.
    return (s(row.get("Application Name")), s(row.get("Sandbox Name")),
            s(row.get("Scan Type")), s(row.get("Issue ID")),
            s(row.get("Finding UID")))


class PreparedBatch:
    """One application's findings, normalised as they arrive.

    Created by StreamingExporter.new_batch() and filled with add() once per
    request context in the worker thread, so a context's raw API dicts can
    be freed before the next context is fetched: peak memory is the
    normalised rows of one app plus the raw dicts of one context, instead of
    the raw dicts AND the rows of the whole app. add() runs the steps
    write_batch used to run on the main thread, in the same order (raw JSON
    line, duplicate check, normalise, --status filter); write_batch() does
    the rest (UID collisions, sort, write).
    """

    def __init__(self, tracker: FailureTracker, status_filter: Optional[str],
                 dedup: bool, raw_json: bool) -> None:
        self._tracker = tracker
        self._status_filter = status_filter
        self._dedup = dedup
        self._raw_json = raw_json
        self._seen: set = set()
        self.rows: list[dict[str, Any]] = []
        self.raw_lines: list[str] = []
        self.retrieved = 0
        self.filtered_out = 0
        self.duplicates = 0
        self.duplicates_removed = 0
        self.retained_dups = 0
        self.duplicate_samples: list[tuple] = []
        self.app_name: Optional[str] = None

    def __len__(self) -> int:
        """Findings retrieved (before dedup and --status filtering)."""
        return self.retrieved

    def add(self, raw_findings: list[dict[str, Any]]) -> None:
        for finding in raw_findings:
            self.retrieved += 1
            if self._raw_json:
                self.raw_lines.append(json.dumps(finding, default=str) + "\n")
            is_dict = isinstance(finding, dict)
            if self.app_name is None and is_dict and finding.get("_app_name"):
                self.app_name = finding.get("_app_name")
            # Only findings with a real issue_id can be compared: SCA
            # findings may carry issue_id=null, and keying those on None
            # made every one of them a "duplicate" of the first.
            if is_dict and not _blank(finding.get("issue_id")):
                key = _finding_key(finding)
                if key in self._seen:
                    self.duplicates += 1
                    if len(self.duplicate_samples) < 20:
                        self.duplicate_samples.append(key)
                    if self._dedup:
                        self.duplicates_removed += 1
                        continue
                    self.retained_dups += 1
                self._seen.add(key)

            row = safe_normalize(finding, self._tracker)
            if not _row_passes_status(row, self._status_filter):
                self.filtered_out += 1
                continue
            self.rows.append(row)


class StreamingExporter:
    """Writes findings to disk incrementally, publishing atomically.

    Three defects are addressed here.

    Memory: the previous design accumulated every raw finding in one list,
    built a second full list during normalisation, and serialised a third
    copy via ``json.dump(..., indent=2)``. At a measured ~1.8 KB retained per
    raw finding that is roughly 4 GB for 700k findings and over 11 GB for two
    million, which will not survive a large tenant. Rows are now written per
    application and released.

    Atomicity: output went straight to the destination path, so a crash left
    a truncated CSV with a valid header AND destroyed the previous good
    export. Everything is written to temp files and moved into place with
    ``os.replace`` only after the run finishes. If the process dies, the
    destination is untouched and the temp files remain for inspection.

    Ordering: rows within an application are sorted, and applications are
    consumed in submission order, so the output is reproducible.
    """

    def __init__(
        self,
        csv_path: str,
        recon_path: str,
        tracker: FailureTracker,
        status_filter: Optional[str] = None,
        raw_json_path: Optional[str] = None,
        dedup: bool = False,
        excel_bom: bool = False,
        raw_cells: bool = False,
    ) -> None:
        self.csv_path = csv_path
        self.recon_path = recon_path
        self.tracker = tracker
        self.status_filter = status_filter
        self.dedup = dedup
        self.raw_cells = raw_cells
        # Plain utf-8 by default. utf-8-sig makes Excel happy but prefixes a
        # BOM to the first header cell, which silently breaks csv.DictReader
        # and any downstream keying on "Application Name".
        self._encoding = "utf-8-sig" if excel_bom else "utf-8"

        # Temp paths are created in __enter__ (tempfile.mkstemp: O_EXCL,
        # mode 0600, unpredictable name, same directory as the destination
        # so os.replace stays atomic).
        self._csv_tmp: Optional[str] = None
        self._recon_tmp: Optional[str] = None
        self._raw_tmp: Optional[str] = None
        self.raw_json_path = raw_json_path

        self.rows_written = 0
        self.rows_filtered_out = 0
        self.duplicates_seen = 0
        self.duplicates_removed = 0
        self.by_scan_type: CollCounter = CollCounter()
        self.recon_written = 0
        self._duplicate_samples: list[tuple] = []
        # Finding UID collision tracking. For API findings a collision can
        # only occur inside one application's batch, so a per-batch set is
        # exact. IaC findings for one asset can span several scan records
        # (batches), so IaC UIDs are tracked across the whole run. IaC
        # volume is small enough that this stays cheap.
        self.uid_collisions = 0
        self._uid_collision_samples: list[tuple[str, str]] = []
        self._iac_uids: set[str] = set()
        self._lock = threading.Lock()
        self._closed = False

    @staticmethod
    def _open_temp(final_path: str, encoding: str, newline: Optional[str]) -> tuple[str, Any]:
        """Create an exclusive 0600 temp file next to *final_path*."""
        directory = os.path.dirname(os.path.abspath(final_path))
        fd, tmp = tempfile.mkstemp(
            prefix=os.path.basename(final_path) + ".", suffix=".tmp", dir=directory)
        try:
            fh = os.fdopen(fd, "w", encoding=encoding, newline=newline)
        except Exception:
            os.close(fd)
            raise
        return tmp, fh

    def __enter__(self) -> "StreamingExporter":
        self._csv_tmp, self._csv_fh = self._open_temp(self.csv_path, self._encoding, "")
        self._csv_writer = csv.DictWriter(
            self._csv_fh, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
        self._csv_writer.writeheader()

        self._recon_tmp, self._recon_fh = self._open_temp(
            self.recon_path, self._encoding, "")
        self._recon_writer = csv.DictWriter(
            self._recon_fh, fieldnames=RECON_FIELDNAMES, extrasaction="ignore")
        self._recon_writer.writeheader()

        self._raw_fh = None
        if self.raw_json_path:
            self._raw_tmp, self._raw_fh = self._open_temp(self.raw_json_path, "utf-8", None)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close(publish=exc_type is None)

    def new_batch(self) -> "PreparedBatch":
        """Empty batch carrying this exporter's filter / dedup settings.

        Safe to call and fill from worker threads.
        """
        return PreparedBatch(self.tracker, self.status_filter, self.dedup,
                             bool(self.raw_json_path))

    def write_batch(self, raw_findings: "list[dict[str, Any]] | PreparedBatch") -> None:
        """Write one application's findings: raw dicts or a PreparedBatch.

        Duplicate detection is exact despite streaming: a duplicate can only
        arise within one (app, sandbox, scan_type), and all of an
        application's contexts are fetched by a single worker, so the whole
        equivalence class is present in this batch.
        """
        if isinstance(raw_findings, PreparedBatch):
            batch = raw_findings
        else:
            if not raw_findings:
                return
            batch = self.new_batch()
            batch.add(raw_findings)
        if not batch.retrieved:
            return

        with self._lock:
            if self._raw_fh:
                # JSON Lines, not one giant indented array: constant memory
                # and the file stays readable if the run is interrupted.
                self._raw_fh.writelines(batch.raw_lines)

            self.duplicates_seen += batch.duplicates
            room = 20 - len(self._duplicate_samples)
            if room > 0:
                self._duplicate_samples.extend(batch.duplicate_samples[:room])
            self.duplicates_removed += batch.duplicates_removed
            self.rows_filtered_out += batch.filtered_out

            if batch.retained_dups:
                # The key includes app, context and scan type, so a duplicate
                # is the same finding written twice: the CSV is not a clean
                # one-row-per-finding extract. With --dedup the extra rows
                # are removed and the output is clean; a repeated API page
                # (the usual cause) has already failed its context in
                # paginate(), so that is not counted a second time here.
                self.tracker.record_failure(
                    f"duplicates[{batch.app_name or '?'}]",
                    f"{batch.retained_dups} duplicate finding row(s) written; "
                    f"re-run, or pass --dedup to drop them")

            rows = batch.rows
            batch_uids: set[str] = set()
            for row in rows:
                uid = row.get("Finding UID")
                if not uid:
                    continue
                pool = self._iac_uids if row.get("Scan Type") == "IAC" else batch_uids
                if uid in pool:
                    self.uid_collisions += 1
                    if len(self._uid_collision_samples) < 20:
                        self._uid_collision_samples.append(
                            (uid, str(row.get("Finding Key"))))
                else:
                    pool.add(uid)

            rows.sort(key=_sort_key)
            for row in rows:
                self._csv_writer.writerow(
                    row if self.raw_cells else _csv_safe_row(row, CSV_FIELDNAMES))
                self.by_scan_type[str(row.get("Scan Type"))] += 1
            self.rows_written += len(rows)

    def write_recon(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        with self._lock:
            for row in rows:
                self._recon_writer.writerow(
                    row if self.raw_cells else _csv_safe_row(row, RECON_FIELDNAMES))
            self.recon_written += len(rows)

    def _publish_one(self, tmp: str, final: str) -> None:
        """os.replace with a few retries for Windows sharing violations."""
        for attempt in range(1, PUBLISH_ATTEMPTS + 1):
            try:
                os.replace(tmp, final)  # atomic on POSIX and Windows
                return
            except PermissionError:
                if attempt == PUBLISH_ATTEMPTS:
                    raise
                print(f"  {final} is locked (open in Excel?); retrying "
                      f"{attempt}/{PUBLISH_ATTEMPTS - 1} in {PUBLISH_RETRY_DELAY:.0f}s")
                time.sleep(PUBLISH_RETRY_DELAY)

    def close(self, publish: bool = True) -> None:
        """Flush, fsync and atomically move temp files into place.

        Raises PublishError (listing the finished temp files) when a
        destination stays locked after PUBLISH_ATTEMPTS tries.
        """
        if self._closed:
            return
        self._closed = True

        for fh in (self._csv_fh, self._recon_fh, self._raw_fh):
            if fh:
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
                fh.close()

        if not publish:
            print(f"\n  Export aborted. Partial data left at:\n"
                  f"    {self._csv_tmp}\n"
                  f"  The previous {self.csv_path} was NOT overwritten.")
            return

        stuck: list[str] = []
        for tmp, final in ((self._csv_tmp, self.csv_path),
                           (self._recon_tmp, self.recon_path),
                           (self._raw_tmp, self.raw_json_path)):
            if tmp and final:
                try:
                    self._publish_one(tmp, final)
                except PermissionError as exc:
                    stuck.append(f"{final}: finished data is in {tmp} ({exc.strerror or exc})")
        if stuck:
            raise PublishError("; ".join(stuck))

    @property
    def duplicate_samples(self) -> list[tuple]:
        return self._duplicate_samples

    @property
    def uid_collision_samples(self) -> list[tuple[str, str]]:
        return self._uid_collision_samples


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Export Veracode FINDINGS data via Findings REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Notes:\n"
            "  The Findings API returns the LATEST policy scan for each application.\n"
            "  Sandbox findings require --include-sandbox.\n"
            "  SCA agent findings appear only when the agent project is linked to\n"
            "  an application profile. For tenant-wide extraction, consider the\n"
            "  Reporting API (FINDINGS report) instead of this per-app fan-out.\n"
        ),
    )
    p.add_argument("--output", default="veracode_findings_api.csv",
                   help="Output CSV filename (default: veracode_findings_api.csv).")
    p.add_argument("--app-name",
                   help="Comma-separated application name(s) to filter.")
    p.add_argument("--app-guid",
                   help="Specific application GUID to process.")
    p.add_argument("--scan-type",
                   help="Comma-separated scan types: STATIC, DYNAMIC, MANUAL, SCA, IAC.")
    p.add_argument("--severity", type=int, choices=range(6), metavar="0-5",
                   help="Exact severity filter (0-5).")
    p.add_argument("--severity-gte", type=int, choices=range(6), metavar="0-5",
                   help="Minimum severity filter (0-5).")
    p.add_argument("--cwe",
                   help="CWE ID filter (single or comma-separated).")
    p.add_argument("--status", choices=["OPEN", "CLOSED"],
                   help="Finding status filter (applied client-side).")
    p.add_argument("--violates-policy", action="store_true", default=False,
                   help="Only return findings that do not pass policy.")
    p.add_argument("--include-sandbox", action="store_true", default=False,
                   help="Include sandbox findings (default: policy scan only).")
    p.add_argument("--no-annotations", action="store_true", default=False,
                   help="Do not request annotations (Mitigation Comments will be blank).")
    p.add_argument("--combine-scan-types", action="store_true", default=False,
                   help="Request STATIC,DYNAMIC,MANUAL in one call instead of "
                        "separately. Fewer calls, but only single scan_type values "
                        "are documented.")
    p.add_argument("--request-all-scan-types", action="store_true", default=False,
                   help="Request DYNAMIC and MANUAL findings for the policy scan of "
                        "every app. By default they are requested only when the "
                        "app's scans list (Applications API) has a scan of that "
                        "type; skipped requests are listed as SKIPPED in the "
                        "reconciliation CSV.")
    p.add_argument("--excel-bom", action="store_true", default=False,
                   help="Write a UTF-8 BOM so Excel opens non-ASCII correctly. "
                        "Off by default because the BOM breaks csv.DictReader.")
    p.add_argument("--raw-json", action="store_true", default=False,
                   help="Also write raw API findings as JSON Lines next to "
                        "--output. Off by default: on a large tenant this file "
                        "is enormous.")
    p.add_argument("--raw-cells", action="store_true", default=False,
                   help="Write CSV cells verbatim. By default a text cell starting "
                        "with = + - @ tab or CR is prefixed with ' so spreadsheets "
                        "do not run it as a formula; use this for machine "
                        "consumers / vulnerability-management imports.")
    p.add_argument("--dedup", action="store_true", default=False,
                   help="Drop duplicate finding identities. Duplicates are always "
                        "reported regardless of this flag.")
    p.add_argument("--iac-all-scans", action="store_true", default=False,
                   help="Export IaC findings from every historical scan of each "
                        "asset (default: only the latest scan per asset).")
    p.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE,
                   help=f"Findings page size, 1-{MAX_PAGE_SIZE} (default: {DEFAULT_PAGE_SIZE}).")
    p.add_argument("--sleep", type=float, default=0.0,
                   help="Extra sleep between API pages (default: 0.0; the rate "
                        "limiter already paces requests).")
    p.add_argument("--max-workers", type=int, default=8,
                   help="Concurrent threads (default: 8). The shared --rate-limit "
                        "still caps the request rate; more workers only keep it "
                        "saturated when each page is slow.")
    p.add_argument("--rate-limit", type=float, default=3.5,
                   help="Max API requests/second (default: 3.5 = 210/min, under "
                        "Veracode's 250/min guidance).")
    p.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
                   help=f"Retry attempts per request (default: {DEFAULT_MAX_ATTEMPTS}).")
    p.add_argument("--max-apps", type=int,
                   help="Limit apps processed (testing).")
    p.add_argument("--ca-cert",
                   help="Path to custom CA certificate bundle (.pem).")
    p.add_argument("--ignore-failures", action="store_true", default=False,
                   help="Exit 0 even when requests failed. Not recommended.")
    args = p.parse_args(argv)
    # Reject values that would otherwise fail deep in the run: a page size
    # above the Findings API maximum, a zero pool, or a zero rate (which
    # divides by zero in the rate limiter).
    if not 1 <= args.page_size <= MAX_PAGE_SIZE:
        p.error(f"--page-size must be between 1 and {MAX_PAGE_SIZE}")
    if args.max_workers < 1:
        p.error("--max-workers must be at least 1")
    if args.rate_limit <= 0:
        p.error("--rate-limit must be greater than 0")
    # 0 used to mean "all apps" (falsy) and -1 silently dropped the last app.
    if args.max_apps is not None and args.max_apps < 1:
        p.error("--max-apps must be at least 1")
    if args.max_attempts < 1:
        p.error("--max-attempts must be at least 1")
    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = _parse_args()

    apply_credential_aliases()
    configure_api_base(resolve_api_base())

    global DEFAULT_MAX_ATTEMPTS  # noqa: PLW0603
    DEFAULT_MAX_ATTEMPTS = args.max_attempts  # validated >= 1 by _parse_args

    rate_limiter = RateLimiter(requests_per_second=args.rate_limit)
    tracker = FailureTracker()

    if args.rate_limit > SAFE_RPS:
        print(f"\n  WARNING: --rate-limit {args.rate_limit}/s is "
              f"{args.rate_limit * 60:.0f} req/min. Veracode guidance is to stay "
              f"under 250 req/min. Expect 429s.\n")

    # --- Build filter dict ---
    filters: dict[str, Any] = {}
    if args.scan_type:
        filters["scan_type"] = args.scan_type
    if args.severity is not None:
        filters["severity"] = args.severity
    if args.severity_gte is not None:
        filters["severity_gte"] = args.severity_gte
    if args.cwe:
        filters["cwe"] = args.cwe
    if args.violates_policy:
        filters["violates_policy"] = True

    # --- Scan-type routing ---
    requested_types = _parse_requested_scan_types(args.scan_type)
    if requested_types:
        unknown = set(requested_types) - VALID_SCAN_TYPES
        if unknown:
            print(f"ERROR: Invalid scan type(s): {', '.join(sorted(unknown))}")
            print(f"  Valid values: {', '.join(sorted(VALID_SCAN_TYPES))}")
            return 2

    fetch_api_findings = not requested_types or bool(set(requested_types) & API_SCAN_TYPES)
    fetch_iac = not requested_types or "IAC" in requested_types
    # The SCA workspace and Dynamic Analysis lookups only build deep links for
    # their own scan type; skip their tenant-wide fan-out when not requested.
    fetch_sca_links = not requested_types or "SCA" in requested_types
    fetch_da_links = not requested_types or "DYNAMIC" in requested_types
    include_annotations = not args.no_annotations

    # --- Banner ---
    print("\n" + "=" * 70)
    print("  VERACODE FINDINGS API EXPORT")
    print("=" * 70)
    print(f"  API Base          : {BASE_URL}")
    print(f"  Output File       : {args.output}")
    print(f"  Include Sandboxes : {args.include_sandbox}")
    print(f"  Include Annotations: {include_annotations}")
    print(f"  Scan Types Split  : {not args.combine_scan_types}")
    print(f"  Page Size         : {args.page_size}")
    print(f"  Max Workers       : {args.max_workers}")
    print(f"  Rate Limit        : {args.rate_limit} req/sec "
          f"({args.rate_limit * 60:.0f}/min)")
    print(f"  Retry Attempts    : {DEFAULT_MAX_ATTEMPTS}")
    for label, val in [
        ("CA Cert Bundle", args.ca_cert), ("Filter App Name", args.app_name),
        ("Filter App GUID", args.app_guid), ("Filter Scan Type", args.scan_type),
        ("Filter CWE", args.cwe), ("Filter Status", args.status),
    ]:
        if val:
            print(f"  {label:18s}: {val}")
    if args.severity is not None:
        print(f"  Filter Severity   : {args.severity}")
    if args.severity_gte is not None:
        print(f"  Filter Sev >=     : {args.severity_gte}")
    if not args.include_sandbox:
        print("\n  NOTE: sandbox findings are EXCLUDED. Pass --include-sandbox to")
        print("        include them. This is a common source of platform vs")
        print("        extract discrepancies.")
    print("=" * 70 + "\n")

    # --- Phase 1: Pre-fetch lookup data ---
    sca_map: dict[str, dict[str, str]] = {}
    da_map: dict[str, list[dict[str, Any]]] = {}
    applications: list[dict[str, Any]] = []

    session = create_session(ca_cert=args.ca_cert)
    try:
        if fetch_api_findings and fetch_sca_links:
            print("=" * 70)
            print("  FETCHING SCA WORKSPACE MAPPINGS")
            print("=" * 70)
            sca_map = get_sca_workspaces(session, args.sleep, rate_limiter, tracker,
                                         max_workers=args.max_workers,
                                         ca_cert=args.ca_cert)
            print("=" * 70 + "\n")

        if fetch_api_findings and fetch_da_links:
            print("=" * 70)
            print("  FETCHING DYNAMIC ANALYSIS MAPPINGS")
            print("=" * 70)
            da_map = get_dynamic_analyses(session, args.sleep, rate_limiter, tracker,
                                          max_workers=args.max_workers,
                                          ca_cert=args.ca_cert)
            if da_map:
                total_da = sum(len(v) for v in da_map.values())
                print(f"  Found {total_da} Dynamic Analyses across {len(da_map)} applications")
            else:
                print("  No Dynamic Analysis found")
            print("=" * 70 + "\n")

        # --- Phase 2: Resolve application list ---
        if args.app_guid:
            # Fetch the real record. The previous stub had no id/oid/profile,
            # so Team Name came out blank and every static and SCA deep link
            # silently degraded to a generic module-list URL.
            print(f"Processing single application: {args.app_guid}")
            try:
                resp = request_with_retry(
                    session, f"{APPLICATIONS_URL}/{args.app_guid}",
                    scope=f"application[{args.app_guid}]",
                    rate_limiter=rate_limiter, tracker=tracker, timeout=60,
                )
                if resp.status_code == 404:
                    print(f"FATAL: application {args.app_guid} not found.\n")
                    return 1
                applications = [_json_object(resp, f"application[{args.app_guid}]")]
                nm = (applications[0].get("profile") or {}).get("name", "Unknown")
                print(f"  Resolved: {nm}\n")
            except FetchError as exc:
                tracker.record_failure(f"application[{args.app_guid}]", str(exc))
                print(f"FATAL: could not resolve application {args.app_guid}: {exc}\n")
                return 1
        else:
            try:
                applications = get_applications(session, rate_limiter, tracker)
            except FetchError as exc:
                tracker.record_failure("applications", str(exc))
                print(f"\nFATAL: could not enumerate applications: {exc}")
                print("Aborting rather than exporting a partial tenant.\n")
                return 1

            if args.app_name:
                target_set = {n.strip() for n in args.app_name.split(",")}
                applications = [
                    a for a in applications
                    if a.get("profile", {}).get("name", "") in target_set
                ]
                print(f"Filtered to {len(applications)} applications matching provided names\n")
                found = {a.get("profile", {}).get("name", "") for a in applications}
                missing = target_set - found
                if missing:
                    print(f"WARNING: Could not find: {', '.join(sorted(missing))}\n")
                    tracker.record_failure(
                        "app-name-filter", f"not found: {', '.join(sorted(missing))}"
                    )
            if args.max_apps is not None:
                applications = applications[:args.max_apps]
                print(f"Limited to {args.max_apps} applications (for testing)\n")
    finally:
        session.close()

    # --- Filter SCA map to relevant apps (link generation only) ---
    if sca_map and applications:
        app_guids = {a.get("guid") for a in applications if a.get("guid")}
        app_names_lc = {a.get("profile", {}).get("name", "").lower() for a in applications}
        app_names_lc.discard("")
        orig = len(sca_map)
        sca_map = {
            k: v for k, v in sca_map.items()
            if (k.startswith("guid:") and k[5:] in app_guids)
            or (not k.startswith("guid:") and k in app_names_lc)
        }
        print(f"  Filtered SCA mappings: {orig} -> {len(sca_map)} (relevant to selected apps)")

    # --- Phase 3: Fetch findings concurrently, streaming to disk ---
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_stem = os.path.splitext(args.output)[0]
    recon_path = out_stem + f"_reconciliation_{timestamp}.csv"
    # Next to --output (same stem as the reconciliation file), not the CWD.
    raw_path = (out_stem + f"_raw_{timestamp}.jsonl") if args.raw_json else None

    apps_with_findings = 0
    apps_ok = 0
    apps_failed = 0
    findings_retrieved = 0

    exporter = StreamingExporter(
        csv_path=args.output,
        recon_path=recon_path,
        tracker=tracker,
        status_filter=args.status,
        raw_json_path=raw_path,
        dedup=args.dedup,
        excel_bom=args.excel_bom,
        raw_cells=args.raw_cells,
    )

    try:
        with exporter:
            if fetch_api_findings:
                print("\n" + "=" * 70)
                print("  FETCHING FINDINGS FROM APPLICATIONS")
                print("=" * 70 + "\n")

                with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
                    def _submit(entry: tuple[int, dict[str, Any]]) -> Any:
                        i, a = entry
                        return executor.submit(
                            _process_application,
                            app=a, idx=i, total=len(applications),
                            filters=filters, sleep_time=args.sleep,
                            include_sandboxes=args.include_sandbox,
                            sca_map=sca_map, da_map=da_map,
                            rate_limiter=rate_limiter, tracker=tracker,
                            page_size=args.page_size,
                            include_annotations=include_annotations,
                            combine_scan_types=args.combine_scan_types,
                            ca_cert=args.ca_cert,
                            request_all_scan_types=args.request_all_scan_types,
                            prepare=exporter.new_batch,
                        )

                    # Bounded sliding window. Submitting all 15,000 tasks up front
                    # and draining with as_completed defeats streaming: completed
                    # futures hold their result lists until consumed, so the whole
                    # tenant ends up resident anyway. Keeping only a few in flight
                    # caps live findings at roughly window x findings-per-app,
                    # while the pool stays saturated.
                    app_iter = iter(list(enumerate(applications, 1)))
                    window = max(2, args.max_workers * 2)
                    pending: deque = deque()
                    for entry in itertools.islice(app_iter, window):
                        pending.append((entry[1], _submit(entry)))

                    while pending:
                        app, future = pending.popleft()
                        name = app.get("profile", {}).get("name", "Unknown")
                        try:
                            findings, rows = future.result()
                            exporter.write_recon(rows)
                            findings_retrieved += len(findings)
                            if findings:
                                apps_with_findings += 1
                            exporter.write_batch(findings)
                            if any(r.get("Status") not in RECON_OK_STATUSES for r in rows):
                                apps_failed += 1
                            else:
                                apps_ok += 1
                            del findings, rows  # release before pulling the next
                        except Exception as exc:
                            apps_failed += 1
                            tracker.record_failure(
                                f"application[{name}]", f"{type(exc).__name__}: {exc}")
                            print(f"    ERROR processing {name}: {exc}\n")

                        nxt = next(app_iter, None)
                        if nxt is not None:
                            pending.append((nxt[1], _submit(nxt)))
            else:
                print("\n  Skipping API findings fetch "
                      "(--scan-type does not include API scan types)\n")

            # --- Phase 4: IaC integration ---
            if fetch_iac:
                print("\n" + "=" * 70)
                print("  FETCHING IAC SCAN DATA")
                print("=" * 70 + "\n")

                iac_filter_set: Optional[set[str]] = None
                if args.app_name:
                    iac_filter_set = {n.strip() for n in args.app_name.split(",") if n.strip()}
                elif args.app_guid:
                    # A single-app run must not export every IaC asset in
                    # the tenant; match IaC assets to the resolved app name.
                    iac_filter_set = {
                        (a.get("profile") or {}).get("name", "")
                        for a in applications
                    } - {""} or {args.app_guid}

                iac_records = _fetch_iac_data_live(
                    rate_limiter=rate_limiter,
                    tracker=tracker,
                    max_workers=args.max_workers,
                    filter_apps=iac_filter_set,
                    ca_cert=args.ca_cert,
                    all_scans=args.iac_all_scans,
                )

                if iac_records:
                    app_by_name: dict[str, dict] = {}
                    app_name_lc: dict[str, str] = {}
                    for app in applications:
                        prof = app.get("profile") or {}
                        nm = prof.get("name", "Unknown")
                        app_by_name[nm] = {"guid": app.get("guid"), "profile": prof}
                        app_name_lc[nm.lower()] = nm

                    iac_count = 0
                    iac_apps = 0
                    unmatched: list[str] = []

                    for rec in iac_records:
                        asset = rec.get("asset_name", "")
                        info = app_by_name.get(asset)
                        if not info:
                            canonical = app_name_lc.get(asset.lower())
                            if canonical:
                                info = app_by_name[canonical]

                        if info:
                            matched_name = info["profile"].get("name", asset)
                            uid_app_key = info["guid"]
                        else:
                            uid_app_key = f"iac-asset:{str(asset).strip().lower()}"
                            sid = rec.get("scan_id", asset)
                            unmatched.append(asset)
                            info = {"guid": str(sid),
                                    "profile": {"name": asset,
                                                "business_unit": {"name": "Unknown"},
                                                "teams": []}}
                            matched_name = asset

                        iac_apps += 1
                        recon_row = rec.get("_recon")
                        if isinstance(recon_row, dict):
                            if info.get("guid") and uid_app_key == info["guid"]:
                                recon_row = {**recon_row, "Application GUID": info["guid"]}
                            exporter.write_recon([recon_row])
                        batch = []
                        for iac_finding in rec.get("detailed_findings", []):
                            try:
                                batch.append(normalize_iac_finding(
                                    iac_finding, rec, matched_name,
                                    info["guid"], info["profile"],
                                    app_key=uid_app_key))
                            except Exception as exc:
                                tracker.record_failure(
                                    f"normalize-iac[{matched_name}]",
                                    f"{type(exc).__name__}: {exc}")
                            iac_count += 1
                        exporter.write_batch(batch)
                        findings_retrieved += len(batch)

                    print(f"\n  Processed {iac_apps} IaC assets")
                    print(f"  Added {iac_count} individual IaC findings")
                    if unmatched:
                        print(f"  {len(unmatched)} IaC asset(s) had no matching "
                              f"application profile and used placeholders")
                else:
                    print("  No IaC scan data found.\n")

    except KeyboardInterrupt:
        print("\n\n  INTERRUPTED by user. The destination file was not modified.")
        return 130
    except PublishError as exc:
        print("\n  ERROR: the export finished but could not be published "
              "(destination locked, e.g. open in Excel).")
        for part in str(exc).split("; "):
            print(f"    {part}")
        print("  Close the file and rename the temp file, or re-run.\n")
        return 1

    # --- Duplicate analysis ---
    print("\n" + "=" * 70)
    print("  DUPLICATE ANALYSIS")
    print("=" * 70)
    print(f"  Duplicate finding identities "
          f"(app+context+scan_type+issue_id): {exporter.duplicates_seen}")
    for key in exporter.duplicate_samples[:5]:
        print(f"    {key}")
    if exporter.duplicates_removed:
        print(f"  --dedup active: removed {exporter.duplicates_removed} rows")
    elif exporter.duplicates_seen:
        print("  Duplicates retained (pass --dedup to remove them).")
    print(f"  Rows sharing a Finding UID          : {exporter.uid_collisions}")
    for uid, key in exporter.uid_collision_samples[:5]:
        print(f"    {uid}  {key}")
    if exporter.uid_collisions:
        print("  Rows sharing a UID describe the same finding: API duplicates")
        print("  (see above) or one IaC finding repeated across scans of an asset.")
    print("=" * 70)

    # --- Outputs ---
    print("\n" + "=" * 70)
    print("  SAVING RESULTS")
    print("=" * 70)
    print(f"  CSV File      : {args.output} ({exporter.rows_written} findings)")
    print(f"  Reconciliation: {recon_path} ({exporter.recon_written} request contexts)")
    if raw_path:
        print(f"  Raw JSONL     : {raw_path}")
    if args.status:
        print(f"  Client-side status filter '{args.status}' excluded "
              f"{exporter.rows_filtered_out} rows")

    by_scan_type = exporter.by_scan_type

    print("\n" + "=" * 70)
    print("  EXPORT SUMMARY")
    print("=" * 70)
    print(f"  Applications discovered   : {len(applications)}")
    print(f"  Applications COMPLETE     : {apps_ok}")
    print(f"  Applications FAILED       : {apps_failed}")
    print(f"  Applications with findings: {apps_with_findings}")
    print(f"  Work contexts registered  : {exporter.recon_written}")
    print(f"  API pages retrieved       : {tracker.pages_ok}")
    print(f"  API pages failed          : {tracker.pages_failed}")
    print(f"  Findings retrieved        : {findings_retrieved}")
    print(f"  Findings exported         : {exporter.rows_written}")
    delta = findings_retrieved - exporter.rows_written - exporter.rows_filtered_out \
        - exporter.duplicates_removed
    print(f"  Reconciliation delta      : {delta}")
    for st, n in sorted(by_scan_type.items()):
        print(f"    {st:<20}: {n}")
    print(f"  Requests retried          : {tracker.retries} "
          f"({tracker.rate_limit_hits} rate-limit)")
    print(f"  Failed request families   : {len(tracker.failures)}")
    print(f"  Count mismatches          : {len(tracker.mismatches)}")

    if delta != 0:
        tracker.record_mismatch("export-accounting", findings_retrieved,
                                exporter.rows_written)
        print("\n  ! ACCOUNTING DELTA IS NON-ZERO. Rows were lost between "
              "retrieval and export.")

    if tracker.failures:
        print("\n  FAILURES (data is INCOMPLETE for these):")
        for f in tracker.failures[:40]:
            print(f"    - {f['scope']}: {f['detail'][:160]}")
        if len(tracker.failures) > 40:
            print(f"    ... and {len(tracker.failures) - 40} more")

    if tracker.mismatches:
        print("\n  COUNT MISMATCHES (API total vs retrieved):")
        for m in tracker.mismatches[:40]:
            print(f"    - {m['scope']}: {m['detail']}")
        if len(tracker.mismatches) > 40:
            print(f"    ... and {len(tracker.mismatches) - 40} more")

    if tracker.clean:
        print("\n  RESULT: COMPLETE. Every request family succeeded, every")
        print("          API-reported total matched what was retrieved, and")
        print("          every retrieved finding is accounted for in the CSV.")
        status_code = 0
    else:
        print("\n  RESULT: INCOMPLETE. Do not treat this extract as authoritative.")
        print("          Review the reconciliation CSV, then re-run. Consider")
        print("          lowering --rate-limit and --max-workers.")
        status_code = 0 if args.ignore_failures else 1

    print("=" * 70 + "\n")
    return status_code


if __name__ == "__main__":
    sys.exit(main())
