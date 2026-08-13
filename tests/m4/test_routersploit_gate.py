import time

from routersploit.core.exploit.printer import print_error, print_success

import config
from pisa.m4 import routersploit_gate


class _VulnerableExploit:
    _Exploit__info__ = {
        "name": "Fake Vuln",
        "description": "Fake vulnerability referencing CVE-2021-1234",
        "references": ("https://example.com/advisory",),
        "devices": ("Fake Device",),
    }

    def __init__(self):
        self.target = None
        self.port = None

    def check(self):
        print_success("looks vulnerable")
        return True

    def run(self):
        print_success("exploited: got shell")


class _NotVulnerableExploit:
    _Exploit__info__ = {"name": "Fake Safe", "description": "no CVE here", "references": (), "devices": ()}

    def __init__(self):
        self.target = None
        self.port = None

    def check(self):
        print_error("not vulnerable")
        return False

    def run(self):
        raise AssertionError("run() should not be called when check() is False")


class _RaisingExploit:
    def check(self):
        raise ConnectionError("boom")


def _patch_index(monkeypatch, index: dict):
    monkeypatch.setattr(routersploit_gate, "_load_module_index", lambda: index)


def test_find_modules_for_cve_matches_by_description(monkeypatch):
    _patch_index(monkeypatch, {"fake.vuln": _VulnerableExploit})

    matches = routersploit_gate.find_modules_for_cve("CVE-2021-1234")

    assert len(matches) == 1
    assert matches[0]["module_path"] == "fake.vuln"
    assert matches[0]["name"] == "Fake Vuln"


def test_find_modules_for_cve_case_insensitive(monkeypatch):
    _patch_index(monkeypatch, {"fake.vuln": _VulnerableExploit})
    assert len(routersploit_gate.find_modules_for_cve("cve-2021-1234")) == 1


def test_find_modules_for_cve_returns_empty_when_no_match(monkeypatch):
    _patch_index(monkeypatch, {"fake.safe": _NotVulnerableExploit})
    assert routersploit_gate.find_modules_for_cve("CVE-9999-9999") == []


def test_run_exploit_check_mode_success(monkeypatch):
    _patch_index(monkeypatch, {"fake.vuln": _VulnerableExploit})

    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.vuln", "check")

    assert outcome["success"] is True
    assert "looks vulnerable" in outcome["result"]


def test_run_exploit_check_mode_not_vulnerable(monkeypatch):
    _patch_index(monkeypatch, {"fake.safe": _NotVulnerableExploit})

    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.safe", "check")

    assert outcome["success"] is False
    assert "not vulnerable" in outcome["result"]


def test_run_exploit_run_mode_calls_run_only_when_vulnerable(monkeypatch):
    _patch_index(monkeypatch, {"fake.vuln": _VulnerableExploit})

    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.vuln", "run")

    assert outcome["success"] is True
    assert "exploited: got shell" in outcome["result"]


def test_run_exploit_run_mode_skips_run_when_not_vulnerable(monkeypatch):
    _patch_index(monkeypatch, {"fake.safe": _NotVulnerableExploit})

    # _NotVulnerableExploit.run() raises if called; no exception means it was correctly skipped
    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.safe", "run")

    assert outcome["success"] is False


def test_run_exploit_unknown_module_path(monkeypatch):
    _patch_index(monkeypatch, {})

    outcome = routersploit_gate.run_exploit("192.0.2.10", "nope.nope", "check")

    assert outcome["success"] is False
    assert "unknown module" in outcome["result"]


def test_run_exploit_catches_exceptions(monkeypatch):
    _patch_index(monkeypatch, {"fake.broken": _RaisingExploit})

    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.broken", "check")

    assert outcome["success"] is False
    assert "error:" in outcome["result"]


def test_run_exploit_sets_target_and_port(monkeypatch):
    captured = {}

    class _Recorder(_VulnerableExploit):
        def check(self):
            captured["target"] = self.target
            captured["port"] = self.port
            return True

    _patch_index(monkeypatch, {"fake.recorder": _Recorder})

    routersploit_gate.run_exploit("192.0.2.10", "fake.recorder", "check", port=8080)

    assert captured["target"] == "192.0.2.10"
    assert captured["port"] == 8080


# ---------------------------------------------------------------------------
# Phase 7: tri-state check(), interactive shell() detection, timeout
# ---------------------------------------------------------------------------

class _InconclusiveExploit:
    """check() returns None — RouterSploit's own "could not verify"
    convention (real example: misfortune_cookie.py)."""
    def __init__(self):
        self.target = None
        self.port = None

    def check(self):
        return None

    def run(self):
        raise AssertionError("run() must never be called when check() is None (inconclusive)")


class _InteractiveShellExploit:
    """Mirrors a real shell()-using module's run() shape closely enough
    that `shell` appears in run()'s bytecode co_names — the actual
    detection mechanism this test exercises. Never actually calls the
    real shell() (would hang the test); the point is that run_exploit()
    refuses to call this run() at all in mode="run"."""
    _Exploit__info__ = {"name": "Fake Interactive", "description": "", "references": (), "devices": ()}

    def __init__(self):
        self.target = None
        self.port = None

    def check(self):
        return True

    def run(self):
        raise AssertionError("run() must never actually execute for a shell()-using module")
        shell()  # noqa: F821,B012 — unreachable; its mere presence in the bytecode is what's under test


class _SlowCheckExploit:
    def __init__(self):
        self.target = None
        self.port = None

    def check(self):
        time.sleep(1.0)
        return True


def test_check_true_maps_to_confirmed_vulnerable(monkeypatch):
    _patch_index(monkeypatch, {"fake.vuln": _VulnerableExploit})
    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.vuln", "check")
    assert outcome["check_state"] == routersploit_gate.CHECK_CONFIRMED_VULNERABLE
    assert outcome["success"] is True


def test_check_false_maps_to_confirmed_not_vulnerable(monkeypatch):
    _patch_index(monkeypatch, {"fake.safe": _NotVulnerableExploit})
    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.safe", "check")
    assert outcome["check_state"] == routersploit_gate.CHECK_CONFIRMED_NOT_VULNERABLE
    assert outcome["success"] is False


def test_check_none_maps_to_inconclusive_not_silently_false(monkeypatch):
    """The mandatory regression test: bool(None) == False must never be
    the mechanism that produces this result — check_state must
    distinguish "confirmed not vulnerable" from "could not verify"."""
    _patch_index(monkeypatch, {"fake.inconclusive": _InconclusiveExploit})

    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.inconclusive", "check")

    assert outcome["check_state"] == routersploit_gate.CHECK_INCONCLUSIVE
    assert outcome["check_state"] != routersploit_gate.CHECK_CONFIRMED_NOT_VULNERABLE
    assert outcome["success"] is False  # legacy bool field stays False, but the detail is preserved above


def test_uses_interactive_shell_detects_real_known_module():
    """Verified against the actual installed RouterSploit package (not a
    fake fixture) — a real module known to call shell() in run()."""
    index = routersploit_gate._load_module_index()
    dgn2200 = index["exploits.routers.netgear.dgn2200_ping_cgi_rce"]
    assert routersploit_gate._uses_interactive_shell(dgn2200) is True


def test_uses_interactive_shell_false_for_real_registered_modules():
    """The two modules this project actually registers as supported
    (pisa/m3/exploitation.py) must both be non-interactive."""
    index = routersploit_gate._load_module_index()
    creds = index["exploits.cameras.multi.dvr_creds_disclosure"]
    traversal = index["exploits.cameras.xiongmai.uc_httpd_path_traversal"]
    assert routersploit_gate._uses_interactive_shell(creds) is False
    assert routersploit_gate._uses_interactive_shell(traversal) is False


def test_run_mode_refuses_interactive_shell_module_instead_of_hanging(monkeypatch):
    _patch_index(monkeypatch, {"fake.interactive": _InteractiveShellExploit})

    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.interactive", "run")

    assert outcome["success"] is False
    assert outcome.get("unsupported") is True
    assert "interactive" in outcome["result"].lower()


def test_check_mode_still_works_on_a_module_whose_run_is_interactive(monkeypatch):
    """check() itself doesn't touch shell() on any real module examined
    in this project — only run() does — so check mode must still work
    normally even for a module flagged unsupported for run mode."""
    _patch_index(monkeypatch, {"fake.interactive": _InteractiveShellExploit})

    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.interactive", "check")

    assert outcome["check_state"] == routersploit_gate.CHECK_CONFIRMED_VULNERABLE
    assert "unsupported" not in outcome


def test_check_timeout_does_not_hang_and_reports_timeout(monkeypatch):
    monkeypatch.setattr(config, "EXPLOIT_TIMEOUT", 0.1)
    _patch_index(monkeypatch, {"fake.slow": _SlowCheckExploit})

    started = time.monotonic()
    outcome = routersploit_gate.run_exploit("192.0.2.10", "fake.slow", "check")
    elapsed = time.monotonic() - started

    assert elapsed < 1.0  # caller got control back well before the fake check()'s own 1s sleep finished
    assert outcome.get("timeout") is True
    assert outcome["check_state"] == routersploit_gate.CHECK_INCONCLUSIVE
    assert outcome["success"] is False
