from routersploit.core.exploit.printer import print_error, print_success

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
