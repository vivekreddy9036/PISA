from pisa.m2 import http_probe


class FakeResponse:
    def __init__(self, headers=None, text=""):
        self.headers = headers or {}
        self.text = text


def test_probe_extracts_server_header(monkeypatch):
    monkeypatch.setattr(
        http_probe, "_get",
        lambda ip, port, timeout: FakeResponse(headers={"Server": "lighttpd"}, text="hello"),
    )

    features = http_probe.probe("192.168.1.30", 80, 3.0)

    assert any(f["feature_key"] == "http.server" and f["feature_value"] == "lighttpd" for f in features)


def test_probe_matches_keyword_hint(monkeypatch):
    monkeypatch.setattr(
        http_probe, "_get",
        lambda ip, port, timeout: FakeResponse(text="<title>IP Camera Login</title>"),
    )

    features = http_probe.probe("192.168.1.30", 80, 3.0)

    assert "IP Camera" in [f["device_type_hint"] for f in features]


def test_probe_returns_empty_on_no_response(monkeypatch):
    monkeypatch.setattr(http_probe, "_get", lambda ip, port, timeout: None)

    assert http_probe.probe("192.168.1.30", 80, 3.0) == []


def test_probe_returns_empty_when_no_server_header_or_keyword(monkeypatch):
    monkeypatch.setattr(http_probe, "_get", lambda ip, port, timeout: FakeResponse(text="plain page"))

    assert http_probe.probe("192.168.1.30", 80, 3.0) == []
