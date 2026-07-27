from pisa.m2 import rtsp_probe


def test_probe_extracts_status_line_and_server(monkeypatch):
    response = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision-Webs\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
    monkeypatch.setattr(rtsp_probe, "_send_options", lambda ip, port, timeout: response)

    features = rtsp_probe.probe("192.168.1.40", 554, 3.0)

    assert features[0]["device_type_hint"] == "IP Camera"
    assert any(f["feature_key"] == "rtsp.server" and f["feature_value"] == "Hikvision-Webs" for f in features)


def test_probe_returns_empty_on_non_rtsp_response(monkeypatch):
    monkeypatch.setattr(rtsp_probe, "_send_options", lambda ip, port, timeout: "HTTP/1.1 200 OK\r\n\r\n")

    assert rtsp_probe.probe("192.168.1.40", 554, 3.0) == []


def test_probe_returns_empty_on_no_response(monkeypatch):
    monkeypatch.setattr(rtsp_probe, "_send_options", lambda ip, port, timeout: None)

    assert rtsp_probe.probe("192.168.1.40", 554, 3.0) == []
