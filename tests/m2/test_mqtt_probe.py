from pisa.m2 import mqtt_probe


def test_probe_returns_feature_on_accepted_connack(monkeypatch):
    monkeypatch.setattr(mqtt_probe, "_connect_and_get_reason_code", lambda ip, port, timeout: 0)

    features = mqtt_probe.probe("192.168.1.10", 1883, 3.0)

    assert len(features) == 1
    assert features[0]["protocol"] == "mqtt"
    assert features[0]["device_type_hint"] == "MQTT Broker"
    assert features[0]["confidence"] == 0.9


def test_probe_lower_confidence_on_rejected_connack(monkeypatch):
    monkeypatch.setattr(mqtt_probe, "_connect_and_get_reason_code", lambda ip, port, timeout: 135)

    features = mqtt_probe.probe("192.168.1.10", 1883, 3.0)

    assert features[0]["confidence"] == 0.5


def test_probe_returns_empty_on_no_response(monkeypatch):
    monkeypatch.setattr(mqtt_probe, "_connect_and_get_reason_code", lambda ip, port, timeout: None)

    assert mqtt_probe.probe("192.168.1.10", 1883, 3.0) == []
