from pisa.m1 import nmap_scan

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="1883">
        <state state="open"/>
        <service name="mqtt"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 4.X" accuracy="95"/>
    </os>
  </host>
</nmaprun>
"""


def test_build_nmap_cmd():
    cmd = nmap_scan._build_nmap_cmd("192.168.1.10", [22, 80])
    assert cmd[0] == "nmap"
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80"
    assert "192.168.1.10" == cmd[-1]


def test_parse_nmap_xml_extracts_open_ports_and_os():
    result = nmap_scan._parse_nmap_xml(SAMPLE_XML)

    assert {"port": 80, "service": "http"} in result["open_ports"]
    assert {"port": 1883, "service": "mqtt"} in result["open_ports"]
    assert all(p["port"] != 23 for p in result["open_ports"])
    assert result["os_guess"] == "Linux 4.X"


def test_parse_nmap_xml_handles_empty_output():
    assert nmap_scan._parse_nmap_xml("") == {"open_ports": [], "os_guess": None}


def test_parse_nmap_xml_handles_malformed_output():
    assert nmap_scan._parse_nmap_xml("not xml") == {"open_ports": [], "os_guess": None}


def test_scan_host_uses_run_nmap_and_parses_result(monkeypatch):
    monkeypatch.setattr(nmap_scan, "_run_nmap", lambda cmd: SAMPLE_XML)

    result = nmap_scan.scan_host("192.168.1.10")

    assert result["os_guess"] == "Linux 4.X"
    assert len(result["open_ports"]) == 2
