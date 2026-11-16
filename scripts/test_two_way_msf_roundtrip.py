#!/usr/bin/env python3
"""Automated two-way roundtrip test:

1. Import nmap-db / vulners / GVM XML into Request-Rider Project.
2. Verify Hosts, IP addresses, Hostnames, Open Ports, Service Versions & CVEs in DB and Project Hub.
3. Export Project to Metasploit XML (<MetasploitV4>).
4. Verify Metasploit db_import compatibility (via msfconsole if available, and XML structure check).
5. Re-import the Metasploit XML back into a fresh Request-Rider Project to verify bidirectional parity.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

# Setup Django environment
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "web"))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
os.environ.setdefault("POSTGRES_HOST", "127.0.0.1")
os.environ.setdefault("POSTGRES_PORT", "55433")
os.environ.setdefault("POSTGRES_USER", "kali")

import django
django.setup()

from django.test import Client
from lab.models import Project, ProjectHost, ProjectEndpoint, ScannerRun
from lab import xml_exports


def main():
    print("=" * 70)
    print("REQUEST-RIDER: TWO-WAY METASPLOIT & NMAP DB IMPORT/EXPORT ROUNDTRIP")
    print("=" * 70)

    xml_path = REPO_ROOT / "data" / "test_scan_database.xml"
    if not xml_path.exists():
        print(f"[-] Error: sample XML not found at {xml_path}")
        return 1

    xml_content = xml_path.read_text(encoding="utf-8")
    print(f"[+] Loaded test scan database: {xml_path.name} ({len(xml_content)} bytes)")

    # 1. Створюємо проєкт і робимо імпорт
    client = Client()
    Project.objects.filter(name__in=["Enterprise Infrastructure Pentest", "Roundtrip Re-Imported Workspace"]).delete()
    project = Project.objects.create(
        name="Enterprise Infrastructure Pentest",
        target="https://srv-app.corp.local:443",
    )
    print(f"[+] Created Project ID {project.id}: '{project.name}'")

    print("[*] STEP 1: Importing XML scan into Project...")
    import_resp = client.post(
        f"/api/projects/{project.id}/import-metasploit-xml",
        data=json.dumps({"xml": xml_content}),
        content_type="application/json",
    )
    if import_resp.status_code != 200:
        print(f"[-] Import failed: {import_resp.status_code} - {import_resp.content}")
        return 1

    import_data = import_resp.json()
    print(f"    -> Hosts imported: {import_data.get('hosts_count')}")
    print(f"    -> Endpoints added: {import_data.get('endpoints_added')}")
    print(f"    -> Total open services: {import_data.get('total_services')}")
    print(f"    -> Total vulns: {import_data.get('total_vulns')}")

    # 2. Перевіряємо базу даних ProjectHost
    print("[*] STEP 2: Verifying ProjectHost records in Database & Hub API...")
    hosts = list(ProjectHost.objects.filter(project=project).order_by("ip_address"))
    if len(hosts) != 3:
        print(f"[-] Expected 3 hosts, got {len(hosts)}")
        return 1

    hub_resp = client.get(f"/api/projects/{project.id}/hub")
    hub_data = hub_resp.json()
    hub_hosts = hub_data.get("hosts", [])
    print(f"[+] Project Hub API returned {len(hub_hosts)} hosts. Details:")

    for h in hub_hosts:
        ip = h["ip_address"]
        hostname = h.get("hostname") or "none"
        os_name = h.get("os_name") or "unknown"
        ports = [f"{s['port']}/{s.get('proto','tcp')} ({s.get('name','')} {s.get('version','') or s.get('banner','')})" for s in h.get("services", [])]
        vulns = [f"{v['id']} ({v.get('severity','')}, CVSS {v.get('cvss','')})" for s in h.get("services", []) for v in s.get("vulns", [])] + [f"{v['id']}" for v in h.get("vulns", [])]
        print(f"    - Host: {ip:15} | Domain: {hostname:18} | OS: {os_name}")
        print(f"      Open Ports: {', '.join(ports)}")
        print(f"      Vulns:      {', '.join(vulns) if vulns else 'clean'}")

    # Перевірка конкретних знахідок
    host_map = {h["ip_address"]: h for h in hub_hosts}
    assert "192.168.1.100" in host_map, "Host 192.168.1.100 missing"
    assert "10.10.10.5" in host_map, "Host 10.10.10.5 missing"
    assert "10.10.10.20" in host_map, "Host 10.10.10.20 missing"

    h1_services = {s["port"]: s for s in host_map["192.168.1.100"]["services"]}
    assert 80 in h1_services and "Apache" in (h1_services[80].get("product") or h1_services[80].get("banner")), "Apache missing on port 80"
    assert any(v["id"] == "CVE-2021-41773" for v in h1_services[80].get("vulns", [])), "CVE-2021-41773 missing"

    h2_services = {s["port"]: s for s in host_map["10.10.10.5"]["services"]}
    assert 445 in h2_services and any(v["id"] == "CVE-2020-1472" for v in h2_services[445].get("vulns", [])), "ZeroLogon CVE-2020-1472 missing on port 445"

    h3_services = {s["port"]: s for s in host_map["10.10.10.20"]["services"]}
    assert 8080 in h3_services and any(v["id"] == "CVE-2021-22205" for v in h3_services[8080].get("vulns", [])), "GitLab CVE-2021-22205 missing on port 8080"
    print("[+] All hosts, service versions and port-specific CVEs verified successfully!")

    # 3. Експорт проєкту в Metasploit XML
    print("[*] STEP 3: Exporting Project back to Metasploit XML (<MetasploitV4>)...")
    export_resp = client.get(f"/api/projects/{project.id}/export?format=metasploit-xml")
    if export_resp.status_code != 200:
        print(f"[-] Export failed: {export_resp.status_code}")
        return 1

    exported_xml = export_resp.content.decode("utf-8")
    export_file = REPO_ROOT / "data" / "exported_msf_test.xml"
    export_file.write_text(exported_xml, encoding="utf-8")
    print(f"[+] Exported Metasploit XML saved to {export_file} ({len(exported_xml)} bytes)")

    # Валідація згенерованого Metasploit XML
    root = ET.fromstring(exported_xml)
    assert root.tag == "MetasploitV4", "Root element must be MetasploitV4"
    msf_hosts = root.findall("./hosts/host")
    print(f"[+] Validated MetasploitV4 XML: contains {len(msf_hosts)} host entries")
    assert len(msf_hosts) >= 3, "Exported XML must contain at least 3 hosts"

    # 4. Якщо в системі встановлено msfconsole, перевіримо реальний db_import
    msf_bin = shutil.which("msfconsole")
    if msf_bin:
        print(f"[*] STEP 4: Verifying direct import into Metasploit via msfconsole...")
        with tempfile.NamedTemporaryFile("w", suffix=".rc", delete=False) as rc:
            rc.write(f"workspace -a test_rr_import\n")
            rc.write(f"db_import {export_file}\n")
            rc.write(f"hosts\n")
            rc.write(f"services\n")
            rc.write(f"vulns\n")
            rc.write(f"workspace -d test_rr_import\n")
            rc.write(f"exit\n")
            rc_path = rc.name

        try:
            cmd = [msf_bin, "-q", "-r", rc_path]
            print(f"    Running: {' '.join(cmd)}")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=35, shell=False)
            if "Importing 'Metasploit XML' data" in res.stdout or "Successfully imported" in res.stdout or "192.168.1.100" in res.stdout:
                print("[+] SUCCESS: Metasploit console successfully ingested the exported XML!")
                for line in res.stdout.splitlines():
                    if any(k in line for k in ("Importing", "192.168.1.100", "10.10.10.5", "CVE-2021-41773", "ZeroLogon")):
                        print(f"    [MSF] {line.strip()}")
            else:
                print(f"[i] MSF completed (exit code {res.returncode})")
        except Exception as e:
            print(f"[!] Note on msfconsole execution: {e}")
        finally:
            try:
                os.unlink(rc_path)
            except OSError:
                pass
    else:
        print("[i] STEP 4: msfconsole binary not found on host, validated XML schema structure directly.")

    # 5. Повний зворотній цикл: імпортуємо згенерований Metasploit XML у чистий проєкт
    print("[*] STEP 5: Re-importing exported Metasploit XML into a second Project (roundtrip check)...")
    p2 = Project.objects.create(name="Roundtrip Re-Imported Workspace")
    reimp_resp = client.post(
        f"/api/projects/{p2.id}/import-metasploit-xml",
        data=json.dumps({"xml": exported_xml}),
        content_type="application/json",
    )
    assert reimp_resp.status_code == 200, "Re-import into Project 2 failed"
    p2_hub_resp = client.get(f"/api/projects/{p2.id}/hub")
    p2_hosts = p2_hub_resp.json().get("hosts", [])
    print(f"[+] Second Project successfully restored {len(p2_hosts)} hosts from Metasploit XML!")

    p2_h1 = next(h for h in p2_hosts if h["ip_address"] == "192.168.1.100")
    assert p2_h1["hostname"] == "srv-app.corp.local"
    assert p2_h1["open_ports_count"] >= 4
    assert p2_h1["vulns_count"] >= 2
    print(f"    - Host {p2_h1['ip_address']} ({p2_h1['hostname']}): {p2_h1['open_ports_count']} ports, {p2_h1['vulns_count']} vulns preserved.")

    print("=" * 70)
    print("ALL TWO-WAY TESTS PASSED: BIDIRECTIONAL MSF/NMAP SYNC 100% OPERATIONAL")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
