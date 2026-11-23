"""Unit and integration tests for ProjectHost models, XML network scan parsing,

two-way Metasploit/Nmap import and export roundtrip, and Project Hub hosts representation.
"""

import json
from unittest.mock import patch
from django.test import TestCase, Client
from django.urls import reverse

from .models import Project, ProjectHost, ProjectEndpoint, ScannerRun
from . import xml_exports
from .fusion_report import build_unified_fusion, generate_fusion_html_report
from .project_transfer import export_bundle, import_bundle


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -v -p- -sS -sV -A --script=vulners 192.168.1.50" version="7.94">
<host comment="target host">
  <status state="up" reason="syn-ack"/>
  <address addr="192.168.1.50" addrtype="ipv4"/>
  <address addr="00:11:22:33:44:55" addrtype="mac"/>
  <hostnames>
    <hostname name="victim.corp" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"/>
      <script id="vulners" output="&#xa;  cpe:/a:apache:http_server:2.4.41: &#xa;    CVE-2021-41773&#x9;7.5&#x9;https://vulners.com/cve/CVE-2021-41773&#x9;*EXPLOIT*&#xa;    CVE-2021-42013&#x9;7.5&#x9;https://vulners.com/cve/CVE-2021-42013">
        <table key="cpe:/a:apache:http_server:2.4.41">
          <table>
            <elem key="id">CVE-2021-41773</elem>
            <elem key="type">cve</elem>
            <elem key="cvss">7.5</elem>
            <elem key="is_exploit">true</elem>
          </table>
          <table>
            <elem key="id">CVE-2021-42013</elem>
            <elem key="type">cve</elem>
            <elem key="cvss">7.5</elem>
            <elem key="is_exploit">false</elem>
          </table>
        </table>
      </script>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu 4ubuntu0.5" method="probed"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4 (Ubuntu 20.04)" accuracy="96"/>
  </os>
</host>
</nmaprun>
"""

SAMPLE_METASPLOIT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<MetasploitV4>
  <generated time="2026-11-16 10:00:00 UTC" user="msf" project="Sample"/>
  <hosts>
    <host>
      <id>1</id>
      <created-at>2026-11-16 10:00:00 UTC</created-at>
      <address>10.0.0.15</address>
      <name>db-primary.corp</name>
      <state>alive</state>
      <os-name>Linux</os-name>
      <os-flavor>Debian 11</os-flavor>
      <mac>AA:BB:CC:DD:EE:FF</mac>
      <services>
        <service>
          <id>101</id>
          <port>5432</port>
          <proto>tcp</proto>
          <state>open</state>
          <name>postgresql</name>
          <info>PostgreSQL DB 14.2</info>
        </service>
        <service>
          <id>102</id>
          <port>443</port>
          <proto>tcp</proto>
          <state>open</state>
          <name>https</name>
          <info>nginx/1.18.0</info>
        </service>
      </services>
      <vulns>
        <vuln>
          <id>501</id>
          <service-id>101</service-id>
          <port>5432</port>
          <name>CVE-2022-1552</name>
          <info>PostgreSQL Autovacuum Privilege Escalation</info>
          <refs>
            <ref>CVE-2022-1552</ref>
            <ref>URL-https://nvd.nist.gov/vuln/detail/CVE-2022-1552</ref>
          </refs>
        </vuln>
      </vulns>
    </host>
  </hosts>
</MetasploitV4>
"""


class ProjectHostModelAndImportExportTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(
            name="Network Infrastructure Audit",
            target="https://victim.corp:80",
        )

    def test_parse_nmap_xml(self):
        parsed = xml_exports.parse_nmap_xml(SAMPLE_NMAP_XML)
        self.assertIn("192.168.1.50", parsed["hosts"])
        self.assertEqual(len(parsed["network_hosts"]), 1)
        net_host = parsed["network_hosts"][0]
        self.assertEqual(net_host["ip_address"], "192.168.1.50")
        self.assertEqual(net_host["hostname"], "victim.corp")
        self.assertEqual(net_host["os_name"], "Linux 5.4 (Ubuntu 20.04)")
        self.assertEqual(net_host["mac_address"], "00:11:22:33:44:55")

        services = net_host["services"]
        self.assertEqual(len(services), 2)
        http_svc = next(s for s in services if s["port"] == 80)
        self.assertEqual(http_svc["name"], "http")
        self.assertIn("Apache", http_svc["product"])
        self.assertEqual(http_svc["version"], "2.4.41")

        vulns = http_svc["vulns"]
        self.assertGreaterEqual(len(vulns), 2)
        cve_ids = [v["id"] for v in vulns]
        self.assertIn("CVE-2021-41773", cve_ids)
        cve1 = next(v for v in vulns if v["id"] == "CVE-2021-41773")
        self.assertEqual(cve1["cvss"], 7.5)
        self.assertEqual(cve1["severity"], "high")

    def test_parse_metasploit_xml(self):
        parsed = xml_exports.parse_metasploit_xml(SAMPLE_METASPLOIT_XML)
        self.assertIn("10.0.0.15", parsed["hosts"])
        self.assertEqual(len(parsed["network_hosts"]), 1)
        net_host = parsed["network_hosts"][0]
        self.assertEqual(net_host["ip_address"], "10.0.0.15")
        self.assertEqual(net_host["hostname"], "db-primary.corp")
        self.assertIn("Debian", net_host["os_name"])

        services = net_host["services"]
        self.assertEqual(len(services), 2)
        pg_svc = next(s for s in services if s["port"] == 5432)
        self.assertEqual(pg_svc["name"], "postgresql")
        self.assertEqual(pg_svc["info"], "PostgreSQL DB 14.2")

        self.assertGreaterEqual(len(pg_svc["vulns"]), 1)
        self.assertEqual(pg_svc["vulns"][0]["id"], "CVE-2022-1552")

    def test_save_project_network_hosts_upsert(self):
        parsed = xml_exports.parse_nmap_xml(SAMPLE_NMAP_XML)
        stats = xml_exports.save_project_network_hosts(self.project, parsed["network_hosts"])
        self.assertEqual(stats["created_hosts"], 1)
        self.assertEqual(stats["total_hosts"], 1)

        host = ProjectHost.objects.get(project=self.project, ip_address="192.168.1.50")
        self.assertEqual(host.hostname, "victim.corp")
        self.assertEqual(host.open_ports_count, 2)
        self.assertGreaterEqual(host.vulns_count, 2)

        # Re-import should update without duplicating
        stats2 = xml_exports.save_project_network_hosts(self.project, parsed["network_hosts"])
        self.assertEqual(stats2["created_hosts"], 0)
        self.assertEqual(stats2["updated_hosts"], 1)
        self.assertEqual(ProjectHost.objects.filter(project=self.project).count(), 1)

    def test_two_way_import_and_export_roundtrip(self):
        # 1. Імпорт Nmap XML через API у проєкт
        resp = self.client.post(
            f"/api/projects/{self.project.id}/import-metasploit-xml",
            data=json.dumps({"xml": SAMPLE_NMAP_XML}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        res_data = resp.json()
        self.assertTrue(res_data["ok"])
        self.assertGreaterEqual(res_data["hosts_count"], 1)
        self.assertGreaterEqual(res_data["total_services"], 2)

        # 2. Перевірка даних через project_hub API
        hub_resp = self.client.get(f"/api/projects/{self.project.id}/hub")
        self.assertEqual(hub_resp.status_code, 200)
        hub_data = hub_resp.json()
        self.assertIn("hosts", hub_data)
        self.assertEqual(len(hub_data["hosts"]), 1)
        h = hub_data["hosts"][0]
        self.assertEqual(h["ip_address"], "192.168.1.50")
        self.assertEqual(h["hostname"], "victim.corp")
        self.assertEqual(h["open_ports_count"], 2)
        self.assertGreaterEqual(h["vulns_count"], 2)

        # 3. Експорт проєкту назад у Metasploit XML
        export_resp = self.client.get(f"/api/projects/{self.project.id}/export?format=metasploit-xml")
        self.assertEqual(export_resp.status_code, 200)
        self.assertEqual(export_resp["Content-Type"], "application/xml; charset=utf-8")
        xml_exported = export_resp.content.decode("utf-8")

        self.assertIn("<MetasploitV4>", xml_exported)
        self.assertIn("192.168.1.50", xml_exported)
        self.assertIn("victim.corp", xml_exported)
        self.assertIn("<port>80</port>", xml_exported)
        self.assertIn("<port>22</port>", xml_exported)
        self.assertIn("Apache httpd 2.4.41", xml_exported)
        self.assertIn("CVE-2021-41773", xml_exported)

        # 4. Імпорт згенерованого Metasploit XML у НОВИЙ проєкт (зворотній цикл)
        new_project = Project.objects.create(name="Re-imported from MSF XML")
        resp_reimport = self.client.post(
            f"/api/projects/{new_project.id}/import-metasploit-xml",
            data=json.dumps({"xml": xml_exported}),
            content_type="application/json",
        )
        self.assertEqual(resp_reimport.status_code, 200)
        reimport_data = resp_reimport.json()
        self.assertTrue(reimport_data["ok"])

        # Перевірка що в новому проєкті є всі хости та порти
        reimported_host = ProjectHost.objects.get(project=new_project, ip_address="192.168.1.50")
        self.assertEqual(reimported_host.hostname, "victim.corp")
        self.assertEqual(reimported_host.open_ports_count, 2)
        self.assertGreaterEqual(reimported_host.vulns_count, 1)

    def test_project_hosts_crud_api(self):
        # GET hosts list (empty)
        resp = self.client.get(f"/api/projects/{self.project.id}/hosts")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["count"], 0)

        # POST create host
        create_resp = self.client.post(
            f"/api/projects/{self.project.id}/hosts",
            data=json.dumps({
                "ip_address": "172.16.0.10",
                "hostname": "api.internal",
                "os_name": "FreeBSD 13",
                "services": [
                    {"port": 8080, "proto": "tcp", "state": "open", "name": "http-proxy", "version": "Squid 4.13"}
                ],
            }),
            content_type="application/json",
        )
        self.assertEqual(create_resp.status_code, 200)
        created_host = create_resp.json()["host"]
        host_id = created_host["id"]
        self.assertEqual(created_host["ip_address"], "172.16.0.10")

        # GET detail
        detail_resp = self.client.get(f"/api/projects/{self.project.id}/hosts/{host_id}")
        self.assertEqual(detail_resp.status_code, 200)
        self.assertEqual(detail_resp.json()["host"]["hostname"], "api.internal")

        # DELETE host
        del_resp = self.client.delete(f"/api/projects/{self.project.id}/hosts/{host_id}")
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(ProjectHost.objects.filter(project=self.project).count(), 0)

    def test_fusion_report_includes_hosts_and_services(self):
        # Створюємо хост із портом, версією сервісу та CVE
        ProjectHost.objects.create(
            project=self.project,
            ip_address="192.168.1.100",
            hostname="web.victim.corp",
            os_name="Ubuntu Linux 20.04",
            os_accuracy=98,
            services=[
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "name": "http",
                    "product": "Apache httpd",
                    "version": "2.4.41",
                    "vulns": [
                        {
                            "cve": "CVE-2021-41773",
                            "name": "Apache Path Traversal",
                            "cvss": 7.5,
                            "severity": "HIGH",
                        }
                    ],
                }
            ],
        )

        fusion_data = build_unified_fusion(self.project)
        self.assertIn("network_hosts", fusion_data)
        self.assertEqual(len(fusion_data["network_hosts"]), 1)
        self.assertEqual(fusion_data["network_hosts"][0]["ip_address"], "192.168.1.100")

        # Перевірка що вразливість з порту потрапила у зведений реєстр знахідок
        finding_cves = [cve for f in fusion_data["unified_findings"] for cve in f.get("cve", [])]
        self.assertIn("CVE-2021-41773", finding_cves)

        # Генерація HTML звіту
        html_uk = generate_fusion_html_report(fusion_data, lang="uk")
        self.assertIn("192.168.1.100", html_uk)
        self.assertIn("web.victim.corp", html_uk)
        self.assertIn("Apache httpd 2.4.41", html_uk)
        self.assertIn("CVE-2021-41773", html_uk)
        self.assertIn("Мережева інфраструктура", html_uk)

        # Перевірка через API endpoint
        api_resp = self.client.get(f"/api/projects/{self.project.id}/fusion-report?format=html")
        self.assertEqual(api_resp.status_code, 200)
        self.assertIn("192.168.1.100", api_resp.content.decode("utf-8"))

    def test_project_bundle_export_import_hosts(self):
        # Створюємо 2 хости в проєкті
        ProjectHost.objects.create(
            project=self.project,
            ip_address="10.10.10.20",
            hostname="app.corp",
            os_name="Debian 11",
            services=[
                {"port": 443, "protocol": "tcp", "state": "open", "name": "https", "product": "nginx", "version": "1.18.0"}
            ],
            vulns=[{"cve": "CVE-2021-23017", "name": "nginx 1-byte memory overwrite", "severity": "HIGH"}],
        )
        ProjectHost.objects.create(
            project=self.project,
            ip_address="10.10.10.21",
            hostname="db.corp",
            os_name="FreeBSD 13",
            services=[
                {"port": 5432, "protocol": "tcp", "state": "open", "name": "postgresql", "product": "PostgreSQL", "version": "14.2"}
            ],
        )

        # Експорт бандла проєкту
        bundle = export_bundle(self.project)
        self.assertIn("hosts", bundle)
        self.assertEqual(len(bundle["hosts"]), 2)
        self.assertEqual(bundle["counts"]["hosts"], 2)

        # Імпорт бандла як нового проєкту
        new_project, report = import_bundle(bundle)
        self.assertNotEqual(new_project.id, self.project.id)
        self.assertEqual(report.get("hosts"), 2)

        # Перевірка що хости створені в новому проєкті
        imported_hosts = list(ProjectHost.objects.filter(project=new_project).order_by("ip_address"))
        self.assertEqual(len(imported_hosts), 2)
        self.assertEqual(imported_hosts[0].ip_address, "10.10.10.20")
        self.assertEqual(imported_hosts[0].hostname, "app.corp")
        self.assertEqual(len(imported_hosts[0].services), 1)
        self.assertEqual(imported_hosts[0].services[0]["name"], "https")
        self.assertEqual(imported_hosts[1].ip_address, "10.10.10.21")
        self.assertEqual(imported_hosts[1].services[0]["port"], 5432)
