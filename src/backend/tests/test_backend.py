import asyncio
import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
from fastapi import HTTPException

from analysis import VulnerabilityAnalyzer
from database import VulnerabilityDB
from pipeline import PipelineConfig, run_scan
from pipeline.engines.nmap import run_nmap_scan
from pipeline.engines.repository import run_gitleaks_scan, run_trivy_scan
from pipeline.engines.zap import run_zap_baseline
from pipeline.orchestrator import STAGE_ORDER, run_pipeline
from routes.scans import PipelineRequest, ScanRequest, pipeline_endpoint, scan_endpoint
from routes.vulnerabilities import get_recommendations, get_vulnerabilities
from scanner import run_scan as legacy_run_scan
from validation import TargetValidationError, validate_scan_type, validate_target
from vulnerability_api import OnlineVulnerabilityService


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = PipelineConfig(
            allowed_targets=("127.0.0.1", "localhost"),
            report_dir=self.temp_dir.name,
            project_root=self.temp_dir.name,
            nmap_command=("nmap",),
            zap_api_url="http://127.0.0.1:8080",
            gitleaks_command=("gitleaks", "dir"),
            trivy_command=("trivy",),
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_legacy_scanner_import_delegates_to_pipeline(self):
        self.assertIs(legacy_run_scan, run_scan)

    def test_parses_basic_nmap_results(self):
        nmap_xml = (
            '<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https" product="Test Server" version="1.2"/>'
            '</port></ports></host></nmaprun>'
        )
        with patch(
            "pipeline.engines.nmap.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=nmap_xml, stderr=""),
        ) as subprocess_run:
            result = run_scan("127.0.0.1", "basic", config=self.config)

        self.assertEqual(result["open_ports"], [{
            "port": 443,
            "state": "open",
            "service": "https",
            "version": "1.2",
            "product": "Test Server",
        }])
        self.assertEqual(result["pipeline"]["stages"]["nmap"]["status"], "completed")
        report_path = result["pipeline"]["report_paths"]["nmap"]
        with open(report_path, encoding="utf-8") as report_file:
            report = json.load(report_file)
        self.assertEqual(report["findings"]["open_ports"], result["open_ports"])
        command = subprocess_run.call_args.args[0]
        self.assertIn("--top-ports", command)
        self.assertIn("100", command)
        self.assertFalse(subprocess_run.call_args.kwargs["shell"])

    def test_returns_clear_error_when_nmap_is_unavailable(self):
        with patch(
            "pipeline.engines.nmap.subprocess.run",
            side_effect=FileNotFoundError("Nmap missing"),
        ):
            result = run_scan("127.0.0.1", "basic", config=self.config)

        self.assertEqual(result["error"], "Nmap CLI was not found.")
        self.assertEqual(result["pipeline"]["stages"]["nmap"]["status"], "failed")

    def test_version_detection_uses_nmap_service_detection_flag(self):
        nmap_xml = "<nmaprun><host><ports/></host></nmaprun>"
        with patch(
            "pipeline.engines.nmap.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=nmap_xml, stderr=""),
        ) as subprocess_run:
            run_nmap_scan("127.0.0.1", "version detection", self.config)

        self.assertIn("-sV", subprocess_run.call_args.args[0])

    def test_zap_passive_api_scan_normalizes_alerts_and_writes_json_report(self):
        alert = {
            "name": "Missing header",
            "riskcode": "2",
            "confidence": "Medium",
            "desc": "Header was not present.",
            "solution": "Add the header.",
            "instances": [{
                "uri": "http://127.0.0.1/",
                "param": "",
                "attack": "",
                "evidence": "",
            }],
        }

        def fake_zap_get(_config, endpoint, params=None, timeout=5):
            if endpoint == "core/view/version":
                return {"version": "2.16.1"}
            if endpoint == "spider/action/scan":
                self.assertEqual(params["url"], "http://127.0.0.1")
                self.assertEqual(params["maxChildren"], 2)
                self.assertEqual(params["recurse"], "false")
                self.assertEqual(params["maxDepth"], 1)
                return {"scan": "1"}
            if endpoint == "spider/view/status":
                return {"status": "100"}
            if endpoint == "pscan/view/recordsToScan":
                return {"recordsToScan": "0"}
            if endpoint == "core/view/alerts":
                return {"alerts": [alert]}
            self.fail(f"Unexpected ZAP endpoint: {endpoint}")

        with patch("pipeline.engines.zap._zap_get", side_effect=fake_zap_get) as zap_get:
            result = run_zap_baseline("http://127.0.0.1", self.config)

        self.assertEqual(result["status"], "vulnerabilities_found")
        self.assertEqual(result["findings"][0]["severity"], "medium")
        self.assertEqual(result["findings"][0]["name"], "Missing header")
        with open(result["report_path"], encoding="utf-8") as report_file:
            standardized_report = json.load(report_file)
        self.assertEqual(standardized_report["scan_mode"], "passive")
        self.assertEqual(standardized_report["findings"], result["findings"])
        endpoints = [call.args[1] for call in zap_get.call_args_list]
        self.assertNotIn("ascan/action/scan", endpoints)

    def test_zap_unavailable_api_returns_a_failure_result(self):
        with patch(
            "pipeline.engines.zap._zap_get",
            side_effect=requests.ConnectionError("ZAP is not running"),
        ):
            result = run_zap_baseline("http://127.0.0.1", self.config)

        self.assertEqual(result["status"], "failed")
        self.assertIn("ZAP API", result["error"])

    def test_gitleaks_uses_requested_cli_options_and_redacts_secrets(self):
        raw_findings = [{
            "RuleID": "generic-api-key",
            "File": "src/sample.py",
            "Secret": "very-secret-value",
            "Match": "API_KEY=very-secret-value",
        }]

        def fake_gitleaks(command, **kwargs):
            self.assertEqual(kwargs["cwd"], self.config.project_root)
            report_path = next(
                argument.split("=", 1)[1]
                for argument in command
                if argument.startswith("--report-path=")
            )
            with open(report_path, "w", encoding="utf-8") as report_file:
                json.dump(raw_findings, report_file)
            return SimpleNamespace(returncode=1, stderr="secrets found")

        with patch(
            "pipeline.engines.repository.subprocess.run",
            side_effect=fake_gitleaks,
        ) as subprocess_run:
            result = run_gitleaks_scan(self.config)

        command = subprocess_run.call_args.args[0]
        self.assertIn("dir", command)
        self.assertIn("./src", command)
        self.assertEqual(result["status"], "vulnerabilities_found")
        self.assertEqual(result["finding_count"], 1)
        self.assertNotIn("Secret", result["findings"][0])
        self.assertNotIn("Match", result["findings"][0])
        with open(result["report_path"], encoding="utf-8") as report_file:
            self.assertEqual(json.load(report_file), raw_findings)

    def test_trivy_generates_json_report_and_counts_vulnerabilities(self):
        trivy_report = {
            "Results": [{
                "Target": "package-lock.json",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2025-0001",
                    "PkgName": "example",
                    "Severity": "HIGH",
                }],
            }]
        }

        def fake_trivy(command, **kwargs):
            self.assertEqual(kwargs["cwd"], self.config.project_root)
            report_path = command[command.index("--output") + 1]
            with open(report_path, "w", encoding="utf-8") as report_file:
                json.dump(trivy_report, report_file)
            return SimpleNamespace(returncode=0, stderr="")

        with patch(
            "pipeline.engines.repository.subprocess.run",
            side_effect=fake_trivy,
        ) as subprocess_run:
            result = run_trivy_scan(self.config)

        command = subprocess_run.call_args.args[0]
        self.assertEqual(command[1:4], ["fs", "./src", "--format"])
        self.assertEqual(result["status"], "vulnerabilities_found")
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"], trivy_report)

    def test_missing_repository_scanner_isolated_as_failed_stage(self):
        with patch(
            "pipeline.engines.repository.subprocess.run",
            side_effect=FileNotFoundError("scanner missing"),
        ):
            result = run_gitleaks_scan(self.config)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["report_path"], None)


class PipelineOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_managed_mode_skips_nmap_and_runs_zap(self):
        config = PipelineConfig(
            environment_type="managed",
            allowed_targets=("127.0.0.1",),
            report_dir=self.temp_dir.name,
            gitleaks_enabled=False,
            trivy_enabled=False,
        )
        with patch("pipeline.orchestrator.run_nmap_scan") as nmap_scan, patch(
            "pipeline.orchestrator.run_zap_baseline",
            return_value={
                "status": "completed",
                "report_path": "zap-report.json",
                "findings": [],
            },
        ) as zap_scan:
            result = run_pipeline(
                "http://127.0.0.1",
                config=config,
                requested_stages=("nmap", "zap"),
            )

        nmap_scan.assert_not_called()
        zap_scan.assert_called_once()
        self.assertEqual(result["stages"]["nmap"]["status"], "skipped")
        self.assertEqual(result["stages"]["zap"]["status"], "completed")
        self.assertEqual(result["report_paths"]["zap"], "zap-report.json")
        self.assertEqual(result["status"], "passed")

    def test_scanner_failure_does_not_prevent_later_engine(self):
        config = PipelineConfig(
            allowed_targets=("127.0.0.1",),
            report_dir=self.temp_dir.name,
            gitleaks_enabled=False,
            trivy_enabled=False,
        )
        execution_order = []

        def failed_nmap(target, scan_type, engine_config, timeout_seconds=None):
            self.assertEqual(target, "127.0.0.1")
            self.assertEqual(scan_type, "version detection")
            self.assertEqual(engine_config.allowed_targets, config.allowed_targets)
            self.assertIsNone(timeout_seconds)
            execution_order.append("nmap")
            return {
                "status": "failed",
                "report_path": None,
                "error": "Nmap unavailable.",
            }

        def successful_zap(target, engine_config, timeout_seconds=None):
            self.assertEqual(target, "http://127.0.0.1")
            self.assertEqual(engine_config.allowed_targets, config.allowed_targets)
            self.assertIsNone(timeout_seconds)
            execution_order.append("zap")
            return {
                "status": "completed",
                "report_path": "zap-report.json",
                "findings": [],
            }

        with patch("pipeline.orchestrator.run_nmap_scan", side_effect=failed_nmap), patch(
            "pipeline.orchestrator.run_zap_baseline", side_effect=successful_zap
        ):
            result = run_pipeline(
                "http://127.0.0.1",
                config=config,
                requested_stages=("nmap", "zap"),
            )

        self.assertEqual(execution_order, ["nmap", "zap"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["stages"]["nmap"]["status"], "failed")
        self.assertEqual(result["stages"]["zap"]["status"], "completed")

    def test_pipeline_scan_runs_only_live_site_engines(self):
        config = PipelineConfig(
            allowed_targets=("127.0.0.1",),
            report_dir=self.temp_dir.name,
        )
        execution_order = []

        def fake_nmap(target, scan_type, received_config, timeout_seconds=None):
            self.assertEqual(target, "127.0.0.1")
            self.assertEqual(scan_type, "version detection")
            self.assertEqual(received_config.allowed_targets, config.allowed_targets)
            self.assertIsNone(timeout_seconds)
            execution_order.append("nmap")
            return {
                "status": "completed",
                "report_path": "nmap-report.json",
                "findings": {"open_ports": [{"port": 80, "state": "open"}]},
            }

        def fake_zap(target, received_config, timeout_seconds=None):
            self.assertEqual(target, "https://127.0.0.1/app")
            self.assertEqual(received_config.allowed_targets, config.allowed_targets)
            self.assertIsNone(timeout_seconds)
            execution_order.append("zap")
            return {
                "status": "completed",
                "report_path": "zap-report.json",
                "findings": [{"name": "Missing header"}],
            }

        execution_order = []

        with patch("pipeline.orchestrator.run_gitleaks_scan") as gitleaks_scan, patch(
            "pipeline.orchestrator.run_trivy_scan"
        ) as trivy_scan, patch("pipeline.orchestrator.run_nmap_scan", side_effect=fake_nmap), patch(
            "pipeline.orchestrator.run_zap_baseline", side_effect=fake_zap
        ):
            result = run_scan(
                "https://127.0.0.1/app",
                "pipeline",
                config=config,
            )

        self.assertEqual(execution_order, ["nmap", "zap"])
        gitleaks_scan.assert_not_called()
        trivy_scan.assert_not_called()
        self.assertEqual(result["open_ports"][0]["port"], 80)
        self.assertEqual(result["web_scan"]["findings"][0]["name"], "Missing header")
        self.assertEqual(result["pipeline"]["status"], "passed")
        self.assertEqual(
            result["pipeline"]["report_paths"],
            {
                "gitleaks": None,
                "trivy": None,
                "nmap": "nmap-report.json",
                "zap": "zap-report.json",
            },
        )
        self.assertEqual(
            result["pipeline"]["stages"]["gitleaks"]["status"],
            "not_requested",
        )

    def test_disallowed_target_runs_local_scanners_but_blocks_network_stages(self):
        config = PipelineConfig(
            allowed_targets=("127.0.0.1",),
            report_dir=self.temp_dir.name,
        )
        with patch(
            "pipeline.orchestrator.run_gitleaks_scan",
            return_value={"status": "passed", "report_path": None, "findings": []},
        ), patch(
            "pipeline.orchestrator.run_trivy_scan",
            return_value={"status": "passed", "report_path": None, "findings": []},
        ), patch("pipeline.orchestrator.run_nmap_scan") as nmap_scan, patch(
            "pipeline.orchestrator.run_zap_baseline"
        ) as zap_scan:
            result = run_pipeline(
                "https://not-allowlisted.example",
                config=config,
            )

        nmap_scan.assert_not_called()
        zap_scan.assert_not_called()
        self.assertEqual(result["stages"]["gitleaks"]["status"], "passed")
        self.assertEqual(result["stages"]["trivy"]["status"], "passed")
        self.assertEqual(result["stages"]["nmap"]["status"], "blocked")
        self.assertEqual(result["stages"]["zap"]["status"], "blocked")

    def test_managed_mode_can_disable_individual_scanners(self):
        config = PipelineConfig(
            environment_type="managed",
            nmap_enabled=False,
            zap_enabled=False,
            gitleaks_enabled=False,
            trivy_enabled=False,
            allowed_targets=("127.0.0.1",),
            report_dir=self.temp_dir.name,
        )
        result = run_pipeline(
            "127.0.0.1",
            config=config,
            requested_stages=("nmap", "zap"),
        )

        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["stages"]["nmap"]["status"], "skipped")
        self.assertIn("managed", result["stages"]["nmap"]["reason"])
        self.assertEqual(result["stages"]["zap"]["status"], "skipped")
        self.assertIn("disabled", result["stages"]["zap"]["reason"])

    def test_pipeline_runs_stages_in_required_order_and_isolates_failures(self):
        config = PipelineConfig(
            allowed_targets=("127.0.0.1",),
            report_dir=self.temp_dir.name,
        )
        order = []

        def stage(name, status="passed"):
            def execute(*_args, **_kwargs):
                order.append(name)
                return {"status": status, "report_path": None, "findings": []}
            return execute

        with patch(
            "pipeline.orchestrator.run_gitleaks_scan",
            side_effect=RuntimeError("Gitleaks crashed"),
        ), patch(
            "pipeline.orchestrator.run_trivy_scan",
            side_effect=stage("trivy"),
        ), patch(
            "pipeline.orchestrator.run_nmap_scan",
            side_effect=stage("nmap"),
        ), patch(
            "pipeline.orchestrator.run_zap_baseline",
            side_effect=stage("zap"),
        ):
            result = run_pipeline("http://127.0.0.1", config=config)

        self.assertEqual(order, ["trivy", "nmap", "zap"])
        self.assertEqual(result["stages"]["gitleaks"]["status"], "failed")
        self.assertEqual(result["status"], "partial")


class TargetValidationTests(unittest.TestCase):
    def test_accepts_valid_ip_addresses_and_hostnames(self):
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_target("::1"), "::1")
        self.assertEqual(validate_target("localhost"), "localhost")
        self.assertEqual(validate_target("scanme.nmap.org"), "scanme.nmap.org")
        self.assertEqual(validate_target("192.0.2.1"), "192.0.2.1")
        self.assertEqual(validate_target("2001:db8::1"), "2001:db8::1")

    def test_accepts_valid_web_urls_and_hosts(self):
        self.assertEqual(
            validate_target("https://example.com:8443/a", "web scan"),
            "https://example.com:8443/a",
        )
        self.assertEqual(validate_target("127.0.0.1:8000", "web scan"),
                         "http://127.0.0.1:8000")
        self.assertEqual(validate_target("example.com", "web scan"), "http://example.com")
        self.assertEqual(
            validate_target("https://127.0.0.1/app", "pipeline"),
            "https://127.0.0.1/app",
        )

    def test_rejects_malformed_targets(self):
        for target in (
            "", "not a host", "bad..example.com", "256.1.1.1", "example.com:abc",
            "http://user@example.com/", "ftp://example.com", "https://bad host/",
        ):
            with self.subTest(target=target):
                with self.assertRaises(TargetValidationError):
                    validate_target(target, "web scan" if "://" in target or "/" in target else "basic")
        with self.assertRaises(TargetValidationError):
            validate_target("https://example.com/path", "basic")

    def test_rejects_unsupported_scan_types(self):
        with self.assertRaises(ValueError):
            validate_scan_type("aggressive")


class PipelineConfigTests(unittest.TestCase):
    def test_default_allowlist_includes_only_the_user_vercel_host(self):
        with patch.dict(os.environ, {}, clear=True):
            config = PipelineConfig.from_env()

        self.assertTrue(config.allows_target("https://pushups-omega.vercel.app/"))
        self.assertFalse(config.allows_target("https://another-project.vercel.app/"))

    def test_prefers_project_local_scanner_executables_when_present(self):
        with tempfile.TemporaryDirectory() as project_root:
            bin_dir = os.path.join(project_root, "bin")
            os.makedirs(bin_dir)
            executable_suffix = ".exe" if os.name == "nt" else ""
            gitleaks_path = os.path.join(bin_dir, f"gitleaks{executable_suffix}")
            trivy_path = os.path.join(bin_dir, f"trivy{executable_suffix}")
            for path in (gitleaks_path, trivy_path):
                with open(path, "w", encoding="utf-8") as executable:
                    executable.write("")

            with patch.dict(
                os.environ,
                {"SCAN_PROJECT_ROOT": project_root},
                clear=True,
            ):
                config = PipelineConfig.from_env()

        self.assertEqual(config.gitleaks_command, (os.path.realpath(gitleaks_path), "dir"))
        self.assertEqual(config.trivy_command, (os.path.realpath(trivy_path),))

    def test_explicit_scanner_commands_override_project_local_executables(self):
        with tempfile.TemporaryDirectory() as project_root:
            bin_dir = os.path.join(project_root, "bin")
            os.makedirs(bin_dir)
            executable_suffix = ".exe" if os.name == "nt" else ""
            for name in ("gitleaks", "trivy"):
                with open(
                    os.path.join(bin_dir, f"{name}{executable_suffix}"),
                    "w",
                    encoding="utf-8",
                ) as executable:
                    executable.write("")

            with patch.dict(
                os.environ,
                {
                    "SCAN_PROJECT_ROOT": project_root,
                    "GITLEAKS_COMMAND": '["custom-gitleaks","dir"]',
                    "TRIVY_COMMAND": "custom-trivy",
                },
                clear=True,
            ):
                config = PipelineConfig.from_env()

        self.assertEqual(config.gitleaks_command, ("custom-gitleaks", "dir"))
        self.assertEqual(config.trivy_command, ("custom-trivy",))

    def test_reads_environment_type_toggles_and_target_allowlist(self):
        with tempfile.TemporaryDirectory() as report_dir, patch.dict(
            os.environ,
            {
                "SCAN_ENVIRONMENT": "managed",
                "NMAP_ENABLED": "false",
                "ZAP_ENABLED": "yes",
                "SCAN_ALLOWED_TARGETS": "example.com,127.0.0.1",
                "SCAN_REPORT_DIR": report_dir,
            },
            clear=True,
        ):
            config = PipelineConfig.from_env()

        self.assertEqual(config.environment_type, "managed")
        self.assertFalse(config.nmap_enabled)
        self.assertTrue(config.zap_enabled)
        self.assertTrue(config.allows_target("https://example.com/app"))
        self.assertFalse(config.allows_target("https://other.example"))
        self.assertFalse(config.allows_target("http://example.com.attacker.invalid"))

    def test_rejects_invalid_environment_or_boolean_configuration(self):
        with patch.dict(os.environ, {"SCAN_ENVIRONMENT": "cloudlike"}, clear=True):
            with self.assertRaises(ValueError):
                PipelineConfig.from_env()
        with patch.dict(
            os.environ,
            {"SCAN_ENVIRONMENT": "self_hosted", "NMAP_ENABLED": "sometimes"},
            clear=True,
        ):
            with self.assertRaises(ValueError):
                PipelineConfig.from_env()


class VulnerabilityClientTests(unittest.TestCase):
    def test_nvd_search_uses_product_keyword_when_version_is_missing(self):
        service = OnlineVulnerabilityService()
        service._request_json = Mock(return_value={
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-12345",
                    "descriptions": [],
                    "metrics": {},
                }
            }]
        })

        results = service.search_vulnerabilities_by_product_version(
            "http", "", deadline=10**12
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["confidence"], "possible")
        self.assertIn("version is missing", results[0]["match_reason"])
        self.assertEqual(
            service._request_json.call_args.kwargs["params"]["keywordSearch"],
            "http",
        )

    def test_incomplete_match_returns_no_generic_cve_when_lookup_times_out(self):
        service = OnlineVulnerabilityService()
        service._request_json = Mock(return_value=None)

        results = service.search_vulnerabilities_by_product_version(
            "http", "", deadline=10**12
        )

        self.assertEqual(results, [])
        self.assertEqual(service._request_json.call_count, 1)

    def test_partial_lookup_respects_remaining_deadline(self):
        service = OnlineVulnerabilityService()
        service.session.get = Mock(return_value=SimpleNamespace(status_code=429))

        service._request_json(
            service.nvd_base_url,
            deadline=time.monotonic() + 0.1,
        )

        timeout = service.session.get.call_args.kwargs["timeout"]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 0.11)

    def test_nvd_match_has_source_and_uncertain_confidence(self):
        client = OnlineVulnerabilityService()
        client._request_json = Mock(return_value={
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-12345",
                    "published": "2024-01-01",
                    "descriptions": [{"lang": "en", "value": "A test issue"}],
                    "metrics": {"cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.8}
                    }]},
                }
            }]
        })
        results = client._search_nvd("example product", "1.2.3")
        self.assertEqual(results[0]["source"], "NVD keyword search")
        self.assertEqual(results[0]["confidence"], "possible")
        self.assertEqual(results[0]["severity"], "critical")
        self.assertIn("unverified", results[0]["match_reason"])

    def test_rate_limit_timeout_and_invalid_json_fail_closed(self):
        service = OnlineVulnerabilityService()
        response = SimpleNamespace(status_code=429)
        service.session.get = Mock(return_value=response)
        self.assertIsNone(service._request_json("https://mock.invalid"))

        import requests
        service.session.get = Mock(side_effect=requests.Timeout())
        self.assertIsNone(service._request_json("https://mock.invalid"))

        response = Mock(status_code=200)
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError("invalid json")
        service.session.get = Mock(return_value=response)
        self.assertIsNone(service._request_json("https://mock.invalid"))

    def test_malformed_nvd_data_is_ignored(self):
        service = OnlineVulnerabilityService()
        service._request_json = Mock(return_value={"vulnerabilities": [
            None, {}, {"cve": {"id": "not-a-cve"}}
        ]})
        self.assertEqual(service._search_nvd("product", "1.0"), [])

    def test_missing_cvss_data_does_not_infer_low_severity(self):
        service = OnlineVulnerabilityService()
        service._request_json = Mock(return_value={"vulnerabilities": [{
            "cve": {"id": "CVE-2024-12345", "descriptions": []}
        }]})
        result = service._search_nvd("product", "1.0")[0]
        self.assertIsNone(result["cvss_score"])
        self.assertEqual(result["severity"], "unknown")


class RepositoryAndRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = VulnerabilityDB(os.path.join(self.temp_dir.name, "test.sqlite"))
        self.scan_calls = []

        def fake_scan(target, scan_type, time_limit):
            self.scan_calls.append((target, scan_type, time_limit))
            return {
                "target": target,
                "scan_time": "0.01",
                "open_ports": [{
                    "port": 443, "state": "open", "service": "https",
                    "product": "Test Server", "version": "1.2",
                }],
            }

        self.fake_client = SimpleNamespace(
            search_vulnerabilities_by_product_version=lambda product, version: [{
                "cve_id": "CVE-2024-12345", "severity": "high", "cvss_score": 8.0,
                "source": "Mock", "confidence": "possible",
            }],
            get_recommendations_for_product=lambda product, version: {"title": "Update"},
        )
        self.request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
            scan_engine=fake_scan,
            vulnerability_client=self.fake_client,
            database=self.db,
            pipeline_config=PipelineConfig(
                allowed_targets=("127.0.0.1", "localhost"),
                report_dir=self.temp_dir.name,
            ),
        )))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scan_route_analyzes_and_replaces_snapshot(self):
        request = ScanRequest(target="127.0.0.1", scanType="version detection")
        result = asyncio.run(scan_endpoint(request, self.request))
        self.assertEqual(result["vulnerability_analysis"]["risk_summary"]["high"], 1)
        self.assertEqual(result["open_ports"][0]["cves"][0]["source"], "Mock")

        # A later snapshot replaces port rows rather than leaving stale entries.
        self.db.save_scan_snapshot("127.0.0.1", "version detection", "0.02", [
            {"port": 8080, "state": "open", "service": "http"}
        ])
        import sqlite3
        conn = sqlite3.connect(self.db.db_path)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT port_number FROM scan_ports").fetchall(), [(8080,)])
        finally:
            conn.close()

    def test_pipeline_scan_type_is_available_through_api(self):
        scan_engine = self.request.app.state.scan_engine

        def fake_pipeline_scan(target, scan_type, time_limit):
            result = scan_engine(target, scan_type, time_limit)
            result["pipeline"] = {"status": "completed"}
            return result

        self.request.app.state.scan_engine = fake_pipeline_scan
        request = ScanRequest(
            target="https://127.0.0.1/app",
            scanType="pipeline",
        )
        result = asyncio.run(scan_endpoint(request, self.request))

        self.assertEqual(self.scan_calls[0][1], "pipeline")
        self.assertEqual(result["open_ports"][0]["port"], 443)
        self.assertEqual(result["pipeline"]["status"], "completed")

    def test_scan_does_not_match_seeded_database_cves_when_version_is_missing(self):
        self.request.app.state.scan_engine = lambda target, scan_type, time_limit: {
            "target": target,
            "scan_time": "0.01",
            "open_ports": [{
                "port": 443, "state": "open", "service": "https",
                "product": "Test Server", "version": "",
            }],
        }
        self.fake_client.search_vulnerabilities_by_product_version = Mock(return_value=[])
        self.fake_client.get_recommendations_for_product = Mock()

        result = asyncio.run(scan_endpoint(
            ScanRequest(target="127.0.0.1", scanType="version detection"),
            self.request,
        ))

        seeded_cves = self.db.get_all_vulnerabilities()
        self.assertTrue(any(
            item["port"] == 443 and item["cve_id"] == "CVE-2021-44228"
            for item in seeded_cves
        ))
        self.assertNotIn("cves", result["open_ports"][0])
        args, kwargs = self.fake_client.search_vulnerabilities_by_product_version.call_args
        self.assertEqual(args, ("Test Server", ""))
        self.assertIsNotNone(kwargs["deadline"])
        self.fake_client.get_recommendations_for_product.assert_not_called()

    def test_scan_uses_service_and_detected_version_when_product_is_missing(self):
        searched = []
        self.request.app.state.scan_engine = lambda target, scan_type, time_limit: {
            "target": target,
            "scan_time": "0.01",
            "open_ports": [{
                "port": 443, "state": "open", "service": "http",
                "product": "", "version": "2.4",
            }],
        }

        def find_vulnerabilities(product, version, deadline=None):
            searched.append((product, version, deadline))
            return [{
                "cve_id": "CVE-2024-12345",
                "severity": "high",
                "cvss_score": 8.0,
                "source": "Mock",
                "confidence": "possible",
            }]

        self.fake_client.search_vulnerabilities_by_product_version = find_vulnerabilities
        result = asyncio.run(scan_endpoint(
            ScanRequest(target="127.0.0.1", scanType="version detection"),
            self.request,
        ))

        self.assertEqual(searched[0][0:2], ("http", "2.4"))
        self.assertIsNotNone(searched[0][2])
        self.assertEqual(result["open_ports"][0]["cves"][0]["confidence"], "possible")

    def test_partial_lookups_share_one_five_second_deadline(self):
        client = SimpleNamespace(
            search_vulnerabilities_by_product_version=Mock(return_value=[]),
            get_recommendations_for_product=Mock(),
        )
        ports = [
            {"port": 80, "service": "http", "product": "Server", "version": ""},
            {"port": 443, "service": "https", "product": "Server", "version": ""},
        ]
        with patch("analysis.time.monotonic", side_effect=[100.0, 101.0, 106.0]):
            VulnerabilityAnalyzer(client).analyze_ports(ports)

        client.search_vulnerabilities_by_product_version.assert_called_once_with(
            "Server", "", deadline=105.0
        )

    def test_scan_route_rejects_invalid_target_before_scanner(self):
        request = ScanRequest(target="bad..example.com")
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(scan_endpoint(request, self.request))
        self.assertEqual(raised.exception.status_code, 422)
        self.assertEqual(self.scan_calls, [])

    def test_scan_route_rejects_target_outside_configured_allowlist(self):
        request = ScanRequest(target="scanme.nmap.org")
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(scan_endpoint(request, self.request))
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(self.scan_calls, [])

    def test_pipeline_route_returns_consolidated_result_for_selected_environment(self):
        expected = {
            "run_id": "test-run",
            "environment_type": "managed",
            "stages": {name: {"status": "passed"} for name in STAGE_ORDER},
            "report_paths": {name: None for name in STAGE_ORDER},
        }
        with patch("routes.scans.run_pipeline", return_value=expected) as runner:
            response = asyncio.run(
                pipeline_endpoint(
                    PipelineRequest(
                        target="https://not-in-network-allowlist.invalid",
                        environmentType="managed",
                    ),
                    self.request,
                )
            )

        self.assertEqual(response, {"pipeline": expected})
        runner.assert_called_once()
        self.assertEqual(
            runner.call_args.kwargs["environment_type"],
            "managed",
        )
        self.assertEqual(
            runner.call_args.kwargs["requested_stages"],
            ("zap",),
        )

    def test_pipeline_route_requests_nmap_only_when_explicitly_enabled(self):
        expected = {"stages": {}}
        with patch("routes.scans.run_pipeline", return_value=expected) as runner:
            asyncio.run(
                pipeline_endpoint(
                    PipelineRequest(
                        target="https://pushups-omega.vercel.app/",
                        environmentType="self_hosted",
                        nmapEnabled=True,
                    ),
                    self.request,
                )
            )

        self.assertEqual(
            runner.call_args.kwargs["requested_stages"],
            ("nmap", "zap"),
        )

    def test_existing_vulnerability_and_recommendation_routes_use_repository(self):
        self.assertTrue(get_vulnerabilities(self.request))
        self.assertEqual(
            get_recommendations(self.request, 80)[0]["title"],
            "Upgrade to HTTPS",
        )


if __name__ == "__main__":
    unittest.main()
