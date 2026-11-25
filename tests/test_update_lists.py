from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import update_lists


class RuleGenerationTests(unittest.TestCase):
    def setUp(self):
        workspace = Path(self.enterContext(TemporaryDirectory()))
        self.sources = workspace / "sources"
        self.output = workspace / "output"
        for path in update_lists.DOMAIN_SOURCE_PATHS:
            self.write_source(path, "EXAMPLE.com.\nexample.com # duplicate\n")
        for path in update_lists.SUBNET_SOURCE_PATHS:
            contents = "192.0.2.0/24\n" if "/IPv4/" in path else "2001:0db8::/32\n"
            self.write_source(path, contents)

    def write_source(self, path, contents):
        target = self.sources / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")

    def run_update(self):
        messages = StringIO()
        with redirect_stdout(messages), redirect_stderr(messages):
            status = update_lists.main(
                ["--source-dir", str(self.sources), "--output-dir", str(self.output)]
            )
        return status, messages.getvalue()

    def outputs(self):
        return {path.name: path.read_bytes() for path in self.output.glob("*.list")}

    def test_generates_mixed_rules_and_deduplicates_sources(self):
        expected = (Path(__file__).parent / "fixtures" / "shadowrocket-mixed.list").read_bytes()
        status, messages = self.run_update()
        self.assertEqual(status, 0, messages)
        output = self.outputs()
        self.assertEqual(output["podkop.list"], expected)
        self.assertEqual(output["podkop.list"], output["domains.list"] + output["subnets.list"])
        self.assertEqual(self.run_update()[0], 0)
        self.assertEqual(self.outputs(), output)

    def test_keeps_shared_networks_from_service_sources(self):
        self.write_source("Subnets/IPv6/discord.lst", "2606:4700::/32\n")
        self.write_source("Subnets/IPv6/cloudflare.lst", "2400:cb00::/32\n")
        subnets = update_lists.build_lists(self.sources)["subnets.list"]
        self.assertIn("IP-CIDR6,2606:4700::/32,no-resolve\n", subnets)
        self.assertNotIn("2400:cb00::/32", subnets)

    def test_bad_source_preserves_previous_outputs(self):
        path = update_lists.SUBNET_SOURCE_PATHS[-1]
        self.assertEqual(self.run_update()[0], 0)
        previous = self.outputs()
        for invalid in ("# empty\n", "not a subnet\n", "192.0.2.0/24\n", "2001:db8::1/32\n", None):
            with self.subTest(invalid=invalid):
                if invalid is None:
                    (self.sources / path).unlink()
                else:
                    self.write_source(path, invalid)
                status, message = self.run_update()
                self.assertEqual(status, 1)
                self.assertIn(path, message)
                self.assertEqual(self.outputs(), previous)

    def test_restores_outputs_when_replacement_fails(self):
        self.assertEqual(self.run_update()[0], 0)
        previous = self.outputs()
        self.write_source(update_lists.DOMAIN_SOURCE_PATHS[0], "new.example\n")
        replace = Path.replace

        def fail_on_second_file(source, target):
            if source.name == "subnets.list":
                raise OSError("cannot replace subnets.list")
            return replace(source, target)

        with patch.object(Path, "replace", fail_on_second_file):
            status, message = self.run_update()
        self.assertEqual(status, 1)
        self.assertIn("cannot replace subnets.list", message)
        self.assertEqual(self.outputs(), previous)

    def test_download_rejects_truncated_response(self):
        path = update_lists.DOMAIN_SOURCE_PATHS[0]
        response = BytesIO(b"example.com\n")
        response.headers = {"Content-Length": "30"}
        with patch.object(update_lists, "urlopen", return_value=response) as download:
            with self.assertRaisesRegex(ValueError, "incomplete download"):
                update_lists.read_entries(path, None)
        download.assert_called_once_with(f"{update_lists.UPSTREAM_RAW_URL}/{path}", timeout=30)

    def test_normalizes_domains_and_rejects_malformed_entries(self):
        self.assertEqual(update_lists.normalize_domain(".ua"), "ua")
        self.assertEqual(update_lists.normalize_domain("ПРИМЕР.РФ"), "xn--e1afmkfd.xn--p1ai")
        for value in ("https://example.com", "*.example.com", "bad..example", "127.0.0.1", "xn--a.test"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    update_lists.normalize_domain(value)


if __name__ == "__main__":
    unittest.main()
