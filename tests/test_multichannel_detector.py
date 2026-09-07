import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from firmware.multichannel_detector import (  # noqa: E402
    WEB_FIXTURE,
    NET_FIXTURE,
    HOST_FIXTURE,
    correlate,
    default_fixtures,
    host_indicators,
    load_channel,
    main,
    net_indicators,
    web_indicators,
)


class LoadChannelTest(unittest.TestCase):
    def test_parses_jsonl_text(self):
        recs = load_channel('{"a": 1}\n# comment\n{"b": 2}\n')
        self.assertEqual(len(recs), 2)

    def test_parses_jsonl_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"x": 1}\n')
            p = f.name
        try:
            recs = load_channel(p)
            self.assertEqual(recs[0]["x"], 1)
        finally:
            os.unlink(p)


class IndicatorTest(unittest.TestCase):
    def test_web_flags_sensitive_paths(self):
        ind = web_indicators(load_channel("\n".join(json.dumps(r) for r in WEB_FIXTURE)))
        paths = [t for _, t, _ in ind]
        self.assertTrue(any("/admin/config.php.bak" in p for p in paths))

    def test_net_flags_hot_ports(self):
        ind = net_indicators(load_channel("\n".join(json.dumps(r) for r in NET_FIXTURE)))
        tags = [t for _, t, _ in ind]
        self.assertTrue(any(t == "net:tcp:3306" for t in tags))

    def test_host_flags_risky_events(self):
        ind = host_indicators(load_channel("\n".join(json.dumps(r) for r in HOST_FIXTURE)))
        tags = [t for _, t, _ in ind]
        self.assertIn("host:susp_kernel_module", tags)


class CorrelateTest(unittest.TestCase):
    def test_fixtures_produce_alerts(self):
        web, net, host = default_fixtures()
        ws, ns, hs = web_indicators(web), net_indicators(net), host_indicators(host)
        timeline, alerts = correlate((ws, ns, hs), window_sec=120, threshold=6)
        self.assertTrue(alerts)
        # There must be a cross-channel cluster for 198.51.100.7
        cross = [e for e in timeline if e["cross_channel"]]
        self.assertTrue(cross)
        srcs = {e["src"] for e in timeline}
        self.assertIn("198.51.100.7", srcs)

    def test_high_threshold_no_alerts(self):
        web, net, host = default_fixtures()
        ws, ns, hs = web_indicators(web), net_indicators(net), host_indicators(host)
        _, alerts = correlate((ws, ns, hs), window_sec=120, threshold=999)
        self.assertFalse(alerts)

    def test_merge_is_deterministic(self):
        web, net, host = default_fixtures()
        ws, ns, hs = web_indicators(web), net_indicators(net), host_indicators(host)
        t1, a1 = correlate((ws, ns, hs), window_sec=60, threshold=6)
        t2, a2 = correlate((ws, ns, hs), window_sec=60, threshold=6)
        self.assertEqual(t1, t2)
        self.assertEqual(a1, a2)


class CliTest(unittest.TestCase):
    def test_demo_writes_report(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "report.md")
            code = main(["--report", rp])
            self.assertEqual(code, 0)  # demo run exits 0 by contract
            text = open(rp).read()
            self.assertIn("MULTICHANNEL", text)
            self.assertIn("198.51.100.7", text)

    def test_strict_exits_one_when_alerts(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "report.md")
            code = main(["--report", rp, "--strict"])
            self.assertEqual(code, 1)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "report.json")
            code = main(["--report", rp, "--threshold", "999"])
            self.assertEqual(code, 0)
            data = json.loads(open(rp).read())
            self.assertEqual(data["alerts"], [])
            self.assertTrue(data["timeline"])

    def test_config_error_exits_two(self):
        with tempfile.TemporaryDirectory() as td:
            bd = os.path.join(td, "bad.json")
            open(bd, "w").write("{not json")
            code = main(["--config", bd, "--report", os.path.join(td, "r.md")])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()