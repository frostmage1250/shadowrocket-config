from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_shadowrocket import (  # noqa: E402
    BuildError,
    render_groups,
    render_rules,
    validate_config,
    validate_model,
)


class ShadowrocketBuilderTests(unittest.TestCase):
    def fixture(self):
        model = {
            "providers": {
                "domain": {"behavior": "domain"},
                "ip": {"behavior": "ipcidr"},
                "fakeip_filter": {"behavior": "domain"},
            },
            "rules": [
                "RULE-SET,domain,Proxy",
                "RULE-SET,ip,Direct,no-resolve",
                "MATCH,Final",
            ],
            "groups": [
                {"name": "Proxy", "proxies": ["订阅", "日本"]},
                {"name": "订阅", "proxies": ["__SUBSCRIPTION__"]},
                {"name": "Direct", "proxies": ["DIRECT", "IPv4优先", "IPv6优先"]},
                {"name": "日本", "proxies": ["__日本__"]},
                {"name": "其他节点", "proxies": ["__其他节点__"]},
                {"name": "低倍率节点", "proxies": ["__低倍率节点__"]},
                {"name": "Final", "proxies": ["Proxy", "Direct"]},
            ],
            "regions": [
                {"name": "香港", "source": "HK|香港", "flags": "i"},
                {"name": "日本", "source": "JP|日本", "flags": "i"},
            ],
            "rateRegions": [
                {"name": "低倍率节点", "source": "0\\.5x", "flags": "i"}
            ],
            "excludeFilter": {"source": "traffic|到期", "flags": "iu"},
            "options": {"过滤非地区节点": True, "过滤低倍率节点": False},
        }
        mapping = {"domain": "domain", "ip": "ip", "fakeip_filter": None}
        return model, mapping

    def test_rule_translation_preserves_order_and_no_resolve(self):
        model, mapping = self.fixture()
        validate_model(model, mapping)
        rules, used = render_rules(model, mapping)
        self.assertEqual(
            rules,
            [
                "DOMAIN-SET,https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/shadowrocket/domain.domain-set,Proxy",
                "RULE-SET,https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/shadowrocket/ip.list,Direct,no-resolve",
                "FINAL,Final",
            ],
        )
        self.assertEqual(len(used), 2)

    def test_groups_remove_mihomo_only_direct_pseudo_proxies(self):
        model, _ = self.fixture()
        groups, filters = render_groups(model)
        self.assertIn("Direct = select,DIRECT", groups)
        self.assertIn("日本", filters)
        self.assertIn("其他节点", filters)

    def test_referenced_nonportable_provider_fails(self):
        model, mapping = self.fixture()
        model["rules"][0] = "RULE-SET,fakeip_filter,Direct"
        with self.assertRaises(BuildError):
            render_rules(model, mapping)

    def test_config_policy_validation(self):
        valid = """[General]
ipv6 = true
[Proxy]
[Proxy Group]
Proxy = select,DIRECT
Final = select,Proxy,DIRECT
[Rule]
FINAL,Final
[Host]
dns.google = 8.8.8.8
"""
        validate_config(valid)


if __name__ == "__main__":
    unittest.main()
