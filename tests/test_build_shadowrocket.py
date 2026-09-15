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
    render_config,
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
                "DOMAIN-SUFFIX,qwen.ai,Direct",
                "DOMAIN-SUFFIX,qwenlm.ai,Direct",
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
            "dns": {
                "nameserver": [
                    "https://cloudflare-dns.com/dns-query#Proxy",
                    "https://dns.google/dns-query#Proxy",
                ],
                "proxy-server-nameserver": [
                    "114.114.114.114#DIRECT",
                    "tls://223.5.5.5#DIRECT",
                    "https://doh.pub/dns-query#DIRECT",
                ]
            },
            "hosts": {
                "doh.pub": ["1.12.12.12", "120.53.53.53"],
                "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"],
                "dns.google": ["8.8.8.8", "8.8.4.4"],
            },
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
        self.assertFalse(any("qwen" in rule.lower() for rule in rules))

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
        model, _ = self.fixture()
        config = render_config(
            ["Proxy = select,DIRECT", "Final = select,Proxy,DIRECT"],
            ["FINAL,Final"],
            model,
        )
        validate_config(config)
        self.assertIn(
            "dns-server = https://cloudflare-dns.com/dns-query#proxy=Proxy,"
            "https://dns.google/dns-query#proxy=Proxy",
            config,
        )
        self.assertIn(
            "proxy-dns-server = 114.114.114.114,tls://223.5.5.5,https://doh.pub/dns-query",
            config,
        )
        self.assertIn("direct-dns-server = system", config)
        self.assertIn("dns-fallback-system = false", config)
        self.assertNotIn("fallback-dns-server = system", config)
        self.assertNotIn("dns-direct-system = true", config)
        self.assertIn("hijack-dns = *:53", config)
        self.assertNotIn("hijack-dns = 8.8.8.8:53,8.8.4.4:53", config)
        for hostname, target in {
            "11612bj3-b76c.aws-agent.biz": "06996bj6-79x5.apt-agent.com",
            "b76c5sh0-fde6.aws-agent.biz": "08233sh6-12d1.apt-agent.com",
            "fde63gz6-1y61.aws-agent.biz": "09571gz6-86k1.apt-agent.com",
        }.items():
            self.assertIn(f"{hostname} = {target}", config)


if __name__ == "__main__":
    unittest.main()
