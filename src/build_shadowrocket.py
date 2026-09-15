#!/usr/bin/env python3
"""Generate a Shadowrocket configuration from the published Mihomo script model."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "shadowrocket.conf"
DEFAULT_REPORT = ROOT / "reports" / "source.json"
RULE_BASE = (
    "https://raw.githubusercontent.com/frostmage1250/"
    "proxy-rules-converter/main/dist/shadowrocket"
)
SELF_URL = (
    "https://raw.githubusercontent.com/frostmage1250/"
    "shadowrocket-config/main/shadowrocket.conf"
)
BUILTIN_POLICIES = {"DIRECT", "PROXY", "REJECT"}
FLOWER_NODE_HOSTS = {
    "11612bj3-b76c.aws-agent.biz": "06996bj6-79x5.apt-agent.com",
    "b76c5sh0-fde6.aws-agent.biz": "08233sh6-12d1.apt-agent.com",
    "fde63gz6-1y61.aws-agent.biz": "09571gz6-86k1.apt-agent.com",
}


class BuildError(RuntimeError):
    pass


def regex_text(item: dict[str, str]) -> str:
    prefix = "(?i)" if "i" in item.get("flags", "") else ""
    return prefix + item["source"]


def negative_filter(patterns: list[str]) -> str:
    active = [pattern for pattern in patterns if pattern]
    return "^(?!.*(?:" + "|".join(active) + ")).*$"


def combined_filter(excluded: list[str], included: str) -> str:
    return (
        "^(?!.*(?:" + "|".join(excluded) + "))"
        "(?=.*(?:" + included + ")).*$"
    )


def provider_url(output_name: str, behavior: str) -> str:
    suffix = ".domain-set" if behavior == "domain" else ".list"
    return f"{RULE_BASE}/{output_name}{suffix}"


def render_groups(model: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    regions = {entry["name"]: regex_text(entry) for entry in model["regions"]}
    rates = {entry["name"]: regex_text(entry) for entry in model["rateRegions"]}
    hong_kong = regions.pop("香港")
    excluded = [hong_kong]
    if model["options"].get("过滤非地区节点"):
        excluded.append(regex_text(model["excludeFilter"]))
    if model["options"].get("过滤低倍率节点"):
        excluded.extend(rates.values())

    display_name = {"台湾省": "台湾"}
    group_filters: dict[str, str] = {"订阅": negative_filter(excluded)}
    for source_name, pattern in regions.items():
        group_filters[display_name.get(source_name, source_name)] = combined_filter(
            excluded, pattern
        )
    for name, pattern in rates.items():
        group_filters[name] = combined_filter(excluded, pattern)
    group_filters["其他节点"] = negative_filter(
        excluded + list(regions.values())
    )

    lines: list[str] = []
    for group in model["groups"]:
        name = group["name"]
        if name in group_filters:
            lines.append(
                f"{name} = select,policy-regex-filter={group_filters[name]}"
            )
            continue
        policies = [
            policy
            for policy in group.get("proxies", [])
            if not policy.startswith("__")
            and policy not in {"IPv4优先", "IPv6优先"}
        ]
        if not policies:
            policies = ["DIRECT"]
        lines.append(f"{name} = select," + ",".join(policies))
    return lines, group_filters


def render_rules(
    model: dict[str, Any], mapping: dict[str, str | None]
) -> tuple[list[str], list[dict[str, str]]]:
    providers = model["providers"]
    rendered: list[str] = []
    used: list[dict[str, str]] = []
    for rule in model["rules"]:
        parts = rule.split(",")
        if parts[0] == "MATCH" and len(parts) == 2:
            rendered.append(f"FINAL,{parts[1]}")
            continue
        if parts[0] != "RULE-SET" or len(parts) < 3:
            raise BuildError(f"Unsupported Mihomo rule: {rule}")
        provider_name = parts[1]
        provider = providers.get(provider_name)
        if provider is None:
            raise BuildError(f"Rule references missing provider: {provider_name}")
        output_name = mapping.get(provider_name)
        if output_name is None:
            raise BuildError(f"Referenced provider is not portable: {provider_name}")
        behavior = provider.get("behavior")
        if behavior not in {"domain", "ipcidr"}:
            raise BuildError(
                f"Unsupported provider behavior for {provider_name}: {behavior}"
            )
        no_resolve = parts[-1] == "no-resolve"
        policy = parts[-2] if no_resolve else parts[-1]
        url = provider_url(output_name, behavior)
        if behavior == "domain":
            rendered.append(f"DOMAIN-SET,{url},{policy}")
        else:
            suffix = ",no-resolve" if no_resolve else ""
            rendered.append(f"RULE-SET,{url},{policy}{suffix}")
        used.append(
            {
                "provider": provider_name,
                "output": output_name,
                "behavior": behavior,
                "url": url,
            }
        )
    return rendered, used


def validate_model(
    model: dict[str, Any], mapping: dict[str, str | None]
) -> None:
    providers = set(model["providers"])
    mapped = set(mapping)
    if providers != mapped:
        raise BuildError(
            "Mihomo/provider mapping mismatch: "
            f"missing={sorted(providers - mapped)}, "
            f"extra={sorted(mapped - providers)}"
        )
    if mapping.get("fakeip_filter") is not None:
        raise BuildError("fakeip_filter must remain explicitly non-portable")


def strip_mihomo_dns_policy(value: str) -> str:
    base, marker, policy = value.rpartition("#")
    if marker and policy.upper() == "DIRECT":
        return base
    return value


def render_node_dns(model: dict[str, Any]) -> str:
    values = model.get("dns", {}).get("proxy-server-nameserver")
    if not isinstance(values, list) or not values:
        raise BuildError("Mihomo proxy-server-nameserver is missing or empty")
    rendered = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise BuildError("Invalid Mihomo proxy-server-nameserver entry")
        dns = strip_mihomo_dns_policy(value.strip())
        if dns and dns not in rendered:
            rendered.append(dns)
    if not rendered:
        raise BuildError("Mihomo proxy-server-nameserver produced no Shadowrocket DNS entries")
    return ",".join(rendered)


def render_hosts(model: dict[str, Any]) -> list[str]:
    source = model.get("hosts")
    if not isinstance(source, dict):
        raise BuildError("Mihomo hosts configuration is missing")
    rendered: dict[str, str] = {}
    for hostname, value in source.items():
        candidates = value if isinstance(value, list) else [value]
        address = next(
            (item.strip() for item in candidates if isinstance(item, str) and item.strip()),
            None,
        )
        if address is not None:
            rendered[str(hostname)] = address
    rendered.update(FLOWER_NODE_HOSTS)
    return [f"{hostname} = {address}" for hostname, address in rendered.items()]


def render_config(
    group_lines: list[str], rule_lines: list[str], model: dict[str, Any]
) -> str:
    node_dns = render_node_dns(model)
    host_lines = render_hosts(model)
    lines = [
        "# Generated from frostmage1250/mihomo-script. Do not edit by hand.",
        "[General]",
        f"update-url = {SELF_URL}",
        "ipv6 = true",
        "dns-server = https://cloudflare-dns.com/dns-query#proxy=Proxy,https://dns.google/dns-query#proxy=Proxy",
        "direct-dns-server = system",
        "dns-fallback-system = false",
        "dns-direct-fallback-proxy = false",
        f"proxy-dns-server = {node_dns}",
        "private-ip-answer = true",
        "use-local-host-item-for-proxy = true",
        "hijack-dns = 8.8.8.8:53,8.8.4.4:53",
        "block-quic = always-allow",
        "",
        "[Proxy]",
        "# Nodes are managed by Shadowrocket subscriptions; credentials are never published here.",
        "",
        "[Proxy Group]",
        *group_lines,
        "",
        "[Rule]",
        *rule_lines,
        "",
        "[Host]",
        *host_lines,
        "",
    ]
    return "\n".join(lines)


def validate_config(config: str) -> None:
    sections = [
        line for line in config.splitlines()
        if line.startswith("[") and line.endswith("]")
    ]
    if sections != ["[General]", "[Proxy]", "[Proxy Group]", "[Rule]", "[Host]"]:
        raise BuildError(f"Unexpected section order: {sections}")
    groups = {
        line.split("=", 1)[0].strip()
        for line in config.split("[Proxy Group]", 1)[1].split("[Rule]", 1)[0].splitlines()
        if "=" in line
    }
    for line in config.split("[Rule]", 1)[1].split("[Host]", 1)[0].splitlines():
        if not line or line.startswith("#"):
            continue
        policy = line.split(",")[-2] if line.endswith(",no-resolve") else line.split(",")[-1]
        if policy not in groups | BUILTIN_POLICIES:
            raise BuildError(f"Rule references undefined policy {policy}: {line}")
    required = {
        "direct-dns-server = system",
        "dns-fallback-system = false",
        "dns-direct-fallback-proxy = false",
        "use-local-host-item-for-proxy = true",
        *(f"{hostname} = {target}" for hostname, target in FLOWER_NODE_HOSTS.items()),
    }
    config_lines = set(config.splitlines())
    missing = sorted(required - config_lines)
    if missing:
        raise BuildError(f"Generated configuration is missing required DNS/Host lines: {missing}")
    forbidden = {"fallback-dns-server = system", "dns-direct-system = true"}
    present_forbidden = sorted(forbidden & config_lines)
    if present_forbidden:
        raise BuildError(f"Generated configuration enables forbidden DNS fallback: {present_forbidden}")
    if sum(line.startswith("proxy-dns-server = ") for line in config.splitlines()) != 1:
        raise BuildError("Generated configuration must contain exactly one proxy-dns-server line")


def validate_remote(used: list[dict[str, str]]) -> None:
    checked: set[str] = set()
    for item in used:
        url = item["url"]
        if url in checked:
            continue
        checked.add(url)
        request = urllib.request.Request(url, headers={"User-Agent": "shadowrocket-config-builder/1"})
        with urllib.request.urlopen(request, timeout=45) as response:
            if getattr(response, "status", 200) != 200:
                raise BuildError(f"Remote provider returned HTTP error: {url}")
            text = response.read().decode("utf-8-sig")
        lines = [line for line in text.splitlines() if line and not line.startswith("#")]
        if not lines:
            raise BuildError(f"Remote provider is empty: {url}")
        if item["behavior"] == "domain":
            if any("," in line or line.startswith("+.") for line in lines):
                raise BuildError(f"Invalid Shadowrocket domain-set content: {url}")
        else:
            for line in lines:
                parts = line.split(",", 1)
                if len(parts) != 2 or parts[0] not in {"IP-CIDR", "IP-CIDR6"}:
                    raise BuildError(f"Invalid Shadowrocket rule-set line in {url}: {line}")
                network = ipaddress.ip_network(parts[1], strict=True)
                expected = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
                if parts[0] != expected:
                    raise BuildError(f"Wrong address family in {url}: {line}")


def write_or_check(path: Path, content: str, check: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    changed = current != content
    if changed and not check:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--converter-sources", type=Path, required=True)
    parser.add_argument("--mihomo-commit", required=True)
    parser.add_argument("--converter-commit", required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--validate-remote", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        model = json.loads(args.model.read_text(encoding="utf-8"))
        sources = json.loads(args.converter_sources.read_text(encoding="utf-8"))
        mapping = sources["bett"]["mihomo_script_provider_outputs"]
        validate_model(model, mapping)
        groups, group_filters = render_groups(model)
        rules, used = render_rules(model, mapping)
        config = render_config(groups, rules, model)
        validate_config(config)
        if args.validate_remote:
            validate_remote(used)
        report_data = {
            "schema_version": 1,
            "mihomo_script_commit": args.mihomo_commit,
            "proxy_rules_converter_commit": args.converter_commit,
            "configuration_sha256": hashlib.sha256(config.encode("utf-8")).hexdigest(),
            "policy_groups": len(groups),
            "rules": len(rules),
            "providers_used": used,
            "non_portable_providers": {
                name: "Handled by Shadowrocket native behavior"
                for name, output in mapping.items()
                if output is None
            },
            "approximations": [
                "Mihomo IPv4/IPv6-preferred DIRECT pseudo-proxies become DIRECT.",
                "Mihomo proxy-server-nameserver dynamically becomes Shadowrocket proxy-dns-server.",
                "Mihomo fake-ip-filter providers use Shadowrocket native Fake-IP behavior.",
                "Mihomo hosts use the first address per hostname; Flower node aliases are preserved.",
                "Node filtering and region grouping use Shadowrocket policy-regex-filter.",
            ],
            "group_filters": group_filters,
        }
        report = json.dumps(report_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        changed = [
            str(path)
            for path, content in ((args.output, config), (args.report, report))
            if write_or_check(path, content, args.check)
        ]
        if args.check and changed:
            raise BuildError("Generated files are out of date: " + ", ".join(changed))
        print(
            f"Generated {len(groups)} policy groups and {len(rules)} rules; "
            f"validated {len({item['url'] for item in used})} providers."
        )
        return 0
    except (BuildError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
