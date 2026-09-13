# Shadowrocket configuration

This repository publishes a generated Shadowrocket configuration aligned with
[`frostmage1250/mihomo-script`](https://github.com/frostmage1250/mihomo-script).

## Subscription

```text
https://raw.githubusercontent.com/frostmage1250/shadowrocket-config/main/shadowrocket.conf
```

Add server subscriptions separately in Shadowrocket. This public repository never
downloads, stores, or publishes airport URLs, node passwords, UUIDs, or private keys.
The generated policy groups use `policy-regex-filter` against the nodes already
available in the app.

## Source boundaries

- Policy groups, provider types, provider order, rule order, and target policies are
  extracted directly from the published `mihomoScript.js`.
- Shadowrocket rule files come only from
  [`proxy-rules-converter`](https://github.com/frostmage1250/proxy-rules-converter).
- That converter maps the exact BettRules `.list` files selected by the Mihomo
  script to Shadowrocket `.domain-set` and typed IP `.list` outputs.
- `geolocation-cn` remains the separately documented V2Fly exception.
- The workflow records immutable upstream commit IDs and the generated configuration
  digest in `reports/source.json`.

## Compatibility policy

Direct equivalents are generated without changing policy or rule order:

- Mihomo domain providers become Shadowrocket `DOMAIN-SET` rules.
- Mihomo IP providers become Shadowrocket `RULE-SET` rules and retain
  `no-resolve`.
- Mihomo `MATCH` becomes Shadowrocket `FINAL`.
- Mihomo select groups become Shadowrocket select groups.

Non-identical client behavior is explicit and conservative:

- Node filtering and region/rate grouping use Shadowrocket
  `policy-regex-filter` with the regexes extracted from the Mihomo script.
- `IPv4优先` and `IPv6优先` Mihomo DIRECT pseudo-proxies become `DIRECT`.
- Foreign DoH uses the `Proxy` group; direct requests use system DNS; node domains
  use the configured China DoH servers.
- Mihomo rule-set DNS policies and `fakeip_filter` have no exact Shadowrocket
  representation and use native Shadowrocket DNS/Fake-IP behavior.
- The two Mihomo DoH host arrays are represented by their first reviewed address.

Generation fails when providers disappear, mappings drift, a referenced provider is
non-portable, a policy is undefined, or a remote generated rule file is missing or
invalid. Unsupported behavior is never silently omitted.

## Automation

The GitHub Actions workflow runs daily and on manual dispatch. It resolves immutable
commits for both upstream repositories, extracts the live model, generates the
configuration, downloads and validates every referenced remote provider, runs tests,
checks deterministic regeneration, and commits only verified generated artifacts.
