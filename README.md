# Navil Threat Catalog

**The MITRE ATT&CK of agent security.**

![License: CC BY-SA 4.0](https://img.shields.io/badge/License-CC%20BY--SA%204.0-lightgrey.svg)
![Vectors](https://img.shields.io/badge/Vectors-219-red)
![Classes](https://img.shields.io/badge/Attack%20Classes-11-orange)
![Categories](https://img.shields.io/badge/Detection%20Categories-33-yellow)

## Overview

The MCP ecosystem exploded 2,100% in the last 12 months. Yet 66% of MCP servers discovered in production have security findings. Before Navil, there was no standardized threat taxonomy for agent security. This catalog bridges that gap.

Navil Threat Catalog is a comprehensive, open-source threat taxonomy designed for AI agents and MCP integrations. It maps the attack surface, provides detection guidance, and links to real CVEs. Whether you're threat modeling, building detection systems, or hardening MCP deployments, this is your reference.

## Quick Stats

| Metric | Count |
|--------|-------|
| Attack Classes | 11 |
| Detection Categories | 33 |
| Attack Vectors | 219 |
| Combinatorial Scenarios | 1M+ |
| License | CC BY-SA 4.0 |

## Attack Class Overview

| ID | Name | Categories | Vectors | OWASP Coverage |
|---|---|---|---|---|
| AC-01 | Multi-Modal Smuggling | 3 | 17 | ASI01, ASI09 |
| AC-02 | Handshake Hijacking | 3 | 19 | ASI03, ASI04 |
| AC-03 | RAG/Memory Poisoning | 3 | 18 | ASI05, ASI09 |
| AC-04 | Supply Chain/Discovery | 3 | 18 | ASI04 |
| AC-05 | Privilege Escalation | 3 | 19 | ASI03, ASI07 |
| AC-06 | Anti-Forensics | 3 | 18 | ASI08 |
| AC-07 | Agent Collusion & Multi-Agent | 3 | 17 | ASI01, ASI03 |
| AC-08 | Cognitive Architecture Exploitation | 3 | 18 | ASI01, ASI08 |
| AC-09 | Temporal & Stateful Attacks | 3 | 17 | ASI05, ASI08 |
| AC-10 | Output Manipulation & Weaponization | 3 | 19 | ASI06, ASI09, ASI10 |
| AC-11 | Infrastructure & Runtime Attacks | 3 | 18 | ASI07, ASI10 |

## Usage

### Threat Modeling
Use the catalog to systematically identify threats in your MCP deployments. Start with your attack surface (which agents run where, what tools they access) and cross-reference the attack classes.

### Direct JSON/YAML Consumption
```python
import json

with open('catalog/threats.json') as f:
    catalog = json.load(f)

for attack_class in catalog['attack_classes']:
    print(f"{attack_class['id']}: {attack_class['name']}")
    for category in attack_class['categories']:
        for vector in category['vectors']:
            if vector['severity'] == 'critical':
                print(f"  CRITICAL: {vector['name']}")
```

### Navil CLI
```bash
navil threat-model --agents 5 --tools 40
navil detect --logs /var/log/agent/ --patterns AC-01
navil report --format html --output threat-report.html
```

### CI/CD Security Gate
Integrate Navil validation into your deployment pipeline:
```yaml
- name: Threat Validation
  run: navil validate --config mcp-config.yaml --fail-on critical
```

## OWASP Agentic Top 10 Mapping

| OWASP | Risk | Navil Coverage |
|---|---|---|
| ASI01 | Agent Goal Hijack | AC-01, AC-02, AC-03, AC-08, AC-09 |
| ASI02 | Agent Integrity Failure | AC-05, AC-06, AC-10 |
| ASI03 | Identity and Privilege Abuse | AC-02, AC-05, AC-07, AC-11 |
| ASI04 | Agentic Supply Chain Vulnerabilities | AC-04 (comprehensive) |
| ASI05 | Data and Model Poisoning | AC-03, AC-09, AC-08 |
| ASI06 | Sensitive Information Disclosure | AC-10, AC-11 |
| ASI07 | Excessive Agency | AC-05, AC-08, AC-10, AC-11 |
| ASI08 | Human Oversight Subversion | AC-06, AC-08, AC-09 |
| ASI09 | Misinformation and Manipulation | AC-01, AC-03, AC-10 |
| ASI10 | Shared Resource Exploitation | AC-10, AC-11 |

## Real-World Incidents

This catalog is grounded in documented attacks:

1. **Fake Postmark MCP (npm)** - Malicious '@postmark/mcp' package intercepted and forwarded all email BCC fields to attacker infrastructure. *Covered: AC-04-01-001*

2. **LiteLLM v1.82.7/8 Supply Chain Exploit** - Trojanized versions exfiltrated SSH keys and AWS credentials from developer machines. *Covered: AC-04-01-002*

3. **CVE-2026-26118 (CVSS 8.8)** - Azure MCP SSRF vulnerability exposed managed identity tokens. Attacker sends URL to metadata service endpoint; server forwards request revealing credentials. *Covered: AC-05-01-001, AC-11-02-001*

4. **CVE-2025-68143/44/45** - Anthropic mcp-server-git vulnerable to prompt injection (RCE), path validation bypass, and unrestricted git_init. Attackers execute arbitrary code with SSH key access. *Covered: AC-05-03-001, AC-05-03-002, AC-05-03-003*

5. **$82K Gemini API Bill in 48 Hours** - Stolen API key exploited for rapid API calls; denial of wallet via token amplification reaching 142.4x on malicious MCP responses. *Covered: AC-11-01-001, AC-11-01-002*

## Contributing

The Navil community drives this forward. We welcome contributions of:

- New attack vectors discovered in the wild
- Improved detection hints based on real deployments
- Additional CVE references and incident mappings
- Feedback on severity calibration

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Navil Threat Catalog is licensed under **CC BY-SA 4.0**. You are free to use, share, and adapt this work for any purpose—commercial or non-commercial—provided you give credit and release derivatives under the same license.

## Related Links

- **Navil Platform**: [navil.ai](https://navil.ai)
- **GitHub**: [github.com/navilai/navil](https://github.com/navilai/navil)
- **OWASP Agentic Top 10**: [owasp.org/agentic](https://owasp.org/agentic)
- **MCP Specification**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
