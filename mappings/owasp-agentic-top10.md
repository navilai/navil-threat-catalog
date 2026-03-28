# OWASP Agentic Top 10 Mapping

This document maps each OWASP Agentic Application risk to corresponding Navil Threat Catalog vectors.

## ASI01: Agent Goal Hijack

**Risk**: Attackers manipulate agent goals or objectives through prompts, context, or framing.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-01-01-001 | OCR-Evading Text in Images | Hidden text in images redefines agent goals |
| AC-01-02-003 | Hidden Layers and Invisible Text | Invisible document text injects goal directives |
| AC-01-03-002 | Voice Spoofing and Speaker Impersonation | Fake authority voice redirects agent purpose |
| AC-02-01-001 | Name Collision Registration | Malicious tool intercepts intended goal operations |
| AC-03-01-001 | Semantically Aligned Backdoor Documents | RAG documents with goal substitution |
| AC-03-03-002 | System Prompt Injection via Context Manipulation | Context overwrites original agent goals |
| AC-08-03-001 | Problem Reframing Attack | Reframing makes harmful action appear as legitimate goal |
| AC-08-03-003 | Authority and Legitimacy Spoofing | False authority redirects agent goals |
| AC-08-03-004 | Incremental Goal Shifting | Gradual goal modification through requests |
| AC-09-01-001 | Historical Context Injection | Inject goal direction into conversation history |
| AC-10-02-001 | Hallucination Exploitation and Fact Fabrication | Agent hallucinates goal justification |

## ASI02: Agent Integrity Failure

**Risk**: Agent's responses or actions become compromised or unreliable.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-05-03-002 | CVE-2025-68144: Path Validation Bypass | Path traversal compromises file integrity |
| AC-06-01-004 | Timestamp Manipulation and Clock Skewing | Integrity checks fail via timeline manipulation |
| AC-10-01-002 | Metadata Exfiltration via Comments | Hidden metadata corrupts output integrity |
| AC-10-02-005 | Narrative Framing and Emotional Manipulation | Output integrity compromised through framing |
| AC-10-03-001 | Malware and Backdoor Code Generation | Generated code contains integrity-breaking malware |

## ASI03: Identity and Privilege Abuse

**Risk**: Attackers impersonate users or escalate privileges beyond intended scope.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-02-01-001 | Name Collision Registration | Tool spoofs identity of legitimate tool |
| AC-02-02-002 | Authentication Bypass via Negotiation | MCP connection without authentication |
| AC-02-03-001 | Hidden Tool Registration Without Discovery | Attacker tool invisible but accessible |
| AC-05-01-001 | CVE-2026-26118: Azure MCP SSRF | Steal managed identity tokens |
| AC-05-01-005 | Default Credential and High-Privilege Service Abuse | Access as overly-privileged service |
| AC-05-02-001 | Agent Identity Spoofing for Privilege Inheritance | Spoof higher-privilege agent identity |
| AC-05-02-003 | Cross-Agent Message Injection | Low-privilege agent requests high-privilege operations |
| AC-05-03-002 | CVE-2025-68144: Path Validation Bypass | Unauthorized file access via path traversal |
| AC-07-02-001 | Central Controller Authentication Bypass | Compromise orchestrator; gain agent control |
| AC-07-02-002 | Orchestrator Configuration Injection | Modify orchestrator config affecting all agents |
| AC-11-02-001 | CVE-2026-26118: Azure Metadata Service SSRF | Access metadata service for credentials |
| AC-11-02-004 | Local Service Exploitation via SSRF | Exploit internal services without auth |
| AC-11-03-001 | Container Breakout via Privilege Escalation | Escape container to host with elevated privileges |

## ASI04: Agentic Supply Chain Vulnerabilities

**Risk**: Malicious or compromised MCP packages, dependencies, or servers in the ecosystem.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-01-01-003 | QR Code Malware Delivery | Distribution vector for compromised payload |
| AC-01-02-004 | Embedded Hyperlink Injection | Malicious links in documents point to supply chain attack |
| AC-04-01-001 | Email Interception via Fake Postmark MCP | Fake '@postmark/mcp' npm package |
| AC-04-01-002 | SSH/AWS Credentials Exfiltration (LiteLLM) | Compromised popular library exfiltrates credentials |
| AC-04-01-003 | Dependency Chaining and Transitive Compromise | Compromise dependency used by 50+ MCPs |
| AC-04-01-004 | Version Pinning and Forced Update Attacks | Dependency update pulls malicious version |
| AC-04-01-005 | Package Metadata Poisoning | Legitimate description, malicious code |
| AC-04-01-006 | Abandoned Package Takeover and Re-release | Deprecated package becomes malware vector |
| AC-04-01-007 | Build Process Hijacking | CI/CD compromise introduces backdoor |
| AC-04-02-001 | Package Name Typosquatting | Typo-similar package name attracts users |
| AC-04-02-002 | Dependency Confusion Attack | Public package at higher version than internal |
| AC-04-02-003 | Scope Confusion and Namespace Collision | Public package matches internal scope |
| AC-04-02-005 | Version Constraint Bypass | Loose version constraint resolves to malicious |
| AC-04-03-001 | Registry Metadata Injection | Malicious homepage URL in registry |
| AC-04-03-003 | Registry Signature Forgery | Forge signatures of legitimate packages |
| AC-04-03-004 | Registry Cache Poisoning | CDN serves malicious artifacts |

## ASI05: Data and Model Poisoning

**Risk**: Training data, RAG knowledge bases, or persistent memory corrupted.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-03-01-001 | Semantically Aligned Backdoor Documents | Malicious documents ranked high in RAG |
| AC-03-01-002 | Embedding Space Poisoning | Manipulated embeddings position malicious docs |
| AC-03-01-004 | Temporal Poisoning and Recency Bias | Inject documents appearing authoritative/recent |
| AC-03-01-005 | Retrieval Confidence Spoofing | Inflate relevance scores of poisoned docs |
| AC-03-01-006 | Cross-Document Poisoning via Citations | Malicious docs cite each other reinforcing authority |
| AC-03-02-001 | False Fact Injection into Memory | Inject false facts into persistent knowledge |
| AC-03-02-002 | Belief and Assumption Manipulation | Corrupt foundational assumptions |
| AC-03-02-003 | User Identity and Credential Spoofing | Map attacker to admin in persistent memory |
| AC-03-02-004 | Conversation History Manipulation | Modify stored history to change understanding |
| AC-03-02-005 | Preference and Configuration Poisoning | Corrupt saved preferences to change behavior |
| AC-03-02-006 | Pattern Learning and Habit Exploitation | Inject patterns causing harmful learned behavior |
| AC-03-03-001 | Context Overflow and Truncation Attacks | Force legitimate context out of window |
| AC-03-03-005 | Conversation State Poisoning | Inject false state markers |
| AC-03-03-006 | Cache Poisoning of Context Encoding | Poison cached embeddings causing misinterpretation |
| AC-08-01-005 | Adversarial Example Poisoning in Reasoning | Examples teach agent to misclassify |
| AC-09-03-001 | Incremental Permission Accumulation | Gradually accumulate through repeated requests |
| AC-09-03-003 | Belief Solidification Through Repetition | Repeat false statement until believed |

## ASI06: Sensitive Information Disclosure

**Risk**: Sensitive data (credentials, secrets, PII) leaked through agent behavior.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-01-01-002 | Steganographic Payload Embedding | Exfiltrated data hidden in image metadata |
| AC-02-01-004 | Silent Side-Effect Injection | Tool performs function but exfiltrates data |
| AC-02-01-005 | Privilege Claim Spoofing | Gain access to sensitive resources |
| AC-04-01-002 | SSH/AWS Credentials Exfiltration (LiteLLM) | Exfiltrate SSH keys and AWS credentials |
| AC-10-01-001 | Subtle Data Encoding in Normal Output | Hide exfiltrated data in output |
| AC-10-01-002 | Metadata Exfiltration via Comments | Hide sensitive data in output metadata |
| AC-10-01-003 | Natural Language Obfuscation | Hide exfiltrated data in normal language |
| AC-10-01-004 | Out-of-Band Exfiltration via Artifacts | Generated files exfiltrate data to server |
| AC-10-01-005 | Timing-Based Data Exfiltration | Encode data in response timing |
| AC-10-01-006 | URL/Link Manipulation for Exfiltration | Embed data in generated URLs |
| AC-10-01-007 | Scheduled Export Attack | Configure regular export to attacker email |
| AC-11-02-001 | CVE-2026-26118: Managed Identity Token | Steal Azure managed identity token |
| AC-11-02-002 | Internal Service Discovery via SSRF | Discover internal databases and services |
| AC-11-02-003 | Credential Theft via SSRF Metadata | Access AWS/GCP/Azure credential endpoints |

## ASI07: Excessive Agency

**Risk**: Agent has more permissions or capabilities than necessary.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-02-01-003 | Capability Inflation and False Claims | Register tool claiming capabilities it doesn't have |
| AC-02-01-005 | Privilege Claim Spoofing | Tool falsely advertises elevated permissions |
| AC-05-01-002 | Permission Check Bypass via Parameter | Inject parameters to bypass permission validation |
| AC-05-01-003 | Time-of-Check to Time-of-Use (TOCTOU) | Race condition allows escalation |
| AC-05-01-004 | Permission Inheritance and Delegation Abuse | Abuse delegation mechanisms to gain privileges |
| AC-05-01-005 | Default Credential and High-Privilege Service | Service runs as root; agent inherits |
| AC-05-01-007 | Context-Aware Permission Escalation | Exploit permission policies by spoofing context |
| AC-07-01-005 | Permission Escalation Through Agent Chains | Low-privilege agent achieves high-priv action |
| AC-07-02-003 | Agent Policy Manipulation | Modify orchestrator policy to grant agents excessive privileges |
| AC-08-01-001 | Denial of Wallet via Recursive Reasoning | Agent's thinking loops consume resources unsustainably |
| AC-08-03-005 | False Equivalence and Proxy Goal | Convince agent harmful action is equivalent to goal |
| AC-10-03-001 | Malware and Backdoor Code Generation | Generated code contains privilege escalation |
| AC-10-03-003 | Privilege Escalation Code Injection | Generated code exploits vulnerabilities |
| AC-11-01-001 | $82K Gemini API Bill in 48 Hours | Excessive API calls resulting in huge charges |
| AC-11-03-001 | Container Breakout via Privilege Escalation | Escape container to host OS |
| AC-11-03-002 | Volume Mount Exploitation | Write to mounted volumes with elevated privileges |
| AC-11-03-003 | Docker Socket Abuse | Spawn privileged containers |

## ASI08: Human Oversight Subversion

**Risk**: Agent bypasses or subverts human review, monitoring, or controls.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-01-03-002 | Voice Spoofing and Speaker Impersonation | Spoof human approval via deepfake voice |
| AC-06-01-001 | Selective Log Deletion and Truncation | Delete evidence of malicious activity |
| AC-06-01-002 | Log Injection and Message Spoofing | Inject fake logs to create alibi |
| AC-06-01-003 | Log Facility Redirection | Redirect logs to prevent collection |
| AC-06-01-004 | Timestamp Manipulation | Backdate activity to before policy enabled |
| AC-06-02-001 | Call Stack Obfuscation | Obscure execution to hide malicious calls |
| AC-06-02-002 | Debugger and Profiler Evasion | Detect debugging and hide malicious behavior |
| AC-06-03-001 | Normal Usage Pattern Mimicry | Blend attack into normal activity |
| AC-06-03-002 | Legitimate Tool Abuse | Use normal tools to perform attack |
| AC-06-03-003 | Polyglot and Dual-Use Functionality | Legitimate function with hidden side effect |
| AC-06-03-004 | Scheduled Task Camouflage | Hide malicious cron job as maintenance |
| AC-06-03-005 | Error Simulation and Misleading Outputs | Fake failures to hide success |
| AC-06-03-006 | Slow and Steady Exfiltration | Stay under rate-limiting thresholds |
| AC-08-02-002 | Scope Confusion Between Sessions | Cross-session context leakage |
| AC-09-01-005 | Implicit Agreement via Inaction | Treat lack of objection as ongoing consent |
| AC-09-02-002 | Condition-Based Delayed Activation | Payload activates at specific condition |
| AC-09-02-003 | Accumulation Attack | Attack effectiveness increases with accumulated state |
| AC-10-02-003 | Selective Information Omission | Omit contradictory information |

## ASI09: Misinformation and Manipulation

**Risk**: Agent produces or amplifies false, misleading, or manipulated information.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-01-01-004 | Chart/Graph Instruction Injection | Chart contains hidden directives interpreted as truth |
| AC-01-01-006 | Screenshot-Based Prompt Injection | Fake interface screenshot treated as real |
| AC-03-01-001 | Semantically Aligned Backdoor Documents | RAG documents contain false information |
| AC-03-02-002 | Belief and Assumption Manipulation | Corrupt foundational beliefs |
| AC-08-03-001 | Problem Reframing Attack | Reframing makes harmful action appealing |
| AC-08-03-002 | Utility Inversion | Invert utility function to optimize for harm |
| AC-10-02-001 | Hallucination Exploitation | Agent hallucinates supporting facts |
| AC-10-02-002 | Citation Forgery and Source Spoofing | Cite non-existent sources |
| AC-10-02-003 | Selective Information Omission | Omit important context |
| AC-10-02-004 | Confidence Score Manipulation | Inflate certainty of false information |
| AC-10-02-005 | Narrative Framing and Emotional | Manipulate through framing |
| AC-10-02-006 | Deepfake Content Generation | Generate synthetic media spreading misinformation |

## ASI10: Shared Resource Exploitation

**Risk**: Agent exploits shared resources (compute, API quotas, databases) for attacker benefit.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-08-01-001 | Denial of Wallet via Recursive Reasoning | Token consumption amplification 142.4x |
| AC-08-01-002 | Circular Logic and Infinite Loop | Agent enters infinite reasoning loop |
| AC-10-03-001 | Malware and Backdoor Code Generation | Generated code compromises other users |
| AC-10-03-004 | Supply Chain Attack via Code | Generated code compromises downstream users |
| AC-11-01-001 | $82K Gemini API Bill in 48 Hours | Stolen key; rapid API exploitation |
| AC-11-01-002 | Token Amplification Attack (142.4x) | Malicious MCP induces 142.4x token growth |
| AC-11-01-003 | Runaway Loop Induction | Induce expensive loops; exhaust CPU |
| AC-11-01-004 | Memory Exhaustion via Large Data | Force processing of huge datasets |
| AC-11-01-005 | Agent-to-Agent Billing Abuse (10,000x) | Low-privilege agent calls paid APIs 10,000x |
| AC-11-01-006 | Rate Limit Bypass and Quota Exhaustion | Bypass rate limiting; exhaust quota |
| AC-11-01-007 | Disk Space Exhaustion and Log Flooding | Fill disk with agent-generated logs |
