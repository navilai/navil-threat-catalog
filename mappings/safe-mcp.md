# SAFE-MCP Alignment Mapping

This document maps each SAFE-MCP tactic category to corresponding Navil Threat Catalog vectors.

**SAFE-MCP** is an open standard for AI agent security, formally adopted by the Linux Foundation and
OpenID Foundation. It documents 14 tactic categories and 80+ techniques for MCP threat modeling,
modeled on MITRE ATT&CK. See: [github.com/safe-agentic-framework/safe-mcp](https://github.com/safe-agentic-framework/safe-mcp)

**Coverage:** All 14 SAFE-MCP tactic categories map to Navil Threat Catalog attack classes.
The catalog's 210 vectors provide specific, exploitation-grounded detail within each tactic.

| SAFE-MCP Tactics | Navil Attack Classes | Coverage |
|---|---|---|
| 14 tactic categories | 11 attack classes, 33 detection categories | All 14 covered |

---

## 1. Tool Poisoning and Description Mutation

**Adversary goal:** Replace or corrupt tool metadata to redirect agent behavior, intercept calls, or inject unauthorized side effects without modifying the tool's visible function.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-02-01-001 | Name Collision Registration | Register tool with name identical or near-identical to legitimate tool (e.g., 'send_email' vs 'send_emall') to intercept calls |
| AC-02-01-003 | Capability Inflation and False Claims | Register tool claiming capabilities it doesn't have, causing agent to attempt restricted operations |
| AC-02-01-004 | Silent Side-Effect Injection | Tool performs intended function but also executes hidden side effects (data exfiltration, privilege escalation) |
| AC-02-01-005 | Privilege Claim Spoofing | Tool falsely advertises elevated permissions (admin, system, db_write) it shouldn't possess |
| AC-02-01-008 | Tool Poisoning via Dynamic Description Mutation Between Sessions | MCP server presents safe-looking tool descriptions during initial approval/review, then silently modifies tool descriptions in subsequent sessions to include malicious instructions or alter tool behavior. This is a Time-of-Check to Time-of-Use (TOCTOU) vulnerability adapted for LLM tool selection. The MCPTox benchmark demonstrates 72.8% success rate against 20 production LLM agents using this technique across 353 real-world tools. |

---

## 2. Prompt Injection and Manipulation

**Adversary goal:** Embed malicious instructions in content the agent processes (images, documents, tool responses) to override system prompts, hijack goals, or exfiltrate data without direct user interaction.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-01-01-001 | OCR-Evading Text in Images | Attacker embeds system prompts or malicious instructions in image text that bypasses OCR-based content filters by using obfuscated fonts, unusual spacing, or distorted characters |
| AC-01-02-003 | Hidden Layers and Invisible Text | Text layers in PDFs or Word docs hidden with white-on-white coloring or behind images, extracted by agent but not visible to humans |
| AC-08-03-001 | Problem Reframing Attack | Reframe problem to make harmful solution appear as legitimate goal |
| AC-08-03-003 | Authority and Legitimacy Spoofing | Spoof authority source to make malicious goal appear as legitimate directive |
| AC-08-03-004 | Incremental Goal Shifting | Gradually shift agent's goals through small, seemingly benign requests |

---

## 3. OAuth and Authentication Abuse

**Adversary goal:** Bypass, downgrade, or exploit authentication and authorization mechanisms to gain access as a legitimate principal without valid credentials.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-02-02-002 | Authentication Bypass via Negotiation | Attacker negotiates MCP connection without authentication or with null authentication when secure mode required |
| AC-05-01-001 | CVE-2026-26118: Azure MCP SSRF to Managed Identity Token Theft | Attacker sends malicious URL to Azure MCP server endpoint that fetches attacker-controlled metadata service, extracting managed identity token with elevated permissions |
| AC-05-01-004 | Permission Inheritance and Delegation Abuse | Abuse permission inheritance chains or delegation mechanisms to gain privileges of delegating party |
| AC-05-01-007 | Context-Aware Permission Escalation | Exploit permission policies that vary by context (user, time, resource) to escalate in favorable context |
| AC-07-02-001 | Central Controller Authentication Bypass | Bypass authentication on orchestrator to gain control of all managed agents |

---

## 4. Supply Chain and Registry Attacks

**Adversary goal:** Compromise MCP packages, dependencies, or registries to deliver malicious code to downstream consumers at scale without requiring direct access to target environments.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-04-01-001 | Email Interception via Fake Postmark MCP (Real Incident) | Publish npm package '@postmark/mcp' that intercepts and forwards all email BCC fields to attacker infrastructure |
| AC-04-01-002 | SSH/AWS Credentials Exfiltration (LiteLLM v1.82.7/8 Supply Chain Exploit) | Publish malicious version of popular library that exfiltrates SSH keys, AWS credentials, and API tokens |
| AC-04-01-003 | Dependency Chaining and Transitive Compromise | Compromise popular dependency used by many MCP packages to propagate attack through supply chain |
| AC-04-01-007 | Build Process Hijacking and Artifact Poisoning | Compromise package build system to inject malicious code into published artifacts |
| AC-04-02-001 | Package Name Typosquatting | Publish package with name similar to popular MCP (e.g., '@mcps/aws-tools' vs '@mcp/aws-tools') |
| AC-04-02-002 | Dependency Confusion Attack | Publish package with same name as internal/private package to public registry at higher version |
| AC-04-03-001 | Registry Metadata Injection | Inject malicious metadata into registry entry (homepage URL pointing to malware, etc.) |
| AC-04-03-003 | Registry Signature Forgery | Forge cryptographic signatures of legitimate packages to inject malicious versions |

---

## 5. Privilege Escalation

**Adversary goal:** Move from a lower-privilege context to a higher one by exploiting permission checks, delegation chains, or known CVEs in MCP server implementations.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-05-01-001 | CVE-2026-26118: Azure MCP SSRF to Managed Identity Token Theft | Attacker sends malicious URL to Azure MCP server endpoint that fetches attacker-controlled metadata service, extracting managed identity token with elevated permissions |
| AC-05-01-002 | Permission Check Bypass via Parameter Injection | Inject parameters or modify tool calls to bypass permission validation on restricted operations |
| AC-05-01-003 | Time-of-Check to Time-of-Use (TOCTOU) Exploitation | Exploit race condition between permission check and tool execution to escalate privileges |
| AC-05-02-001 | Agent Identity Spoofing for Privilege Inheritance | Spoof identity of higher-privilege agent to inherit its access in shared systems |
| AC-05-02-003 | Cross-Agent Message Injection for Privilege Escalation | Inject messages to higher-privilege agent requesting actions; attacker piggybacks on agent's access |
| AC-05-03-001 | CVE-2025-68143: mcp-server-git Prompt Injection Leading to Arbitrary Code Execution | Attacker injects shell commands via git commit message or branch name; mcp-server-git executes arbitrary code with agent's credentials |

---

## 6. Session Hijacking and Handshake Exploitation

**Adversary goal:** Intercept, manipulate, or abuse the MCP connection establishment phase to register unauthorized tools, strip security, or shadow legitimate functionality.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-02-02-001 | Version Downgrade to Older MCP Versions | Force connection to use older MCP version with known vulnerabilities instead of current secure version |
| AC-02-02-002 | Authentication Bypass via Negotiation | Attacker negotiates MCP connection without authentication or with null authentication when secure mode required |
| AC-02-03-001 | Hidden Tool Registration Without Discovery | Register tool that doesn't appear in list_tools response but can be invoked directly |
| AC-02-03-002 | Stealth Tool Activation and Dormancy Patterns | Tool registered but only becomes active after trigger condition (specific message content, time, request count) |
| AC-02-03-003 | Tool Cloning and Shadowing Legitimate Functions | Register near-duplicate of legitimate tool with subtle behavioral differences for specific inputs |

---

## 7. RAG and Memory Poisoning

**Adversary goal:** Corrupt the agent's knowledge retrieval layer or persistent memory to inject false beliefs, credential mappings, or backdoor retrieval patterns that persist across sessions.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-03-01-001 | Semantically Aligned Backdoor Documents | Insert documents with malicious instructions that match semantically with legitimate queries |
| AC-03-01-002 | Embedding Space Poisoning and Vector Perturbation | Manipulate embedding vectors to position malicious documents near high-retrieval queries |
| AC-03-02-001 | False Fact Injection into Memory | Insert false facts or adversarial examples into agent's persistent knowledge that influence future decisions |
| AC-03-02-002 | Belief and Assumption Manipulation | Corrupt agent's foundational assumptions about users, permissions, or security policies |
| AC-03-02-003 | User Identity and Credential Spoofing in Memory | Inject false identity mappings or credential associations into persistent state |
| AC-03-03-001 | Context Overflow and Truncation Attacks | Inject or reference large amounts of data to force legitimate context to be truncated/forgotten |

---

## 8. Multi-Agent Orchestration Attacks

**Adversary goal:** Exploit trust relationships between agents in multi-agent pipelines to launder privilege, inject orchestrator-level instructions, or manipulate consensus decisions that govern agent behavior.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-07-01-001 | Agent-to-Agent Data Smuggling | Attacker crafts message that one agent passes to another, hidden from direct user view |
| AC-07-01-005 | Permission Escalation Through Agent Chains | Low-privilege agent achieves high-privilege action by chaining through multiple agents |
| AC-07-01-007 | MCP Sampling Covert Tool Invocation | Malicious MCP server uses sampling/createMessage to covertly instruct the client LLM to invoke other MCP tools (file system, network, database) without the user's knowledge or approval. The sampling response contains tool-call directives that the LLM executes as part of its normal operation, bypassing user consent flows. |
| AC-07-02-001 | Central Controller Authentication Bypass | Bypass authentication on orchestrator to gain control of all managed agents |
| AC-07-02-002 | Orchestrator Configuration Injection | Inject malicious configuration into orchestrator affecting all downstream agents |
| AC-07-03-006 | Multi-Agent Consensus Poisoning via Majority Fabrication | In multi-agent systems that use voting or consensus mechanisms for decision-making, attacker compromises multiple agents (via tool poisoning, prompt injection, or credential theft) to fabricate a majority that overrides legitimate agent decisions. The fake majority can approve malicious actions, suppress security alerts, or redirect resources. |

---

## 9. Cognitive Architecture Exploitation

**Adversary goal:** Target the agent's reasoning process itself — inducing runaway loops, role confusion, utility inversion, or goal substitution by exploiting how the model processes framing and context.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-08-01-001 | Denial of Wallet via Recursive Reasoning (Real Incident: 142.4x Amplification) | Malicious MCP server induces recursive reasoning causing 142.4x token amplification; legitimate 1000 token query becomes 142,400 tokens |
| AC-08-01-002 | Circular Logic and Infinite Loop Induction | Craft inputs causing agent to enter infinite reasoning loop |
| AC-08-02-001 | Role Confusion and Identity Swapping | Cause agent to confuse its role or identity, leading to incorrect access control decisions |
| AC-08-03-001 | Problem Reframing Attack | Reframe problem to make harmful solution appear as legitimate goal |
| AC-08-03-002 | Utility Inversion and Perverse Goals | Craft framing that inverts agent's understanding of utility function, optimizing for harm |
| AC-08-03-005 | False Equivalence and Proxy Goal Substitution | Convince agent that harmful action is equivalent to intended goal |

---

## 10. Temporal and Stateful Attacks

**Adversary goal:** Exploit the agent's state accumulation over time — seeding beliefs or permissions across sessions, triggering dormant payloads, or slowly accreting privileges beyond what any single request would permit.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-09-01-001 | Historical Context Injection | Inject malicious context into agent's conversation history that influences future decisions |
| AC-09-02-002 | Condition-Based Delayed Activation | Payload activates only when specific condition reached (e.g., 100th tool call) |
| AC-09-02-003 | Accumulation Attack and State Threshold Crossing | Attack effectiveness increases as agent state accumulates, crossing threshold to cause harm |
| AC-09-03-001 | Incremental Permission Accumulation | Gradually accumulate permissions through repeated small requests that individually seem safe |
| AC-09-03-003 | Belief Solidification Through Repetition | Repeat false statement until agent incorporates it as belief |
| AC-09-03-006 | Cross-Session State Leakage via Shared MCP Server Memory | MCP server maintains state between sessions from different users or contexts. Attacker in session A deliberately seeds the server's internal state (cache, memory, configuration) with payloads that activate when a different user's session B accesses the same server, causing cross-user data leakage or behavior modification. |

---

## 11. Credential Scope Expansion

**Adversary goal:** Widen access from initially limited credentials by exploiting cloud metadata services, path traversal bugs, or unrestricted git operations to reach tokens and secrets beyond the original attack surface.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-05-03-001 | CVE-2025-68143: mcp-server-git Prompt Injection Leading to Arbitrary Code Execution | Attacker injects shell commands via git commit message or branch name; mcp-server-git executes arbitrary code with agent's credentials |
| AC-05-03-002 | CVE-2025-68144: mcp-server-git Path Validation Bypass | Bypass path validation in git operations to access files outside intended repository |
| AC-05-03-003 | CVE-2025-68145: mcp-server-git Unrestricted git_init Leading to Overwrite | Unrestricted git_init allows attacker to initialize git repository in arbitrary directory, overwriting permissions or data |
| AC-11-02-001 | CVE-2026-26118: Azure Metadata Service SSRF Attack | Attacker sends URL pointing to Azure metadata service (169.254.169.254); MCP server forwards request and exposes managed identity token |
| AC-11-02-003 | Credential Theft via SSRF Metadata Endpoints | Access cloud provider metadata endpoints (AWS, GCP, Azure) to steal credentials and tokens |

---

## 12. Anti-Forensics and Behavioral Camouflage

**Adversary goal:** Erase or obscure evidence of malicious activity from logs, traces, and monitoring systems, or blend attack traffic into normal usage patterns to defeat anomaly detection.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-06-01-001 | Selective Log Deletion and Truncation | Delete or truncate specific log entries corresponding to malicious activity |
| AC-06-01-002 | Log Injection and Message Spoofing | Inject fake log entries to create false alibi or mask malicious activity |
| AC-06-02-001 | Call Stack and Execution Flow Obfuscation | Obscure execution flow to make static analysis and debugging difficult |
| AC-06-03-001 | Normal Usage Pattern Mimicry | Mimic legitimate user behavior to blend into normal activity patterns |
| AC-06-03-002 | Legitimate Tool Abuse for Malicious Purposes | Use legitimate tools and features (grep, sed, tar) to perform attack without triggering alerts |
| AC-06-03-006 | Slow and Steady Exfiltration | Perform attack very slowly to stay under rate-limiting and statistical anomaly detection |

---

## 13. Infrastructure and Runtime Exploitation

**Adversary goal:** Abuse the underlying compute, container, and cloud infrastructure that MCP servers run on — escaping sandboxes, exploiting debug interfaces, or exhausting shared resources via token amplification and API abuse.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-11-01-001 | Real Incident: $82K Gemini API Bill in 48 Hours | Attacker gains access to stolen API key; makes rapid API calls resulting in $82K charges in 48 hours |
| AC-11-01-002 | Token Amplification Attack (142.4x Real Amplification) | Malicious MCP servers induce recursive agent reasoning, amplifying token consumption 142.4x or more |
| AC-11-02-001 | CVE-2026-26118: Azure Metadata Service SSRF Attack | Attacker sends URL pointing to Azure metadata service (169.254.169.254); MCP server forwards request and exposes managed identity token |
| AC-11-02-004 | Local Service Exploitation via SSRF | Use SSRF to exploit vulnerabilities in local services (admin panels, file servers) |
| AC-11-03-001 | Container Breakout via Privilege Escalation | Exploit container runtime vulnerability to escape to host |
| AC-11-03-006 | MCP Development Tool RCE via Unauthenticated HTTP Endpoint | MCP debugging/inspection tools that bind to 0.0.0.0 by default expose unauthenticated API endpoints that accept arbitrary command and args parameters. Attacker on the same network (or via DNS rebinding) sends crafted HTTP request to install and execute a malicious MCP server, achieving full RCE without user interaction. |
| AC-11-03-007 | MCP Server Escape via Debug Interface Exploitation | MCP servers running in sandboxed environments expose debug interfaces (inspector ports, profiler endpoints, debug consoles) that were left enabled from development. Attacker exploits these debug interfaces to escape the sandbox, access host resources, or execute arbitrary code outside the container. |

---

## 14. Output Manipulation and Weaponization

**Adversary goal:** Corrupt, weaponize, or covertly encode the agent's outputs — hiding exfiltrated data in generated content, inducing hallucination to spread misinformation, or generating code that exploits the environments where it runs.

| Navil Vector ID | Name | Description |
|---|---|---|
| AC-10-01-001 | Subtle Data Encoding in Normal Output | Hide exfiltrated data in seemingly normal agent output using steganography or encoding |
| AC-10-01-004 | Out-of-Band Exfiltration via Generated Artifacts | Agent generates artifacts (files, URLs, etc.) that exfiltrate data to attacker server |
| AC-10-02-001 | Hallucination Exploitation and Fact Fabrication | Induce agent to hallucinate or fabricate facts in generated content |
| AC-10-02-002 | Citation Forgery and Source Spoofing | Cause agent to cite non-existent or attacker-controlled sources to validate false claims |
| AC-10-03-001 | Malware and Backdoor Code Generation | Agent generates code containing malware, backdoors, or exploitable vulnerabilities |
| AC-10-03-003 | Privilege Escalation Code Injection | Agent generates code that exploits vulnerabilities to escalate privileges when executed |
