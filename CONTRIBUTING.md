# Contributing to Navil Threat Catalog

Thank you for helping strengthen agent security. This guide explains how to contribute vectors, categories, and improvements.

## How to Add a Vector

### Step 1: Identify the Attack Class and Category
Determine which attack class and category your vector belongs to. Review the [README.md](README.md) attack table.

### Step 2: Propose a New Vector

Use the [GitHub Issue template](/.github/ISSUE_TEMPLATE/new-vector.md) to propose:

- **Vector Name**: Concise, memorable name (2-5 words)
- **Attack Class**: AC-XX (e.g., AC-01 for Multi-Modal Smuggling)
- **Category**: AC-XX-XX (e.g., AC-01-01 for Image-Embedded Instruction Injection)
- **Description**: 1-2 sentence explanation of the attack mechanism
- **Real-World Example**: Specific, grounded example from the wild
- **Detection Hint**: Actionable guidance for detection/monitoring
- **Severity**: Critical | High | Medium | Low
- **CVE References**: Any related CVEs (optional)

### Step 3: PR and Review

1. Fork the repository
2. Create a branch: `git checkout -b add-vector-AC-XX-XX-XXX`
3. Update `catalog/threats.json` with your vector
4. Update `catalog/threats.yaml` to match
5. Run `scripts/validate.py` to check format
6. Submit a PR with reference to the issue

### Vector Quality Standards

- **Specificity**: Describe concrete attack mechanism, not vague risk
- **Detectability**: Detection hint must be actionable (not "monitor for attacks")
- **Grounding**: Reference CVEs, real incidents, or published research
- **Clarity**: Clear to both security experts and practitioners

Good: "Craft SVG file with javascript: URI in <a> tag; agent extracts and follows link"
Bad: "Web-based attack involving links"

## How to Propose a New Category

If you identify an attack pattern that doesn't fit existing categories:

1. **Open an issue** describing the pattern and which attack class it belongs to
2. **Propose category name** (e.g., "Cache Poisoning")
3. **Outline 5-7 vectors** you expect to fit this category
4. **Reference incident(s)** that motivate the category

New categories require community consensus; discuss in the issue before submitting PRs.

## How to Propose a New Attack Class

New top-level attack classes are rare but welcome if they represent fundamentally distinct threat:

1. **Open an issue** with title "New Attack Class Proposal: [Name]"
2. **Articulate the threat**: What is the root cause? Why can't it fit in existing classes?
3. **Scope**: Plan 3 categories with 5-7 vectors each (15-21 total vectors minimum)
4. **Reference incidents**: Link to CVEs, research, or documented exploits
5. **OWASP alignment**: Which OWASP Agentic risks does it address?

Community review required before merging.

## Review Process

All PRs undergo review for:

1. **Schema Validation**: All JSON/YAML must be valid; run `scripts/validate.py`
2. **ID Consistency**: IDs must follow format AC-XX, AC-XX-XX, AC-XX-XX-XXX
3. **Severity Calibration**:
   - CRITICAL = Active exploitation documented OR Proof-of-concept with real impact
   - HIGH = Proof-of-concept exists OR Plausible with moderate skill
   - MEDIUM = Theoretically plausible, requires specific conditions
   - LOW = Very rare edge case or requires extreme assumptions
4. **Completeness**: All required fields present (name, description, severity, detection_hint)
5. **No duplicates**: Doesn't duplicate existing vector
6. **Actionable detection**: Detection hint is specific enough to implement

PR reviews typically complete within 1 week.

## Attribution Policy

All contributors are credited:

- **In catalog**: Contributors listed in header of released versions
- **In releases**: Changelog notes the PR and contributor GitHub handle
- **Community**: You gain standing in the Navil security community

For major contributions (new attack class, 10+ vectors), we recognize in:
- Quarterly "Threat Researcher" announcements
- Annual Navil security report

## Severity Calibration Examples

### CRITICAL Examples
- CVE-2026-26118 (Azure MCP SSRF): Active exploitation in production
- LiteLLM supply chain attack: Real malware distribution
- Deepfake voice spoofing: POC demonstrated and deployed

### HIGH Examples
- CVE-2025-68143 (mcp-server-git RCE): POC exists, reasonable skill needed
- Log injection: Technique proven in other domains, applicable to agents
- Permission escalation patterns: Published research on MCP scope

### MEDIUM Examples
- Context window poisoning: Plausible but requires specific agent architecture
- Cache poisoning: Depends on cache implementation details
- Timing side-channel: Possible but low real-world impact

### LOW Examples
- Theoretical quantum computing attacks: Not actionable in 2026
- Extreme edge cases: Requires 5+ simultaneous failures
- Deprecated attack techniques: Mitigated in all modern platforms

## PR Template

```markdown
## Vector Addition/Update

### Issue Reference
Closes #XXX

### Vector Details
- **ID**: AC-XX-XX-XXX
- **Name**: [Vector Name]
- **Class/Category**: AC-XX / AC-XX-XX
- **Severity**: [Critical/High/Medium/Low]

### Motivation
[Explain why this vector matters. Reference CVE, incident, or research.]

### Example
[Concrete example of attack in the wild or POC.]

### Detection Hint
[Specific, actionable monitoring/detection guidance.]

### Validation
- [ ] `scripts/validate.py` passes
- [ ] ID format correct (AC-XX-XX-XXX)
- [ ] No duplicate with existing vectors
- [ ] Detection hint is actionable
- [ ] Severity justified with references
```

## Code of Conduct

We value respect, constructive feedback, and diverse perspectives. All contributors agree to:

- Discuss ideas and disagree respectfully
- Give credit to prior research
- Help less experienced contributors
- Prioritize accuracy over speed

## Questions?

- **Technical**: Open a GitHub issue or discussion
- **Community**: Join Navil security researcher Discord (link in README)
- **Security**: Email security@navil.ai for sensitive disclosure

Thank you for strengthening agent security!
