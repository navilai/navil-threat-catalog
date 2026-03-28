---
name: Propose New Attack Vector
about: Suggest a new threat vector for the Navil Catalog
title: "[VECTOR] Vector Name Here"
labels: vector-proposal
assignees: ''

---

## Vector Details

**Attack Class**: AC-XX (e.g., AC-01 for Multi-Modal Smuggling)
**Category**: AC-XX-XX (e.g., AC-01-01 for Image-Embedded Instruction Injection)

## Vector Information

### Name
Brief, memorable name (2-5 words):
*e.g., "OCR-Evading Text in Images"*

### Description
Concise explanation of the attack mechanism (1-2 sentences):

### Real-World Example
Specific, grounded example of the attack in the wild or POC:

### Detection Hint
Actionable, specific monitoring or detection guidance:

*Example: "Perform spectrographic analysis of audio; alert on unusual frequency patterns >15kHz"*

NOT: "Monitor for attacks" (too vague)

### Severity
Choose one:
- [ ] **Critical**: Active exploitation documented OR proof-of-concept with real impact
- [ ] **High**: Proof-of-concept exists OR plausible with moderate skill
- [ ] **Medium**: Theoretically plausible, requires specific conditions
- [ ] **Low**: Very rare edge case or requires extreme assumptions

### CVE References
If applicable, list any related CVEs:
- CVE-XXXX-XXXXX
- CVE-XXXX-XXXXX

### OWASP Agentic Top 10 Coverage
Which risks does this vector address? (Select all that apply)
- [ ] ASI01: Agent Goal Hijack
- [ ] ASI02: Agent Integrity Failure
- [ ] ASI03: Identity and Privilege Abuse
- [ ] ASI04: Agentic Supply Chain Vulnerabilities
- [ ] ASI05: Data and Model Poisoning
- [ ] ASI06: Sensitive Information Disclosure
- [ ] ASI07: Excessive Agency
- [ ] ASI08: Human Oversight Subversion
- [ ] ASI09: Misinformation and Manipulation
- [ ] ASI10: Shared Resource Exploitation

## Justification

### Why This Vector Matters
Explain the threat model and impact:

### Related Research or Incidents
Link to or reference:
- Published CVEs
- Security research
- Real-world incidents
- Industry reports

## Additional Context

### Related Vectors
Are there existing vectors this relates to?

### Suggested Improvements
Feedback on existing vectors or categories?

---

## Checklist

Before submitting, verify:
- [ ] Description is concrete and specific (not vague)
- [ ] Detection hint is actionable for practitioners
- [ ] Severity is justified with references
- [ ] Attack class and category are correct
- [ ] No duplicate with existing vectors (check [README](../../README.md))
- [ ] Example is grounded in real attack or documented research

Thank you for strengthening agent security!
