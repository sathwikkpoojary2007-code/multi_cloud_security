"""Local retrieval assistant for cloud security and remediation guidance.

Answers are grounded in a small, reviewed cloud security knowledge base and the
current resource findings. No external model or cloud credentials are called.
"""
import re


KNOWLEDGE = [
    ("aws s3 public access", "AWS S3", "For an S3 bucket that should remain private, enable all four Block Public Access controls: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets. Also review bucket policies and ACLs. Rescan the bucket and confirm AWS-S3-001 is absent. Check applications that intentionally serve public objects before changing access."),
    ("aws encryption", "AWS S3", "Enable default server-side encryption with SSE-S3 or SSE-KMS. For SSE-KMS, review key policy, grants, rotation, and the workload's decrypt permissions. Verify the bucket encryption configuration and test a representative application write/read."),
    ("aws iam", "AWS IAM", "Use least privilege: grant only required actions and resource ARNs, prefer roles and short-lived credentials, enable MFA for human users, remove unused access keys, and review policies for wildcard actions or resources. Validate changes with IAM Access Analyzer and workload tests."),
    ("azure storage public access", "Azure Storage", "For private storage, set Public network access to Disabled where private connectivity is available, set Allow Blob anonymous access to Disabled, require secure transfer, and set minimum TLS to TLS 1.2. Review private endpoints, firewall rules, and dependent clients before restricting access; then rescan and verify the relevant controls."),
    ("azure network", "Azure networking", "Use Network Security Groups and Azure Firewall rules that allow only required sources, destinations, ports, and protocols. Prefer private endpoints for storage and databases. Review effective routes and application dependencies before narrowing access."),
    ("azure iam", "Azure identity", "Use Microsoft Entra ID groups and managed identities where possible, enforce MFA and Conditional Access for privileged users, scope RBAC assignments narrowly, and remove stale role assignments. Review privileged role activation and audit logs."),
    ("cisco meraki firewall", "Cisco Meraki", "Review Layer 3 firewall rules from top to bottom. Replace broad allow rules such as Any source + Any destination + Any protocol with the narrowest required CIDRs, ports, and protocols; place specific rules before general rules. Check syslog and test business traffic after changes."),
    ("cloudflare waf", "Cloudflare", "Deploy the managed WAF ruleset for each active zone, review rules in log/simulate mode where available, tune exceptions narrowly, then move to blocking and monitor security events. Confirm existing phase rules are preserved and verify deployment status per zone."),
    ("encryption", "Encryption", "Use encryption in transit (TLS 1.2 or newer) and at rest with a managed encryption key. Restrict key administration separately from data access, enable rotation where appropriate, and verify that backups and replicas are covered."),
    ("logging monitoring", "Logging and monitoring", "Centralize control-plane and data-access logs, retain them according to policy, protect log integrity, and alert on public exposure, privilege changes, key use, and suspicious access. Test that alerts reach an owner."),
    ("mfa", "Identity security", "Require phishing-resistant MFA for administrators when available, use separate privileged accounts, and protect recovery methods. Apply least privilege and review sign-in and role-change logs."),
    ("shared responsibility", "Cloud fundamentals", "The cloud provider secures the underlying cloud infrastructure; the customer remains responsible for configuration, identities, data, and workload security according to the service model. Responsibilities vary by IaaS, PaaS, and SaaS, so check the specific service's responsibility matrix."),
    ("remediation verification", "Remediation workflow", "A safe remediation workflow identifies the exact resource and evidence, proposes a narrow change, obtains authorized approval, applies the change, rescans the provider configuration, and marks the finding resolved only when the new observed configuration satisfies the rule. A submitted edit alone is not proof of a fix."),
    ("cloud security", "Cloud security basics", "Start with identity least privilege and MFA, private-by-default network exposure, encryption at rest and in transit, centralized audit logging, tested backups, and regular configuration scans. Prioritize internet exposure and privileged access, and verify changes with a fresh scan."),
]


def _tokens(text):
    return {word for word in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(word) > 2}


def _finding_advice(resource):
    if not resource:
        return ""
    findings = resource.get("findings", [])
    if not findings:
        return f"Selected resource {resource.get('resource_id')} currently has no active findings in the latest saved scan. Check the scan time and run a fresh read-only scan if its cloud configuration may have changed."
    provider = resource.get("provider", "cloud")
    bits = [f"For {provider.title()} resource {resource.get('resource_id')}, the latest scan reports:"]
    for finding in findings[:4]:
        bits.append(f"• {finding.get('severity', 'Finding')}: {finding.get('title')} ({finding.get('rule')}).")
        rule = finding.get("rule", "")
        match = next((entry for entry in KNOWLEDGE if rule.lower().startswith(entry[0].split()[0]) and provider in entry[1].lower()), None)
        if not match:
            provider_keyword = {"aws": "aws s3", "azure": "azure storage", "cisco": "cisco meraki", "cloudflare": "cloudflare waf"}.get(provider)
            match = next((entry for entry in KNOWLEDGE if provider_keyword and entry[0] == provider_keyword), None)
        if match:
            bits.append(match[2])
    bits.append("After changing settings, run a fresh scan. The finding should remain active if the observed configuration still violates the rule; a saved form by itself does not count as a verified fix.")
    return "\n\n".join(bits)


def answer(question, resource=None):
    """Return a concise answer using ranked knowledge and optional live context."""
    text = (question or "").strip()
    if not text:
        return "Ask a cloud or security question, or ask how to fix the selected finding."
    lowered = text.lower()
    if any(phrase in lowered for phrase in ("this finding", "this issue", "how do i fix", "how to fix", "remediate", "remediation", "fix this", "why is this failing")) and resource:
        return _finding_advice(resource)

    query = _tokens(text)
    ranked = []
    for keywords, title, guidance in KNOWLEDGE:
        words = _tokens(keywords + " " + guidance + " " + title)
        score = len(query & words)
        if score:
            ranked.append((score, title, guidance))
    if not ranked:
        scope = "I can help with AWS, Azure, Cisco Meraki, Cloudflare, identity, networking, encryption, logging, and remediation. Ask about a specific service or control and I’ll give steps to check it."
        if resource:
            scope = _finding_advice(resource) + "\n\n" + scope
        return scope
    ranked.sort(key=lambda item: item[0], reverse=True)
    best = ranked[0]
    response = best[2]
    if len(ranked) > 1 and ranked[1][0] >= best[0] - 1 and ranked[1][1] != best[1]:
        response += "\n\nRelated: " + ranked[1][2]
    return response
