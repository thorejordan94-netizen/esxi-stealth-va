"""Contextual finding knowledge base and deterministic remediation engine.

Scanner output remains the source of truth. This module maps known scenarios to
operational implications, remediation steps, and verification guidance. Unknown
findings receive a conservative fallback instead of fabricated conclusions.
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}


def _rule(rule_id, keywords, implications, actions, validation,
          ids=None, tags=None, id_pattern=None, problematic=True):
    return {
        "id": rule_id,
        "ids": ids or [],
        "keywords": keywords or [],
        "tags": tags or [],
        "id_pattern": id_pattern,
        "implications": implications,
        "actions": actions,
        "validation": validation,
        "problematic": problematic,
    }


KNOWLEDGE_BASE = [
    _rule(
        "anonymous-ftp",
        ["anonymous ftp", "ftp anonymous"],
        [
            "Unauthenticated users may read or upload files, depending on server permissions.",
            "Writable anonymous areas can be abused for malware staging, data exchange, or storage exhaustion.",
        ],
        [
            "Disable anonymous authentication unless it is an explicitly approved requirement.",
            "Restrict FTP to required source networks and prefer SFTP or another authenticated protocol.",
            "Review the anonymous root for sensitive or attacker-supplied files and remove write access.",
        ],
        ["Reconnect without credentials and confirm listing, download, and upload are rejected."],
        ids=["NMAP-FTP-ANON"], tags=["ftp", "misconfig"],
    ),
    _rule(
        "smbv1",
        ["smbv1", "smb1", "nt lm 0.12"],
        [
            "SMBv1 is obsolete and lacks modern protocol protections.",
            "Its presence materially increases lateral-movement and ransomware risk.",
        ],
        [
            "Disable SMBv1 on servers and dependent clients.",
            "Upgrade legacy systems before enforcing SMBv2/SMBv3 only.",
            "Segment systems that cannot be upgraded and restrict TCP/445 paths.",
        ],
        ["Repeat protocol enumeration and verify that only SMBv2/SMBv3 dialects are offered."],
        ids=["NMAP-SMB1"], tags=["smb", "legacy"],
    ),
    _rule(
        "smb-signing",
        ["smb signing", "signing not required", "signing disabled"],
        [
            "Unsigned SMB sessions are more exposed to relay and man-in-the-middle attacks.",
            "Internal credential material may be abused when an attacker can influence network traffic.",
        ],
        [
            "Require SMB signing on servers and clients through policy.",
            "Reduce NTLM usage and prefer Kerberos where supported.",
            "Restrict TCP/445 between network segments to required paths only.",
        ],
        ["Re-run SMB security-mode checks and confirm message signing is required."],
        ids=["NMAP-SMB-SIGNING"], tags=["smb", "misconfig"],
    ),
    _rule(
        "dangerous-http-methods",
        ["dangerous http methods", "http methods", "trace method", "put method", "delete method"],
        [
            "Unnecessary HTTP methods can enable content modification, disclosure, or proxy abuse.",
            "Actual impact depends on authentication, path permissions, and application routing.",
        ],
        [
            "Allow only methods required by the application at the proxy and application server.",
            "Disable TRACE and restrict PUT, DELETE, and CONNECT unless explicitly required.",
            "Test method handling on every affected path.",
        ],
        ["Confirm disallowed methods return 405 or 403 without authentication."],
        ids=["NMAP-HTTP-METHODS"], tags=["http", "misconfig"],
    ),
    _rule(
        "weak-ssh",
        ["weak ssh", "ssh-dss", "group1-sha1", "3des-cbc", "arcfour", "hmac-md5"],
        [
            "Legacy SSH algorithms reduce cryptographic assurance and may violate security baselines.",
            "Compatible clients may continue negotiating weak primitives while they remain enabled.",
        ],
        [
            "Remove weak key-exchange, cipher, host-key, and MAC algorithms.",
            "Upgrade incompatible clients and rotate legacy host keys where required.",
            "Manage the SSH cryptographic policy centrally and monitor drift.",
        ],
        ["Repeat algorithm enumeration and confirm prohibited algorithms are absent."],
        ids=["NMAP-SSH-WEAK-ALGO"], tags=["ssh", "crypto"],
    ),
    _rule(
        "rdp-nla",
        ["rdp nla", "network level authentication", "credssp"],
        [
            "Without NLA, RDP exposes a broader pre-authentication surface.",
            "The endpoint is more susceptible to credential attacks and resource exhaustion.",
        ],
        [
            "Require Network Level Authentication and current CredSSP settings.",
            "Restrict RDP to approved administration networks or a hardened gateway.",
            "Enforce MFA and account lockout controls.",
        ],
        ["Confirm a client without NLA support is rejected before desktop negotiation."],
        ids=["NMAP-RDP-NLA"], tags=["rdp", "misconfig"],
    ),
    _rule(
        "dns-recursion",
        ["dns recursion", "recursion enabled"],
        [
            "Unrestricted recursion can disclose DNS behavior and enable amplification abuse.",
            "Risk is lower when recursion is deliberately limited to trusted clients.",
        ],
        [
            "Limit recursive queries to approved internal client networks.",
            "Disable recursion on authoritative-only servers.",
            "Block external UDP/TCP 53 access where it is not required.",
        ],
        ["Query an unrelated domain from an untrusted segment and confirm recursion is refused."],
        ids=["NMAP-DNS-RECURSION"], tags=["dns", "exposure"],
    ),
    _rule(
        "unauthenticated-datastore",
        ["unauthenticated redis", "unauthenticated memcached", "redis information", "memcached information"],
        [
            "A reachable datastore without effective authentication can expose data or administrative functions.",
            "Depending on configuration, an attacker may alter data, cause denial of service, or pivot.",
        ],
        [
            "Bind the service to required interfaces and restrict it with host and network firewalls.",
            "Enable supported authentication and transport protection.",
            "Review stored data and dependent credentials after access is restricted.",
        ],
        ["Confirm unauthorized segments cannot connect or must authenticate."],
        ids=["NMAP-REDIS-INFO", "NMAP-MEMCACHED-INFO"], tags=["redis", "memcached", "exposure"],
    ),
    _rule(
        "snmp-exposure",
        ["snmp service information", "snmp-info", "public community"],
        [
            "SNMP can disclose detailed device, software, interface, and network information.",
            "SNMPv1/v2c community strings provide weak access control and no confidentiality.",
        ],
        [
            "Use SNMPv3 with authentication and privacy where monitoring is required.",
            "Restrict manager source addresses and remove default community strings.",
            "Disable SNMP where it is not actively used.",
        ],
        ["Verify unauthorized sources receive no response and approved monitoring uses SNMPv3."],
        ids=["NMAP-SNMP-INFO"], tags=["snmp", "exposure"],
    ),
    _rule(
        "legacy-tls",
        ["tls 1.0", "tls1.0", "tls 1.1", "tls1.1", "sslv2", "sslv3", "legacy tls", "deprecated tls"],
        [
            "Legacy TLS/SSL protocols use obsolete constructions and commonly fail security baselines.",
            "Clients may negotiate weaker protection while old versions remain enabled.",
        ],
        [
            "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 unless an approved exception exists.",
            "Require TLS 1.2 or TLS 1.3 with an approved cipher policy.",
            "Upgrade dependent legacy clients before enforcement.",
        ],
        ["Repeat negotiation tests and confirm only approved TLS versions succeed."],
        tags=["tls", "ssl", "crypto"],
    ),
    _rule(
        "certificate-trust",
        ["self-signed", "self signed", "untrusted certificate", "unknown ca", "certificate trust"],
        [
            "Clients cannot reliably authenticate the service when certificate trust is not established.",
            "Users may become conditioned to ignore warnings, increasing man-in-the-middle risk.",
        ],
        [
            "Issue the certificate from the approved internal or public CA.",
            "Install the complete chain and remove obsolete certificates.",
            "Automate renewal and monitor expiry and hostname coverage.",
        ],
        ["Validate chain, hostname, and expiry from a managed client without suppressing checks."],
        tags=["certificate", "tls", "ssl"],
    ),
    _rule(
        "certificate-expiry",
        ["expired certificate", "certificate expired", "expires soon", "certificate expiry"],
        [
            "Expired or near-expiry certificates can cause service disruption and warning bypass.",
            "Renewal failures indicate missing ownership or ineffective lifecycle controls.",
        ],
        [
            "Renew and deploy the certificate with the correct chain and SAN entries.",
            "Assign ownership and configure automated renewal with early alerting.",
            "Verify all clustered nodes receive the replacement.",
        ],
        ["Confirm the new validity period and chain from every served endpoint."],
        tags=["certificate", "tls", "ssl"],
    ),
    _rule(
        "weak-cipher",
        ["weak cipher", "rc4", "3des", "des-cbc", "null cipher", "export cipher", "sweet32"],
        [
            "Weak cipher suites reduce confidentiality or integrity and may permit known attacks.",
            "Their availability can create audit findings even when modern ciphers are preferred.",
        ],
        [
            "Remove NULL, export, RC4, DES, 3DES, and other prohibited suites.",
            "Prefer modern AEAD suites and centrally managed cryptographic policy.",
            "Retest supported clients after tightening configuration.",
        ],
        ["Enumerate accepted suites and confirm only the approved baseline remains."],
        tags=["tls", "ssl", "crypto"],
    ),
    _rule(
        "missing-security-header",
        ["missing security header", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "hsts"],
        [
            "Missing browser security headers weaken defense in depth against common client-side attacks.",
            "Impact depends on application sensitivity and existing frontend controls.",
        ],
        [
            "Deploy an application-appropriate security-header baseline.",
            "Enable HSTS only after confirming HTTPS is consistently available.",
            "Test CSP in report-only mode before enforcement.",
        ],
        ["Inspect all relevant paths and confirm required headers and directives are present."],
        tags=["headers", "http", "misconfig"],
    ),
    _rule(
        "default-credentials",
        ["default login", "default credential", "default password", "factory credential"],
        [
            "Default or predictable credentials can provide immediate unauthorized access.",
            "Administrative interfaces may enable complete system compromise.",
        ],
        [
            "Change or disable all default accounts and rotate associated credentials immediately.",
            "Restrict the management interface to approved administration networks.",
            "Review authentication logs and system changes for prior unauthorized access.",
        ],
        ["Confirm vendor-default credential combinations fail."],
        tags=["default-login", "credentials"],
    ),
    _rule(
        "known-cve",
        ["known vulnerability", "cve-"],
        [
            "The scanner matched a condition associated with a published vulnerability.",
            "Exploitability depends on product version, configuration, reachability, and template accuracy.",
        ],
        [
            "Validate the product and version against the vendor advisory and scanner evidence.",
            "Apply the vendor patch or documented mitigation according to severity and exposure.",
            "Restrict access until remediation is complete and review relevant logs.",
        ],
        ["Re-run the specific template and verify the fixed version or mitigation is present."],
        tags=["cve"], id_pattern=r"^CVE-\d{4}-\d+$",
    ),
    _rule(
        "information-exposure",
        ["information disclosure", "version disclosure", "exposed", "banner", "debug", "stack trace", "directory listing"],
        [
            "Exposed technical details improve reconnaissance and can reveal sensitive paths or versions.",
            "The issue may be low severity alone but can materially assist exploitation of other weaknesses.",
        ],
        [
            "Remove unnecessary banners, debug output, directory listings, and unauthenticated diagnostics.",
            "Restrict administrative and diagnostic interfaces to approved networks.",
            "Review exposed data for secrets, internal addresses, usernames, and vulnerable versions.",
        ],
        ["Repeat the unauthenticated request and confirm sensitive details are no longer returned."],
        tags=["exposure", "tech"],
    ),
]


def normalize_severity(value):
    severity = str(value or "info").strip().lower()
    return severity if severity in SEVERITY_ORDER else "info"


def priority_for_severity(severity):
    return {
        "critical": "P0 - immediate",
        "high": "P1 - urgent",
        "medium": "P2 - planned promptly",
        "low": "P3 - scheduled hardening",
        "info": "P4 - review",
    }[normalize_severity(severity)]


def _text_blob(finding):
    values = [
        finding.get("id", ""), finding.get("title", ""), finding.get("description", ""),
        finding.get("evidence", ""), finding.get("category", ""), finding.get("scanner", ""),
        " ".join(str(value) for value in finding.get("tags", []) or []),
    ]
    return " ".join(str(value or "") for value in values).lower()


def _rule_score(rule, finding):
    finding_id = str(finding.get("id", ""))
    tags = {str(value).lower() for value in finding.get("tags", []) or []}
    blob = _text_blob(finding)
    score = 0
    if finding_id and finding_id in rule.get("ids", []):
        score += 100
    pattern = rule.get("id_pattern")
    if pattern and re.match(pattern, finding_id, re.IGNORECASE):
        score += 90
    for keyword in rule.get("keywords", []):
        if str(keyword).lower() in blob:
            score += 10
    overlap = tags.intersection(str(value).lower() for value in rule.get("tags", []))
    score += len(overlap) * 3
    return score


def match_rule(finding):
    best = None
    best_score = 0
    for rule in KNOWLEDGE_BASE:
        score = _rule_score(rule, finding)
        if score > best_score:
            best = rule
            best_score = score
    return best if best_score >= 3 else None


def _generic_context(finding):
    severity = normalize_severity(finding.get("severity"))
    title = finding.get("title") or finding.get("id") or "Scanner finding"
    implications = [
        "The scanner detected a condition that requires validation in the context of this asset and service.",
        "Risk depends on reachability, authentication, version, exposed data, and scanner evidence quality.",
    ]
    if severity == "info":
        implications[0] = "The observation is contextual and does not by itself prove a vulnerability."
    return {
        "knowledge_rule": "generic-validated-fallback",
        "risk_statement": "{} was reported on {}. Treat it as {} until validated.".format(
            title, finding.get("target", "unknown target"), priority_for_severity(severity)
        ),
        "implications": implications,
        "recommended_actions": [
            "Validate the observation manually or with a second independent check.",
            "Identify the owning system, affected component, business function, and exposure path.",
            "Apply the vendor-recommended fix or remove unnecessary exposure, then repeat the original test.",
        ],
        "validation_steps": ["Repeat the exact check and confirm the result after remediation."],
        "problematic": severity != "info",
        "confidence": "scanner-dependent",
    }


def contextualize_finding(finding):
    result = dict(finding)
    severity = normalize_severity(result.get("severity"))
    result["severity"] = severity
    result["priority"] = priority_for_severity(severity)
    rule = match_rule(result)
    if rule is None:
        result["context"] = _generic_context(result)
        return result
    title = result.get("title") or result.get("id") or "Finding"
    result["context"] = {
        "knowledge_rule": rule["id"],
        "risk_statement": "{} affects {} and is classified as {}.".format(
            title, result.get("target", "the assessed asset"), result["priority"]
        ),
        "implications": list(rule.get("implications", [])),
        "recommended_actions": list(rule.get("actions", [])),
        "validation_steps": list(rule.get("validation", [])),
        "problematic": bool(rule.get("problematic", severity != "info")),
        "confidence": "rule-matched",
    }
    return result


def contextualize_all(findings):
    contextual = [contextualize_finding(item) for item in findings]
    return sorted(
        contextual,
        key=lambda item: (
            -SEVERITY_ORDER.get(item.get("severity", "info"), 1),
            str(item.get("target", "")),
            str(item.get("title", "")),
        ),
    )


def risk_score(findings):
    """Return a bounded 0-100 operational risk indicator, not a CVSS score."""
    total = sum(SEVERITY_WEIGHTS.get(normalize_severity(item.get("severity")), 0) for item in findings)
    return min(100, total)


def overall_risk(score, findings):
    severities = {normalize_severity(item.get("severity")) for item in findings}
    if "critical" in severities or score >= 60:
        return "critical"
    if "high" in severities or score >= 35:
        return "high"
    if "medium" in severities or score >= 15:
        return "medium"
    if "low" in severities or score > 0:
        return "low"
    return "informational"


def prioritized_actions(findings, limit=12):
    seen = set()
    actions = []
    for finding in findings:
        for action in finding.get("context", {}).get("recommended_actions", []):
            key = action.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            actions.append({
                "priority": finding.get("priority", priority_for_severity(finding.get("severity"))),
                "action": action,
                "source_finding": finding.get("id") or finding.get("title"),
                "target": finding.get("target", ""),
            })
            if len(actions) >= limit:
                return actions
    return actions
