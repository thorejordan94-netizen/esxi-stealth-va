"""Contextual finding knowledge base and deterministic remediation engine.

The scanner output remains the source of truth.  This module adds operational
context without inventing exploitability: it maps known scenarios to explicit
implications, remediation steps, and verification guidance, and uses a safe
fallback for unknown scanner findings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}


KNOWLEDGE_BASE = [
    {
        "id": "anonymous-ftp",
        "ids": ["NMAP-FTP-ANON"],
        "keywords": ["anonymous ftp", "ftp anonymous"],
        "implications": [
            "Unauthenticated users may read or upload files, depending on server permissions.",
            "Writable anonymous areas can be abused for malware staging, data exchange, or storage exhaustion.",
        ],
        "actions": [
            "Disable anonymous authentication unless it is an explicitly approved business requirement.",
            "Restrict the FTP service to required source networks and prefer SFTP or another authenticated protocol.",
            "Review the anonymous root for sensitive or attacker-supplied files and remove unnecessary write permissions.",
        ],
        "validation": ["Reconnect without credentials and confirm that listing, download, and upload are rejected."],
        "problematic": True,
    },
    {
        "id": "smbv1",
        "ids": ["NMAP-SMB1"],
        "keywords": ["smbv1", "smb1", "nt lm 0.12"],
        "implications": [
            "SMBv1 is obsolete and lacks modern protocol protections.",
            "Its presence materially increases lateral-movement and ransomware risk on internal networks.",
        ],
        "actions": [
            "Disable SMBv1 on the server and all dependent clients.",
            "Identify and upgrade legacy systems before enforcing SMBv2/SMBv3 only.",
            "Segment systems that cannot be upgraded and block SMB access from unrelated network zones.",
        ],
        "validation": ["Repeat protocol enumeration and verify that only SMBv2/SMBv3 dialects are offered."],
        "problematic": True,
    },
    {
        "id": "smb-signing",
        "ids": ["NMAP-SMB-SIGNING"],
        "keywords": ["smb signing", "signing not required", "signing disabled"],
        "implications": [
            "Unsigned SMB sessions are more exposed to relay and man-in-the-middle attacks.",
            "Internal credential material may be abused when an attacker can influence network traffic.",
        ],
        "actions": [
            "Require SMB signing on servers and clients through policy.",
            "Reduce NTLM usage and prefer Kerberos where the environment supports it.",
            "Restrict TCP/445 between network segments to required communication paths only.",
        ],
        "validation": ["Re-run SMB security-mode checks and confirm that message signing is required."],
        "problematic": True,
    },
    {
        "id": "dangerous-http-methods",
        "ids": ["NMAP-HTTP-METHODS"],
        "keywords": ["dangerous http methods", "http methods", "trace method", "put method", "delete method"],
        "implications": [
            "Unnecessary HTTP methods can enable content modification, information disclosure, or proxy abuse.",
            "The actual impact depends on authentication, path permissions, and application routing.",
        ],
        "actions": [
            "Allow only the HTTP methods required by the application at the reverse proxy and application server.",
            "Disable TRACE and restrict PUT, DELETE, and CONNECT unless explicitly required and authenticated.",
            "Test method handling on every affected path because server-wide and application-level policies may differ.",
        ],
        "validation": ["Send unauthenticated OPTIONS and direct method requests and confirm disallowed methods return 405 or 403."],
        "problematic": True,
    },
    {
        "id": "weak-ssh",
        "ids": ["NMAP-SSH-WEAK-ALGO"],
        "keywords": ["weak ssh", "ssh-dss", "group1-sha1", "3des-cbc", "arcfour", "hmac-md5"],
        "implications": [
            "Legacy SSH algorithms reduce cryptographic assurance and may violate security baselines.",
            "Downgrade-compatible clients can continue using weak primitives even when stronger options are present.",
        ],
        "actions": [
            "Remove weak key-exchange, cipher, host-key, and MAC algorithms from the SSH server configuration.",
            "Upgrade incompatible clients and rotate legacy host keys where required.",
            "Use a centrally managed SSH cryptographic policy and monitor for configuration drift.",
        ],
        "validation": ["Repeat SSH algorithm enumeration and confirm that no prohibited algorithms are advertised."],
        "problematic": True,
    },
    {
        "id": "rdp-nla",
        "ids": ["NMAP-RDP-NLA"],
        "keywords": ["rdp nla", "network level authentication", "credssp"],
        "implications": [
            "Without NLA, the RDP service performs more work before authentication and exposes a broader pre-authentication surface.",
            "The endpoint is more susceptible to credential attacks and resource-exhaustion attempts.",
        ],
        "actions": [
            "Require Network Level Authentication and current CredSSP settings.",
            "Restrict RDP to approved administration networks or a hardened access gateway.",
            "Enforce MFA and account lockout controls for administrative access.",
        ],
        "validation": ["Reconnect with a client that does not support NLA and confirm the session is rejected before desktop negotiation."],
        "problematic": True,
    },
    {
        "id": "dns-recursion",
        "ids": ["NMAP-DNS-RECURSION"],
        "keywords": ["dns recursion", "recursion enabled"],
        "implications": [
            "Unrestricted recursion can disclose internal DNS behavior and enable amplification or abuse from reachable networks.",
            "Risk is lower when recursion is deliberately limited to trusted resolvers and clients.",
        ],
        "actions": [
            "Limit recursive queries to approved internal client networks.",
            "Disable recursion on authoritative-only servers.",
            "Apply response-rate limiting and block external access to UDP/TCP 53 where it is not required.",
        ],
        "validation": ["Query an unrelated external domain from an untrusted test segment and confirm recursion is refused."],
        "problematic": True,
    },
    {
        "id": "unauthenticated-datastore",
        "ids": ["NMAP-REDIS-INFO", "NMAP-MEMCACHED-INFO"],
        "keywords": ["unauthenticated redis", "unauthenticated memcached", "redis information", "memcached information"],
        "implications": [
            "A reachable datastore without effective authentication can expose cached data, application state, or administrative functions.",
            "Depending on configuration, an attacker may alter data, trigger denial of service, or pivot to dependent applications.",
        ],
        "actions": [
            "Bind the service to required interfaces only and restrict access with host and network firewalls.",
            "Enable supported authentication and transport protection.",
            "Review stored data and dependent credentials for exposure after access has been restricted.",
        ],
        "validation": ["Connect from an unauthorized segment and confirm the service is unreachable or requires authentication."],
        "problematic": True,
    },
    {
        "id": "snmp-exposure",
        "ids": ["NMAP-SNMP-INFO"],
        "keywords": ["snmp service information", "snmp-info", "public community"],
        "implications": [
            "SNMP can expose detailed device, software, interface, and network information useful for reconnaissance.",
            "SNMPv1/v2c community strings provide weak access control and no transport confidentiality.",
        ],
        "actions": [
            "Use SNMPv3 with authentication and privacy where monitoring is required.",
            "Restrict manager source addresses and remove default or shared community strings.",
            "Disable SNMP on systems that are not actively monitored.",
        ],
        "validation": ["Verify that unauthorized sources receive no response and that approved monitoring uses SNMPv3."],
        "problematic": True,
    },
    {
        "id": "legacy-tls",
        "keywords": ["tls 1.0", "tls1.0", "tls 1.1", "tls1.1", "sslv2", "sslv3", "legacy tls"],
        "tags": ["tls", "ssl", "crypto"],
        "implications": [
            "Legacy TLS/SSL protocols use obsolete constructions and commonly fail current compliance baselines.",
            "Clients may negotiate weaker protection than intended when old protocol versions remain enabled.",
        ],
        "actions": [
            "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 unless a documented exception exists.",
            "Require TLS 1.2 or TLS 1.3 with an approved cipher policy.",
            "Identify and upgrade dependent legacy clients before enforcement.",
        ],
        "validation": ["Repeat protocol negotiation tests and confirm only approved TLS versions succeed."],
        "problematic": True,
    },
    {
        "id": "certificate-trust",
        "keywords": ["self-signed", "self signed", "untrusted certificate", "unknown ca", "certificate trust"],
        "tags": ["certificate", "tls", "ssl"],
        "implications": [
            "Clients cannot reliably authenticate the service when certificate trust is not centrally established.",
            "Users may become conditioned to ignore warnings, increasing man-in-the-middle risk.",
        ],
        "actions": [
            "Issue the service certificate from the approved internal or public CA.",
            "Install the complete certificate chain and remove obsolete certificates.",
            "Automate certificate renewal and monitor expiry and hostname coverage.",
        ],
        "validation": ["Validate the chain, hostname, and expiry from a standard managed client without suppressing trust checks."],
        "problematic": True,
    },
    {
        "id": "certificate-expiry",
        "keywords": ["expired certificate", "certificate expired", "expires soon", "certificate expiry"],
        "tags": ["certificate", "tls", "ssl"],
        "implications": [
            "Expired or near-expiry certificates can cause service disruption and train users to bypass security warnings.",
            "Renewal failures often indicate missing ownership or ineffective certificate lifecycle controls.",
        ],
        "actions": [
            "Renew and deploy the certificate with the correct chain and subject alternative names.",
            "Assign certificate ownership and configure automated renewal with alerting before expiry.",
            "Remove unused certificates and verify all clustered nodes receive the replacement.",
        ],
        "validation": ["Confirm the new validity period and chain from every served endpoint."],
        "problematic": True,
    },
    {
        "id": "weak-cipher",
        "keywords": ["weak cipher", "rc4", "3des", "des-cbc", "null cipher", "export cipher", "sweet32"],
        "tags": ["tls", "ssl", "crypto"],
        "implications": [
            "Weak cipher suites reduce confidentiality or integrity and may permit known cryptographic attacks.",
            "Their availability can also create audit and regulatory findings even when modern ciphers are preferred.",
        ],
        "actions": [
            "Remove NULL, export, RC4, DES, 3DES, and other prohibited suites.",
            "Prefer modern AEAD suites and server-side cryptographic policy management.",
            "Retest all supported clients after tightening the cipher configuration.",
        ],
        "validation": ["Enumerate accepted cipher suites and confirm only the approved baseline remains."],
        "problematic": True,
    },
    {
        "id": "missing-security-header",
        "keywords": ["missing security header", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "hsts"],
        "tags": ["headers", "http", "misconfig"],
        "implications": [
            "Missing browser security headers weaken defense in depth against downgrade, framing, content-type confusion, and script injection.",
            "Impact depends on whether the application handles sensitive data and on its existing frontend controls.",
        ],
        "actions": [
            "Define and deploy an application-appropriate security-header baseline at the reverse proxy or application layer.",
            "Use HSTS only after confirming HTTPS is consistently available for the affected hostname.",
            "Test CSP in report-only mode before enforcement to avoid breaking required application behavior.",
        ],
        "validation": ["Inspect responses for all relevant paths and confirm the required headers and directives are present."],
        "problematic": True,
    },
    {
        "id": "default-credentials",
        "keywords": ["default login", "default credential", "default password", "factory credential"],
        "tags": ["default-login", "credentials"],
        "implications": [
            "Default or predictable credentials can provide immediate unauthorized access.",
            "Administrative interfaces with default credentials may enable full system compromise.",
        ],
        "actions": [
            "Change or disable all default accounts and rotate associated credentials immediately.",
            "Restrict the management interface to approved administration networks.",
            "Review authentication logs and system changes for evidence of prior unauthorized access.",
        ],
        "validation": ["Confirm all vendor-default credential combinations fail and approved accounts require the intended controls."],
        "problematic": True,
    },
    {
        "id": "known-cve",
        "id_pattern": r"^CVE-\d{4}-\d+$",
        "keywords": ["known vulnerability", "cve-"],
        "tags": ["cve"],
        "implications": [
            "The scanner matched a condition associated with a published vulnerability.",
            "Actual exploitability depends on the detected product version, configuration, reachability, and template accuracy.",
        ],
        "actions": [
            "Validate the affected product and version against the vendor advisory and the scanner evidence.",
            "Apply the vendor patch or documented mitigation according to severity and exposure.",
            "Restrict network access until remediation is complete and check logs for indicators relevant to the advisory.",
        ],
        "validation": ["Re-run the specific scanner template and verify the vendor-fixed version or mitigation is present."],
        "problematic": True,
    },
    {
        "id": "information-exposure",
        "keywords": ["information disclosure", "version disclosure", "exposed", "banner", "debug", "stack trace", "directory listing"],
        "tags": ["exposure", "tech"],
        "implications": [
            "Exposed technical details improve attacker reconnaissance and can reveal sensitive paths, versions, or configuration data.",
            "The finding may be low severity by itself but can materially assist exploitation of other weaknesses.",
        ],
        "actions": [
            "Remove unnecessary banners, debug output, directory listings, and sensitive unauthenticated endpoints.",
            "Restrict administrative and diagnostic interfaces to approved networks.",
            "Review the exposed data for secrets, internal addresses, usernames, and vulnerable component versions.",
        ],
        "validation": ["Repeat the unauthenticated request and confirm sensitive details are no longer returned."],
        "problematic": True,
    },
]


def normalize_severity(value: Any) -> str:
    severity = str(value or "info").strip().lower()
    return severity if severity in SEVERITY_ORDER else "info"


def priority_for_severity(severity: str) -> str:
    return {
        "critical": "P0 - immediate",
        "high": "P1 - urgent",
        "medium": "P2 - planned promptly",
        "low": "P3 - scheduled hardening",
        "info": "P4 - review",
    }[normalize_severity(severity)]


def _text_blob(finding: Dict[str, Any]) -> str:
    values = [
        finding.get("id", ""), finding.get("title", ""), finding.get("description", ""),
        finding.get("evidence", ""), finding.get("category", ""), finding.get("scanner", ""),
        " ".join(str(value) for value in finding.get("tags", []) or []),
    ]
    return " ".join(str(value or "") for value in values).lower()


def _rule_score(rule: Dict[str, Any], finding: Dict[str, Any]) -> int:
    finding_id = str(finding.get("id", ""))
    lowered_id = finding_id.lower()
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
    if lowered_id and lowered_id == str(rule.get("id", "")).lower():
        score += 80
    return score


def match_rule(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    best = None
    best_score = 0
    for rule in KNOWLEDGE_BASE:
        score = _rule_score(rule, finding)
        if score > best_score:
            best = rule
            best_score = score
    return best if best_score >= 3 else None


def _generic_context(finding: Dict[str, Any]) -> Dict[str, Any]:
    severity = normalize_severity(finding.get("severity"))
    title = finding.get("title") or finding.get("id") or "Scanner finding"
    implications = [
        "The scanner detected a condition that requires validation in the context of this asset and service.",
        "Risk depends on reachability, authentication, affected version, exposed data, and the reliability of the scanner evidence.",
    ]
    actions = [
        "Validate the observation manually or with a second independent check.",
        "Identify the owning system, affected component, business function, and exposure path.",
        "Apply the vendor-recommended fix or remove unnecessary exposure, then repeat the original test.",
    ]
    if severity == "info":
        implications[0] = "The observation is primarily contextual and does not by itself prove a security vulnerability."
    return {
        "knowledge_rule": "generic-validated-fallback",
        "risk_statement": "{} was reported on {}. Treat it as {} until validated.".format(
            title, finding.get("target", "unknown target"), priority_for_severity(severity)
        ),
        "implications": implications,
        "recommended_actions": actions,
        "validation_steps": ["Repeat the exact check and confirm the result after remediation."],
        "problematic": severity != "info",
        "confidence": "scanner-dependent",
    }


def contextualize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
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


def contextualize_all(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    contextual = [contextualize_finding(item) for item in findings]
    return sorted(
        contextual,
        key=lambda item: (
            -SEVERITY_ORDER.get(item.get("severity", "info"), 1),
            str(item.get("target", "")),
            str(item.get("title", "")),
        ),
    )


def risk_score(findings: Iterable[Dict[str, Any]]) -> int:
    """Return a bounded 0-100 operational risk indicator, not a CVSS score."""
    total = sum(SEVERITY_WEIGHTS.get(normalize_severity(item.get("severity")), 0) for item in findings)
    return min(100, total)


def overall_risk(score: int, findings: Sequence[Dict[str, Any]]) -> str:
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


def prioritized_actions(findings: Sequence[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
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
