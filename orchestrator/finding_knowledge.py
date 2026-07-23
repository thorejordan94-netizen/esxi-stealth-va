"""Contextual security finding knowledge base and report enrichment.

The scanner output remains the source of truth.  This module adds deterministic,
human-readable conclusions and remediation guidance without requiring network
access or an external AI service.  Exact scanner/template identifiers are
preferred; keyword and tag matching provide a conservative fallback for new
scanner templates.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
SEVERITY_WEIGHTS = {"Critical": 40, "High": 25, "Medium": 12, "Low": 4, "Info": 0}


def _rule(rule_id, title, ids=(), contains=(), tags=(), categories=(),
          conclusion="", implications=(), remediation=(), validation=(),
          references=(), compliance=(), likelihood="Possible",
          confidence="high"):
    return {
        "rule_id": rule_id,
        "title": title,
        "ids": tuple(value.lower() for value in ids),
        "contains": tuple(value.lower() for value in contains),
        "tags": tuple(value.lower() for value in tags),
        "categories": tuple(value.lower() for value in categories),
        "conclusion": conclusion,
        "implications": list(implications),
        "remediation": list(remediation),
        "validation": list(validation),
        "references": list(references),
        "compliance": list(compliance),
        "likelihood": likelihood,
        "confidence": confidence,
    }


# Hardcoded scenario database.  It intentionally contains actionable security
# classes rather than scanner-specific prose only, so one rule can cover new
# templates that describe the same underlying control failure.
KNOWLEDGE_BASE = [
    _rule(
        "remote-code-execution", "Remote code execution exposure",
        contains=("remote code execution", " rce", "command injection", "code execution"),
        tags=("rce", "command-injection"),
        conclusion="The affected service may allow an attacker to execute code in the service or operating-system context.",
        implications=(
            "Successful exploitation can lead to complete host compromise, credential theft, persistence, and lateral movement.",
            "On an ESXi or management host, the blast radius can include multiple virtual machines and administrative credentials.",
        ),
        remediation=(
            "Apply the vendor security update or mitigation immediately and verify that the vulnerable component version is no longer present.",
            "Restrict the affected service to dedicated management networks and authorized administration sources.",
            "Review host, authentication, and network telemetry for exploitation indicators before returning the service to normal exposure.",
        ),
        validation=("Re-run the original scanner template and confirm the vulnerable response is absent.", "Verify the installed build against the vendor fixed-version matrix."),
        compliance=("CIS: secure configuration and patch management", "NIST CSF: PR.IP-12 / DE.CM"),
        likelihood="Likely when reachable and unpatched",
    ),
    _rule(
        "authentication-bypass", "Authentication bypass",
        contains=("authentication bypass", "auth bypass", "unauthenticated access"),
        tags=("auth-bypass", "authentication-bypass"),
        conclusion="The application or service may permit access to protected functionality without the intended authentication control.",
        implications=("An unauthenticated actor may obtain privileged data or administrative actions.", "Compromise may be difficult to attribute because valid credentials are not required."),
        remediation=("Apply the vendor fix or disable the affected feature.", "Place the service behind a strongly authenticated management gateway until remediation is complete.", "Invalidate potentially exposed sessions or credentials and review access logs."),
        validation=("Attempt the previously detected unauthenticated request and confirm it is rejected.",),
        compliance=("CIS: access control management", "NIST CSF: PR.AA"),
        likelihood="Likely when the endpoint is reachable",
    ),
    _rule(
        "default-credentials", "Default or weak administrative credentials",
        contains=("default credential", "default login", "default password", "weak password"),
        tags=("default-login", "default-credentials"),
        conclusion="A service appears to accept a default or predictably weak authentication secret.",
        implications=("Attackers can obtain administrative access without exploiting a software defect.", "Compromised credentials can be reused for lateral movement across similarly configured systems."),
        remediation=("Replace default credentials with unique, high-entropy secrets stored in the approved privileged-access system.", "Disable or rename unused default accounts and enforce MFA where supported.", "Search for the same account pattern across the environment."),
        validation=("Confirm the default credential no longer authenticates and the replacement account policy is enforced.",),
        compliance=("CIS Controls 5 and 6", "NIST CSF: PR.AA"),
        likelihood="Highly likely when exposed",
    ),
    _rule(
        "anonymous-ftp", "Anonymous FTP access",
        ids=("nmap-ftp-anon",), contains=("anonymous ftp",), tags=("ftp",),
        conclusion="The FTP service permits anonymous authentication, which can expose files or allow untracked data transfer depending on directory permissions.",
        implications=("Sensitive files may be downloaded without identity attribution.", "Writable anonymous directories can be abused for malware staging or data exchange."),
        remediation=("Disable anonymous FTP unless there is a documented business requirement.", "Prefer SFTP or another authenticated encrypted transfer service.", "Review anonymous directories for sensitive or attacker-supplied files and enforce read-only permissions if the feature must remain."),
        validation=("Verify anonymous login is rejected and confirm the replacement transfer workflow requires authentication and encryption.",),
        compliance=("CIS: controlled use of administrative and transfer protocols",),
    ),
    _rule(
        "smbv1", "Obsolete SMBv1 protocol enabled",
        ids=("nmap-smb1",), contains=("smbv1", "smb1 protocol", "nt lm 0.12"), tags=("smb", "legacy"),
        conclusion="The host supports SMBv1, an obsolete protocol that lacks modern security protections and has a history of critical remote exploitation.",
        implications=("The service increases exposure to downgrade, relay, and legacy SMB exploitation paths.", "A compromise can provide rapid lateral movement in Windows-compatible networks."),
        remediation=("Disable SMBv1 on the server and all clients that communicate with it.", "Upgrade or isolate legacy applications that still require SMBv1.", "Require SMBv2/SMBv3 with signing and, where appropriate, encryption."),
        validation=("Re-run SMB protocol enumeration and confirm only approved SMBv2/SMBv3 dialects are offered.",),
        references=("Microsoft SMBv1 deprecation guidance",),
        compliance=("CIS Microsoft benchmarks: disable SMBv1",),
        likelihood="Possible to likely on reachable internal networks",
    ),
    _rule(
        "smb-signing", "SMB signing is not required",
        ids=("nmap-smb-signing",), contains=("smb signing not required", "signing disabled"), tags=("smb",),
        conclusion="SMB traffic is not required to be cryptographically signed, permitting modification or relay in suitable network positions.",
        implications=("An attacker with network access may relay credentials or tamper with SMB sessions.", "The risk is amplified where NTLM is accepted and network segmentation is weak."),
        remediation=("Require SMB signing on servers and clients through centrally managed policy.", "Reduce or disable NTLM where feasible and prioritize Kerberos.", "Segment SMB services and restrict ports 139/445 to required peers."),
        validation=("Re-run SMB security-mode enumeration and confirm signing is required.",),
        compliance=("CIS Microsoft benchmarks: digitally sign communications",),
    ),
    _rule(
        "weak-ssh", "Weak SSH cryptographic algorithms",
        ids=("nmap-ssh-weak-algo",), contains=("weak ssh", "ssh-dss", "group1-sha1", "arcfour", "3des-cbc"), tags=("ssh", "crypto"),
        conclusion="The SSH service offers obsolete algorithms that weaken confidentiality, integrity, or resistance to downgrade attacks.",
        implications=("Legacy algorithms can permit weaker session protection and may enable downgrade against older clients.", "Their presence usually indicates outdated software or configuration drift."),
        remediation=("Disable obsolete key exchange, host-key, cipher, and MAC algorithms.", "Retain modern algorithms such as curve25519, strong ECDH, AES-GCM/ChaCha20-Poly1305, and SHA-2 MACs as supported.", "Upgrade SSH implementations that cannot provide a modern algorithm set."),
        validation=("Enumerate SSH algorithms again and compare the result with the approved cryptographic baseline.",),
        compliance=("CIS: use approved cryptographic protocols",),
    ),
    _rule(
        "rdp-nla", "RDP Network Level Authentication not enforced",
        ids=("nmap-rdp-nla",), contains=("rdp nla", "network level authentication: not supported"), tags=("rdp",),
        conclusion="RDP appears reachable without mandatory Network Level Authentication.",
        implications=("The server exposes more of the RDP stack before authentication and is more susceptible to credential and protocol attacks.", "Unauthenticated connection handling increases resource-exhaustion and exploit exposure."),
        remediation=("Require Network Level Authentication and restrict RDP to managed administration networks or a secure access gateway.", "Enable MFA at the gateway or identity layer and keep the RDP service fully patched."),
        validation=("Confirm non-NLA clients cannot establish an RDP session and re-run encryption enumeration.",),
    ),
    _rule(
        "dns-recursion", "DNS recursion exposed",
        ids=("nmap-dns-recursion",), contains=("dns recursion", "recursion appears to be enabled"), tags=("dns",),
        conclusion="The DNS service accepts recursive queries from the assessment network.",
        implications=("Unauthorized clients may use the resolver for reconnaissance, policy bypass, or amplification if the service is exposed more broadly.", "The resolver can leak internal lookup behavior and consume resources."),
        remediation=("Restrict recursion to explicitly authorized client networks.", "Separate authoritative and recursive DNS roles where practical.", "Apply response-rate limiting and ensure the service is not reachable from untrusted networks."),
        validation=("Submit a recursive query from an unauthorized segment and confirm it is refused.",),
    ),
    _rule(
        "redis-exposure", "Unauthenticated Redis access",
        ids=("nmap-redis-info",), contains=("unauthenticated redis",), tags=("redis",),
        conclusion="Redis returned service information without application credentials, indicating potentially unauthenticated data-plane access.",
        implications=("An attacker may read or alter cached data, retrieve secrets, or abuse dangerous Redis functionality.", "Misconfigured Redis has historically enabled persistence and remote compromise in permissive deployments."),
        remediation=("Bind Redis to trusted interfaces only and enforce authentication/ACLs.", "Use TLS where supported and block direct access from user or untrusted network segments.", "Review the data set and host for unauthorized changes."),
        validation=("Confirm unauthenticated INFO and data commands are rejected from the assessment source.",),
    ),
    _rule(
        "memcached-exposure", "Unauthenticated Memcached access",
        ids=("nmap-memcached-info",), contains=("unauthenticated memcached",), tags=("memcached",),
        conclusion="Memcached is reachable without authentication and exposes service information.",
        implications=("Cached application data may be disclosed or modified.", "UDP exposure can enable amplification abuse when reachable from untrusted networks."),
        remediation=("Restrict Memcached to application hosts and disable UDP unless explicitly required.", "Use network controls or a protected local socket because Memcached has no native strong authentication model."),
        validation=("Verify the service is unreachable from unauthorized segments and UDP is disabled when unused.",),
    ),
    _rule(
        "snmp-exposure", "SNMP information exposure",
        ids=("nmap-snmp-info",), contains=("snmp service information exposed", "public community"), tags=("snmp",),
        conclusion="SNMP responded to unauthenticated or community-based queries from the assessment network.",
        implications=("System, network, and software inventory data can accelerate targeted attacks.", "Writable or default communities may permit configuration changes."),
        remediation=("Use SNMPv3 with authentication and privacy.", "Remove default communities and restrict manager addresses with host and network controls.", "Verify that read-write communities are not enabled."),
        validation=("Confirm SNMPv1/v2c and default-community queries fail from unauthorized sources.",),
    ),
    _rule(
        "dangerous-http-methods", "Potentially dangerous HTTP methods",
        ids=("nmap-http-methods",), contains=("dangerous http methods", "trace method", "put method", "delete method"), tags=("http",),
        conclusion="The web service advertises HTTP methods that can alter resources, proxy traffic, or expose diagnostic behavior and therefore require explicit justification.",
        implications=("PUT or DELETE may permit unauthorized content modification when authorization is weak.", "TRACE can aid cross-site tracing and CONNECT can create an unintended proxy path."),
        remediation=("Allow only methods required by the application at the reverse proxy and application server.", "Enforce authentication and authorization independently for every state-changing method.", "Disable TRACE and CONNECT unless a documented design requires them."),
        validation=("Issue OPTIONS and direct method requests and confirm unnecessary methods return 405 or 403.",),
    ),
    _rule(
        "deprecated-tls", "Deprecated TLS protocol enabled",
        ids=("ssl-deprecated-protocols",), contains=("tls 1.0", "tls 1.1", "deprecated tls", "obsolete tls"), tags=("tls", "ssl"), categories=("crypto", "vulnerability"),
        conclusion="The endpoint supports a deprecated TLS protocol that no longer meets modern cryptographic baselines.",
        implications=("Clients may be downgraded to weaker protocol behavior and legacy cipher suites.", "The configuration can violate organizational, regulatory, or vendor security requirements."),
        remediation=("Disable TLS 1.0 and TLS 1.1 and require TLS 1.2 or TLS 1.3.", "Verify all dependent clients support the modern protocol baseline before enforcement.", "Remove legacy cipher suites and retest the complete negotiation matrix."),
        validation=("Confirm handshakes using TLS 1.0 and TLS 1.1 fail while approved TLS 1.2/1.3 handshakes succeed.",),
        compliance=("PCI DSS: strong cryptography", "CIS: approved TLS protocols"),
    ),
    _rule(
        "self-signed-certificate", "Self-signed TLS certificate",
        contains=("self-signed certificate", "self signed certificate"), tags=("ssl", "certificate"), categories=("crypto", "vulnerability"),
        conclusion="The endpoint uses a self-signed certificate that cannot be validated through the expected trust chain.",
        implications=("Users and automation may ignore certificate warnings, making man-in-the-middle attacks harder to detect.", "Identity assurance and centralized certificate lifecycle controls are reduced."),
        remediation=("Issue a certificate from the approved internal or public CA with correct subject alternative names.", "Deploy the required CA trust chain to clients and remove instructions that bypass validation.", "Automate certificate renewal and expiry monitoring."),
        validation=("Validate the endpoint with a clean trust store and confirm hostname and chain verification succeed without overrides.",),
    ),
    _rule(
        "expired-certificate", "Expired or not-yet-valid certificate",
        contains=("certificate expired", "expired certificate", "not yet valid"), tags=("certificate", "ssl"), categories=("crypto", "vulnerability"),
        conclusion="The TLS certificate is outside its validity period and cannot provide normal identity assurance.",
        implications=("Clients may reject the service or operators may disable certificate validation to restore connectivity.", "The condition indicates a certificate lifecycle or monitoring failure."),
        remediation=("Replace the certificate with a valid certificate from the approved CA.", "Correct system time if inaccurate and implement renewal alerts well before expiry."),
        validation=("Confirm the full certificate chain is valid at the current time and renewal monitoring is active.",),
    ),
    _rule(
        "weak-certificate-crypto", "Weak certificate cryptography",
        contains=("weak key", "1024 bit", "sha1", "md5withrsa", "weak signature"), tags=("certificate", "crypto"), categories=("crypto", "vulnerability"),
        conclusion="The certificate or key uses cryptographic parameters below the approved security baseline.",
        implications=("Weak signatures or key sizes reduce resistance to forgery and cryptanalytic attack.", "Modern clients may reject the certificate, encouraging insecure compatibility exceptions."),
        remediation=("Reissue the certificate with an approved key type and size and a SHA-256-or-stronger signature.", "Remove weak certificates and private keys from all listeners and backups according to key-management policy."),
        validation=("Inspect the deployed certificate and confirm the approved key size, signature algorithm, and chain.",),
    ),
    _rule(
        "missing-hsts", "HTTP Strict Transport Security missing",
        contains=("missing hsts", "strict-transport-security", "downgrade prevention"), tags=("headers", "misconfig"), categories=("web", "vulnerability"),
        conclusion="The HTTPS service does not instruct compatible browsers to enforce HTTPS for subsequent requests.",
        implications=("Users can be exposed to downgrade or SSL-stripping attacks during an initial HTTP interaction.", "The practical risk depends on whether users access the service through browsers and whether HTTP is reachable."),
        remediation=("Add a Strict-Transport-Security header with an appropriate max-age after confirming HTTPS is consistently available.", "Include subdomains only after validating every covered hostname; use preload only after operational review.", "Redirect HTTP to HTTPS and remove mixed-content dependencies."),
        validation=("Confirm the header is returned on HTTPS responses and browser traffic cannot remain on HTTP.",),
    ),
    _rule(
        "missing-csp", "Content Security Policy missing",
        contains=("missing csp", "content-security-policy", "xss mitigation"), tags=("headers", "misconfig"), categories=("web", "vulnerability"),
        conclusion="The application does not provide a Content Security Policy to constrain browser content execution and loading.",
        implications=("A separate injection flaw can have greater impact because the browser has fewer restrictions on scripts and content sources.", "CSP absence is a defense-in-depth gap rather than proof of exploitable XSS by itself."),
        remediation=("Deploy a restrictive, application-specific Content-Security-Policy and eliminate unsafe-inline/unsafe-eval where possible.", "Start with report-only telemetry, correct violations, then enforce the policy."),
        validation=("Confirm the enforced CSP is present on relevant responses and does not contain broad wildcard or unsafe directives without justification.",),
    ),
    _rule(
        "clickjacking-protection", "Clickjacking protection missing",
        contains=("missing x-frame-options", "clickjacking protection", "frame-ancestors"), tags=("headers", "misconfig"), categories=("web", "vulnerability"),
        conclusion="The application may be framed by another site because frame restrictions were not observed.",
        implications=("An attacker may overlay or disguise application controls to trick an authenticated user into unintended actions.",),
        remediation=("Set CSP frame-ancestors to the required origins and use X-Frame-Options for legacy-client compatibility where needed.", "Confirm legitimate embedding use cases before enforcing deny or same-origin."),
        validation=("Attempt to frame the application from an unauthorized origin and confirm the browser blocks it.",),
    ),
    _rule(
        "mime-sniffing", "MIME-sniffing protection missing",
        contains=("missing x-content-type-options", "mime-sniffing prevention"), tags=("headers", "misconfig"), categories=("web", "vulnerability"),
        conclusion="The response does not explicitly disable browser MIME-type sniffing.",
        implications=("Incorrectly typed user-controlled content may be interpreted as active content in some browser contexts.",),
        remediation=("Return X-Content-Type-Options: nosniff and set accurate Content-Type headers for every response.",),
        validation=("Confirm the nosniff header is present and uploaded/static content is served with correct media types.",),
    ),
    _rule(
        "cookie-secure", "Session cookie missing Secure flag",
        contains=("cookie missing 'secure'", "cookie missing secure"), tags=("cookie",), categories=("web", "vulnerability"),
        conclusion="A cookie used by an HTTPS application is not restricted to encrypted transport.",
        implications=("The browser may transmit the cookie over HTTP, exposing it to interception where HTTP access is possible.",),
        remediation=("Set the Secure flag on all authentication and sensitive cookies.", "Redirect or disable HTTP and review cookie Domain, Path, SameSite, and lifetime settings."),
        validation=("Inspect Set-Cookie responses and confirm sensitive cookies include Secure and are never sent over HTTP.",),
    ),
    _rule(
        "cookie-httponly", "Session cookie missing HttpOnly flag",
        contains=("cookie missing 'httponly'", "cookie missing httponly"), tags=("cookie",), categories=("web", "vulnerability"),
        conclusion="A cookie is accessible to client-side scripts because HttpOnly is not set.",
        implications=("A successful script injection can read and exfiltrate the cookie, increasing session-theft impact.", "HttpOnly is defense in depth and does not replace XSS remediation."),
        remediation=("Set HttpOnly on session and sensitive cookies unless client-side access is explicitly required.", "Review the application for script injection and use short session lifetimes and reauthentication for critical actions."),
        validation=("Confirm document.cookie cannot read the protected cookie and the application still functions.",),
    ),
    _rule(
        "esxi-management-exposure", "ESXi management interface or sensitive path exposed",
        contains=("esxi path accessible", "vmware esxi", "vsphere client", "management interface"), tags=("esxi", "vmware"),
        conclusion="A VMware/ESXi management surface is reachable from the assessment network.",
        implications=("Management interfaces are high-value targets because compromise can affect hypervisor configuration and hosted virtual machines.", "Even when patched, broad reachability increases password-attack and zero-day exposure."),
        remediation=("Restrict ESXi and vCenter management interfaces to dedicated administration networks and approved jump hosts.", "Require MFA and privileged-access workflows, remove direct user-network access, and keep VMware builds current.", "Monitor management authentication and configuration changes centrally."),
        validation=("Verify unauthorized network segments cannot connect and approved administrators still reach the interface through the controlled path.",),
        compliance=("CIS VMware ESXi benchmark: management network isolation",),
    ),
    _rule(
        "sqli", "SQL injection",
        contains=("sql injection", "sqli"), tags=("sqli",),
        conclusion="User-controlled input may alter a backend SQL query.",
        implications=("An attacker may read or modify application data, bypass authentication, or execute database-specific functions.",),
        remediation=("Use parameterized queries for all database operations and remove dynamic query concatenation.", "Apply least-privilege database accounts and validate authorization independently of query construction.", "Review logs and data integrity for exploitation evidence."),
        validation=("Repeat the exact test with safe verification payloads and confirm input is treated strictly as data.",),
    ),
    _rule(
        "xss", "Cross-site scripting",
        contains=("cross-site scripting", " xss"), tags=("xss",),
        conclusion="Untrusted input may execute as script in a user's browser.",
        implications=("Attackers may steal sessions, perform actions as the victim, or alter displayed content.",),
        remediation=("Apply context-aware output encoding and safe templating.", "Sanitize only where rich HTML is required and deploy a restrictive CSP as defense in depth.", "Protect session cookies with HttpOnly, Secure, and appropriate SameSite settings."),
        validation=("Confirm the reported input is rendered as inert text in every affected output context.",),
    ),
    _rule(
        "path-traversal", "Path traversal or local file inclusion",
        contains=("path traversal", "directory traversal", "local file inclusion", " lfi"), tags=("lfi", "path-traversal"),
        conclusion="Input may escape an intended file-system path and access unintended files.",
        implications=("Sensitive configuration, credentials, keys, or operating-system files may be disclosed.", "Writable traversal paths may enable code execution in some application designs."),
        remediation=("Use server-side allowlisted identifiers instead of user-supplied paths.", "Canonicalize paths and enforce that resolved paths remain within the intended directory.", "Run the service with minimal file-system permissions and rotate exposed secrets."),
        validation=("Confirm traversal encodings and absolute paths cannot access files outside the approved directory.",),
    ),
    _rule(
        "exposed-admin", "Administrative service exposure",
        contains=("admin panel", "administrative interface", "management console", "dashboard exposed"),
        tags=("panel", "exposure", "admin"),
        conclusion="An administrative interface is reachable from the assessment network.",
        implications=("The interface provides a concentrated target for credential attacks, misconfiguration abuse, and future software vulnerabilities.",),
        remediation=("Restrict access to approved management networks or a zero-trust access gateway.", "Require MFA, strong privileged-account controls, and current software versions.", "Disable unused administrative listeners."),
        validation=("Confirm the interface is unreachable from unauthorized segments and authentication controls meet the privileged-access baseline.",),
    ),
    _rule(
        "known-cve", "Known vulnerability detected",
        contains=("cve-",), tags=("cve",), categories=("vulnerability",),
        conclusion="The scanner matched behavior associated with a published vulnerability. The exact affected-version and exploitability conditions must be confirmed against the vendor advisory.",
        implications=("Impact ranges from information disclosure to full compromise depending on the referenced vulnerability.", "Scanner evidence is significant but version and configuration prerequisites can produce false positives."),
        remediation=("Identify the authoritative vendor advisory for the reported CVE and apply the fixed version or documented mitigation.", "Confirm the component inventory and exposure path, then prioritize using severity, reachability, and asset criticality.", "Retest after remediation and retain evidence of the fixed build."),
        validation=("Verify the installed version and configuration against the vendor advisory and re-run the matching template.",),
        confidence="medium",
    ),
    _rule(
        "generic-exposure", "Unnecessary service or information exposure",
        contains=("exposed", "information disclosure", "information access"), tags=("exposure",),
        conclusion="The service exposes information or functionality beyond what appears necessary for unauthenticated clients on the assessment network.",
        implications=("The exposure can improve attacker reconnaissance and may reveal data, software versions, or control interfaces.",),
        remediation=("Confirm the business requirement and restrict the service to required clients.", "Remove unauthenticated information responses, minimize banners, and segment the service.",),
        validation=("Repeat the request from an unauthorized source and confirm the information or function is no longer available.",),
        confidence="medium",
    ),
    _rule(
        "generic-misconfiguration", "Security configuration weakness",
        contains=("misconfiguration", "not enforced", "missing", "weak", "deprecated", "obsolete"), tags=("misconfig",),
        conclusion="The scanner identified a configuration that does not meet a typical hardened baseline.",
        implications=("The weakness may increase the impact or likelihood of a separate attack even when it is not independently exploitable.",),
        remediation=("Compare the affected service with the approved hardening baseline and vendor guidance.", "Change the specific control identified by the evidence, test dependent applications, and document any accepted exception."),
        validation=("Re-run the same check and independently inspect the effective service configuration.",),
        confidence="medium",
    ),
    _rule(
        "technology-detection", "Technology or service fingerprint",
        contains=("technology detected", "version detected", "service detected"), tags=("tech",),
        conclusion="The scanner identified a technology or version. This is an inventory observation, not automatically a vulnerability.",
        implications=("Version disclosure can improve attacker targeting when the software is outdated or unnecessarily exposed.",),
        remediation=("Verify the asset inventory, patch status, and exposure requirement.", "Suppress unnecessary version banners where operationally feasible, but prioritize patching and access control over cosmetic banner changes."),
        validation=("Confirm the detected product/version matches the authoritative inventory and is within support.",),
        confidence="medium",
    ),
]


GENERIC_CONTEXT = {
    "Critical": {
        "conclusion": "The scanner reported a critical security condition that can plausibly lead to severe compromise and requires immediate validation.",
        "implications": ["Potential impact includes complete system compromise, major data exposure, or broad administrative control."],
        "remediation": ["Validate the finding immediately, apply the vendor fix or containment, and restrict exposure until remediation is confirmed.", "Review relevant telemetry for evidence of exploitation."],
    },
    "High": {
        "conclusion": "The scanner reported a high-impact weakness that should be treated as a priority remediation item.",
        "implications": ["Exploitation could materially affect confidentiality, integrity, availability, or privileged access."],
        "remediation": ["Confirm affected versions and prerequisites, apply the fix or mitigation, and reduce network exposure."],
    },
    "Medium": {
        "conclusion": "The finding represents a meaningful control weakness whose practical risk depends on reachability, authentication, and asset criticality.",
        "implications": ["The weakness can enable or amplify another attack path and should not remain indefinitely."],
        "remediation": ["Correct the reported configuration or software condition during the next planned security remediation window."],
    },
    "Low": {
        "conclusion": "The finding is a defense-in-depth or exposure issue with limited standalone impact.",
        "implications": ["Risk becomes more relevant when combined with other weaknesses or broad network reachability."],
        "remediation": ["Harden the configuration when practical and document any accepted exception."],
    },
    "Info": {
        "conclusion": "This is an informational observation that should be checked against the expected asset inventory and exposure design.",
        "implications": ["No direct vulnerability is proven, but the observation can support attack-surface management."],
        "remediation": ["Verify that the service, product, and exposure are intentional and maintained."],
    },
}


def canonical_severity(value: Any) -> str:
    text = str(value or "Info").strip().lower()
    mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium", "low": "Low", "info": "Info", "informational": "Info"}
    return mapping.get(text, "Info")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join("{} {}".format(key, _text(item)) for key, item in value.items())
    return str(value)


def _rule_score(rule: Dict[str, Any], finding: Dict[str, Any]) -> int:
    source_id = str(finding.get("source_id", "")).lower()
    category = str(finding.get("category", "")).lower()
    tags = set(str(value).lower() for value in finding.get("tags", []))
    haystack = " ".join([
        source_id,
        str(finding.get("title", "")).lower(),
        str(finding.get("description", "")).lower(),
        str(finding.get("evidence", "")).lower(),
        " ".join(sorted(tags)),
    ])
    score = 0
    if source_id and source_id in rule["ids"]:
        score += 100
    for token in rule["contains"]:
        if token and token in haystack:
            score += 18
    score += 12 * len(tags.intersection(rule["tags"]))
    if category and category in rule["categories"]:
        score += 8
    if rule["categories"] and category not in rule["categories"]:
        score -= 5
    return score


def match_rule(finding: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], int]:
    ranked = sorted(((_rule_score(rule, finding), rule) for rule in KNOWLEDGE_BASE), key=lambda item: item[0], reverse=True)
    if not ranked or ranked[0][0] <= 0:
        return None, 0
    return ranked[0][1], ranked[0][0]


def _priority(severity: str, category: str) -> str:
    if severity == "Critical":
        return "P0 - contain and remediate immediately"
    if severity == "High":
        return "P1 - remediate urgently"
    if severity == "Medium":
        return "P2 - remediate in the next planned security window"
    if severity == "Low":
        return "P3 - harden and track"
    if category == "exposure":
        return "P3 - verify exposure is intentional"
    return "P4 - inventory and monitor"


def contextualize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    severity = canonical_severity(finding.get("severity"))
    category = str(finding.get("category", "vulnerability"))
    rule, score = match_rule(finding)
    fallback = GENERIC_CONTEXT[severity]
    if rule:
        conclusion = rule["conclusion"] or fallback["conclusion"]
        implications = rule["implications"] or fallback["implications"]
        remediation = rule["remediation"] or fallback["remediation"]
        validation = rule["validation"] or ["Re-run the originating check and independently verify the effective configuration."]
        title = finding.get("title") or rule["title"]
        references = list(dict.fromkeys(list(finding.get("references", [])) + rule["references"]))
        context = {
            "knowledge_rule": rule["rule_id"],
            "knowledge_title": rule["title"],
            "match_score": score,
            "confidence": rule["confidence"],
            "likelihood": rule["likelihood"],
            "conclusion": conclusion,
            "implications": implications,
            "remediation": remediation,
            "validation": validation,
            "compliance": rule["compliance"],
        }
    else:
        title = finding.get("title") or "Unclassified scanner finding"
        references = list(finding.get("references", []))
        context = {
            "knowledge_rule": "generic-{}".format(severity.lower()),
            "knowledge_title": "Generic {} finding".format(severity.lower()),
            "match_score": 0,
            "confidence": "low",
            "likelihood": "Requires validation",
            "conclusion": fallback["conclusion"],
            "implications": fallback["implications"],
            "remediation": fallback["remediation"],
            "validation": ["Validate the scanner evidence, affected version, reachability, and required preconditions before closure."],
            "compliance": [],
        }
    result = dict(finding)
    result["title"] = title
    result["severity"] = severity
    result["priority"] = _priority(severity, category)
    result["references"] = references
    result["context"] = context
    stable = "|".join(str(result.get(key, "")) for key in ("category", "host", "port", "source_id", "title", "evidence"))
    result["finding_key"] = hashlib.sha256(stable.encode("utf-8", errors="replace")).hexdigest()[:16]
    return result


def _base_finding(category, host, port, title, severity, description="", evidence="", source_id="", scanner="", tags=None, references=None, url=""):
    return {
        "category": category,
        "host": host or "",
        "port": int(port or 0),
        "url": url or "",
        "title": title or source_id or "Finding",
        "severity": canonical_severity(severity),
        "description": description or "",
        "evidence": _text(evidence),
        "source_id": source_id or "",
        "scanner": scanner or "",
        "tags": list(tags or []),
        "references": list(references or []),
    }


def normalize_report_findings(report) -> List[Dict[str, Any]]:
    findings = []

    for item in report.findings_vulns:
        findings.append(_base_finding(
            "vulnerability", item.host, item.port, item.name, item.severity,
            item.description, item.evidence, item.template_id, item.scanner,
            item.tags, item.reference, item.url,
        ))

    for web_result in report.findings_web:
        for item in web_result.findings:
            findings.append(_base_finding(
                "web", web_result.host, web_result.port, item.title, item.severity,
                item.description, item.evidence, item.id, "web-assessment", ["web"], [], web_result.url,
            ))

    for crypto in report.findings_crypto:
        produced = False
        for vulnerability in crypto.vulnerabilities:
            findings.append(_base_finding(
                "crypto", crypto.host, crypto.port, vulnerability, crypto.severity,
                "TLS or certificate analysis reported this condition.", vulnerability,
                "TLS-{}".format(hashlib.sha1(vulnerability.encode("utf-8", errors="replace")).hexdigest()[:10]),
                crypto.scan_method, ["tls", "crypto"], [], "",
            ))
            produced = True
        certificate = crypto.certificate
        if certificate and certificate.self_signed and not any("self-signed" in str(value).lower() for value in crypto.vulnerabilities):
            findings.append(_base_finding(
                "crypto", crypto.host, crypto.port, "Self-signed certificate", crypto.severity,
                "The endpoint certificate is self-signed.", certificate.subject,
                "TLS-SELF-SIGNED", crypto.scan_method, ["tls", "certificate"], [], "",
            ))
            produced = True
        if not produced and crypto.grade not in ("A+", "A", "N/A"):
            findings.append(_base_finding(
                "crypto", crypto.host, crypto.port, "TLS configuration grade {}".format(crypto.grade), crypto.severity,
                "The TLS scanner assigned a suboptimal configuration grade.", ", ".join(crypto.cipher_suites[:10]),
                "TLS-GRADE-{}".format(crypto.grade), crypto.scan_method, ["tls", "misconfig"], [], "",
            ))

    # Explicitly assess high-value or plaintext service exposure.  Every port is
    # still listed in the asset inventory; only notable exposures become findings.
    for host in report.findings_infrastructure:
        for port in host.ports:
            service = (port.service or "").lower()
            title = ""
            severity = "Info"
            tags = ["exposure", service or "unknown-service"]
            if port.port in (21, 23, 69, 110, 143) or service in ("ftp", "telnet", "tftp", "pop3", "imap"):
                title = "Plaintext service exposed: {}".format(service or port.port)
                severity = "Medium"
            elif port.port in (22, 3389, 5900, 5985, 5986, 902) or any(value in service for value in ("ssh", "rdp", "vnc", "winrm", "vmware-auth")):
                title = "Remote administration service exposed: {}".format(service or port.port)
                severity = "Low"
                tags.append("admin")
            elif port.port in (2375, 2376, 3306, 5432, 6379, 9200, 11211, 27017) or any(value in service for value in ("docker", "mysql", "postgres", "redis", "elasticsearch", "memcached", "mongodb")):
                title = "Data or control service exposed: {}".format(service or port.port)
                severity = "Medium"
                tags.append("admin")
            elif host.role == "esxi_host" and port.port in (443, 902, 5989, 8000, 9080, 9443):
                title = "ESXi management service reachable"
                severity = "Medium"
                tags.extend(["esxi", "vmware", "admin"])
            if title:
                findings.append(_base_finding(
                    "exposure", host.host, port.port, title, severity,
                    "The service is reachable from the assessment source and should be checked against the intended network-access design.",
                    "{} {}/{} {}".format(port.state, port.protocol, port.port, port.version).strip(),
                    "PORT-{}-{}".format(port.protocol.upper(), port.port), "nmap", tags, [], "",
                ))

    return [contextualize_finding(item) for item in findings]


def _risk_rating(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 10:
        return "Low"
    return "Informational"


def _risk_score(findings: Iterable[Dict[str, Any]]) -> int:
    ordered = sorted((SEVERITY_WEIGHTS[item["severity"]] for item in findings), reverse=True)
    if not ordered:
        return 0
    # The highest finding drives the baseline; additional findings contribute
    # with diminishing weight so large inventories do not automatically score 100.
    total = ordered[0]
    multipliers = (0.55, 0.35, 0.20, 0.12, 0.08)
    for index, value in enumerate(ordered[1:]):
        multiplier = multipliers[index] if index < len(multipliers) else 0.04
        total += value * multiplier
    return min(100, int(round(total)))


def build_contextual_analysis(report) -> Dict[str, Any]:
    findings = normalize_report_findings(report)
    findings.sort(key=lambda item: (-SEVERITY_ORDER[item["severity"]], item["host"], item["port"], item["title"]))
    severity_distribution = {name: 0 for name in ("Critical", "High", "Medium", "Low", "Info")}
    for item in findings:
        severity_distribution[item["severity"]] += 1

    score = _risk_score(findings)
    actions = []
    seen_actions = set()
    for item in findings:
        if item["severity"] not in ("Critical", "High", "Medium"):
            continue
        first_action = item["context"]["remediation"][0] if item["context"]["remediation"] else "Validate and remediate the finding."
        key = (item["host"], item["context"]["knowledge_rule"], first_action)
        if key in seen_actions:
            continue
        seen_actions.add(key)
        actions.append({
            "priority": item["priority"],
            "severity": item["severity"],
            "target": "{}:{}".format(item["host"], item["port"]) if item["port"] else item["host"],
            "finding": item["title"],
            "action": first_action,
        })
        if len(actions) >= 12:
            break

    protocols = {"tcp": 0, "udp": 0}
    for host in report.findings_infrastructure:
        for port in host.ports:
            protocols[port.protocol] = protocols.get(port.protocol, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "knowledge_base_version": "2026.07",
        "method": "deterministic hardcoded scenario matching with conservative generic fallback",
        "risk_score": score,
        "risk_rating": _risk_rating(score),
        "severity_distribution": severity_distribution,
        "priority_actions": actions,
        "coverage": {
            "hosts_in_report": len(report.findings_infrastructure),
            "open_ports_total": sum(protocols.values()),
            "open_ports_by_protocol": protocols,
            "web_endpoints_assessed": len(report.findings_web),
            "tls_endpoints_assessed": len(report.findings_crypto),
            "scanner_findings": len(report.findings_vulns),
            "execution_errors": len(report.execution_errors),
        },
        "findings": findings,
        "interpretation_note": "Context is selected from a local rule base. Scanner evidence and vendor advisories remain authoritative; unknown scenarios are not assigned fabricated CVE-specific facts.",
    }


def build_enriched_report(report) -> Dict[str, Any]:
    payload = report.to_dict()
    payload["report_summary"] = report.summary()
    payload["contextual_analysis"] = build_contextual_analysis(report)
    payload["schema_version"] = "2.2-contextual"
    return payload


def write_enriched_json(report, filepath: str, indent: int = 2):
    payload = build_enriched_report(report)
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=indent, ensure_ascii=False, sort_keys=False)
        handle.write("\n")
