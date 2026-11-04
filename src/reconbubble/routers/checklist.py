from __future__ import annotations
from pathlib import Path
import asyncio, json, ipaddress, os, re, shlex, socket, ssl, sys, tempfile, uuid
import html as html_lib
from urllib.parse import quote_plus, parse_qsl, urlencode, urlsplit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import APIRouter, Request, UploadFile, File, Form, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse

from sqlalchemy import select, func, text, or_
from sqlalchemy.orm import Session

from .. import netproxy
from .. import nsecatalog
from ..nse import SEVERITY_RANK
from ..models import (
    Host,
    Service,
    Subdomain,
    Email,
    Artifact,
    ServiceEvidence,
    Document,
    Note,
    GlobalNote,
    ScopeItem,
    ScopeExclusion,
    CloudItem,
    ValidUser,
    Credential,
    NameItem,
    SocialMedia,
    WebUrl,
    DomainInfo,
    PasswordSprayService,
    PasswordSprayAttempt,
    ProfilingRow,
    RegistrarInfo,
    AppSettings,
    UploadLog,
    SmbShare,
    TimelineDay,
    TimelineEntry,
    WebScreenshot,
    WebProtocolProbe,
    ServiceApiKey,
    NseResult,
    ServiceFinding,
)
from ..parsers import (
    upsert_artifact,
    import_nmap_xml,
    import_subdomains,
    import_emails,
    import_document,
    extract_doc_names,
    extract_doc_software,
    upsert_host,
    import_ad_users,
    import_names_emails,
    import_creds_to_names,
    import_web_urls,
    import_names,
    import_prowl_phase1,
    import_zone_transfers,
    import_smtp,
    import_bbot,
    import_bbot_cloud,
    import_mixed_hashes,
    import_smbmap,
    resolve_ips_concurrent,
    DOMAIN_RE,
    hostname_as_domain,
    link_host_domain as parser_link_host_domain,
)
from ..tools import (
    build_tools,
    find_tool,
    run_tool,
    run_cero,
    run_vhost_socket,
    run_builtin,
    _CERO_DEFAULT_PORTS,
    keys_for_tool,
    parse_tool_config,
    service_key_registry,
    tool_config_preview,
    tool_version,
    validate_target,
    validate_wordlist,
    validate_socket,
    validate_ip,
    validate_resolvers,
    run_rev_dns,
    REVDNS_RESOLVERS,
    REVDNS_MAX_IPS,
    _materialize_wordlist,
)

from ..helpers import (
    _WEB_PORTS, _VHOST_SOCKET_PORTS, _WEB_SERVICE_NAME_RE,
    _WEB_PRODUCT_RE, _HTTP_STATUS_RE, _HTTP_HTML_RE,
    _HTTP_CONTENT_TYPE_RE, _HTTP_HEADER_RE, _hostname_as_domain,
    _web_url_host_from_domain, _like_escape, _web_url_host_from_url,
    _smb_user_label, load_scope_exclusions, scope_sets,
    ip_in_scope, domain_in_scope, host_in_scope,
    email_in_scope, list_host_domains, list_all_host_domains,
    _split_lines, list_subdomain_ips, list_all_subdomain_ips,
    list_subdomain_hosts, list_hosts_by_ip, get_open_web_ports_by_ip,
    link_host_domain,
)
from ..state import AppState


def build(st: AppState, app) -> APIRouter:
    router = APIRouter()

    def _default_checklist_map(map_name: str) -> dict:
        if map_name == "authenticated":
            return {
                "title": "Domain Auth Checklist",
                "phase_label": "Enumeration",
                "nodes": [
                    {
                        "key": "adcs",
                        "label": "ADCS Enumeration",
                        "color_start": "#1abc9c",
                        "color_end": "#148f77",
                        "initial": 1,
                        "exploit_text": "Map templates and enrollment rights for ESC paths.",
                    },
                    {
                        "key": "ldap_security",
                        "label": "LDAP Security (Signing / Binding)",
                        "color_start": "#2980b9",
                        "color_end": "#1f618d",
                        "initial": 1,
                        "exploit_text": "Test for relay-enabling LDAP security misconfigurations.",
                    },
                    {
                        "key": "smb_signing",
                        "label": "SMB Signing",
                        "color_start": "#8e44ad",
                        "color_end": "#6c3483",
                        "initial": 1,
                        "exploit_text": "Validate SMB signing enforcement and relay viability.",
                    },
                    {
                        "key": "ntlmv1",
                        "label": "NTLMv1",
                        "color_start": "#b91c1c",
                        "color_end": "#7f1d1d",
                        "initial": 1,
                        "exploit_text": "Identify NTLMv1 usage and prioritize downgrade/crack abuse paths.",
                    },
                    {
                        "key": "endpoint_detection",
                        "label": "Endpoint Protection Detected",
                        "color_start": "#2ecc71",
                        "color_end": "#1e8449",
                        "initial": 1,
                        "exploit_text": "Identify endpoint protection coverage and bypass opportunities.",
                    },
                    {
                        "key": "domain_trusts",
                        "label": "Domain Trusts",
                        "color_start": "#e74c3c",
                        "color_end": "#c0392b",
                        "initial": 1,
                        "exploit_text": "Review trust boundaries and abuse paths.",
                    },
                    {
                        "key": "weak_user_flags",
                        "label": "Weak User Flags",
                        "color_start": "#3498db",
                        "color_end": "#2980b9",
                        "initial": 1,
                        "exploit_text": "Assess weak account control settings.",
                    },
                    {
                        "key": "accounts_no_password",
                        "label": "Accounts That Do Not Require Passwords",
                        "color_start": "#c0392b",
                        "color_end": "#922b21",
                        "initial": 1,
                        "exploit_text": "Identify accounts configured with password-not-required behavior and validate abuse paths.",
                    },
                    {
                        "key": "insecure_domain_priv_dacl",
                        "label": "Insecure Domain Privileges and DACL",
                        "color_start": "#7c2d12",
                        "color_end": "#9a3412",
                        "initial": 1,
                        "exploit_text": "Track risky delegated privileges and DACL misconfigurations that enable privilege escalation.",
                    },
                    {
                        "key": "pre2k_auth",
                        "label": "Pre2k Computer Account Checks",
                        "color_start": "#334155",
                        "color_end": "#1e293b",
                        "initial": 1,
                        "exploit_text": "Test legacy machine-account naming/password patterns for weak auth.",
                    },
                    {
                        "key": "ldap_descriptions",
                        "label": "LDAP Descriptions Harvest",
                        "color_start": "#9b59b6",
                        "color_end": "#8e44ad",
                        "initial": 1,
                        "exploit_text": "Look for secrets and internal metadata in descriptions.",
                    },
                    {
                        "key": "maq",
                        "label": "MachineAccountQuota (MAQ)",
                        "color_start": "#16a085",
                        "color_end": "#117864",
                        "initial": 1,
                        "exploit_text": "Check if machine account creation can be abused.",
                    },
                    {
                        "key": "gpo_enum",
                        "label": "Domain GPO Enumeration",
                        "color_start": "#d35400",
                        "color_end": "#a04000",
                        "initial": 1,
                        "exploit_text": "Identify writable or risky GPOs and scripts.",
                    },
                    {
                        "key": "sysvol_policy",
                        "label": "SYSVOL Password Policy Parsing",
                        "color_start": "#2c3e50",
                        "color_end": "#1f2d3a",
                        "initial": 1,
                        "exploit_text": "Validate lockout and complexity weaknesses.",
                    },
                    {
                        "key": "dangerous_attrs",
                        "label": "Dangerous LDAP Attributes",
                        "color_start": "#7f8c8d",
                        "color_end": "#566573",
                        "initial": 1,
                        "exploit_text": "Identify exposed password-like attributes.",
                    },
                    {
                        "key": "kerberoast",
                        "label": "Kerberoastable Accounts",
                        "color_start": "#8e44ad",
                        "color_end": "#6c3483",
                        "initial": 1,
                        "exploit_text": "Find service accounts vulnerable to Kerberoasting.",
                    },
                    {
                        "key": "asreproast",
                        "label": "AS-REP Roastable Accounts",
                        "color_start": "#c0392b",
                        "color_end": "#922b21",
                        "initial": 1,
                        "exploit_text": "Find users with pre-auth disabled.",
                    },
                    {
                        "key": "unconstrained_delegation",
                        "label": "Unconstrained Delegation",
                        "color_start": "#f39c12",
                        "color_end": "#b9770e",
                        "initial": 1,
                        "exploit_text": "Identify hosts/users allowing unconstrained delegation abuse.",
                    },
                    {
                        "key": "constrained_delegation",
                        "label": "Constrained Delegation",
                        "color_start": "#27ae60",
                        "color_end": "#1e8449",
                        "initial": 1,
                        "exploit_text": "Assess S4U abuse paths on constrained delegation objects.",
                    },
                    {
                        "key": "rbcd",
                        "label": "RBCD",
                        "color_start": "#e67e22",
                        "color_end": "#af601a",
                        "initial": 1,
                        "exploit_text": "Assess msDS-AllowedToActOnBehalfOfOtherIdentity abuse paths.",
                    },
                    {
                        "key": "laps",
                        "label": "LAPS Presence Check",
                        "color_start": "#5dade2",
                        "color_end": "#2e86c1",
                        "initial": 1,
                        "exploit_text": "Determine LAPS deployment and read-access exposure.",
                    },
                    {
                        "key": "sccm",
                        "label": "SCCM Discovery",
                        "color_start": "#884ea0",
                        "color_end": "#6c3483",
                        "initial": 1,
                        "exploit_text": "Evaluate SCCM infrastructure and takeover opportunities.",
                    },
                    {
                        "key": "mssql",
                        "label": "MSSQL Host Discovery",
                        "color_start": "#cb4335",
                        "color_end": "#943126",
                        "initial": 1,
                        "exploit_text": "Identify SQL hosts and credential/delegation pivot paths.",
                    },
                    {
                        "key": "wsus",
                        "label": "WSUS Discovery",
                        "color_start": "#17a589",
                        "color_end": "#117a65",
                        "initial": 1,
                        "exploit_text": "Assess WSUS trust and update-delivery abuse risk.",
                    },
                    {
                        "key": "managed_service_accounts",
                        "label": "Managed Service Accounts",
                        "color_start": "#7d3c98",
                        "color_end": "#5b2c6f",
                        "initial": 1,
                        "exploit_text": "Assess gMSA/MSA retrieval permissions and abuse paths.",
                    },
                    {
                        "key": "protected_users",
                        "label": "Protected Users Membership",
                        "color_start": "#34495e",
                        "color_end": "#212f3d",
                        "initial": 1,
                        "exploit_text": "Validate hardening coverage for protected accounts.",
                    },
                    {
                        "key": "legacy_hosts",
                        "label": "Obsolete Host / Legacy OS",
                        "color_start": "#a04000",
                        "color_end": "#6e2c00",
                        "initial": 1,
                        "exploit_text": "Prioritize legacy systems with high exploitability.",
                    },
                    {
                        "key": "dns_permissions",
                        "label": "DNS Permissions",
                        "color_start": "#566573",
                        "color_end": "#2e4053",
                        "initial": 1,
                        "exploit_text": "Assess dynamic update and ACL abuse opportunities.",
                    },
                ],
                "edges": [
                    {
                        "from": "ldap_security",
                        "to": "rbcd",
                        "label": "Relay/identity chain",
                    },
                    {
                        "from": "kerberoast",
                        "to": "constrained_delegation",
                        "label": "Credential to delegation pivot",
                    },
                    {
                        "from": "asreproast",
                        "to": "kerberoast",
                        "label": "Credential capture progression",
                    },
                ],
                "vuln_branches": [
                    {
                        "id": "trust_external_forest",
                        "parent_id": "domain_trusts",
                        "label": "External/forest trust misconfig",
                        "title": "Trust Misconfiguration",
                        "text": "Validate filtering, SID history protections, and trust direction weaknesses.",
                    },
                    {
                        "id": "trust_sidhistory",
                        "parent_id": "domain_trusts",
                        "label": "SIDHistory abuse path",
                        "title": "SIDHistory Abuse",
                        "text": "Test SIDHistory injection paths across trust boundaries.",
                    },
                    {
                        "id": "trust_selective_auth",
                        "parent_id": "domain_trusts",
                        "label": "Selective auth bypass checks",
                        "title": "Selective Auth Review",
                        "text": "Assess selective authentication controls and bypass opportunities.",
                    },
                    {
                        "id": "flags_no_pwd",
                        "parent_id": "weak_user_flags",
                        "label": "No Password Required users",
                        "title": "No Password Required",
                        "text": "Validate accounts with weak UAC flags and prioritise privileged accounts.",
                    },
                    {
                        "id": "flags_smartcard",
                        "parent_id": "weak_user_flags",
                        "label": "Smartcard-required edge cases",
                        "title": "Smartcard Required Edge Cases",
                        "text": "Check for fallback auth paths and inconsistent enforcement.",
                    },
                    {
                        "id": "flags_no_deleg",
                        "parent_id": "weak_user_flags",
                        "label": "No delegation accounts review",
                        "title": "No Delegation Review",
                        "text": "Verify protected accounts are correctly flagged and applied.",
                    },
                    {
                        "id": "desc_creds",
                        "parent_id": "ldap_descriptions",
                        "label": "Credentials in descriptions",
                        "title": "Credential Leakage",
                        "text": "Look for passwords/tokens/API keys in description fields.",
                    },
                    {
                        "id": "desc_internal",
                        "parent_id": "ldap_descriptions",
                        "label": "Internal URLs/hosts leakage",
                        "title": "Internal Metadata Leakage",
                        "text": "Map leaked hostnames and internal endpoints for pivoting.",
                    },
                    {
                        "id": "desc_service",
                        "parent_id": "ldap_descriptions",
                        "label": "Service account clues",
                        "title": "Service Account Clues",
                        "text": "Extract service identities and infer privilege relationships.",
                    },
                    {
                        "id": "maq_gt_zero",
                        "parent_id": "maq",
                        "label": "MAQ > 0 exploitation path",
                        "title": "MAQ Abuse",
                        "text": "Create machine account and chain into delegation abuse paths.",
                    },
                    {
                        "id": "maq_computer_create",
                        "parent_id": "maq",
                        "label": "Computer account creation abuse",
                        "title": "Computer Account Creation",
                        "text": "Assess ability to create and control machine identities.",
                    },
                    {
                        "id": "maq_rbcd_chain",
                        "parent_id": "maq",
                        "label": "RBCD chain setup",
                        "title": "MAQ to RBCD",
                        "text": "Link newly created machine account to RBCD attack chain.",
                    },
                    {
                        "id": "gpo_writable",
                        "parent_id": "gpo_enum",
                        "label": "Writable GPO paths",
                        "title": "Writable GPO",
                        "text": "Identify ACL misconfigs enabling policy/script tampering.",
                    },
                    {
                        "id": "gpo_scripts",
                        "parent_id": "gpo_enum",
                        "label": "Risky startup/logon scripts",
                        "title": "Risky Scripts",
                        "text": "Review scripts for command injection and credential exposure.",
                    },
                    {
                        "id": "gpo_priv_assign",
                        "parent_id": "gpo_enum",
                        "label": "Privilege assignment abuse",
                        "title": "Privilege Assignment Abuse",
                        "text": "Abuse dangerous user-right assignments from linked GPOs.",
                    },
                    {
                        "id": "sysvol_lockout",
                        "parent_id": "sysvol_policy",
                        "label": "Weak lockout policy",
                        "title": "Weak Lockout",
                        "text": "Low lockout thresholds enable effective spraying.",
                    },
                    {
                        "id": "sysvol_complexity",
                        "parent_id": "sysvol_policy",
                        "label": "Weak complexity policy",
                        "title": "Weak Complexity",
                        "text": "Inadequate complexity controls reduce cracking cost.",
                    },
                    {
                        "id": "sysvol_spray_window",
                        "parent_id": "sysvol_policy",
                        "label": "Spray window identified",
                        "title": "Spray Window",
                        "text": "Use reset durations and thresholds to tune spray cadence.",
                    },
                    {
                        "id": "attrs_userpwd",
                        "parent_id": "dangerous_attrs",
                        "label": "userPassword found",
                        "title": "userPassword Exposure",
                        "text": "Validate plaintext/legacy password attribute exposure.",
                    },
                    {
                        "id": "attrs_unicodepwd",
                        "parent_id": "dangerous_attrs",
                        "label": "unicodePwd indicators",
                        "title": "unicodePwd Indicators",
                        "text": "Investigate unexpected password data artifacts.",
                    },
                    {
                        "id": "attrs_legacy",
                        "parent_id": "dangerous_attrs",
                        "label": "Other legacy password attrs",
                        "title": "Legacy Password Attributes",
                        "text": "Review msSFU30Password/dbCSPwd and similar fields.",
                    },
                    {
                        "id": "kerb_high_value",
                        "parent_id": "kerberoast",
                        "label": "High-value SPN accounts",
                        "title": "High-Value SPNs",
                        "text": "Prioritise SPNs linked to admin/service control contexts.",
                    },
                    {
                        "id": "kerb_rc4",
                        "parent_id": "kerberoast",
                        "label": "RC4-enabled targets",
                        "title": "RC4 Targets",
                        "text": "Prefer targets with weaker encryption for cracking success.",
                    },
                    {
                        "id": "kerb_cracked",
                        "parent_id": "kerberoast",
                        "label": "Cracked hash follow-up",
                        "title": "Cracked Credential Follow-up",
                        "text": "Validate lateral movement and privilege gained from cracked creds.",
                    },
                    {
                        "id": "asrep_preauth",
                        "parent_id": "asreproast",
                        "label": "Pre-auth disabled users",
                        "title": "Pre-auth Disabled",
                        "text": "Enumerate users with UF_DONT_REQUIRE_PREAUTH set.",
                    },
                    {
                        "id": "asrep_cracked",
                        "parent_id": "asreproast",
                        "label": "Cracked credential follow-up",
                        "title": "AS-REP Crack Follow-up",
                        "text": "Use recovered credentials for privilege and path validation.",
                    },
                    {
                        "id": "asrep_priv_context",
                        "parent_id": "asreproast",
                        "label": "Privilege context validation",
                        "title": "Privilege Context",
                        "text": "Map cracked users to groups and delegated rights.",
                    },
                    {
                        "id": "adcs_esc1",
                        "parent_id": "adcs",
                        "label": "ESC1 candidate templates",
                        "title": "ESC1 Candidates",
                        "text": "Find client-auth templates with dangerous enrollment controls.",
                    },
                    {
                        "id": "adcs_esc23",
                        "parent_id": "adcs",
                        "label": "ESC2/ESC3 checks",
                        "title": "ESC2/ESC3 Checks",
                        "text": "Assess alternate template abuse and agent constraints.",
                    },
                    {
                        "id": "adcs_enroll_rights",
                        "parent_id": "adcs",
                        "label": "Enrollment rights abuse",
                        "title": "Enrollment Rights Abuse",
                        "text": "Identify low-priv users with enrollment rights on risky templates.",
                    },
                    {
                        "id": "ldap_signing_off",
                        "parent_id": "ldap_security",
                        "label": "Signing not required",
                        "title": "LDAP Signing Disabled",
                        "text": "Validate unsigned LDAP channel exploitation/relay viability.",
                    },
                    {
                        "id": "ldap_binding_off",
                        "parent_id": "ldap_security",
                        "label": "Channel binding not enforced",
                        "title": "LDAP Binding Weak",
                        "text": "Assess missing channel-binding protections for relay chains.",
                    },
                    {
                        "id": "ldap_relay",
                        "parent_id": "ldap_security",
                        "label": "Relay path validation",
                        "title": "LDAP Relay Path",
                        "text": "Confirm practical relay path in the target environment.",
                    },
                    {
                        "id": "smb_signing_required",
                        "parent_id": "smb_signing",
                        "label": "Signing not required",
                        "title": "SMB Signing Weak",
                        "text": "Identify hosts where SMB signing is not enforced.",
                    },
                    {
                        "id": "smb_relay_path",
                        "parent_id": "smb_signing",
                        "label": "SMB relay path validation",
                        "title": "SMB Relay Path",
                        "text": "Validate practical NTLM relay paths via SMB services.",
                    },
                    {
                        "id": "smb_coercion",
                        "parent_id": "smb_signing",
                        "label": "Coercion opportunities",
                        "title": "SMB Coercion",
                        "text": "Check coercion vectors that force auth to relay targets.",
                    },
                    {
                        "id": "ntlmv1_hosts",
                        "parent_id": "ntlmv1",
                        "label": "NTLMv1 detected on hosts",
                        "title": "NTLMv1 Hosts",
                        "text": "Record hosts/services still accepting NTLMv1.",
                    },
                    {
                        "id": "ntlmv1_downgrade",
                        "parent_id": "ntlmv1",
                        "label": "Downgrade/coercion path",
                        "title": "Downgrade Path",
                        "text": "Validate downgrade or coercion paths forcing NTLMv1 auth.",
                    },
                    {
                        "id": "ntlmv1_crack",
                        "parent_id": "ntlmv1",
                        "label": "Captured challenge crackable",
                        "title": "Crackability",
                        "text": "Assess crack feasibility and credential reuse impact.",
                    },
                    {
                        "id": "endpoint_edr",
                        "parent_id": "endpoint_detection",
                        "label": "EDR",
                        "title": "EDR Present",
                        "text": "Document vendor/coverage and validate realistic bypass paths.",
                    },
                    {
                        "id": "endpoint_antivirus",
                        "parent_id": "endpoint_detection",
                        "label": "Antivirus",
                        "title": "Antivirus Present",
                        "text": "Document AV controls, signatures, and likely payload constraints.",
                    },
                    {
                        "id": "ud_host_compromise",
                        "parent_id": "unconstrained_delegation",
                        "label": "Delegation host compromise path",
                        "title": "Host Compromise Path",
                        "text": "Target unconstrained hosts for ticket capture opportunities.",
                    },
                    {
                        "id": "ud_ticket_capture",
                        "parent_id": "unconstrained_delegation",
                        "label": "Ticket capture opportunity",
                        "title": "Ticket Capture",
                        "text": "Capture and reuse inbound TGT/TGS material.",
                    },
                    {
                        "id": "ud_da_impersonation",
                        "parent_id": "unconstrained_delegation",
                        "label": "DA impersonation validation",
                        "title": "DA Impersonation",
                        "text": "Validate impersonation of high-privilege users via delegation.",
                    },
                    {
                        "id": "cd_s4u",
                        "parent_id": "constrained_delegation",
                        "label": "S4U2Self/S4U2Proxy abuse",
                        "title": "S4U Abuse",
                        "text": "Test constrained delegation principals for S4U abuse.",
                    },
                    {
                        "id": "cd_target_expand",
                        "parent_id": "constrained_delegation",
                        "label": "Service target expansion",
                        "title": "Service Target Expansion",
                        "text": "Map reachable SPNs and constrained target scope.",
                    },
                    {
                        "id": "cd_sensitive_imp",
                        "parent_id": "constrained_delegation",
                        "label": "Sensitive account impersonation",
                        "title": "Sensitive Impersonation",
                        "text": "Assess impersonation impact against privileged identities.",
                    },
                    {
                        "id": "rbcd_writable_obj",
                        "parent_id": "rbcd",
                        "label": "Writable computer object path",
                        "title": "Writable Object Path",
                        "text": "Find writable machine objects for msDS-AllowedToAct abuse.",
                    },
                    {
                        "id": "rbcd_set_attr",
                        "parent_id": "rbcd",
                        "label": "Set AllowedToAct attribute",
                        "title": "Set AllowedToAct",
                        "text": "Set msDS-AllowedToActOnBehalfOfOtherIdentity on target object.",
                    },
                    {
                        "id": "rbcd_impersonate",
                        "parent_id": "rbcd",
                        "label": "Impersonation to target service",
                        "title": "RBCD Impersonation",
                        "text": "Use S4U chain to impersonate users to target services.",
                    },
                    {
                        "id": "laps_missing",
                        "parent_id": "laps",
                        "label": "LAPS missing",
                        "title": "LAPS Missing",
                        "text": "No managed local admin password control present.",
                    },
                    {
                        "id": "laps_acl",
                        "parent_id": "laps",
                        "label": "LAPS ACL overexposed",
                        "title": "LAPS ACL Exposure",
                        "text": "Too many principals can read LAPS-managed passwords.",
                    },
                    {
                        "id": "laps_read_abuse",
                        "parent_id": "laps",
                        "label": "Password read permission abuse",
                        "title": "LAPS Read Abuse",
                        "text": "Exploit excessive LAPS read rights for local admin access.",
                    },
                    {
                        "id": "sccm_takeover",
                        "parent_id": "sccm",
                        "label": "SCCM site takeover path",
                        "title": "SCCM Takeover",
                        "text": "Assess SCCM role trust for administrative takeover.",
                    },
                    {
                        "id": "sccm_client_push",
                        "parent_id": "sccm",
                        "label": "Client push account abuse",
                        "title": "Client Push Abuse",
                        "text": "Test client push credentials/permissions for lateral movement.",
                    },
                    {
                        "id": "sccm_dp_trust",
                        "parent_id": "sccm",
                        "label": "Distribution point trust abuse",
                        "title": "DP Trust Abuse",
                        "text": "Abuse content distribution trust and package execution paths.",
                    },
                    {
                        "id": "mssql_auth",
                        "parent_id": "mssql",
                        "label": "Weak SQL auth / trusted links",
                        "title": "SQL Auth Weakness",
                        "text": "Check weak SQL auth, linked servers, and trust misconfigs.",
                    },
                    {
                        "id": "mssql_xpcmd",
                        "parent_id": "mssql",
                        "label": "xp_cmdshell path",
                        "title": "xp_cmdshell Abuse",
                        "text": "Assess command execution via xp_cmdshell and proxy contexts.",
                    },
                    {
                        "id": "mssql_service_pivot",
                        "parent_id": "mssql",
                        "label": "Service account pivot",
                        "title": "Service Account Pivot",
                        "text": "Pivot using SQL service account privileges and delegation.",
                    },
                    {
                        "id": "wsus_insecure",
                        "parent_id": "wsus",
                        "label": "Insecure WSUS config",
                        "title": "Insecure WSUS",
                        "text": "Review WSUS transport/signing and policy constraints.",
                    },
                    {
                        "id": "wsus_http_unsigned",
                        "parent_id": "wsus",
                        "label": "HTTP/unsigned update path",
                        "title": "Unsigned Update Path",
                        "text": "Test unsigned update acceptance and transport downgrade.",
                    },
                    {
                        "id": "wsus_client_trust",
                        "parent_id": "wsus",
                        "label": "Client trust abuse",
                        "title": "Client Trust Abuse",
                        "text": "Exploit client trust in rogue or tampered update paths.",
                    },
                    {
                        "id": "pre2k_auth_hostlist",
                        "parent_id": "pre2k_auth",
                        "label": "Hostname list built",
                        "title": "Pre2k Candidate Hostnames",
                        "text": "Prepared host-derived candidate machine accounts for pre2k checks.",
                    },
                    {
                        "id": "pre2k_auth_userpass",
                        "parent_id": "pre2k_auth",
                        "label": "hostname$:hostname hit",
                        "title": "Pre2k Default Pattern Hit",
                        "text": "Legacy computer-account password pattern produced successful auth.",
                    },
                    {
                        "id": "pre2k_auth_blank",
                        "parent_id": "pre2k_auth",
                        "label": "Blank machine password works",
                        "title": "Blank Machine Password",
                        "text": "Blank password accepted for candidate machine account.",
                    },
                    {
                        "id": "msa_principals",
                        "parent_id": "managed_service_accounts",
                        "label": "Overbroad retrieval principals",
                        "title": "Overbroad Retrieval",
                        "text": "Too many principals allowed to retrieve managed passwords.",
                    },
                    {
                        "id": "msa_gmsa_retrieval",
                        "parent_id": "managed_service_accounts",
                        "label": "gMSA retrieval abuse",
                        "title": "gMSA Retrieval Abuse",
                        "text": "Abuse retrieval rights to obtain gMSA credentials.",
                    },
                    {
                        "id": "msa_priv_pivot",
                        "parent_id": "managed_service_accounts",
                        "label": "Service account privilege pivot",
                        "title": "Service Account Pivot",
                        "text": "Use managed account context for privilege escalation paths.",
                    },
                    {
                        "id": "protected_missing",
                        "parent_id": "protected_users",
                        "label": "Expected protected admins missing",
                        "title": "Missing Protected Users",
                        "text": "Critical admins absent from Protected Users group.",
                    },
                    {
                        "id": "protected_bypass",
                        "parent_id": "protected_users",
                        "label": "Policy bypass opportunities",
                        "title": "Protection Bypass",
                        "text": "Identify alternate auth paths bypassing expected restrictions.",
                    },
                    {
                        "id": "protected_fallback",
                        "parent_id": "protected_users",
                        "label": "Fallback auth path checks",
                        "title": "Fallback Auth Review",
                        "text": "Validate NTLM/legacy fallback isn't available for protected accounts.",
                    },
                    {
                        "id": "legacy_proto",
                        "parent_id": "legacy_hosts",
                        "label": "Legacy protocol exposure",
                        "title": "Legacy Protocols",
                        "text": "SMBv1/NTLMv1/old cipher support on legacy systems.",
                    },
                    {
                        "id": "legacy_exploitable",
                        "parent_id": "legacy_hosts",
                        "label": "Known exploitable OS targets",
                        "title": "Known Exploitable Targets",
                        "text": "Prioritize hosts with known unpatched exploit paths.",
                    },
                    {
                        "id": "legacy_patch_gap",
                        "parent_id": "legacy_hosts",
                        "label": "Patch/segmentation gap",
                        "title": "Patch and Segmentation Gap",
                        "text": "Assess segmentation failures and patch debt on legacy hosts.",
                    },
                    {
                        "id": "dns_dynamic",
                        "parent_id": "dns_permissions",
                        "label": "Dynamic update abuse",
                        "title": "Dynamic Update Abuse",
                        "text": "Assess unauthenticated/weakly-authenticated update permissions.",
                    },
                    {
                        "id": "dns_acl",
                        "parent_id": "dns_permissions",
                        "label": "Zone ACL misconfig",
                        "title": "Zone ACL Misconfiguration",
                        "text": "Review zone ACLs for writable records by low-priv users.",
                    },
                    {
                        "id": "dns_hijack",
                        "parent_id": "dns_permissions",
                        "label": "Record hijack path",
                        "title": "Record Hijack",
                        "text": "Exploit writable DNS records for relay and service redirection.",
                    },
                ],
            }
        return {
            "title": "Domain Unauth Checklist",
            "phase_label": "Enumeration",
            "nodes": [
                {
                    "key": "traffic_capture",
                    "label": "Network Traffic Baseline",
                    "color_start": "#2563eb",
                    "color_end": "#1d4ed8",
                    "initial": 1,
                    "exploit_text": "Capture baseline traffic and identify broadcast/authentication opportunities.",
                },
                {
                    "key": "network_equipment",
                    "label": "Network Equipment Discovery",
                    "color_start": "#0f766e",
                    "color_end": "#115e59",
                    "initial": 1,
                    "exploit_text": "Map infrastructure devices and management-plane exposure from passive data.",
                },
                {
                    "key": "dns_dc_discovery",
                    "label": "Find DNS / Domain Controllers",
                    "color_start": "#7c3aed",
                    "color_end": "#6d28d9",
                    "initial": 1,
                    "exploit_text": "Identify name servers and DCs via resolv/nslookup/SRV records.",
                },
                {
                    "key": "guest_null_sessions",
                    "label": "Guest / Null Session Enumeration",
                    "color_start": "#b45309",
                    "color_end": "#92400e",
                    "initial": 1,
                    "exploit_text": "Test anonymous SMB/RPC access and collect shares/users/policy data.",
                },
                {
                    "key": "smb_security",
                    "label": "SMB Security Weaknesses",
                    "color_start": "#9333ea",
                    "color_end": "#7e22ce",
                    "initial": 1,
                    "exploit_text": "Track SMB signing disabled and SMBv1 exposure for relay and legacy abuse.",
                },
                {
                    "key": "responder_poisoning",
                    "label": "LLMNR/NBNS Poisoning (Responder)",
                    "color_start": "#dc2626",
                    "color_end": "#b91c1c",
                    "initial": 1,
                    "exploit_text": "Validate poisoning opportunities and capture authentication attempts safely.",
                },
                {
                    "key": "mitm6_relay",
                    "label": "IPv6 MITM / NTLM Relay",
                    "color_start": "#0891b2",
                    "color_end": "#0e7490",
                    "initial": 1,
                    "exploit_text": "Assess mitm6 + ntlmrelayx path to LDAP/SMB/ADCS targets.",
                },
                {
                    "key": "ldap_unauth",
                    "label": "LDAP Unauthenticated Access",
                    "color_start": "#4f46e5",
                    "color_end": "#4338ca",
                    "initial": 1,
                    "exploit_text": "Test unauthenticated bind and LDAP-based user discovery opportunities.",
                },
                {
                    "key": "valid_user_discovery",
                    "label": "Valid User Discovery",
                    "color_start": "#15803d",
                    "color_end": "#166534",
                    "initial": 1,
                    "exploit_text": "Build/verify a valid user list through LDAP, Kerberos, and external sources.",
                },
                {
                    "key": "password_attacks",
                    "label": "Password Attack Paths",
                    "color_start": "#be123c",
                    "color_end": "#9f1239",
                    "initial": 1,
                    "exploit_text": "Run low-noise spray checks aligned to policy windows and engagement limits.",
                },
                {
                    "key": "asrep_roast",
                    "label": "AS-REP Roasting",
                    "color_start": "#b91c1c",
                    "color_end": "#991b1b",
                    "initial": 1,
                    "exploit_text": "Check blind AS-REP roastability and prioritize crackable/high-value accounts.",
                },
                {
                    "key": "kerberoast_blind",
                    "label": "Blind Kerberoast",
                    "color_start": "#a16207",
                    "color_end": "#854d0e",
                    "initial": 1,
                    "exploit_text": "Test no-preauth chaining paths for SPN roast opportunities without creds.",
                },
                {
                    "key": "timeroast",
                    "label": "Timeroast",
                    "color_start": "#0d9488",
                    "color_end": "#0f766e",
                    "initial": 1,
                    "exploit_text": "Validate SNTP-based roastability and extract usable hashes.",
                },
                {
                    "key": "pre2k",
                    "label": "Pre2k Computer Account Checks",
                    "color_start": "#334155",
                    "color_end": "#1e293b",
                    "initial": 1,
                    "exploit_text": "Test legacy machine-account naming/password patterns for weak auth.",
                },
                {
                    "key": "sccm_unauth",
                    "label": "SCCM Unauthenticated Vulnerabilities",
                    "color_start": "#6d28d9",
                    "color_end": "#5b21b6",
                    "initial": 1,
                    "exploit_text": "Track SCCM servers and validate unauthenticated vulnerability paths.",
                },
                {
                    "key": "auth_coerce",
                    "label": "Authentication Coercion",
                    "color_start": "#ea580c",
                    "color_end": "#c2410c",
                    "initial": 1,
                    "exploit_text": "Validate coercion vectors and whether relay targets are practically reachable.",
                },
                {
                    "key": "adcs_relay",
                    "label": "ADCS Relay Opportunities",
                    "color_start": "#0369a1",
                    "color_end": "#075985",
                    "initial": 1,
                    "exploit_text": "Identify certsrv endpoints and validate NTLM relay-to-ADCS feasibility.",
                },
                {
                    "key": "dns_updates",
                    "label": "Anonymous DNS Updates",
                    "color_start": "#7c2d12",
                    "color_end": "#9a3412",
                    "initial": 1,
                    "exploit_text": "Assess non-secure/anonymous dynamic DNS update risk and relay implications.",
                },
                {
                    "key": "wsus_unauth",
                    "label": "WSUS Discovery (Unauth)",
                    "color_start": "#166534",
                    "color_end": "#14532d",
                    "initial": 1,
                    "exploit_text": "Check unauth WSUS discovery paths before authenticated validation.",
                },
                {
                    "key": "web_applications",
                    "label": "Web Applications",
                    "color_start": "#0369a1",
                    "color_end": "#0c4a6e",
                    "initial": 1,
                    "exploit_text": "Check internal web apps for default credentials and practical exploit paths.",
                },
            ],
            "edges": [
                {
                    "from": "traffic_capture",
                    "to": "responder_poisoning",
                    "label": "Broadcast intel",
                },
                {
                    "from": "dns_dc_discovery",
                    "to": "guest_null_sessions",
                    "label": "Target list",
                },
                {"from": "smb_security", "to": "mitm6_relay", "label": "Relay targets"},
                {
                    "from": "valid_user_discovery",
                    "to": "password_attacks",
                    "label": "Spray input",
                },
                {"from": "auth_coerce", "to": "adcs_relay", "label": "Coerce to relay"},
            ],
            "vuln_branches": [
                {
                    "id": "traffic_llmnr",
                    "parent_id": "traffic_capture",
                    "label": "LLMNR/NBNS observed",
                    "title": "Broadcast Name Resolution",
                    "text": "LLMNR/NBNS traffic observed; poisoning and capture paths likely present.",
                },
                {
                    "id": "traffic_ipv6",
                    "parent_id": "traffic_capture",
                    "label": "IPv6 auth traffic observed",
                    "title": "IPv6 Authentication Traffic",
                    "text": "IPv6 auth chatter present; mitm6/relay path may be viable.",
                },
                {
                    "id": "traffic_sensitive",
                    "parent_id": "traffic_capture",
                    "label": "Sensitive data in capture",
                    "title": "Sensitive Packet Data",
                    "text": "Review PCAP for leaked creds, tokens, hostnames, and internal service clues.",
                },
                {
                    "id": "equip_arp",
                    "parent_id": "network_equipment",
                    "label": "ARP MACs translated",
                    "title": "ARP Device Identification",
                    "text": "Mapped MAC OUIs to likely vendors/network gear.",
                },
                {
                    "id": "equip_cdp",
                    "parent_id": "network_equipment",
                    "label": "CDP/LLDP discovered",
                    "title": "Discovery Protocol Exposure",
                    "text": "CDP/LLDP details exposed topology and device metadata.",
                },
                {
                    "id": "equip_mgmt",
                    "parent_id": "network_equipment",
                    "label": "Mgmt interfaces identified",
                    "title": "Management Plane Targets",
                    "text": "Potentially exposed switch/router management interfaces identified.",
                },
                {
                    "id": "dc_srv_records",
                    "parent_id": "dns_dc_discovery",
                    "label": "LDAP SRV records found",
                    "title": "Domain Controller SRV Records",
                    "text": "_ldap._tcp.dc._msdcs records resolved and DC list extracted.",
                },
                {
                    "id": "dc_nameservers",
                    "parent_id": "dns_dc_discovery",
                    "label": "Authoritative NS discovered",
                    "title": "Authoritative Name Servers",
                    "text": "Domain DNS servers identified for follow-on checks.",
                },
                {
                    "id": "dc_scope_hosts",
                    "parent_id": "dns_dc_discovery",
                    "label": "DCs in scope confirmed",
                    "title": "In-Scope DC Confirmation",
                    "text": "Validated which discovered DCs are approved targets.",
                },
                {
                    "id": "null_enum4",
                    "parent_id": "guest_null_sessions",
                    "label": "Unauth LDAP sessions",
                    "title": "Unauthenticated LDAP Sessions",
                    "text": "Validate anonymous/unauth LDAP session behavior and exposed directory data.",
                },
                {
                    "id": "null_smbmap",
                    "parent_id": "guest_null_sessions",
                    "label": "SMB null/anon session",
                    "title": "SMB Null/Anonymous Session",
                    "text": "Validate SMB null/anonymous session access and reachable share data.",
                },
                {
                    "id": "null_rpc",
                    "parent_id": "guest_null_sessions",
                    "label": "RPC null session works",
                    "title": "RPC Null Session",
                    "text": "rpcclient unauthenticated calls returned domain user/group data.",
                },
                {
                    "id": "smb_signing_off_unauth",
                    "parent_id": "smb_security",
                    "label": "SMB signing disabled",
                    "title": "SMB Signing Not Required",
                    "text": "Hosts identified where SMB signing is not enforced.",
                },
                {
                    "id": "smb_v1_legacy",
                    "parent_id": "smb_security",
                    "label": "SMBv1 enabled",
                    "title": "SMBv1 Exposure",
                    "text": "Legacy SMBv1-enabled hosts identified.",
                },
                {
                    "id": "smb_relay_list",
                    "parent_id": "smb_security",
                    "label": "Relay target list built",
                    "title": "SMB Relay Candidate List",
                    "text": "Generated relay list for ntlmrelayx and downstream validation.",
                },
                {
                    "id": "resp_host_repeat",
                    "parent_id": "responder_poisoning",
                    "label": "Repeated hostname requests",
                    "title": "Repeated Name Requests",
                    "text": "Recurring unresolved hostnames indicate likely broad poison opportunity.",
                },
                {
                    "id": "resp_hashes",
                    "parent_id": "responder_poisoning",
                    "label": "NTLM captures collected",
                    "title": "Captured NTLM Material",
                    "text": "Responder collected NTLM authentication attempts for validation.",
                },
                {
                    "id": "resp_relay_chain",
                    "parent_id": "responder_poisoning",
                    "label": "Capture-to-relay path",
                    "title": "Capture to Relay",
                    "text": "Observed captures can be chained into relay against approved targets.",
                },
                {
                    "id": "mitm6_running",
                    "parent_id": "mitm6_relay",
                    "label": "mitm6 successful",
                    "title": "mitm6 Active",
                    "text": "mitm6 operational and intercepting relevant authentication traffic.",
                },
                {
                    "id": "mitm6_ntlmrelay",
                    "parent_id": "mitm6_relay",
                    "label": "ntlmrelayx IPv6 relay works",
                    "title": "IPv6 NTLM Relay Success",
                    "text": "IPv6 relay chain validated with ntlmrelayx against target set.",
                },
                {
                    "id": "mitm6_ldap_or_adcs",
                    "parent_id": "mitm6_relay",
                    "label": "LDAP/ADCS relay target reachable",
                    "title": "High-Value Relay Target",
                    "text": "Relayable LDAP/ADCS endpoint reachable from coerced traffic.",
                },
                {
                    "id": "ldap_anon_bind",
                    "parent_id": "ldap_unauth",
                    "label": "Anonymous bind allowed",
                    "title": "Anonymous LDAP Bind",
                    "text": "LDAP accepts unauthenticated bind with meaningful response data.",
                },
                {
                    "id": "ldap_anon_enum",
                    "parent_id": "ldap_unauth",
                    "label": "Unauth user enumeration",
                    "title": "Unauthenticated LDAP Enumeration",
                    "text": "LDAP unauth enumeration yielded users/groups/metadata for follow-up.",
                },
                {
                    "id": "ldap_anon_null",
                    "parent_id": "ldap_unauth",
                    "label": "Null session LDAP checks",
                    "title": "LDAP Null Session Path",
                    "text": "Null/anonymous LDAP checks returned exploitable directory visibility.",
                },
                {
                    "id": "users_seed_lists",
                    "parent_id": "valid_user_discovery",
                    "label": "Seed lists collected",
                    "title": "User Seed Collection",
                    "text": "Built initial user list from OSINT, printer books, and naming patterns.",
                },
                {
                    "id": "users_ldapnomnom",
                    "parent_id": "valid_user_discovery",
                    "label": "LDAP user validation",
                    "title": "LDAP User Validation",
                    "text": "Validated candidate users through LDAP-focused enumeration tooling.",
                },
                {
                    "id": "users_kerbrute",
                    "parent_id": "valid_user_discovery",
                    "label": "Kerberos userenum hits",
                    "title": "Kerberos User Enumeration",
                    "text": "Kerberos userenum produced confirmed valid accounts.",
                },
                {
                    "id": "pwd_policy_checked",
                    "parent_id": "password_attacks",
                    "label": "Policy-safe spray window",
                    "title": "Spray Safety Confirmed",
                    "text": "Password policy reviewed before spraying to reduce lockout risk.",
                },
                {
                    "id": "pwd_blank_or_userpass",
                    "parent_id": "password_attacks",
                    "label": "Blank/user-as-pass tested",
                    "title": "Low-Noise Password Guessing",
                    "text": "Tested blank and user-as-password patterns against valid users.",
                },
                {
                    "id": "pwd_common_format_hits",
                    "parent_id": "password_attacks",
                    "label": "Common format hit",
                    "title": "Password Format Success",
                    "text": "Season/company-based pattern produced valid authentication.",
                },
                {
                    "id": "asrep_enum",
                    "parent_id": "asrep_roast",
                    "label": "AS-REP roastable users found",
                    "title": "Roastable Users Identified",
                    "text": "Enumerated users with pre-auth disabled and collected hashes.",
                },
                {
                    "id": "asrep_crackable",
                    "parent_id": "asrep_roast",
                    "label": "Crackable hash material",
                    "title": "AS-REP Crackability",
                    "text": "Captured hashes suitable for cracking workflows.",
                },
                {
                    "id": "asrep_priv",
                    "parent_id": "asrep_roast",
                    "label": "Privileged account impact",
                    "title": "High-Impact AS-REP Accounts",
                    "text": "Roastable/cracked accounts map to elevated access.",
                },
                {
                    "id": "kerb_no_preauth_chain",
                    "parent_id": "kerberoast_blind",
                    "label": "No-preauth chain viable",
                    "title": "Blind Kerberoast Chain",
                    "text": "No-preauth account path supports blind Kerberoast attempt.",
                },
                {
                    "id": "kerb_spn_candidates",
                    "parent_id": "kerberoast_blind",
                    "label": "SPN candidates identified",
                    "title": "SPN Candidate Set",
                    "text": "Built candidate SPN user list for focused roasting checks.",
                },
                {
                    "id": "kerb_ticket_material",
                    "parent_id": "kerberoast_blind",
                    "label": "TGS material captured",
                    "title": "Kerberoast Ticket Capture",
                    "text": "Collected ticket material for offline cracking assessment.",
                },
                {
                    "id": "time_hashes",
                    "parent_id": "timeroast",
                    "label": "SNTP roast hashes found",
                    "title": "Timeroast Hash Capture",
                    "text": "Timeroast module returned hash artifacts for cracking attempts.",
                },
                {
                    "id": "time_crackability",
                    "parent_id": "timeroast",
                    "label": "Hash crackability assessed",
                    "title": "Timeroast Crackability",
                    "text": "Validated cracking feasibility and likely impact of recovered material.",
                },
                {
                    "id": "time_reuse",
                    "parent_id": "timeroast",
                    "label": "Recovered cred reuse path",
                    "title": "Credential Reuse Path",
                    "text": "Recovered/derived creds can be reused against additional services.",
                },
                {
                    "id": "pre2k_hostlist",
                    "parent_id": "pre2k",
                    "label": "Hostname list built",
                    "title": "Pre2k Candidate Hostnames",
                    "text": "Prepared host-derived candidate machine accounts for pre2k checks.",
                },
                {
                    "id": "pre2k_userpass",
                    "parent_id": "pre2k",
                    "label": "hostname$:hostname hit",
                    "title": "Pre2k Default Pattern Hit",
                    "text": "Legacy computer-account password pattern produced successful auth.",
                },
                {
                    "id": "pre2k_blank",
                    "parent_id": "pre2k",
                    "label": "Blank machine password works",
                    "title": "Blank Machine Password",
                    "text": "Blank password accepted for candidate machine account.",
                },
                {
                    "id": "sccm_pxe",
                    "parent_id": "sccm_unauth",
                    "label": "PXE discovery path",
                    "title": "PXE Exposure",
                    "text": "PXE services exposed enough data for unauth reconnaissance.",
                },
                {
                    "id": "sccm_policy_read",
                    "parent_id": "sccm_unauth",
                    "label": "Unauth policy read",
                    "title": "Unauthenticated Policy Access",
                    "text": "SCCM policies readable without valid credentials.",
                },
                {
                    "id": "sccm_file_read",
                    "parent_id": "sccm_unauth",
                    "label": "Unauth file read",
                    "title": "Unauthenticated File Access",
                    "text": "SCCM distribution/file endpoints exposed sensitive artifacts.",
                },
                {
                    "id": "coerce_petipotam",
                    "parent_id": "auth_coerce",
                    "label": "PetitPotam works",
                    "title": "PetitPotam Coercion",
                    "text": "Unauthentication coercion triggered target auth to listener.",
                },
                {
                    "id": "coerce_printerbug",
                    "parent_id": "auth_coerce",
                    "label": "Printer bug path works",
                    "title": "Printer Coercion",
                    "text": "Printer-based coercion path validated against in-scope hosts.",
                },
                {
                    "id": "coerce_relayable",
                    "parent_id": "auth_coerce",
                    "label": "Coerced auth relayable",
                    "title": "Relayable Coercion",
                    "text": "Coerced authentication can be relayed to approved targets.",
                },
                {
                    "id": "adcs_web_enum",
                    "parent_id": "adcs_relay",
                    "label": "certsrv endpoints found",
                    "title": "ADCS Web Enrollment Found",
                    "text": "Identified /certsrv endpoints reachable over HTTP/HTTPS.",
                },
                {
                    "id": "adcs_ntlmrelay",
                    "parent_id": "adcs_relay",
                    "label": "Relay-to-ADCS successful",
                    "title": "ADCS Relay Success",
                    "text": "ntlmrelayx relay to ADCS endpoint succeeded.",
                },
                {
                    "id": "adcs_template_dc",
                    "parent_id": "adcs_relay",
                    "label": "Template abuse path",
                    "title": "ADCS Template Abuse",
                    "text": "Identified viable certificate template for escalation path.",
                },
                {
                    "id": "dns_anon_update",
                    "parent_id": "dns_updates",
                    "label": "Anonymous update accepted",
                    "title": "Anonymous DNS Update",
                    "text": "DNS server accepted unauthenticated/non-secure dynamic update.",
                },
                {
                    "id": "dns_safe_demo",
                    "parent_id": "dns_updates",
                    "label": "Non-disruptive proof",
                    "title": "Safe DNS Update Demonstration",
                    "text": "Demonstrated update using controlled/non-destructive record target.",
                },
                {
                    "id": "dns_kerbrelay_path",
                    "parent_id": "dns_updates",
                    "label": "Kerberos relay implication",
                    "title": "DNS-to-Relay Path",
                    "text": "Confirmed that DNS update weakness can support relay/impersonation chain.",
                },
                {
                    "id": "wsus_discover",
                    "parent_id": "wsus_unauth",
                    "label": "WSUS service discovered",
                    "title": "WSUS Discovery",
                    "text": "WSUS identified and reachable for unauth reconnaissance.",
                },
                {
                    "id": "wsus_only_discover",
                    "parent_id": "wsus_unauth",
                    "label": "Discovery-only evidence",
                    "title": "WSUS Discovery Evidence",
                    "text": "Captured discovery evidence for follow-on authenticated validation.",
                },
                {
                    "id": "wsus_followup_auth",
                    "parent_id": "wsus_unauth",
                    "label": "Auth follow-up required",
                    "title": "Authenticated WSUS Follow-up",
                    "text": "Marked for authenticated checks on trust/signing and update abuse.",
                },
                {
                    "id": "webapp_default_creds",
                    "parent_id": "web_applications",
                    "label": "Default creds",
                    "title": "Default Credentials Path",
                    "text": "Default or weak baseline credentials identified on a web application.",
                },
                {
                    "id": "webapp_exploit",
                    "parent_id": "web_applications",
                    "label": "Exploit",
                    "title": "Web Exploit Path",
                    "text": "Exploit path identified against a web application component.",
                },
            ],
        }

    def _load_checklist_map(s: Session, map_name: str) -> dict:
        row = s.execute(
            text(
                "SELECT title, phase_label, data_json FROM checklist_maps WHERE map_name = :n"
            ),
            {"n": map_name},
        ).fetchone()
        if not row:
            default = _default_checklist_map(map_name)
            s.execute(
                text(
                    "INSERT INTO checklist_maps(map_name, title, phase_label, data_json, updated_at) "
                    "VALUES (:n, :t, :p, :d, :u)"
                ),
                {
                    "n": map_name,
                    "t": default["title"],
                    "p": default["phase_label"],
                    "d": json.dumps(
                        {
                            "nodes": default["nodes"],
                            "edges": default["edges"],
                            "vuln_branches": default.get("vuln_branches", []),
                        }
                    ),
                    "u": datetime.utcnow().isoformat(),
                },
            )
            s.commit()
            return default
        data = json.loads(row[2] or "{}")
        if (
            map_name == "unauthenticated"
            and not data.get("nodes")
            and not data.get("vuln_branches")
        ):
            default = _default_checklist_map(map_name)
            s.execute(
                text(
                    "UPDATE checklist_maps SET title = :t, phase_label = :p, data_json = :d, updated_at = :u "
                    "WHERE map_name = :n"
                ),
                {
                    "n": map_name,
                    "t": default["title"],
                    "p": default["phase_label"],
                    "d": json.dumps(
                        {
                            "nodes": default["nodes"],
                            "edges": default["edges"],
                            "vuln_branches": default.get("vuln_branches", []),
                        }
                    ),
                    "u": datetime.utcnow().isoformat(),
                },
            )
            s.commit()
            return default

        if map_name in ("unauthenticated", "authenticated"):
            default = _default_checklist_map(map_name)
            cur_nodes = (
                data.get("nodes", []) if isinstance(data.get("nodes"), list) else []
            )
            cur_branches = (
                data.get("vuln_branches", [])
                if isinstance(data.get("vuln_branches"), list)
                else []
            )
            cur_node_keys = {str(n.get("key") or "") for n in cur_nodes}
            cur_branch_ids = {str(b.get("id") or "") for b in cur_branches}

            added = False
            for n in default.get("nodes", []):
                k = str(n.get("key") or "")
                if k and k not in cur_node_keys:
                    cur_nodes.append(n)
                    added = True

            for b in default.get("vuln_branches", []):
                bid = str(b.get("id") or "")
                if bid and bid not in cur_branch_ids:
                    cur_branches.append(b)
                    added = True

            if added:
                data["nodes"] = cur_nodes
                data["vuln_branches"] = cur_branches
                if not isinstance(data.get("edges"), list):
                    data["edges"] = default.get("edges", [])
                s.execute(
                    text(
                        "UPDATE checklist_maps SET data_json = :d, updated_at = :u WHERE map_name = :n"
                    ),
                    {
                        "n": map_name,
                        "d": json.dumps(data),
                        "u": datetime.utcnow().isoformat(),
                    },
                )
                s.commit()
        return {
            "title": row[0]
            or (
                "Domain Auth Checklist"
                if map_name == "authenticated"
                else "Domain Unauth Checklist"
            ),
            "phase_label": row[1] or "Enumeration",
            "nodes": data.get("nodes", []),
            "edges": data.get("edges", []),
            "vuln_branches": data.get("vuln_branches", []),
        }

    @router.get("/checklist-unauthenticated", response_class=HTMLResponse)
    def checklist_unauthenticated_page(request: Request):
        with st.db() as s:
            map_data = _load_checklist_map(s, "unauthenticated")
        for n in map_data.get("nodes", []):
            if str(n.get("key") or "") == "sccm_unauth":
                n["label"] = "SCCM Unauthenticated Vulnerabilities"
                n["exploit_text"] = (
                    "Track SCCM servers and validate unauthenticated vulnerability paths."
                )
        for b in map_data.get("vuln_branches", []):
            bid = str(b.get("id") or "")
            if bid == "null_enum4":
                b["label"] = "Unauth LDAP sessions"
                b["title"] = "Unauthenticated LDAP Sessions"
                b["text"] = (
                    "Validate anonymous/unauth LDAP session behavior and exposed directory data."
                )
            elif bid == "null_smbmap":
                b["label"] = "SMB null/anon session"
                b["title"] = "SMB Null/Anonymous Session"
                b["text"] = (
                    "Validate SMB null/anonymous session access and reachable share data."
                )
        map_data["title"] = "Domain Unauth Checklist"
        return st.templates.TemplateResponse(
            "checklist.html",
            {"request": request, "map_name": "unauthenticated", "map_data": map_data},
        )

    @router.get("/checklist", response_class=HTMLResponse)
    def checklist_page(request: Request):
        with st.db() as s:
            map_data = _load_checklist_map(s, "authenticated")
        map_data["title"] = "Domain Auth Checklist"
        return st.templates.TemplateResponse(
            "checklist.html",
            {"request": request, "map_name": "authenticated", "map_data": map_data},
        )

    @router.get("/checklist-attack-path", response_class=HTMLResponse)
    def checklist_attack_path_page(request: Request):
        def checklist_state(s: Session) -> dict[str, object]:
            rows = s.execute(text("SELECT item_key, done FROM checklist")).fetchall()
            out: dict[str, object] = {}
            for r in rows:
                key = str(r[0])
                val = int(r[1] or 0)
                if key.endswith("_vuln"):
                    out[key] = (
                        "vuln" if val == 1 else ("notvuln" if val == 2 else "unchecked")
                    )
                else:
                    out[key] = bool(val)
            return out

        def build_attack_map_for_source(
            map_data: dict,
            state: dict[str, object],
        ) -> dict[str, list[dict]]:
            nodes = (
                map_data.get("nodes", [])
                if isinstance(map_data.get("nodes"), list)
                else []
            )
            branches = (
                map_data.get("vuln_branches", [])
                if isinstance(map_data.get("vuln_branches"), list)
                else []
            )
            branch_by_id = {str(b.get("id") or ""): b for b in branches if b.get("id")}

            def node_is_vuln(node_key: str) -> bool:
                return state.get(f"{node_key}_vuln") == "vuln"

            def branch_selected(branch_id: str) -> bool:
                return bool(state.get(f"branch_{branch_id}", False))

            def branch_active(branch_id: str) -> bool:
                b = branch_by_id.get(branch_id)
                if not b:
                    return False
                if not branch_selected(branch_id):
                    return False
                parent_id = str(b.get("parent_id") or "")
                if parent_id in branch_by_id:
                    return branch_active(parent_id)
                return node_is_vuln(parent_id)

            vuln_node_keys = {
                str(n.get("key") or "")
                for n in nodes
                if str(n.get("key") or "") and node_is_vuln(str(n.get("key") or ""))
            }

            active_branch_ids = {
                str(b.get("id") or "")
                for b in branches
                if str(b.get("id") or "") and branch_active(str(b.get("id") or ""))
            }

            filtered_nodes = [
                n for n in nodes if str(n.get("key") or "") in vuln_node_keys
            ]
            filtered_branches = []
            for b in branches:
                bid = str(b.get("id") or "")
                if bid not in active_branch_ids:
                    continue
                parent_id = str(b.get("parent_id") or "")
                if parent_id in vuln_node_keys or parent_id in active_branch_ids:
                    filtered_branches.append(b)

            return {"nodes": filtered_nodes, "vuln_branches": filtered_branches}

        with st.db() as s:
            state = checklist_state(s)
            auth_map = _load_checklist_map(s, "authenticated")
            unauth_map = _load_checklist_map(s, "unauthenticated")

        unauth_attack = build_attack_map_for_source(unauth_map, state)
        auth_attack = build_attack_map_for_source(auth_map, state)

        merged_nodes: list[dict] = []
        merged_branches: list[dict] = []
        seen_nodes: set[str] = set()
        seen_branches: set[str] = set()

        for n in unauth_attack["nodes"] + auth_attack["nodes"]:
            key = str(n.get("key") or "")
            if not key or key in seen_nodes:
                continue
            seen_nodes.add(key)
            merged_nodes.append(n)

        for b in unauth_attack["vuln_branches"] + auth_attack["vuln_branches"]:
            bid = str(b.get("id") or "")
            parent_id = str(b.get("parent_id") or "")
            if not bid or bid in seen_branches:
                continue
            if parent_id not in seen_nodes and parent_id not in seen_branches:
                continue
            seen_branches.add(bid)
            merged_branches.append(b)

        if not merged_nodes:
            merged_nodes = [
                {
                    "key": "attack_path_empty",
                    "label": "No Vulnerable Items Yet",
                    "color_start": "#64748b",
                    "color_end": "#334155",
                    "initial": 1,
                    "exploit_text": "Mark items as Vulnerable in Domain Unauth Checklist or Domain Auth Checklist to build this attack path map.",
                }
            ]
            merged_branches = []

        attack_map = {
            "title": "Attack Path",
            "phase_label": "Consolidated",
            "nodes": merged_nodes,
            "edges": [],
            "vuln_branches": merged_branches,
        }
        return st.templates.TemplateResponse(
            "checklist.html",
            {"request": request, "map_name": "attack_path", "map_data": attack_map},
        )

    @router.get("/checklist/edit", response_class=HTMLResponse)
    def checklist_edit(request: Request, map_name: str = Query("authenticated")):
        with st.db() as s:
            map_data = _load_checklist_map(s, map_name)
        return st.templates.TemplateResponse(
            "checklist_edit.html",
            {"request": request, "map_name": map_name, "map_data": map_data},
        )

    @router.post("/api/checklist-map/{map_name}")
    async def api_checklist_map_save(map_name: str, request: Request):
        body = await request.json()
        title = (body.get("title") or "").strip() or (
            "Domain Auth Checklist"
            if map_name == "authenticated"
            else "Domain Unauth Checklist"
        )
        phase_label = (body.get("phase_label") or "").strip() or "Enumeration"
        nodes = body.get("nodes") if isinstance(body.get("nodes"), list) else []
        edges = body.get("edges") if isinstance(body.get("edges"), list) else []
        vuln_branches = (
            body.get("vuln_branches")
            if isinstance(body.get("vuln_branches"), list)
            else []
        )
        data_json = json.dumps(
            {"nodes": nodes, "edges": edges, "vuln_branches": vuln_branches}
        )
        with st.db() as s:
            s.execute(
                text(
                    "INSERT OR REPLACE INTO checklist_maps(map_name, title, phase_label, data_json, updated_at) "
                    "VALUES (:n, :t, :p, :d, :u)"
                ),
                {
                    "n": map_name,
                    "t": title,
                    "p": phase_label,
                    "d": data_json,
                    "u": datetime.utcnow().isoformat(),
                },
            )
            s.commit()
        return {"ok": True}

    @router.get("/api/checklist")
    def api_checklist_get():
        from sqlalchemy import text

        with st.db() as s:
            rows = s.execute(text("SELECT item_key, done FROM checklist")).fetchall()
        result = {}
        for r in rows:
            if str(r[0]).endswith("_vuln"):
                result[r[0]] = (
                    "vuln" if r[1] == 1 else ("notvuln" if r[1] == 2 else "unchecked")
                )
            else:
                result[r[0]] = bool(r[1])
        return result

    @router.get("/api/checklist-notes")
    def api_checklist_notes_get():
        from sqlalchemy import text

        with st.db() as s:
            rows = s.execute(
                text("SELECT item_key, note FROM checklist_notes")
            ).fetchall()
        return {str(r[0]): str(r[1] or "") for r in rows}

    @router.post("/api/checklist-note/{item_key}")
    def api_checklist_note_set(item_key: str, note: str = Form("")):
        from sqlalchemy import text

        with st.db() as s:
            s.execute(
                text(
                    "INSERT OR REPLACE INTO checklist_notes (item_key, note) VALUES (:k, :n)"
                ),
                {"k": item_key, "n": note},
            )
            s.commit()
        return {"ok": True}

    @router.post("/api/checklist/ldap_vuln")
    def api_checklist_ldap_vuln(vuln: str = Form("")):
        from sqlalchemy import text

        val = 0 if vuln == "unchecked" else (1 if vuln == "vuln" else 2)
        with st.db() as s:
            s.execute(
                text(
                    "INSERT OR REPLACE INTO checklist (item_key, done) VALUES ('ldap_vuln', :vuln)"
                ),
                {"vuln": val},
            )
            s.commit()
        return {"ok": True}

    @router.post("/api/checklist/{item_key}")
    def api_checklist_set(item_key: str, done: int = Form(0), vuln: str = Form("")):
        from sqlalchemy import text

        if str(item_key).endswith("_vuln"):
            done = 0 if vuln == "unchecked" else (1 if vuln == "vuln" else 2)
        with st.db() as s:
            s.execute(
                text(
                    "INSERT OR REPLACE INTO checklist (item_key, done) VALUES (:key, :done)"
                ),
                {"key": item_key, "done": done},
            )
            s.commit()
        return {"ok": True}

    # Lists
    return router
