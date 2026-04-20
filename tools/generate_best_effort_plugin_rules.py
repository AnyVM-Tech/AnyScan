#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "data" / "leakix_plugin_catalog.json"
VERSION_RULE_ADVISORY_CACHE_PATH = ROOT / "data" / "version_rule_advisories.json"
RULES_DIR = ROOT / "extensions" / "bundled" / "rules"
HTTP_RULES_PATH = RULES_DIR / "http-plugin-rules.json"
VERSION_RULES_PATH = RULES_DIR / "version-plugin-rules.json"

PROTOCOL_BUILTIN_PROMOTIONS = {
    "FirebirdPlugin",
    "FreeSWITCHOpenPlugin",
    "JdwpPlugin",
    "OpenEdgePlugin",
    "PostgreSQLOpenPlugin",
    "SshRegresshionPlugin",
    "TelnetAuthBypassPlugin",
}

RULE_LABEL_OVERRIDES = {
    "BrowserlessPlugin": ["best_effort", "http_rule", "rce_surface", "headless_browser"],
    "GeoserverRcePlugin": ["best_effort", "http_rule", "rce_surface"],
    "GeoserverXxePlugin": ["best_effort", "http_rule", "xxe_surface"],
    "GuacamolePlugin": ["best_effort", "http_rule", "admin_panel", "default_creds"],
    "LangflowPlugin": ["best_effort", "http_rule", "ai_llm", "rce_surface"],
    "MagentoXxePlugin": ["best_effort", "http_rule", "xxe_surface"],
    "MeshCentralPlugin": ["best_effort", "http_rule", "registration_surface"],
    "NetBoxPlugin": ["best_effort", "http_rule", "admin_panel", "api_token"],
    "NodeREDPlugin": ["best_effort", "http_rule", "rce_surface", "admin_panel"],
    "RabbitMQPlugin": ["best_effort", "http_rule", "default_creds", "admin_panel"],
    "SelenoidPlugin": ["best_effort", "http_rule", "browser_automation", "rce_surface"],
    "SupersetPlugin": ["best_effort", "http_rule", "admin_panel", "secret_key"],
    "TraversalHttpPlugin": ["best_effort", "http_rule", "path_traversal"],
    "WpUserEnumHttp": ["best_effort", "http_rule", "enumeration"],
    "LiteLLMPlugin": ["version_rule", "high_confidence", "ai_llm"],
    "FlowiseVersionPlugin": ["version_rule", "high_confidence", "ai_llm"],
}

MANUAL_HTTP_RULES = [
    {
        "plugin_id": "CraftCMSPlugin",
        "detector": "craftcms_exposed_panel",
        "severity": "medium",
        "confidence": "high",
        "body_contains": ["craft cms", r"craft\\web\\application"],
        "product_name": "Craft CMS",
        "redacted_value": "craftcms_exposed_panel",
        "summary": "Craft CMS markers were observed in a public response.",
        "evidence_template": "{product_name} panel markers were observed at {path}.",
        "evidence": "Craft CMS panel markers were observed in a public response.",
    },
    {
        "plugin_id": "MoodlePlugin",
        "detector": "moodle_exposed_panel",
        "severity": "medium",
        "confidence": "high",
        "body_contains": ["moodle", "moodleform"],
        "product_name": "Moodle",
        "redacted_value": "moodle_exposed_panel",
        "summary": "Moodle markers were observed in a public response.",
        "evidence_template": "{product_name} application markers were observed at {path}.",
        "evidence": "Moodle application markers were observed in a public response.",
    },
    {
        "plugin_id": "MirthPlugin",
        "detector": "mirth_connect_exposed_panel",
        "severity": "medium",
        "confidence": "high",
        "body_contains": ["mirth connect", "nextgen health care"],
        "product_name": "Mirth Connect",
        "redacted_value": "mirth_connect_exposed_panel",
        "summary": "Mirth Connect markers were observed in a public response.",
        "evidence_template": "{product_name} panel markers were observed at {path}.",
        "evidence": "Mirth Connect panel markers were observed in a public response.",
    },
    {
        "plugin_id": "SAPNetWeaverPlugin",
        "detector": "sap_netweaver_exposed_panel",
        "severity": "medium",
        "confidence": "high",
        "body_contains": ["sap netweaver", "sap enterprise portal"],
        "product_name": "SAP NetWeaver",
        "redacted_value": "sap_netweaver_exposed_panel",
        "summary": "SAP NetWeaver markers were observed in a public response.",
        "evidence_template": "{product_name} panel markers were observed at {path}.",
        "evidence": "SAP NetWeaver panel markers were observed in a public response.",
    },
]

HTTP_RULE_OVERRIDES = {
    "MalwareHttpPlugin": {
        "aliases": [],
        "detector": "malware_http_indicator",
        "confidence": "medium",
        "body_regex": r"(?i)(?:mirai|gafgyt|botnet|cobalt strike|sliver|metasploit|malware|webshell)",
        "summary": "Suspicious malware/operator markers were observed in an unsolicited HTTP response.",
        "evidence_template": "Suspicious malware/operator markers were observed in the response at {path}.",
        "evidence": "Suspicious malware/operator markers were observed in an unsolicited HTTP response.",
    },
    "BrowserlessPlugin": {
        "aliases": ["browserless"],
        "any_of_path_contains": [
            "/json/version",
            "/content",
            "/download",
            "/function",
            "/pdf",
            "/screenshot",
            "/scrape",
            "/unblock",
        ],
        "path_not_contains": ["/docs", "/blog", "/changelog"],
    },
    "GeoserverRcePlugin": {
        "aliases": ["geoserver"],
        "any_of_path_contains": ["/geoserver", "/web/"],
    },
    "GeoserverXxePlugin": {
        "aliases": ["geoserver"],
        "any_of_path_contains": ["/geoserver", "/web/"],
    },
    "GuacamolePlugin": {
        "aliases": ["apache guacamole", "guacamole"],
        "any_of_path_contains": ["/guacamole/", "/api/tokens", "/#/client/"],
        "path_not_contains": ["/documentation", "/manual"],
    },
    "ICTBroadcastRcePlugin": {
        "aliases": ["ictbroadcast"],
        "any_of_path_contains": ["/ictbroadcast", "/broadcast", "/livecallcenter"],
    },
    "LangflowPlugin": {
        "aliases": ["langflow"],
        "any_of_path_contains": ["/api/v1", "/health", "/login", "/lf/"],
        "path_not_contains": ["/docs", "/blog"],
    },
    "Log4JOpportunistic": {
        "aliases": [],
        "detector": "log4j_opportunistic_marker",
        "confidence": "medium",
        "body_regex": r"(?i)(?:\$\{jndi:(?:ldap|rmi|dns|nis|iiop):|log4shell|log4j)",
        "summary": "Log4J exploit markers were observed in a public response.",
        "evidence_template": "Log4J exploit markers were observed in the response at {path}.",
        "evidence": "Log4J exploit markers were observed in a public response.",
    },
    "MagentoXxePlugin": {
        "aliases": ["magento", "adobe commerce"],
        "any_of_path_contains": ["/rest/", "/graphql", "/admin"],
        "path_not_contains": ["/docs", "/developer"],
    },
    "MeshCentralPlugin": {
        "aliases": ["meshcentral", "mesh central"],
        "any_of_path_contains": ["/meshagents", "/control.ashx", "/agentinvite", "/login"],
    },
    "NetBoxPlugin": {
        "aliases": ["netbox"],
        "any_of_path_contains": ["/api/status", "/dcim/", "/ipam/", "/circuits/"],
    },
    "NodeREDPlugin": {
        "aliases": ["node-red", "nodered"],
        "any_of_path_contains": ["/red/", "/flows", "/settings"],
    },
    "PhpCgiRcePlugin": {
        "aliases": [],
        "detector": "php_cgi_rce_best_effort",
        "confidence": "medium",
        "body_regex": r"(?i)(?:php[- ]cgi|cgi-bin/.+\.php|php/[\d.]+)",
        "any_of_path_contains": ["/cgi-bin/", ".php"],
        "summary": "PHP CGI markers were observed in a potentially unsafe execution path.",
        "evidence_template": "PHP CGI execution markers were observed at {path}.",
        "evidence": "PHP CGI markers were observed in a potentially unsafe execution path.",
    },
    "PhpStdinPlugin": {
        "aliases": [],
        "detector": "php_stdin_best_effort",
        "confidence": "medium",
        "body_regex": r"(?i)(?:php://input|stdin|auto_prepend_file)",
        "summary": "PHP stdin/input execution markers were observed in a public response.",
        "evidence_template": "PHP stdin/input execution markers were observed at {path}.",
        "evidence": "PHP stdin/input execution markers were observed in a public response.",
    },
    "RabbitMQPlugin": {
        "aliases": ["rabbitmq management", "rabbitmq"],
        "any_of_path_contains": ["/api/overview", "/api/whoami", "/api/nodes", "/rabbitmq/"],
    },
    "RustFSPlugin": {
        "aliases": ["rustfs"],
        "any_of_path_contains": ["/minio/health", "/rpc/", "/console/"],
    },
    "SelenoidPlugin": {
        "aliases": ["selenoid"],
        "any_of_path_contains": ["/status", "/wd/hub", "/video/", "/vnc/"],
    },
    "SpipRcePlugin": {
        "aliases": ["spip"],
        "any_of_path_contains": ["/spip.php", "/ecrire/", "/spip/"],
    },
    "SupersetPlugin": {
        "aliases": ["apache superset", "superset"],
        "any_of_path_contains": ["/superset/welcome", "/api/v1", "/login/"],
        "path_not_contains": ["/docs", "/faq"],
    },
    "SurrealDBPlugin": {
        "aliases": ["surrealdb", "surreal db"],
        "any_of_path_contains": ["/health", "/signin", "/sql"],
    },
    "TacticalRMMPlugin": {
        "aliases": ["tactical rmm", "tacticalrmm"],
        "any_of_path_contains": ["/api/v3", "/login", "/mesh/"],
    },
    "TikaPlugin": {
        "aliases": ["apache tika", "tika"],
        "any_of_path_contains": ["/tika", "/meta", "/rmeta", "/detect/stream"],
    },
    "TraversalHttpPlugin": {
        "aliases": [],
        "detector": "traversal_http_best_effort",
        "confidence": "high",
        "body_regex": r"(?i)(?:root:.:0:0:|for 16-bit app support|\[extensions\]|boot loader|zone\.transfer|<!doctype html public)",
        "summary": "Traversal markers were observed in a public HTTP response.",
        "evidence_template": "Traversal response markers were observed at {path}.",
        "evidence": "Traversal markers were observed in a public HTTP response.",
    },
    "WpUserEnumHttp": {
        "aliases": [],
        "detector": "wordpress_user_enumeration_best_effort",
        "confidence": "medium",
        "path_regex": r"(?i)(?:/wp-json/wp/v2/users|[?&]author=\d+)",
        "body_regex": r'(?i)"slug"\s*:\s*"[^"]+"',
        "summary": "WordPress user enumeration markers were observed in a public response.",
        "evidence_template": "WordPress user-enumeration markers were observed at {path}.",
        "evidence": "WordPress user enumeration markers were observed in a public response.",
    },
}

MANUAL_VERSION_RULES = [
    {
        "plugin_id": "LiteLLMPlugin",
        "detector": "litellm_vulnerable_version",
        "severity": "high",
        "confidence": "high",
        "body_contains": ["litellm"],
        "version_regex": r"(?i)(?:version|litellm)[^0-9]*(?P<version>\d+\.\d+\.\d+(?:\.\d+)?)",
        "affected_ranges": [{"introduced": "0", "fixed": "1.83.0"}],
        "cve_ids": ["CVE-2026-35029", "CVE-2026-35030"],
        "kev_matched": False,
        "product_name": "LiteLLM",
        "redacted_value": "litellm_vulnerable_version",
        "evidence_template": "{product_name} version {product_version} matched affected LiteLLM ranges for CVE-2026-35029/CVE-2026-35030 at {path}.",
        "evidence": "LiteLLM version markers matched affected releases for CVE-2026-35029 and CVE-2026-35030.",
    },
    {
        "plugin_id": "FlowiseVersionPlugin",
        "detector": "flowise_vulnerable_version",
        "severity": "high",
        "confidence": "high",
        "body_contains": ["flowise"],
        "version_regex": r"(?i)(?:version|flowise)[^0-9]*(?P<version>\d+\.\d+\.\d+(?:\.\d+)?)",
        "affected_ranges": [
            {"introduced": "0", "last_affected": "2.2.6"},
            {"introduced": "0", "fixed": "3.0.6"},
            {"introduced": "0", "fixed": "3.0.8"},
        ],
        "cve_ids": [
            "CVE-2025-26319",
            "CVE-2025-50538",
            "CVE-2025-58434",
            "CVE-2025-61913",
            "CVE-2025-8943",
        ],
        "kev_matched": False,
        "product_name": "Flowise",
        "redacted_value": "flowise_vulnerable_version",
        "evidence_template": "{product_name} version {product_version} matched affected Flowise release ranges at {path}.",
        "evidence": "Flowise version markers matched release ranges with published CVEs.",
    },
]

VERSION_RULE_OVERRIDES = {
    "ApacheOFBizPlugin": {
        "aliases": ["apache ofbiz", "ofbiz"],
        "any_of_path_contains": ["/webtools", "/control", "/ecommerce"],
    },
    "AppsmithPlugin": {
        "aliases": ["appsmith"],
        "version_headers": ["x-appsmith-version"],
        "any_of_path_contains": ["/api/v1/health", "/applications", "/user/login"],
        "path_not_contains": ["/docs", "/blog"],
        "affected_ranges": [{"introduced": "0", "fixed": "1.51"}],
        "cve_ids": ["CVE-2024-55965"],
        "kev_matched": False,
        "evidence_template": "{product_name} version {product_version} matched affected Appsmith versions for CVE-2024-55965 at {path}.",
    },
    "BeyondTrustRSPlugin": {
        "aliases": [
            "beyondtrust",
            "beyondtrust remote support",
            "privileged remote access",
        ],
        "any_of_path_contains": ["/login", "/portal", "/session"],
    },
    "BitbucketPlugin": {
        "aliases": ["bitbucket"],
        "any_of_path_contains": ["/users/sign_in", "/account/signin", "/login"],
        "path_not_contains": ["/documentation", "/docs"],
        "affected_ranges": [{"introduced": "7.0.0", "last_affected": "8.3.0"}],
        "cve_ids": ["CVE-2022-36804"],
        "kev_matched": True,
        "evidence_template": "{product_name} version {product_version} matched affected Bitbucket ranges for CVE-2022-36804 at {path}.",
    },
    "CalcomPlugin": {
        "aliases": ["cal.com", "calcom"],
        "any_of_path_contains": ["/auth/login", "/booking", "/api/auth"],
        "path_not_contains": ["/docs", "/blog"],
        "affected_ranges": [{"introduced": "0", "last_affected": "5.9.7"}],
        "cve_ids": ["CVE-2025-66489"],
        "kev_matched": False,
        "evidence_template": "{product_name} version {product_version} matched affected Cal.com versions for CVE-2025-66489 at {path}.",
    },
    "CentosWebPanelPlugin": {"aliases": ["centos web panel", "cwp"]},
    "CheckpointGwPlugin": {"aliases": ["check point", "checkpoint", "gaia"]},
    "CiscoASAPlugin": {"aliases": ["cisco asa", "adaptive security appliance"]},
    "CiscoRV": {"aliases": ["cisco rv"]},
    "CiscoSDWANPlugin": {"aliases": ["cisco sd-wan", "sd-wan", "vmanage"]},
    "CitrixADCPlugin": {"aliases": ["citrix adc", "netscaler"]},
    "CloudPanelPlugin": {"aliases": ["cloudpanel", "cloud panel"]},
    "ComfyUIPlugin": {
        "aliases": ["comfyui", "comfy ui"],
        "any_of_path_contains": ["/queue", "/history", "/prompt"],
    },
    "ConfluenceVersionIssue": {
        "aliases": ["confluence"],
        "any_of_path_contains": ["/login.action", "/spaces/", "/wiki/"],
        "path_not_contains": ["/rest/api", "/swagger"],
        "affected_ranges": [
            {"introduced": "8.0.0", "fixed": "8.3.3"},
            {"introduced": "8.4.0", "fixed": "8.4.3"},
            {"introduced": "8.5.0", "fixed": "8.5.2"},
        ],
        "cve_ids": ["CVE-2023-22515"],
        "kev_matched": True,
        "evidence_template": "{product_name} version {product_version} matched affected Confluence ranges for CVE-2023-22515 at {path}.",
    },
    "CrushFTPPlugin": {"aliases": ["crushftp", "crush ftp"]},
    "CyberPanelPlugin": {"aliases": ["cyberpanel", "cyber panel"]},
    "EsxVersionPlugin": {"aliases": ["esxi", "vmware esxi"]},
    "ExchangeVersion": {"aliases": ["microsoft exchange", "exchange server"]},
    "EzGED3Plugin": {"aliases": ["ezged3", "ez ged3"]},
    "FortiGatePlugin": {"aliases": ["fortigate"]},
    "FortiOSPlugin": {"aliases": ["fortios", "forti os"]},
    "FortiWebPlugin": {"aliases": ["fortiweb", "forti web"]},
    "FreePBXPlugin": {"aliases": ["freepbx", "free pbx"]},
    "GitlabPlugin": {
        "aliases": ["gitlab"],
        "any_of_path_contains": ["/users/sign_in", "/-/health", "/help"],
        "path_not_contains": ["/docs", "/blog"],
        "affected_ranges": [
            {"introduced": "16.1.0", "fixed": "16.1.6"},
            {"introduced": "16.2.0", "fixed": "16.2.9"},
            {"introduced": "16.3.0", "fixed": "16.3.7"},
            {"introduced": "16.4.0", "fixed": "16.4.5"},
            {"introduced": "16.5.0", "fixed": "16.5.6"},
            {"introduced": "16.6.0", "fixed": "16.6.4"},
            {"introduced": "16.7.0", "fixed": "16.7.2"},
        ],
        "cve_ids": ["CVE-2023-7028"],
        "kev_matched": True,
        "evidence_template": "{product_name} version {product_version} matched affected GitLab ranges for CVE-2023-7028 at {path}.",
    },
    "GladinetPlugin": {"aliases": ["gladinet", "centrestack", "triofox"]},
    "GLPIVersionPlugin": {"aliases": ["glpi"]},
    "IceWarpPlugin": {"aliases": ["icewarp", "ice warp"]},
    "IOSEXPlugin": {"aliases": ["ios xe", "cisco ios xe"]},
    "IvantiConnectSecure": {
        "aliases": ["ivanti connect secure", "pulse secure", "connect secure"]
    },
    "IvantiEPMMPlugin": {
        "aliases": ["ivanti epmm", "mobileiron core", "ivanti mobileiron"]
    },
    "JiraPlugin": {
        "aliases": ["jira"],
        "any_of_path_contains": ["/login.jsp", "/secure/", "/servicedesk/"],
        "path_not_contains": ["/rest/api/latest/serverInfo"],
        "affected_ranges": [
            {"introduced": "0", "fixed": "8.5.14"},
            {"introduced": "8.6.0", "fixed": "8.13.6"},
            {"introduced": "8.14.0", "fixed": "8.16.1"},
        ],
        "cve_ids": ["CVE-2021-26086"],
        "kev_matched": True,
        "evidence_template": "{product_name} version {product_version} matched affected Jira ranges for CVE-2021-26086 at {path}.",
    },
    "JunosJWebPlugin": {"aliases": ["junos", "j-web", "jweb", "juniper"]},
    "KerioControlPlugin": {"aliases": ["kerio control"]},
    "KestrelPlugin": {"aliases": ["kestrel"]},
    "MagicInfoPlugin": {"aliases": ["magicinfo", "magic info"]},
    "MetabaseHttpPlugin": {
        "aliases": ["metabase"],
        "version_headers": ["x-metabase-version"],
        "any_of_path_contains": ["/api/health", "/api/session/properties", "/auth/login"],
        "path_not_contains": ["/docs", "/learn"],
        "affected_ranges": [
            {"introduced": "0", "fixed": "0.55.13"},
            {"introduced": "0.56.0", "fixed": "0.56.3"},
            {"introduced": "0.57.0", "fixed": "0.57.1"},
        ],
        "cve_ids": ["CVE-2026-22805"],
        "kev_matched": False,
        "evidence_template": "{product_name} version {product_version} matched affected Metabase ranges for CVE-2026-22805 at {path}.",
    },
    "MinioPlugin": {"aliases": ["minio"]},
    "MitelMiCollabPlugin": {"aliases": ["micollab", "mi collab", "mitel micollab"]},
    "MobileIronCorePlugin": {
        "aliases": ["mobileiron core", "ivanti mobileiron", "mobileiron"]
    },
    "MobileIronSentryPlugin": {
        "aliases": ["mobileiron sentry", "ivanti mobileiron sentry"]
    },
    "MonstaFtpVersionPlugin": {"aliases": ["monstaftp", "monsta ftp"]},
    "N8nPlugin": {
        "aliases": ["n8n"],
        "version_headers": ["x-n8n-version"],
        "any_of_path_contains": ["/rest/settings", "/rest/login", "/login"],
        "path_not_contains": ["/docs", "/courses"],
        "affected_ranges": [
            {"introduced": "0.211.0", "fixed": "1.120.4"},
            {"introduced": "1.121.0", "fixed": "1.121.1"},
        ],
        "cve_ids": ["CVE-2025-68613"],
        "kev_matched": False,
        "evidence_template": "{product_name} version {product_version} matched affected n8n ranges for CVE-2025-68613 at {path}.",
    },
    "NCentralPlugin": {"aliases": ["n-able n-central", "n-central", "ncentral"]},
    "NexusRepoPlugin": {"aliases": ["nexus repository", "sonatype nexus", "nexus repo"]},
    "OracleEBSPlugin": {"aliases": ["oracle e-business", "oracle ebs"]},
    "PaloAltoPlugin": {"aliases": ["palo alto", "pan-os", "panos"]},
    "PaperCutPlugin": {
        "aliases": ["papercut", "paper cut"],
        "any_of_path_contains": ["/app", "/admin", "/user"],
        "path_not_contains": ["/help", "/kb"],
    },
    "PulseConnectPlugin": {"aliases": ["pulse secure", "pulse connect secure"]},
    "QnapVersion": {"aliases": ["qnap"]},
    "React2ShellPlugin": {"aliases": ["next.js", "nextjs", "react"]},
    "SessionReaperPlugin": {"aliases": ["magento", "adobe commerce"]},
    "SharePoint202501": {
        "aliases": ["sharepoint", "microsoft sharepoint"],
        "any_of_path_contains": ["/_layouts/", "/sites/", "/_vti_bin/"],
        "path_not_contains": ["/_api/web", "/docs"],
        "affected_ranges": [{"introduced": "0", "fixed": "16.0.17928.20356"}],
        "cve_ids": ["CVE-2025-21344", "CVE-2025-21348", "CVE-2025-21393"],
        "kev_matched": False,
        "evidence_template": "{product_name} version {product_version} matched SharePoint January 2025 affected builds at {path}.",
    },
    "SharePoint202502": {
        "aliases": ["sharepoint", "microsoft sharepoint"],
        "any_of_path_contains": ["/_layouts/", "/sites/", "/_vti_bin/"],
        "path_not_contains": ["/_api/web", "/docs"],
        "affected_ranges": [{"introduced": "0", "fixed": "16.0.17928.20396"}],
        "cve_ids": ["CVE-2025-21400"],
        "kev_matched": False,
        "evidence_template": "{product_name} version {product_version} matched SharePoint February 2025 affected builds at {path}.",
    },
    "SharePointPlugin": {
        "aliases": ["sharepoint", "microsoft sharepoint"],
        "any_of_path_contains": ["/_layouts/", "/sites/", "/_vti_bin/"],
        "path_not_contains": ["/_api/web", "/docs"],
        "affected_ranges": [{"introduced": "0", "fixed": "16.0.18526.20508"}],
        "cve_ids": [
            "CVE-2025-49704",
            "CVE-2025-49706",
            "CVE-2025-53770",
            "CVE-2025-53771",
        ],
        "kev_matched": True,
        "evidence_template": "{product_name} version {product_version} matched SharePoint ToolShell-affected builds at {path}.",
    },
    "SmarterMailPlugin": {"aliases": ["smartermail", "smarter mail"]},
    "SolarWindsWHDPlugin": {
        "aliases": ["solarwinds web help desk", "solarwinds whd"]
    },
    "SonicWallGMSPlugin": {"aliases": ["sonicwall gms"]},
    "SonicWallSMA202501": {
        "aliases": ["sonicwall sma", "secure mobile access", "sonicwall"]
    },
    "SonicWallSMAPlugin": {
        "aliases": ["sonicwall sma", "secure mobile access", "sonicwall"]
    },
    "SophosPlugin": {"aliases": ["sophos"]},
    "SplunkPlugin": {
        "aliases": ["splunk"],
        "any_of_path_contains": ["/en-US/account/login", "/en-US/app", "/en-US/manager"],
        "path_not_contains": ["/documentation", "/docs"],
    },
    "SysAidPlugin": {"aliases": ["sysaid", "sys aid"]},
    "TeamCityPlugin": {
        "aliases": ["teamcity", "team city"],
        "any_of_path_contains": ["/login.html", "/app/rest/server", "/app/agents"],
        "path_not_contains": ["/documentation", "/docs"],
        "affected_ranges": [{"introduced": "0", "fixed": "2023.11.4"}],
        "cve_ids": ["CVE-2024-27198"],
        "kev_matched": True,
        "evidence_template": "{product_name} version {product_version} matched affected TeamCity ranges for CVE-2024-27198 at {path}.",
    },
    "TraccarPlugin": {"aliases": ["traccar"]},
    "TwonkyPlugin": {"aliases": ["twonky"]},
    "VBulletinPlugin": {"aliases": ["vbulletin", "v bulletin"]},
    "VCenterVersionPlugin": {"aliases": ["vcenter", "vsphere", "vmware vcenter"]},
    "veeaml9": {"aliases": ["veeam"]},
    "VeeamPlugin": {"aliases": ["veeam"]},
    "ViciboxVersionPlugin": {"aliases": ["vicibox"]},
    "VinChinBackupPlugin": {"aliases": ["vinchin", "vin chin"]},
    "VMWareCloudDirector": {
        "aliases": ["vmware cloud director", "cloud director"]
    },
    "WatchGuardFireboxPlugin": {
        "aliases": ["watchguard firebox", "firebox", "watchguard"]
    },
    "WazuhPlugin": {
        "aliases": ["wazuh"],
        "any_of_path_contains": ["/app/login", "/security/user/authenticate", "/api/status"],
        "path_not_contains": ["/documentation", "/docs"],
        "affected_ranges": [{"introduced": "4.4.0", "fixed": "4.9.1"}],
        "cve_ids": ["CVE-2025-24016"],
        "kev_matched": False,
        "evidence_template": "{product_name} version {product_version} matched affected Wazuh ranges for CVE-2025-24016 at {path}.",
    },
    "WsFTPPlugin": {"aliases": ["ws_ftp", "ws ftp"]},
    "Wso2Plugin": {"aliases": ["wso2"]},
    "XWikiPlugin": {"aliases": ["xwiki"]},
    "ZimbraPlugin": {"aliases": ["zimbra"]},
    "ZitadelPlugin": {"aliases": ["zitadel"]},
    "ZoneMinderPlugin": {
        "aliases": ["zoneminder", "zone minder"],
        "any_of_path_contains": ["/zm", "/index.php", "/api/host"],
        "path_not_contains": ["/docs", "/wiki"],
        "affected_ranges": [{"introduced": "0", "fixed": "1.36.33"}],
        "cve_ids": [
            "CVE-2023-25825",
            "CVE-2023-26032",
            "CVE-2023-26034",
            "CVE-2023-26035",
            "CVE-2023-26036",
            "CVE-2023-26037",
            "CVE-2023-26039",
        ],
        "kev_matched": False,
        "evidence_template": "{product_name} version {product_version} matched affected ZoneMinder versions before 1.36.33 at {path}.",
    },
    "ZyxelVersion": {"aliases": ["zyxel"]},
}


def load_version_rule_advisory_cache() -> dict[str, list[dict[str, object]]]:
    if not VERSION_RULE_ADVISORY_CACHE_PATH.exists():
        return {}
    return json.loads(VERSION_RULE_ADVISORY_CACHE_PATH.read_text())


def maybe_attach_auto_version_advisories(
    rule: dict[str, object], advisory_cache: dict[str, list[dict[str, object]]]
) -> dict[str, object]:
    plugin_id = str(rule.get("plugin_id", "")).strip()
    if not plugin_id:
        return rule
    advisories = advisory_cache.get(plugin_id, [])
    if advisories:
        rule["advisories"] = advisories
    return rule


def derived_product_name(display_name: str, aliases: list[str], plugin_id: str) -> str:
    name = display_name.strip()
    removals = [
        " with Known Vulnerabilities",
        " - Known Vulnerabilities",
        " - Vulnerable Instance",
        " instance outdated",
        " is outdated",
        " outdated",
        " looks outdated",
        " exposed and vulnerable",
        " vulnerable",
        " - Unauthenticated Access / Vulnerable Version",
        " is backdoored",
        " hardware outdated",
        " service outdated",
        " appliance outdated",
    ]
    for removal in removals:
        if name.endswith(removal):
            name = name[: -len(removal)].rstrip(" -")
            break
    if name and name != display_name:
        return name
    if aliases:
        return aliases[0]
    return plugin_id


def derived_review_labels(
    entry: dict[str, object], plugin_id: str, base_labels: list[str]
) -> list[str]:
    labels = list(base_labels)
    family = str(entry.get("family", "")).strip()
    execution_mode = str(entry.get("execution_mode", "")).strip()
    if execution_mode == "passive_http":
        labels.append("passive_http")
    elif execution_mode == "version_correlation":
        labels.append("version_correlation")
    elif execution_mode == "active_authorized":
        labels.append("active_authorized")
    if family == "ai_llm_vector":
        labels.append("ai_llm")
    elif family == "enterprise_web_apps":
        labels.append("enterprise_web")
    elif family == "network_security_appliances":
        labels.append("appliance")
    elif family == "ops_observability":
        labels.append("ops_surface")
    labels.extend(RULE_LABEL_OVERRIDES.get(plugin_id, []))
    deduped = []
    seen = set()
    for label in labels:
        cleaned = str(label).strip().lower().replace(" ", "_")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            deduped.append(cleaned)
    return deduped


def load_catalog() -> list[dict[str, object]]:
    return json.loads(CATALOG_PATH.read_text())


def generated_http_rules(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    rules = list(MANUAL_HTTP_RULES)
    seen = {rule["plugin_id"] for rule in rules}
    for entry in entries:
        if entry["implementation_source"] != "external_reported":
            continue
        if entry["plugin_id"] in PROTOCOL_BUILTIN_PROMOTIONS:
            continue
        if entry["execution_mode"] not in {"passive_http", "active_authorized"}:
            continue
        plugin_id = entry["plugin_id"]
        if plugin_id in seen:
            continue
        rule = {
            "plugin_id": plugin_id,
            "severity": entry["default_severity"],
            "confidence": "medium",
            "review_labels": derived_review_labels(
                entry, plugin_id, ["best_effort", "bundled_rule", "generated_rule", "http_rule"]
            ),
            "summary": f"{entry['display_name']} markers were observed in a public response.",
            "evidence_template": "{product_name} markers were observed at {path}.",
            "evidence": f"{entry['display_name']} markers were observed in a public response.",
        }
        rule.update(HTTP_RULE_OVERRIDES.get(plugin_id, {}))
        aliases = rule.get("aliases", [])
        if (
            isinstance(aliases, list)
            and aliases
            and (
                rule.get("path_contains")
                or rule.get("any_of_path_contains")
                or rule.get("body_contains")
                or rule.get("any_of_body_contains")
                or rule.get("path_regex")
                or rule.get("body_regex")
                or rule.get("header_contains")
                or rule.get("header_regex")
            )
        ):
            rule.setdefault("min_score", 2)
        if "product_name" not in rule:
            rule["product_name"] = derived_product_name(
                str(entry["display_name"]),
                [str(value) for value in aliases] if isinstance(aliases, list) else [],
                plugin_id,
            )
        rules.append(rule)
        seen.add(plugin_id)
    return sorted(rules, key=lambda rule: rule["plugin_id"])


def generated_version_rules(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    advisory_cache = load_version_rule_advisory_cache()
    rules = [
        maybe_attach_auto_version_advisories(dict(rule), advisory_cache)
        for rule in MANUAL_VERSION_RULES
    ]
    seen = {rule["plugin_id"] for rule in rules}
    for entry in entries:
        if entry["implementation_source"] != "external_reported":
            continue
        if entry["execution_mode"] != "version_correlation":
            continue
        plugin_id = entry["plugin_id"]
        if plugin_id in seen:
            continue
        rule = {
            "plugin_id": plugin_id,
            "severity": entry["default_severity"],
            "confidence": "medium",
            "review_labels": derived_review_labels(
                entry,
                plugin_id,
                ["best_effort", "bundled_rule", "generated_rule", "version_rule"],
            ),
            "presence_only": True,
            "fallback_any_version": True,
            "evidence_template": "{product_name} version {product_version} matched best-effort route/header hints at {path}.",
            "evidence": f"{entry['display_name']} version markers were observed in a public response.",
        }
        rule.update(VERSION_RULE_OVERRIDES.get(plugin_id, {}))
        aliases = rule.get("aliases", [])
        rule.setdefault("min_score", 2)
        rule.setdefault("version_score", 1)
        if "product_name" not in rule:
            rule["product_name"] = derived_product_name(
                str(entry["display_name"]),
                [str(value) for value in aliases] if isinstance(aliases, list) else [],
                plugin_id,
            )
        rule = maybe_attach_auto_version_advisories(rule, advisory_cache)
        rules.append(rule)
        seen.add(plugin_id)
    return sorted(rules, key=lambda rule: rule["plugin_id"])


def main() -> int:
    entries = load_catalog()
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    HTTP_RULES_PATH.write_text(json.dumps(generated_http_rules(entries), indent=2) + "\n")
    VERSION_RULES_PATH.write_text(json.dumps(generated_version_rules(entries), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
