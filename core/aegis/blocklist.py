"""
Blocklist and Domain Filter Engine for AegisDNS.
Supports exact matching, wildcard/subdomain matching, CIDR IP filtering,
hosts-file format, AdBlock-style rules, and CNAME cloaking inspection.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Set, Dict, List, Optional, Tuple


_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$")


class BlocklistManager:
    def __init__(self):
        # Exact domains blocked: {"ads.com", "tracker.org"}
        self.exact_blocks: Set[str] = set()
        # Wildcard root domains blocked (matches self and all subdomains): {"doubleclick.net"}
        self.wildcard_blocks: Set[str] = set()
        # Regex patterns
        self.regex_blocks: List[Tuple[re.Pattern, str]] = []
        # Allowlist (exact or suffix):
        self.allowlist_exact: Set[str] = set()
        self.allowlist_wildcard: Set[str] = set()
        # Blocked IP networks
        self.blocked_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._blocked_network_strs: Set[str] = set()
        # Source metadata: rule -> category/source
        self.rule_metadata: Dict[str, str] = {}
        # Stats
        self.stats = {"rules_loaded": 0, "allows_loaded": 0}

    def clear(self):
        self.exact_blocks.clear()
        self.wildcard_blocks.clear()
        self.regex_blocks.clear()
        self.allowlist_exact.clear()
        self.allowlist_wildcard.clear()
        self.blocked_networks.clear()
        self._blocked_network_strs.clear()
        self.rule_metadata.clear()
        self.stats = {"rules_loaded": 0, "allows_loaded": 0}

    def add_allowed_domain(self, domain: str, wildcard: bool = False) -> bool:
        domain = self._normalize_domain(domain)
        if not domain:
            return False
        if wildcard or domain.startswith("*."):
            clean = domain.lstrip("*.")
            if not self._is_valid_domain(clean):
                return False
            if clean in self.allowlist_wildcard:
                return False
            self.allowlist_wildcard.add(clean)
        else:
            if not self._is_valid_domain(domain):
                return False
            if domain in self.allowlist_exact:
                return False
            self.allowlist_exact.add(domain)
        self.stats["allows_loaded"] += 1
        return True

    def remove_allowed_domain(self, domain: str, wildcard: Optional[bool] = None) -> bool:
        domain = self._normalize_domain(domain)
        clean = domain.lstrip("*.")
        removed = False
        if wildcard is None or wildcard is True:
            if clean in self.allowlist_wildcard:
                self.allowlist_wildcard.remove(clean)
                self.stats["allows_loaded"] = max(0, self.stats["allows_loaded"] - 1)
                removed = True
        if wildcard is None or wildcard is False:
            if domain in self.allowlist_exact:
                self.allowlist_exact.remove(domain)
                self.stats["allows_loaded"] = max(0, self.stats["allows_loaded"] - 1)
                removed = True
        return removed

    def add_blocked_domain(
        self, domain: str, wildcard: bool = False, category: str = "custom"
    ) -> bool:
        domain = self._normalize_domain(domain)
        if not domain:
            return False
        if wildcard or domain.startswith("*."):
            clean = domain.lstrip("*.")
            if not self._is_valid_domain(clean):
                return False
            is_new = clean not in self.wildcard_blocks
            self.wildcard_blocks.add(clean)
            self.rule_metadata[clean] = category
        else:
            if not self._is_valid_domain(domain):
                return False
            is_new = domain not in self.exact_blocks
            self.exact_blocks.add(domain)
            self.rule_metadata[domain] = category
        if is_new:
            self.stats["rules_loaded"] += 1
        return is_new

    def remove_blocked_domain(self, domain: str, wildcard: Optional[bool] = None) -> bool:
        domain = self._normalize_domain(domain)
        clean = domain.lstrip("*.")
        removed = False
        if wildcard is None or wildcard is True:
            if clean in self.wildcard_blocks:
                self.wildcard_blocks.remove(clean)
                self.rule_metadata.pop(clean, None)
                self.stats["rules_loaded"] = max(0, self.stats["rules_loaded"] - 1)
                removed = True
        if wildcard is None or wildcard is False:
            if domain in self.exact_blocks:
                self.exact_blocks.remove(domain)
                self.rule_metadata.pop(domain, None)
                self.stats["rules_loaded"] = max(0, self.stats["rules_loaded"] - 1)
                removed = True
        return removed

    def add_blocked_ip_or_cidr(self, cidr: str, category: str = "custom") -> bool:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            net_str = str(net)
            if net_str in self._blocked_network_strs:
                self.rule_metadata[net_str] = category
                return False
            self.blocked_networks.append(net)
            self._blocked_network_strs.add(net_str)
            self.rule_metadata[net_str] = category
            self.stats["rules_loaded"] += 1
            return True
        except ValueError:
            return False

    def add_regex_block(self, pattern: str, category: str = "regex") -> bool:
        try:
            if any(raw == pattern for _, raw in self.regex_blocks):
                self.rule_metadata[pattern] = category
                return False
            compiled = re.compile(pattern, re.IGNORECASE)
            self.regex_blocks.append((compiled, pattern))
            self.rule_metadata[pattern] = category
            self.stats["rules_loaded"] += 1
            return True
        except re.error:
            return False

    def load_from_text(self, content: str, default_category: str = "blocklist") -> int:
        """Parses /etc/hosts format, Adblock DNS syntax, plain domain lists, and CIDRs."""
        loaded = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue

            # Skip Adblock cosmetic / element-hiding filters before stripping '#' comments
            if any(tok in line for tok in ("##", "#@#", "#?#", "#$#", "#@$#")):
                continue

            # Strip inline '#' comments
            if "#" in line:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue

            # Adblock exception / whitelist rule: @@||domain^ or @@||domain or @@domain
            if line.startswith("@@"):
                clean = line[2:].strip()
                if "$" in clean:
                    clean = clean.split("$", 1)[0].strip()
                clean = clean.rstrip("^")
                is_wildcard = False
                if clean.startswith("||"):
                    clean = clean[2:]
                    is_wildcard = True
                elif clean.startswith("*."):
                    clean = clean[2:]
                    is_wildcard = True
                # Skip URL/path rules that are not pure DNS hostnames
                if clean and "/" not in clean and "*" not in clean:
                    if self.add_allowed_domain(clean, wildcard=is_wildcard):
                        loaded += 1
                continue

            # Adblock style: ||example.com^ or ||example.com^$third-party or ||example.com
            if line.startswith("||"):
                clean = line[2:].strip()
                if "$" in clean:
                    clean = clean.split("$", 1)[0].strip()
                clean = clean.rstrip("^")
                # Skip URL path rules (e.g. ||example.com/ads.js^) in DNS-level filtering
                if clean and "/" not in clean and "*" not in clean:
                    if self.add_blocked_domain(clean, wildcard=True, category=default_category):
                        loaded += 1
                continue

            # Hosts file format: 0.0.0.0 ads.example.com or 127.0.0.1 domain
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                for domain in parts[1:]:
                    if domain.lower() not in (
                        "localhost",
                        "localhost.localdomain",
                        "local",
                        "broadcasthost",
                        "ip6-localhost",
                        "ip6-loopback",
                    ):
                        if self.add_blocked_domain(domain, wildcard=False, category=default_category):
                            loaded += 1
                continue

            # Single domain or CIDR per line
            if len(parts) == 1:
                token = parts[0]
                if "/" in token:
                    if self.add_blocked_ip_or_cidr(token, category=default_category):
                        loaded += 1
                else:
                    is_wildcard = token.startswith("*.")
                    if self.add_blocked_domain(token, wildcard=is_wildcard, category=default_category):
                        loaded += 1

        return loaded

    def is_domain_allowed(self, domain: str) -> bool:
        domain = self._normalize_domain(domain)
        if not domain:
            return False
        if domain in self.allowlist_exact:
            return True
        labels = domain.split(".")
        for i in range(len(labels)):
            sub = ".".join(labels[i:])
            if sub in self.allowlist_wildcard:
                return True
        return False

    def is_domain_blocked(self, domain: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Evaluates whether domain is blocked.
        Returns: (is_blocked, rule_matched, category)
        """
        domain = self._normalize_domain(domain)
        if not domain:
            return False, None, None

        # Check allowlist first
        if self.is_domain_allowed(domain):
            return False, None, None

        # 1. Exact match
        if domain in self.exact_blocks:
            cat = self.rule_metadata.get(domain, "blocked")
            return True, domain, cat

        # 2. Wildcard / Suffix match
        labels = domain.split(".")
        for i in range(len(labels)):
            sub = ".".join(labels[i:])
            if sub in self.wildcard_blocks:
                cat = self.rule_metadata.get(sub, "wildcard")
                return True, f"*.{sub}", cat

        # 3. Regex match
        for pattern, raw_pat in self.regex_blocks:
            if pattern.search(domain):
                cat = self.rule_metadata.get(raw_pat, "regex")
                return True, raw_pat, cat

        return False, None, None

    def check_cname_chain(
        self, original_domain: str, cname_targets: List[str]
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """
        Inspects a list of CNAME targets for CNAME cloaking against the blocklist.
        Explicitly allowlisted original domains bypass CNAME cloaking blocks.
        Returns: (is_blocked, matched_cname, matched_rule, category)
        """
        if self.is_domain_allowed(original_domain):
            return False, None, None, None
        for target in cname_targets:
            blocked, rule, cat = self.is_domain_blocked(target)
            if blocked:
                return True, self._normalize_domain(target), rule, cat
        return False, None, None, None

    def is_ip_blocked(self, ip_str: str) -> Tuple[bool, Optional[str]]:
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            for net in self.blocked_networks:
                if ip in net:
                    return True, str(net)
        except ValueError:
            pass
        return False, None

    def summary(self) -> dict:
        return {
            "exact_blocks": len(self.exact_blocks),
            "wildcard_blocks": len(self.wildcard_blocks),
            "regex_blocks": len(self.regex_blocks),
            "blocked_networks": len(self.blocked_networks),
            "allowlist_exact": len(self.allowlist_exact),
            "allowlist_wildcard": len(self.allowlist_wildcard),
            "rules_loaded": self.stats["rules_loaded"],
            "allows_loaded": self.stats["allows_loaded"],
        }

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        return domain.strip().rstrip(".").lower()

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        if not domain or len(domain) > 253 or " " in domain or "/" in domain:
            return False
        labels = domain.split(".")
        return all(_DOMAIN_LABEL_RE.match(lbl) is not None for lbl in labels)
