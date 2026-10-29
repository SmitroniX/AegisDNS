"""
Blocklist and Domain Filter Engine for AegisDNS.
Supports exact matching, wildcard/subdomain matching, CIDR IP filtering,
hosts-file format, and AdBlock-style rules.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Set, Dict, List, Optional, Tuple


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
        self.rule_metadata.clear()
        self.stats = {"rules_loaded": 0, "allows_loaded": 0}

    def add_allowed_domain(self, domain: str, wildcard: bool = False):
        domain = self._normalize_domain(domain)
        if not domain:
            return
        if wildcard or domain.startswith("*."):
            clean = domain.lstrip("*.")
            self.allowlist_wildcard.add(clean)
        else:
            self.allowlist_exact.add(domain)
        self.stats["allows_loaded"] += 1

    def add_blocked_domain(self, domain: str, wildcard: bool = False, category: str = "custom"):
        domain = self._normalize_domain(domain)
        if not domain:
            return
        if wildcard or domain.startswith("*."):
            clean = domain.lstrip("*.")
            self.wildcard_blocks.add(clean)
            self.rule_metadata[clean] = category
        else:
            self.exact_blocks.add(domain)
            self.rule_metadata[domain] = category
        self.stats["rules_loaded"] += 1

    def add_blocked_ip_or_cidr(self, cidr: str, category: str = "custom"):
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            self.blocked_networks.append(net)
            self.rule_metadata[str(net)] = category
            self.stats["rules_loaded"] += 1
        except ValueError:
            pass

    def add_regex_block(self, pattern: str, category: str = "regex"):
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self.regex_blocks.append((compiled, pattern))
            self.rule_metadata[pattern] = category
            self.stats["rules_loaded"] += 1
        except re.error:
            pass

    def load_from_text(self, content: str, default_category: str = "blocklist") -> int:
        """Parses /etc/hosts format, Adblock syntax, and plain domain lists."""
        loaded = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue

            # Strip comments
            if "#" in line:
                line = line.split("#", 1)[0].strip()

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
                if clean:
                    self.add_allowed_domain(clean, wildcard=is_wildcard)
                    loaded += 1
                continue

            # Adblock style: ||example.com^ or ||example.com^$third-party or ||example.com
            if line.startswith("||"):
                clean = line[2:].strip()
                if "$" in clean:
                    clean = clean.split("$", 1)[0].strip()
                clean = clean.rstrip("^")
                if clean:
                    self.add_blocked_domain(clean, wildcard=True, category=default_category)
                    loaded += 1
                continue

            # Hosts file format: 0.0.0.0 ads.example.com or 127.0.0.1 domain
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                for domain in parts[1:]:
                    if domain.lower() not in ("localhost", "local", "broadcasthost"):
                        self.add_blocked_domain(domain, wildcard=False, category=default_category)
                        loaded += 1
                continue

            # Single domain per line
            if len(parts) == 1:
                domain = parts[0]
                if "/" in domain:
                    # CIDR
                    self.add_blocked_ip_or_cidr(domain, category=default_category)
                    loaded += 1
                else:
                    is_wildcard = domain.startswith("*.")
                    self.add_blocked_domain(domain, wildcard=is_wildcard, category=default_category)
                    loaded += 1

        return loaded

    def is_domain_allowed(self, domain: str) -> bool:
        domain = self._normalize_domain(domain)
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

    def is_ip_blocked(self, ip_str: str) -> Tuple[bool, Optional[str]]:
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            for net in self.blocked_networks:
                if ip in net:
                    return True, str(net)
        except ValueError:
            pass
        return False, None

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        return domain.strip().rstrip(".").lower()
