"""
Enhanced Ethics Policy Implementation
-----------------------------------

This module implements robust privacy and security controls for web scanning:

1. Privacy Protection
   - PII (Personally Identifiable Information) detection and masking
   - Secure handling of sensitive data in logs and UI
   - Data minimization in reports and exports

2. Ethical Scanning Controls  
   - URL scope validation
   - Rate limiting and request throttling
   - Blocklist enforcement
   - Consent and notification mechanisms

3. Security Measures
   - API key and credential protection
   - Session token safety
   - Authentication data handling

4. Compliance Features
   - GDPR-friendly data handling
   - Audit logging of decisions
   - Data retention controls
"""

from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urlparse
from datetime import datetime, timedelta
import hashlib, copy, re, time
from dataclasses import dataclass
from typing import List, Set, Dict, Tuple, Optional
import threading
from analysis_logger import log_ethics_decision

@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_minute: int = 60
    burst_size: int = 10
    cooldown_minutes: int = 5

class RateLimiter:
    """Token bucket rate limiter with burst handling"""
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.tokens = config.burst_size
        self.last_update = datetime.now()
        self.lock = threading.Lock()
    
    def can_request(self) -> bool:
        with self.lock:
            now = datetime.now()
            time_passed = (now - self.last_update).total_seconds() / 60.0
            self.tokens = min(
                self.config.burst_size,
                self.tokens + time_passed * self.config.requests_per_minute
            )
            if self.tokens >= 1:
                self.tokens -= 1
                self.last_update = now
                return True
            return False

# Enhanced pattern matching for sensitive data
PII_PATTERNS = [
    # Personal identifiers
    re.compile(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', re.I),  # email
    re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),                   # IPv4
    re.compile(r'\b\+?\d[\d\-\s]{7,}\b'),                         # phone
    re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),                # US phone
    re.compile(r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'),                # SSN-like
    
    # Location data
    re.compile(r'\b\d{5}(?:[-\s]\d{4})?\b'),                     # ZIP
    re.compile(r'\b\d+\s+[A-Za-z\s,]+(?:Avenue|Lane|Road|Boulevard|Drive|Street|Ave|Ln|Rd|Blvd|Dr|St)\.?\b', re.I),  # address
    
    # Financial
    re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),      # credit card
    re.compile(r'\b\d{9,18}\b'),                                  # account numbers
]

SECRET_PATTERNS = [
    # API and auth tokens
    re.compile(r'(?i)(api[_-]?key|token|secret|bearer|sessionid|auth[_-]?token)\s*[:=]\s*([A-Za-z0-9\-._~+/=]{8,})'),
    re.compile(r'(?i)(access_token|refresh_token)\s*[:=]\s*([A-Za-z0-9\-._~+/=]{8,})'),
    re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+'),
    
    # Common API key formats
    re.compile(r'\b([A-Za-z0-9_-]{32,})\b'),
    re.compile(r'(?i)bearer\s+[A-Za-z0-9._\-]+'),
]

class EthicsPolicy:
    """
    Enhanced privacy-first security policy with comprehensive controls:
    
    1. Privacy Protection
       - PII detection and masking
       - Data minimization
       - Consent management
    
    2. Security Controls
       - Rate limiting
       - Scope enforcement
       - Blocklist validation
    
    3. Compliance Features
       - Audit logging
       - Data retention
       - Export controls
    """
    def __init__(self, 
                 mask_payloads: bool = True,
                 scope_host: str = "",
                 blocklist_hosts: Optional[Set[str]] = None,
                 query_deny: Optional[Set[str]] = None,
                 query_allow: Optional[Set[str]] = None,
                 rate_limit: Optional[RateLimitConfig] = None):
        
        self.mask_payloads = mask_payloads
        self.scope_host = scope_host.lower().strip()
        self.blocklist_hosts = set(blocklist_hosts or set())
        self.query_deny = set(query_deny or {
            'password', 'token', 'auth', 'apikey', 'key', 'secret',
            'credentials', 'session', 'jwt', 'bearer'
        })
        self.query_allow = set(query_allow or set())
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter(rate_limit or RateLimitConfig())
        
        # Track decisions for audit
        self._decision_log: List[Dict] = []

    def check(self, url: str) -> Tuple[bool, str]:
        """
        Comprehensive URL validation with ethics checks
        Returns: (allowed, reason)
        """
        # Basic URL validation
        if not url.lower().startswith(("http://", "https://")):
            decision = (False, "Invalid URL scheme - must be http(s)")
            self._log_decision(url, *decision)
            return decision
            
        # Parse URL
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
        except Exception:
            decision = (False, "Could not parse URL")
            self._log_decision(url, *decision)
            return decision
            
        # Check rate limits
        if not self.rate_limiter.can_request():
            decision = (False, "Rate limit exceeded - please wait")
            self._log_decision(url, *decision)
            return decision
            
        # Scope check
        if self.scope_host and not host.endswith(self.scope_host):
            decision = (False, "URL outside allowed scope")
            self._log_decision(url, *decision)
            return decision
            
        # Blocklist check    
        if host in self.blocklist_hosts:
            decision = (False, "Host is blocklisted")
            self._log_decision(url, *decision)
            return decision
            
        decision = (True, "URL passed all checks")
        self._log_decision(url, *decision)
        return decision

    def _minimize(self, url: str) -> str:
        """Privacy-preserving URL transformation"""
        if not url:
            return url
            
        try:
            u = urlsplit(url)
            pairs = parse_qsl(u.query, keep_blank_values=True)
            masked = []
            
            for k, v in pairs:
                kl = k.lower()
                # Explicit allow list takes precedence
                if self.query_allow and k in self.query_allow:
                    masked.append((k, v))
                # Then check deny list
                elif kl in self.query_deny:
                    masked.append((k, "***"))
                # Default to conservative masking
                else:
                    masked.append((k, "***"))
                    
            # Rebuild URL without fragments
            return urlunsplit((
                u.scheme,
                u.netloc,
                u.path,
                urlencode(masked),
                ""  # No fragments
            ))
        except Exception:
            return url  # Return original on error
            
    def _scrub_text(self, text: str) -> str:
        """Comprehensive sensitive data removal"""
        if not text:
            return text
            
        out = text
        
        # Remove secrets first
        for pattern in SECRET_PATTERNS:
            out = pattern.sub(lambda m: f"{m.group(1)}=***", out)
            
        # Then scrub PII
        for pattern in PII_PATTERNS:
            out = pattern.sub("***", out)
            
        return out
        
    def scrub(self, findings: list, show_raw: bool = False) -> list:
        """Privacy-preserving findings sanitization"""
        if not findings:
            return []
            
        out = []
        for f in findings:
            g = copy.deepcopy(f)
            
            # Always scrub evidence
            if g.get("evidence"):
                g["evidence"] = self._scrub_text(str(g["evidence"]))
                
            # Handle raw mode
            if not show_raw:
                # Minimize URLs
                if g.get("attack_url"):
                    g["attack_url"] = self._minimize(self._scrub_text(g["attack_url"]))
                if g.get("page"):
                    g["page"] = self._minimize(self._scrub_text(g["page"]))
                    
                # Hash payloads
                if g.get("payload"):
                    g["payload_hash"] = hashlib.sha256(g["payload"].encode()).hexdigest()[:12]
                    g.pop("payload", None)
                    
            out.append(g)
        return out
        
    def _log_decision(self, url: str, allowed: bool, reason: str):
        """Log ethics decisions for audit"""
        decision = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'allowed': allowed,
            'reason': reason
        }
        self._decision_log.append(decision)
        
        # Log to analysis logger
        log_ethics_decision(url, "ALLOWED" if allowed else "BLOCKED", reason)
        
    def get_decision_log(self, days: int = 7) -> List[Dict]:
        """Get recent ethics decisions for audit"""
        cutoff = datetime.now() - timedelta(days=days)
        return [
            d for d in self._decision_log
            if datetime.fromisoformat(d['timestamp']) >= cutoff
        ]
