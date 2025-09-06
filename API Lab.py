#!/usr/bin/env python3
# hackerhunt_lab.py
"""
HackerHunt-Lab: Safe, intentionally vulnerable lab for API & recon practice.

⚠️ This tool is for ethical training and authorized lab use only.
Do not run on systems you don’t own or have explicit permission to test.
"""

import sys
import argparse
import json
import socket
import ssl
import re
import gzip
import io
import threading
import time
import traceback
import os
from urllib.parse import urlparse, urljoin
from collections import defaultdict

# Load .env if available (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Dependency detection
HAS_REQUESTS = False
HAS_BS4 = False
HAS_DNSPYTHON = False
HAS_WHOIS = False
HAS_SSFUZZ = False  # ssdeep

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    pass

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    pass

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    pass

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    pass

try:
    import ssdeep
    HAS_SSFUZZ = True
except ImportError:
    pass

# Constants
USER_AGENT = "HackerHunt-Lab/1.0 (+https://github.com/blackbox-ai/hackerhunt_lab)"
DEFAULT_TIMEOUT = 5
MAX_PORT_SCAN_THREADS = 100
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Educational disclaimer
def print_disclaimer():
    print("⚠️ This tool is for ethical training and authorized lab use only. "
          "Do not run on systems you don’t own or have explicit permission to test.\n")

# Utility functions
def safe_decode(b):
    if isinstance(b, str):
        return b
    try:
        return b.decode('utf-8', errors='replace')
    except Exception:
        return str(b)

def print_warn(msg):
    print(f"[!] Warning: {msg}")

def print_info(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)

def http_get(url, allow_redirects=True, headers=None, timeout=DEFAULT_TIMEOUT):
    if not HAS_REQUESTS:
        print_warn("requests module not found, falling back to urllib for HTTP GET")
        import urllib.request
        req_headers = headers or {}
        req_headers.setdefault('User-Agent', USER_AGENT)
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content = resp.read()
                return resp.getcode(), resp.headers, content
        except Exception as e:
            print_warn(f"HTTP GET failed for {url}: {e}")
            return None, None, None
    else:
        try:
            resp = requests.get(url, allow_redirects=allow_redirects, headers=headers or {'User-Agent': USER_AGENT}, timeout=timeout)
            return resp.status_code, resp.headers, resp.content
        except Exception as e:
            print_warn(f"HTTP GET failed for {url}: {e}")
            return None, None, None

def normalize_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc
    return domain

def is_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except Exception:
        return False

# --- crtsh_client module ---

import json

def crtsh_query(domain):
    """
    Query crt.sh for subdomains of the given domain.
    No API key required.

    Returns:
        list of subdomains (strings) or None on failure.
    """
    if not HAS_REQUESTS:
        print_warn("requests not installed, skipping crt.sh API client")
        return None
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        status, headers, content = http_get(url)
        if status != 200 or content is None:
            print_warn(f"crt.sh API query failed with status {status}")
            return None
        data = json.loads(safe_decode(content))
        subdomains = set()
        for entry in data:
            name_value = entry.get('name_value', '')
            for d in name_value.split('\n'):
                d = d.strip().lower()
                if d.endswith(domain):
                    subdomains.add(d)
        return sorted(subdomains)
    except Exception as e:
        print_warn(f"crt.sh API client error: {e}")
        return None

# === MODULES ===

# Passive modules

def module_whois(target):
    if not HAS_WHOIS:
        print_warn("python-whois not installed, skipping WHOIS module")
        return None
    try:
        w = whois.whois(target)
        # Convert to dict and sanitize
        result = {}
        for k, v in w.items():
            try:
                if isinstance(v, list):
                    result[k] = [str(x) for x in v]
                else:
                    result[k] = str(v)
            except Exception:
                result[k] = repr(v)
        return result
    except Exception as e:
        print_warn(f"WHOIS lookup failed: {e}")
        return None

def module_dns(target):
    if not HAS_DNSPYTHON:
        print_warn("dnspython not installed, skipping DNS module")
        return None
    resolver = dns.resolver.Resolver()
    records = {}
    try:
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
            try:
                answers = resolver.resolve(target, rtype, lifetime=DEFAULT_TIMEOUT)
                records[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                records[rtype] = []
            except Exception as e:
                print_warn(f"DNS query {rtype} failed: {e}")
                records[rtype] = []
        return records
    except Exception as e:
        print_warn(f"DNS module failed: {e}")
        return None

def module_crtsh(target):
    return crtsh_query(target)

def module_robots(target):
    # Fetch robots.txt from http://target/robots.txt and https://target/robots.txt
    urls = [f"http://{target}/robots.txt", f"https://{target}/robots.txt"]
    robots_txt = None
    for url in urls:
        status, headers, content = http_get(url)
        if status == 200 and content:
            robots_txt = safe_decode(content)
            break
    if robots_txt is None:
        print_warn("robots.txt not found or inaccessible")
    return robots_txt

def module_sitemap(target):
    # Try to fetch sitemap.xml from http://target/sitemap.xml and https://target/sitemap.xml
    urls = [f"http://{target}/sitemap.xml", f"https://{target}/sitemap.xml"]
    sitemap_content = None
    for url in urls:
        status, headers, content = http_get(url)
        if status == 200 and content:
            # Handle gzip content
            ct = headers.get('Content-Type', '').lower() if headers else ''
            ce = headers.get('Content-Encoding', '').lower() if headers else ''
            try:
                if ce == 'gzip' or url.endswith('.gz'):
                    with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
                        content = gz.read()
                sitemap_content = safe_decode(content)
                # Basic check if XML or HTML
                if sitemap_content.lstrip().startswith('<?xml') or '<urlset' in sitemap_content or '<sitemapindex' in sitemap_content:
                    return sitemap_content
                else:
                    print_warn("sitemap.xml content does not appear to be valid XML sitemap")
                    return sitemap_content
            except Exception as e:
                print_warn(f"Failed to parse sitemap.xml content: {e}")
                return None
    print_warn("sitemap.xml not found or inaccessible")
    return None

def module_headers(target):
    # Fetch HTTP headers from http://target/ and https://target/
    urls = [f"http://{target}/", f"https://{target}/"]
    headers_all = {}
    for url in urls:
        status, headers, content = http_get(url, allow_redirects=True)
        if headers:
            headers_all[url] = dict(headers)
    if not headers_all:
        print_warn("Failed to fetch HTTP headers from target")
    return headers_all

# Crawler module

def extract_links_bs4(html, base_url):
    links = set()
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
        attr = None
        if tag.name in ['a', 'link']:
            attr = tag.get('href')
        elif tag.name == 'script':
            attr = tag.get('src')
        elif tag.name == 'img':
            attr = tag.get('src')
        elif tag.name == 'form':
            attr = tag.get('action')
        if attr:
            full_url = urljoin(base_url, attr)
            links.add(full_url)
    return sorted(links)

def extract_links_regex(html, base_url):
    # fallback regex to extract href/src/action attributes
    links = set()
    try:
        text = html
        # href
        hrefs = re.findall(r'href=["\'](.*?)["\']', text, re.I)
        # src
        srcs = re.findall(r'src=["\'](.*?)["\']', text, re.I)
        # action
        actions = re.findall(r'action=["\'](.*?)["\']', text, re.I)
        for link in hrefs + srcs + actions:
            full_url = urljoin(base_url, link)
            links.add(full_url)
    except Exception as e:
        print_warn(f"Regex link extraction failed: {e}")
    return sorted(links)

def module_crawl(target):
    # Crawl homepage only (to keep it simple and safe)
    urls_to_crawl = [f"http://{target}/", f"https://{target}/"]
    all_links = set()
    for url in urls_to_crawl:
        status, headers, content = http_get(url)
        if status != 200 or content is None:
            continue
        html = safe_decode(content)
        if HAS_BS4:
            links = extract_links_bs4(html, url)
        else:
            print_warn("bs4 not installed, using regex fallback for crawling")
            links = extract_links_regex(html, url)
        all_links.update(links)
    # Extract endpoints (paths + query strings)
    endpoints = set()
    for link in all_links:
        parsed = urlparse(link)
        if parsed.netloc.endswith(target):
            ep = parsed.path
            if parsed.query:
                ep += '?' + parsed.query
            endpoints.add(ep)
    return {
        "links": sorted(all_links),
        "endpoints": sorted(endpoints)
    }

# Ports module (TCP connect scan)

def scan_port(target_ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                return True
    except Exception:
        pass
    return False

def module_ports(target, authorize):
    if not authorize:
        print_warn("Ports module requires --authorize flag, skipping")
        return None
    # Resolve target to IP
    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        print_warn(f"Failed to resolve target IP for port scan: {e}")
        return None
    open_ports = []
    threads = []
    lock = threading.Lock()

    def worker(port):
        if scan_port(target_ip, port):
            with lock:
                open_ports.append(port)

    ports_to_scan = COMMON_PORTS
    # Limit threads
    sem = threading.BoundedSemaphore(MAX_PORT_SCAN_THREADS)
    def thread_worker(port):
        with sem:
            worker(port)

    for port in ports_to_scan:
        t = threading.Thread(target=thread_worker, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return sorted(open_ports)

# Vuln indicators module

def test_reflected_xss(url):
    # Non-destructive reflected XSS test by injecting a harmless payload in query param
    # We test only if URL has query params, else skip
    parsed = urlparse(url)
    if not parsed.query:
        return False
    # Inject payload
    payload = "<script>HackerHuntXSS</script>"
    # Replace all query params with payload
    params = parsed.query.split('&')
    new_params = []
    for p in params:
        if '=' in p:
            k, _ = p.split('=', 1)
            new_params.append(f"{k}={payload}")
        else:
            new_params.append(f"{p}={payload}")
    new_query = '&'.join(new_params)
    test_url = parsed._replace(query=new_query).geturl()
    status, headers, content = http_get(test_url)
    if content is None:
        return False
    content_str = safe_decode(content).lower()
    # Check if payload reflected verbatim (case insensitive)
    if payload.lower() in content_str:
        return True
    return False

def test_sqli_errors(url):
    # Non-destructive SQLi error detection by injecting a single quote in query param
    parsed = urlparse(url)
    if not parsed.query:
        return False
    payload = "'"
    params = parsed.query.split('&')
    new_params = []
    for p in params:
        if '=' in p:
            k, v = p.split('=', 1)
            new_params.append(f"{k}={v+payload}")
        else:
            new_params.append(f"{p}={payload}")
    new_query = '&'.join(new_params)
    test_url = parsed._replace(query=new_query).geturl()
    status, headers, content = http_get(test_url)
    if content is None:
        return False
    content_str = safe_decode(content).lower()
    # Common SQL error signatures
    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sqlite error",
        "syntax error",
        "mysql_fetch",
        "mysql_num_rows",
        "pg_query",
        "sqlstate",
        "sql syntax",
        "mysql_query",
        "mysql_numrows",
        "mysql_fetch_array",
        "mysql_fetch_assoc",
        "mysql_num_rows",
        "mysql_error",
        "syntax error",
        "sql error",
        "odbc sql",
        "db2 sql error",
        "unexpected end of sql command",
    ]
    for err in sql_errors:
        if err in content_str:
            return True
    return False

def module_vuln(target, authorize):
    if not authorize:
        print_warn("Vuln module requires --authorize flag, skipping")
        return None
    # Crawl first to get endpoints with query params
    crawl_data = module_crawl(target)
    if not crawl_data:
        print_warn("Vuln module: failed to crawl target for endpoints")
        return None
    endpoints = crawl_data.get('endpoints', [])
    xss_found = []
    sqli_found = []
    for ep in endpoints:
        if '?' not in ep:
            continue
        url_http = f"http://{target}{ep}"
        url_https = f"https://{target}{ep}"
        # Test HTTP
        try:
            if test_reflected_xss(url_http):
                xss_found.append(url_http)
            if test_sqli_errors(url_http):
                sqli_found.append(url_http)
        except Exception:
            pass
        # Test HTTPS
        try:
            if test_reflected_xss(url_https):
                xss_found.append(url_https)
            if test_sqli_errors(url_https):
                sqli_found.append(url_https)
        except Exception:
            pass
    return {
        "reflected_xss": sorted(set(xss_found)),
        "sql_injection_errors": sorted(set(sqli_found))
    }

# Self-test mode

def selftest():
    print_info("Running self-test mode (offline tests)...")

    # Test safe_decode
    assert safe_decode(b"hello") == "hello"
    assert safe_decode("world") == "world"
    assert isinstance(safe_decode(b"\xff\xfe"), str)

    # Test normalize_domain
    assert normalize_domain("http://Example.com") == "example.com"
    assert normalize_domain("example.com") == "example.com"

    # Test is_ip
    assert is_ip("8.8.8.8")
    assert not is_ip("example.com")

    # Test extract_links regex fallback
    sample_html = '''
    <html><head><link href="/style.css"></head>
    <body>
    <a href="http://example.com/page1">Page1</a>
    <script src="/js/app.js"></script>
    <img src="image.png"/>
    <form action="/submit"></form>
    </body></html>
    '''
    links = extract_links_regex(sample_html, "http://example.com")
    expected = sorted([
        "http://example.com/style.css",
        "http://example.com/page1",
        "http://example.com/js/app.js",
        "http://example.com/image.png",
        "http://example.com/submit"
    ])
    assert links == expected

    # Test extract_links_bs4 if bs4 installed
    if HAS_BS4:
        links_bs4 = extract_links_bs4(sample_html, "http://example.com")
        assert sorted(links_bs4) == expected

    # Test scan_port on localhost common ports (just test function runs)
    scan_port("127.0.0.1", 80, timeout=0.5)

    print_info("Self-test completed successfully.")

# CLI and main

def parse_args():
    parser = argparse.ArgumentParser(description="HackerHunt-Lab: Safe API & recon practice lab")
    parser.add_argument('--target', help="Target domain or host (required unless --selftest)")
    parser.add_argument('--modules', help="Comma-separated modules to run: passive,whois,dns,crtsh,robots,sitemap,crawl,headers,ports,vuln,all", default="")
    parser.add_argument('--output', help="Output JSON report file")
    parser.add_argument('--selftest', action='store_true', help="Run self-test mode")
    parser.add_argument('--authorize', action='store_true', help="Authorize active scanning (ports, vuln)")
    return parser.parse_args()

def main():
    print_disclaimer()
    args = parse_args()
    if args.selftest:
        selftest()
        return
    if not args.target:
        print_error("Target is required unless --selftest")
        sys.exit(1)
    target = normalize_domain(args.target)
    modules = args.modules.split(',') if args.modules else []
    if 'all' in modules or not modules:
        modules = ['whois', 'dns', 'crtsh', 'robots', 'sitemap', 'headers', 'crawl']
        if args.authorize:
            modules += ['ports', 'vuln']
    results = {}
    for mod in modules:
        print_info(f"Running module: {mod}")
        if mod == 'whois':
            results['whois'] = module_whois(target)
        elif mod == 'dns':
            results['dns'] = module_dns(target)
        elif mod == 'crtsh':
            results['crtsh'] = module_crtsh(target)
        elif mod == 'robots':
            results['robots'] = module_robots(target)
        elif mod == 'sitemap':
            results['sitemap'] = module_sitemap(target)
        elif mod == 'headers':
            results['headers'] = module_headers(target)
        elif mod == 'crawl':
            results['crawl'] = module_crawl(target)
        elif mod == 'ports':
            results['ports'] = module_ports(target, args.authorize)
        elif mod == 'vuln':
            results['vuln'] = module_vuln(target, args.authorize)
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print_info(f"Results saved to {args.output}")
        except Exception as e:
            print_error(f"Failed to save output: {e}")
    else:
        print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()
