#!/usr/bin/env python3
"""
Ethical Web Crawler for Penetration Testing
A powerful and ethical Python-based web crawler designed for security testing
on websites where explicit permission has been granted.
"""

import asyncio
import json
import logging
import re
import sqlite3
import time
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.robotparser import RobotFileParser
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import aiohttp
import click
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from playwright.async_api import async_playwright
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Import new modules
from subdomain_enum import SubdomainEnumerator
from js_analyzer import JavaScriptAnalyzer
from endpoint_guesser import EndpointGuesser
from hidden_file_scanner import HiddenFileScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('crawler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class CrawlConfig:
    """Configuration for the web crawler."""
    base_url: str
    max_depth: int = 5
    max_pages: int = 1000
    delay: float = 1.0
    concurrent_requests: int = 5
    respect_robots: bool = True
    override_robots: bool = False
    include_subdomains: bool = False
    user_agent: Optional[str] = None
    custom_headers: Dict[str, str] = None
    ignored_extensions: Set[str] = None
    focused_extensions: Set[str] = None
    auth_cookies: Dict[str, str] = None
    auth_headers: Dict[str, str] = None
    timeout: int = 30
    use_playwright: bool = True
    headless: bool = True
    
    # New features
    enable_subdomain_enumeration: bool = False
    enable_endpoint_guessing: bool = False
    enable_hidden_file_scanning: bool = False
    enable_js_analysis: bool = True
    subdomain_wordlist: Optional[str] = None
    endpoint_wordlist: Optional[str] = None
    hidden_file_wordlist: Optional[str] = None
    subdomain_enumeration_methods: List[str] = None

@dataclass
class CrawlResult:
    """Results from crawling a single page."""
    url: str
    status_code: int
    content_type: str
    title: str
    forms: List[Dict]
    links: List[str]
    api_endpoints: List[str]
    js_files: List[str]
    cookies: Dict[str, str]
    headers: Dict[str, str]
    hidden_fields: List[Dict]
    csrf_tokens: List[str]
    depth: int
    timestamp: float
    error: Optional[str] = None

class RobotsTxtParser:
    """Parse and handle robots.txt files."""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.robots_url = urljoin(base_url, '/robots.txt')
        self.parser = RobotFileParser()
        self.parser.set_url(self.robots_url)
        self.disallowed_paths = set()
        self.allowed_paths = set()
        self.crawl_delay = 0
        
    async def parse_robots_txt(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Parse robots.txt and return structured data."""
        try:
            async with session.get(self.robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    self.parser.read()
                    
                    # Parse disallowed and allowed paths
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.startswith('Disallow:'):
                            path = line.split(':', 1)[1].strip()
                            self.disallowed_paths.add(path)
                        elif line.startswith('Allow:'):
                            path = line.split(':', 1)[1].strip()
                            self.allowed_paths.add(path)
                        elif line.startswith('Crawl-delay:'):
                            try:
                                self.crawl_delay = float(line.split(':', 1)[1].strip())
                            except ValueError:
                                pass
                    
                    return {
                        'robots_url': self.robots_url,
                        'disallowed_paths': list(self.disallowed_paths),
                        'allowed_paths': list(self.allowed_paths),
                        'crawl_delay': self.crawl_delay,
                        'content': content
                    }
                else:
                    logger.warning(f"Robots.txt not found at {self.robots_url}")
                    return {'robots_url': self.robots_url, 'error': 'Not found'}
        except Exception as e:
            logger.error(f"Error parsing robots.txt: {e}")
            return {'robots_url': self.robots_url, 'error': str(e)}
    
    def can_fetch(self, url: str) -> bool:
        """Check if URL can be fetched according to robots.txt."""
        if not self.parser:
            return True
        return self.parser.can_fetch(self.user_agent, url)

class WebCrawler:
    """Main web crawler class."""
    
    def __init__(self, config: CrawlConfig):
        self.config = config
        self.console = Console()
        self.visited_urls = set()
        self.url_queue = deque([(config.base_url, 0)])
        self.results = []
        self.forms = []
        self.api_endpoints = set()
        self.js_files = set()
        self.cookies = {}
        self.headers = {}
        self.robots_parser = RobotsTxtParser(config.base_url)
        self.user_agent = config.user_agent or UserAgent().random
        self.session = None
        self.playwright = None
        self.browser = None
        self.page = None
        
        # New features data
        self.subdomains = []
        self.guessed_endpoints = []
        self.hidden_files = []
        self.js_analysis_results = {}
        
        # Initialize ignored/focused extensions
        if config.ignored_extensions is None:
            config.ignored_extensions = {'.pdf', '.zip', '.exe', '.dmg', '.mp4', '.mp3', '.avi'}
        if config.focused_extensions is None:
            config.focused_extensions = {'.html', '.php', '.asp', '.aspx', '.jsp', '.js', '.css'}
        
        # Initialize custom headers
        if config.custom_headers is None:
            config.custom_headers = {}
        
        # Initialize auth data
        if config.auth_cookies is None:
            config.auth_cookies = {}
        if config.auth_headers is None:
            config.auth_headers = {}
        
        # Initialize subdomain enumeration methods
        if config.subdomain_enumeration_methods is None:
            config.subdomain_enumeration_methods = ['dns', 'wordlist']
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.setup()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()
    
    async def setup(self):
        """Initialize crawler components."""
        # Setup aiohttp session
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        connector = aiohttp.TCPConnector(limit=self.config.concurrent_requests)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': self.user_agent,
                **self.config.custom_headers,
                **self.config.auth_headers
            }
        )
        
        # Setup Playwright if enabled
        if self.config.use_playwright:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=self.config.headless)
            self.page = await self.browser.new_page()
            
            # Set cookies if provided
            if self.config.auth_cookies:
                await self.page.context.add_cookies([
                    {'name': k, 'value': v, 'domain': urlparse(self.config.base_url).netloc}
                    for k, v in self.config.auth_cookies.items()
                ])
    
    async def cleanup(self):
        """Clean up resources."""
        if self.session:
            await self.session.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid for crawling."""
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(self.config.base_url)
            
            # Check if URL is within the same domain
            if not self.config.include_subdomains:
                if parsed.netloc != base_parsed.netloc:
                    return False
            else:
                # Allow subdomains
                if not parsed.netloc.endswith(base_parsed.netloc.split('.', 1)[1]):
                    return False
            
            # Check file extensions
            path = parsed.path.lower()
            if self.config.ignored_extensions and any(path.endswith(ext) for ext in self.config.ignored_extensions):
                return False
            
            if self.config.focused_extensions and not any(path.endswith(ext) for ext in self.config.focused_extensions):
                return False
            
            return True
        except Exception:
            return False
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL to avoid duplicates."""
        parsed = urlparse(url)
        # Remove fragments and normalize
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
    
    async def parse_robots_txt(self) -> Dict[str, Any]:
        """Parse robots.txt file."""
        self.console.print(Panel("🔍 Parsing robots.txt...", style="blue"))
        robots_data = await self.robots_parser.parse_robots_txt(self.session)
        
        # Display robots.txt information
        table = Table(title="Robots.txt Analysis")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in robots_data.items():
            if key == 'content':
                table.add_row(key, f"{len(str(value))} characters")
            elif isinstance(value, list):
                table.add_row(key, f"{len(value)} items")
            else:
                table.add_row(key, str(value))
        
        self.console.print(table)
        return robots_data
    
    async def crawl_page(self, url: str, depth: int) -> Optional[CrawlResult]:
        """Crawl a single page and extract information."""
        if url in self.visited_urls:
            return None
        
        self.visited_urls.add(url)
        
        try:
            # Respect robots.txt unless overridden
            if self.config.respect_robots and not self.config.override_robots:
                if not self.robots_parser.can_fetch(url):
                    logger.info(f"Skipping {url} due to robots.txt restrictions")
                    return None
            
            # Fetch page content
            if self.config.use_playwright:
                result = await self._crawl_with_playwright(url, depth)
            else:
                result = await self._crawl_with_requests(url, depth)
            
            if result:
                self.results.append(result)
                self._extract_global_data(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return CrawlResult(
                url=url,
                status_code=0,
                content_type="",
                title="",
                forms=[],
                links=[],
                api_endpoints=[],
                js_files=[],
                cookies={},
                headers={},
                hidden_fields=[],
                csrf_tokens=[],
                depth=depth,
                timestamp=time.time(),
                error=str(e)
            )
    
    async def _crawl_with_playwright(self, url: str, depth: int) -> CrawlResult:
        """Crawl page using Playwright for JavaScript rendering."""
        try:
            response = await self.page.goto(url, wait_until='networkidle', timeout=self.config.timeout * 1000)
            
            # Get page content and metadata
            title = await self.page.title()
            content = await self.page.content()
            
            # Extract forms, links, and other elements
            forms = await self._extract_forms_playwright()
            links = await self._extract_links_playwright()
            api_endpoints = await self._extract_api_endpoints_playwright()
            js_files = await self._extract_js_files_playwright()
            
            # Get cookies and headers
            cookies = await self.page.context.cookies()
            cookies_dict = {cookie['name']: cookie['value'] for cookie in cookies}
            
            # Parse HTML for additional data
            soup = BeautifulSoup(content, 'html.parser')
            hidden_fields = self._extract_hidden_fields(soup)
            csrf_tokens = self._extract_csrf_tokens(soup)
            
            return CrawlResult(
                url=url,
                status_code=response.status if response else 0,
                content_type=response.headers.get('content-type', '') if response else '',
                title=title,
                forms=forms,
                links=links,
                api_endpoints=api_endpoints,
                js_files=js_files,
                cookies=cookies_dict,
                headers=dict(response.headers) if response else {},
                hidden_fields=hidden_fields,
                csrf_tokens=csrf_tokens,
                depth=depth,
                timestamp=time.time()
            )
            
        except Exception as e:
            logger.error(f"Playwright error for {url}: {e}")
            raise
    
    async def _crawl_with_requests(self, url: str, depth: int) -> CrawlResult:
        """Crawl page using requests library."""
        async with self.session.get(url) as response:
            content = await response.text()
            
            # Parse HTML
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract data
            title = soup.title.string if soup.title else ""
            forms = self._extract_forms(soup)
            links = self._extract_links(soup)
            api_endpoints = self._extract_api_endpoints(soup)
            js_files = self._extract_js_files(soup)
            hidden_fields = self._extract_hidden_fields(soup)
            csrf_tokens = self._extract_csrf_tokens(soup)
            
            return CrawlResult(
                url=url,
                status_code=response.status,
                content_type=response.headers.get('content-type', ''),
                title=title,
                forms=forms,
                links=links,
                api_endpoints=api_endpoints,
                js_files=js_files,
                cookies=dict(response.cookies),
                headers=dict(response.headers),
                hidden_fields=hidden_fields,
                csrf_tokens=csrf_tokens,
                depth=depth,
                timestamp=time.time()
            )
    
    async def _extract_forms_playwright(self) -> List[Dict]:
        """Extract forms using Playwright."""
        forms = await self.page.query_selector_all('form')
        form_data = []
        
        for form in forms:
            try:
                action = await form.get_attribute('action') or ''
                method = await form.get_attribute('method') or 'get'
                
                # Get form inputs
                inputs = await form.query_selector_all('input, textarea, select')
                fields = []
                
                for inp in inputs:
                    field_type = await inp.get_attribute('type') or 'text'
                    field_name = await inp.get_attribute('name') or ''
                    field_value = await inp.get_attribute('value') or ''
                    
                    fields.append({
                        'type': field_type,
                        'name': field_name,
                        'value': field_value
                    })
                
                form_data.append({
                    'action': action,
                    'method': method.upper(),
                    'fields': fields
                })
            except Exception as e:
                logger.error(f"Error extracting form: {e}")
        
        return form_data
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract forms from HTML."""
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            
            fields = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                field_type = inp.get('type', 'text')
                field_name = inp.get('name', '')
                field_value = inp.get('value', '')
                
                fields.append({
                    'type': field_type,
                    'name': field_name,
                    'value': field_value
                })
            
            forms.append({
                'action': action,
                'method': method,
                'fields': fields
            })
        
        return forms
    
    async def _extract_links_playwright(self) -> List[str]:
        """Extract links using Playwright."""
        links = await self.page.query_selector_all('a[href]')
        urls = []
        
        for link in links:
            try:
                href = await link.get_attribute('href')
                if href:
                    full_url = urljoin(self.page.url, href)
                    if self.is_valid_url(full_url):
                        urls.append(self.normalize_url(full_url))
            except Exception as e:
                logger.error(f"Error extracting link: {e}")
        
        return urls
    
    def _extract_links(self, soup: BeautifulSoup) -> List[str]:
        """Extract links from HTML."""
        urls = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(self.config.base_url, href)
            if self.is_valid_url(full_url):
                urls.append(self.normalize_url(full_url))
        
        return urls
    
    async def _extract_api_endpoints_playwright(self) -> List[str]:
        """Extract API endpoints using Playwright."""
        # This would require intercepting network requests
        # For now, we'll extract from JavaScript files
        scripts = await self.page.query_selector_all('script[src]')
        endpoints = []
        
        for script in scripts:
            try:
                src = await script.get_attribute('src')
                if src:
                    # Analyze JavaScript files for API endpoints
                    # This is a simplified approach
                    pass
            except Exception as e:
                logger.error(f"Error extracting API endpoints: {e}")
        
        return endpoints
    
    def _extract_api_endpoints(self, soup: BeautifulSoup) -> List[str]:
        """Extract API endpoints from HTML."""
        endpoints = []
        
        # Look for common API endpoint patterns in scripts
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Find API endpoints in JavaScript
                api_patterns = [
                    r'["\'](/api/[^"\']+)["\']',
                    r'["\'](/rest/[^"\']+)["\']',
                    r'["\'](/v\d+/[^"\']+)["\']',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']'
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        if isinstance(match, tuple):
                            endpoints.extend(match)
                        else:
                            endpoints.append(match)
        
        return list(set(endpoints))
    
    async def _extract_js_files_playwright(self) -> List[str]:
        """Extract JavaScript files using Playwright."""
        scripts = await self.page.query_selector_all('script[src]')
        js_files = []
        
        for script in scripts:
            try:
                src = await script.get_attribute('src')
                if src and src.endswith('.js'):
                    full_url = urljoin(self.page.url, src)
                    js_files.append(full_url)
            except Exception as e:
                logger.error(f"Error extracting JS file: {e}")
        
        return js_files
    
    def _extract_js_files(self, soup: BeautifulSoup) -> List[str]:
        """Extract JavaScript files from HTML."""
        js_files = []
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.endswith('.js'):
                full_url = urljoin(self.config.base_url, src)
                js_files.append(full_url)
        
        return js_files
    
    def _extract_hidden_fields(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract hidden form fields."""
        hidden_fields = []
        for inp in soup.find_all('input', type='hidden'):
            hidden_fields.append({
                'name': inp.get('name', ''),
                'value': inp.get('value', ''),
                'id': inp.get('id', '')
            })
        
        return hidden_fields
    
    def _extract_csrf_tokens(self, soup: BeautifulSoup) -> List[str]:
        """Extract CSRF tokens."""
        csrf_tokens = []
        
        # Common CSRF token patterns
        csrf_patterns = [
            'input[name*="csrf"]',
            'input[name*="token"]',
            'meta[name*="csrf"]',
            'meta[name*="token"]'
        ]
        
        for pattern in csrf_patterns:
            elements = soup.select(pattern)
            for element in elements:
                if element.name == 'input':
                    value = element.get('value', '')
                    if value:
                        csrf_tokens.append(value)
                elif element.name == 'meta':
                    content = element.get('content', '')
                    if content:
                        csrf_tokens.append(content)
        
        return csrf_tokens
    
    def _extract_global_data(self, result: CrawlResult):
        """Extract and store global data from crawl results."""
        # Store forms
        self.forms.extend(result.forms)
        
        # Store API endpoints
        self.api_endpoints.update(result.api_endpoints)
        
        # Store JS files
        self.js_files.update(result.js_files)
        
        # Store cookies
        self.cookies.update(result.cookies)
        
        # Store headers
        self.headers.update(result.headers)
    
    async def _run_subdomain_enumeration(self):
        """Run subdomain enumeration."""
        self.console.print(Panel("🔍 Running Subdomain Enumeration", style="blue"))
        
        try:
            domain = urlparse(self.config.base_url).netloc
            enumerator = SubdomainEnumerator(domain, self.config.subdomain_wordlist)
            results = await enumerator.enumerate_subdomains(self.config.subdomain_enumeration_methods)
            
            self.subdomains = results['subdomains']
            
            # Add discovered subdomains to crawl queue
            for subdomain in self.subdomains:
                subdomain_url = f"https://{subdomain}"
                if subdomain_url not in self.visited_urls:
                    self.url_queue.append((subdomain_url, 0))
            
            self.console.print(f"✅ Found {len(self.subdomains)} subdomains")
            
        except Exception as e:
            self.console.print(f"❌ Subdomain enumeration failed: {e}")
    
    async def _run_endpoint_guessing(self):
        """Run endpoint guessing."""
        self.console.print(Panel("🎯 Running Endpoint Guessing", style="blue"))
        
        try:
            async with EndpointGuesser(self.config.base_url, self.config.endpoint_wordlist) as guesser:
                results = await guesser.guess_endpoints()
                self.guessed_endpoints = results
                
                # Add discovered endpoints to crawl queue
                for endpoint in results:
                    if endpoint['found']:
                        endpoint_url = endpoint['url']
                        if endpoint_url not in self.visited_urls:
                            self.url_queue.append((endpoint_url, 0))
                
                self.console.print(f"✅ Found {len(results)} endpoints")
                
        except Exception as e:
            self.console.print(f"❌ Endpoint guessing failed: {e}")
    
    async def _run_hidden_file_scanning(self):
        """Run hidden file scanning."""
        self.console.print(Panel("🔍 Running Hidden File Scanning", style="blue"))
        
        try:
            async with HiddenFileScanner(self.config.base_url, self.config.hidden_file_wordlist) as scanner:
                results = await scanner.scan_hidden_files()
                self.hidden_files = results
                
                # Add discovered hidden files to crawl queue
                for hidden_file in results:
                    if hidden_file['found']:
                        hidden_file_url = hidden_file['url']
                        if hidden_file_url not in self.visited_urls:
                            self.url_queue.append((hidden_file_url, 0))
                
                self.console.print(f"✅ Found {len(results)} hidden files")
                
        except Exception as e:
            self.console.print(f"❌ Hidden file scanning failed: {e}")
    
    async def _analyze_javascript(self, content: str, url: str):
        """Analyze JavaScript content for additional endpoints."""
        if not self.config.enable_js_analysis:
            return
        
        try:
            analyzer = JavaScriptAnalyzer(url)
            results = analyzer.analyze_javascript(content, url)
            
            # Store JS analysis results
            self.js_analysis_results[url] = results
            
            # Add discovered URLs to queue
            for discovered_url in results['urls']:
                if discovered_url not in self.visited_urls:
                    self.url_queue.append((discovered_url, 0))
            
        except Exception as e:
            logger.error(f"JavaScript analysis failed for {url}: {e}")
    
    async def crawl(self) -> Dict[str, Any]:
        """Main crawling method."""
        self.console.print(Panel("🚀 Starting Web Crawler", style="green"))
        
        # Parse robots.txt first
        robots_data = await self.parse_robots_txt()
        
        # Run subdomain enumeration if enabled
        if self.config.enable_subdomain_enumeration:
            await self._run_subdomain_enumeration()
        
        # Run endpoint guessing if enabled
        if self.config.enable_endpoint_guessing:
            await self._run_endpoint_guessing()
        
        # Run hidden file scanning if enabled
        if self.config.enable_hidden_file_scanning:
            await self._run_hidden_file_scanning()
        
        # Start crawling
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            task = progress.add_task("Crawling pages...", total=None)
            
            while self.url_queue and len(self.results) < self.config.max_pages:
                url, depth = self.url_queue.popleft()
                
                if depth > self.config.max_depth:
                    continue
                
                progress.update(task, description=f"Crawling: {url}")
                
                result = await self.crawl_page(url, depth)
                
                if result and not result.error:
                    # Add new URLs to queue
                    for link in result.links:
                        if link not in self.visited_urls:
                            self.url_queue.append((link, depth + 1))
                
                # Rate limiting
                await asyncio.sleep(self.config.delay)
        
        return self._generate_report(robots_data)
    
    def _generate_report(self, robots_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive crawling report."""
        # Deduplicate and normalize data
        unique_forms = self._deduplicate_forms()
        unique_endpoints = list(self.api_endpoints)
        unique_js_files = list(self.js_files)
        
        # Group forms by method
        forms_by_method = defaultdict(list)
        for form in unique_forms:
            forms_by_method[form['method']].append(form)
        
        # Group endpoints by type
        endpoints_by_type = self._group_endpoints(unique_endpoints)
        
        report = {
            'crawl_summary': {
                'base_url': self.config.base_url,
                'total_pages_crawled': len(self.results),
                'total_forms_found': len(unique_forms),
                'total_api_endpoints': len(unique_endpoints),
                'total_js_files': len(unique_js_files),
                'crawl_depth_reached': max([r.depth for r in self.results]) if self.results else 0,
                'robots_txt_data': robots_data,
                'subdomain_enumeration_enabled': self.config.enable_subdomain_enumeration,
                'endpoint_guessing_enabled': self.config.enable_endpoint_guessing,
                'hidden_file_scanning_enabled': self.config.enable_hidden_file_scanning,
                'js_analysis_enabled': self.config.enable_js_analysis
            },
            'forms': {
                'all_forms': unique_forms,
                'by_method': dict(forms_by_method)
            },
            'api_endpoints': {
                'all_endpoints': unique_endpoints,
                'by_type': endpoints_by_type
            },
            'javascript_files': unique_js_files,
            'cookies': self.cookies,
            'headers': self.headers,
            'detailed_results': [asdict(result) for result in self.results],
            
            # New features data
            'subdomain_enumeration': {
                'enabled': self.config.enable_subdomain_enumeration,
                'subdomains_found': self.subdomains,
                'total_subdomains': len(self.subdomains)
            },
            'endpoint_guessing': {
                'enabled': self.config.enable_endpoint_guessing,
                'endpoints_found': self.guessed_endpoints,
                'total_endpoints': len(self.guessed_endpoints)
            },
            'hidden_file_scanning': {
                'enabled': self.config.enable_hidden_file_scanning,
                'hidden_files_found': self.hidden_files,
                'total_hidden_files': len(self.hidden_files)
            },
            'javascript_analysis': {
                'enabled': self.config.enable_js_analysis,
                'analysis_results': self.js_analysis_results,
                'total_analyzed_pages': len(self.js_analysis_results)
            }
        }
        
        return report
    
    def _deduplicate_forms(self) -> List[Dict]:
        """Deduplicate forms based on action and method."""
        seen = set()
        unique_forms = []
        
        for form in self.forms:
            key = f"{form['action']}:{form['method']}"
            if key not in seen:
                seen.add(key)
                unique_forms.append(form)
        
        return unique_forms
    
    def _group_endpoints(self, endpoints: List[str]) -> Dict[str, List[str]]:
        """Group endpoints by type."""
        grouped = defaultdict(list)
        
        for endpoint in endpoints:
            if '/api/' in endpoint:
                grouped['api'].append(endpoint)
            elif '/rest/' in endpoint:
                grouped['rest'].append(endpoint)
            elif '/v' in endpoint and any(c.isdigit() for c in endpoint):
                grouped['versioned'].append(endpoint)
            else:
                grouped['other'].append(endpoint)
        
        return dict(grouped)
    
    def save_to_json(self, report: Dict[str, Any], filename: str = 'crawl_report.json'):
        """Save report to JSON file."""
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        self.console.print(f"✅ Report saved to {filename}")
    
    def save_to_sqlite(self, report: Dict[str, Any], filename: str = 'crawl_data.db'):
        """Save report to SQLite database."""
        conn = sqlite3.connect(filename)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crawl_summary (
                id INTEGER PRIMARY KEY,
                base_url TEXT,
                total_pages INTEGER,
                total_forms INTEGER,
                total_endpoints INTEGER,
                total_js_files INTEGER,
                max_depth INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS forms (
                id INTEGER PRIMARY KEY,
                action TEXT,
                method TEXT,
                fields TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_endpoints (
                id INTEGER PRIMARY KEY,
                endpoint TEXT,
                type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert data
        summary = report['crawl_summary']
        cursor.execute('''
            INSERT INTO crawl_summary 
            (base_url, total_pages, total_forms, total_endpoints, total_js_files, max_depth)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            summary['base_url'],
            summary['total_pages_crawled'],
            summary['total_forms_found'],
            summary['total_api_endpoints'],
            summary['total_js_files'],
            summary['crawl_depth_reached']
        ))
        
        for form in report['forms']['all_forms']:
            cursor.execute('''
                INSERT INTO forms (action, method, fields)
                VALUES (?, ?, ?)
            ''', (
                form['action'],
                form['method'],
                json.dumps(form['fields'])
            ))
        
        for endpoint in report['api_endpoints']['all_endpoints']:
            endpoint_type = 'other'
            if '/api/' in endpoint:
                endpoint_type = 'api'
            elif '/rest/' in endpoint:
                endpoint_type = 'rest'
            elif '/v' in endpoint and any(c.isdigit() for c in endpoint):
                endpoint_type = 'versioned'
            
            cursor.execute('''
                INSERT INTO api_endpoints (endpoint, type)
                VALUES (?, ?)
            ''', (endpoint, endpoint_type))
        
        conn.commit()
        conn.close()
        self.console.print(f"✅ Database saved to {filename}")
    
    def display_report(self, report: Dict[str, Any]):
        """Display crawling report in console."""
        summary = report['crawl_summary']
        
        # Summary table
        table = Table(title="Crawling Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Base URL", summary['base_url'])
        table.add_row("Pages Crawled", str(summary['total_pages_crawled']))
        table.add_row("Forms Found", str(summary['total_forms_found']))
        table.add_row("API Endpoints", str(summary['total_api_endpoints']))
        table.add_row("JS Files", str(summary['total_js_files']))
        table.add_row("Max Depth", str(summary['crawl_depth_reached']))
        
        # New features summary
        if summary.get('subdomain_enumeration_enabled'):
            table.add_row("Subdomains Found", str(report['subdomain_enumeration']['total_subdomains']))
        if summary.get('endpoint_guessing_enabled'):
            table.add_row("Guessed Endpoints", str(report['endpoint_guessing']['total_endpoints']))
        if summary.get('hidden_file_scanning_enabled'):
            table.add_row("Hidden Files", str(report['hidden_file_scanning']['total_hidden_files']))
        if summary.get('js_analysis_enabled'):
            table.add_row("JS Analysis Pages", str(report['javascript_analysis']['total_analyzed_pages']))
        
        self.console.print(table)
        
        # Subdomain enumeration results
        if report['subdomain_enumeration']['enabled'] and report['subdomain_enumeration']['subdomains_found']:
            subdomain_table = Table(title="🔍 Subdomain Enumeration Results")
            subdomain_table.add_column("Subdomain", style="yellow")
            
            for subdomain in report['subdomain_enumeration']['subdomains_found'][:10]:
                subdomain_table.add_row(subdomain)
            
            if len(report['subdomain_enumeration']['subdomains_found']) > 10:
                subdomain_table.add_row(f"... and {len(report['subdomain_enumeration']['subdomains_found']) - 10} more")
            
            self.console.print(subdomain_table)
        
        # Endpoint guessing results
        if report['endpoint_guessing']['enabled'] and report['endpoint_guessing']['endpoints_found']:
            endpoint_table = Table(title="🎯 Endpoint Guessing Results")
            endpoint_table.add_column("Path", style="cyan")
            endpoint_table.add_column("Status", style="green")
            endpoint_table.add_column("Method", style="yellow")
            
            for endpoint in report['endpoint_guessing']['endpoints_found'][:10]:
                status_color = "green" if endpoint['status_code'] == 200 else "yellow"
                endpoint_table.add_row(
                    endpoint['path'],
                    f"[{status_color}]{endpoint['status_code']}[/{status_color}]",
                    endpoint['method']
                )
            
            if len(report['endpoint_guessing']['endpoints_found']) > 10:
                endpoint_table.add_row(f"... and {len(report['endpoint_guessing']['endpoints_found']) - 10} more", "", "")
            
            self.console.print(endpoint_table)
        
        # Hidden file scanning results
        if report['hidden_file_scanning']['enabled'] and report['hidden_file_scanning']['hidden_files_found']:
            hidden_files_table = Table(title="🔍 Hidden File Scanning Results")
            hidden_files_table.add_column("Path", style="cyan")
            hidden_files_table.add_column("Status", style="green")
            hidden_files_table.add_column("Sensitivity", style="yellow")
            hidden_files_table.add_column("Content-Type", style="blue")
            
            for hidden_file in report['hidden_file_scanning']['hidden_files_found'][:10]:
                sensitivity_level = hidden_file.get('sensitivity_level', 5)
                sensitivity_color = "red" if sensitivity_level <= 2 else "yellow" if sensitivity_level <= 3 else "green"
                hidden_files_table.add_row(
                    hidden_file['path'],
                    f"[{sensitivity_color}]{hidden_file['status_code']}[/{sensitivity_color}]",
                    f"Level {sensitivity_level}",
                    hidden_file.get('content_type', '')[:30]
                )
            
            if len(report['hidden_file_scanning']['hidden_files_found']) > 10:
                hidden_files_table.add_row(f"... and {len(report['hidden_file_scanning']['hidden_files_found']) - 10} more", "", "", "")
            
            self.console.print(hidden_files_table)
        
        # Forms by method
        if report['forms']['by_method']:
            forms_table = Table(title="Forms by Method")
            forms_table.add_column("Method", style="cyan")
            forms_table.add_column("Count", style="green")
            
            for method, forms in report['forms']['by_method'].items():
                forms_table.add_row(method.upper(), str(len(forms)))
            
            self.console.print(forms_table)
        
        # API endpoints by type
        if report['api_endpoints']['by_type']:
            endpoints_table = Table(title="API Endpoints by Type")
            endpoints_table.add_column("Type", style="cyan")
            endpoints_table.add_column("Count", style="green")
            
            for endpoint_type, endpoints in report['api_endpoints']['by_type'].items():
                endpoints_table.add_row(endpoint_type.title(), str(len(endpoints)))
            
            self.console.print(endpoints_table)

@click.command()
@click.argument('url', required=True)
@click.option('--max-depth', default=5, help='Maximum crawling depth')
@click.option('--max-pages', default=1000, help='Maximum pages to crawl')
@click.option('--delay', default=1.0, help='Delay between requests (seconds)')
@click.option('--concurrent', default=5, help='Concurrent requests')
@click.option('--respect-robots/--override-robots', default=True, help='Respect robots.txt')
@click.option('--include-subdomains', is_flag=True, help='Include subdomains')
@click.option('--use-playwright/--no-playwright', default=True, help='Use Playwright for JS rendering')
@click.option('--headless/--no-headless', default=True, help='Run browser in headless mode')
@click.option('--output-format', type=click.Choice(['json', 'sqlite', 'both']), default='both', help='Output format')
@click.option('--output-file', default=None, help='Output filename (without extension)')
@click.option('--enable-subdomain-enumeration', is_flag=True, help='Enable subdomain enumeration')
@click.option('--enable-endpoint-guessing', is_flag=True, help='Enable endpoint guessing')
@click.option('--enable-hidden-file-scanning', is_flag=True, help='Enable hidden file scanning')
@click.option('--disable-js-analysis', is_flag=True, help='Disable JavaScript analysis')
@click.option('--subdomain-wordlist', default=None, help='Path to subdomain wordlist')
@click.option('--endpoint-wordlist', default=None, help='Path to endpoint wordlist')
@click.option('--hidden-file-wordlist', default=None, help='Path to hidden file wordlist')
@click.option('--subdomain-methods', default='dns,wordlist', help='Subdomain enumeration methods (comma-separated)')
def main(url, max_depth, max_pages, delay, concurrent, respect_robots, include_subdomains, 
         use_playwright, headless, output_format, output_file, enable_subdomain_enumeration,
         enable_endpoint_guessing, enable_hidden_file_scanning, disable_js_analysis, 
         subdomain_wordlist, endpoint_wordlist, hidden_file_wordlist, subdomain_methods):
    """Ethical Web Crawler for Penetration Testing."""
    
    console = Console()
    
    # Display ethical warning
    console.print(Panel(
        "⚠️  ETHICAL WARNING ⚠️\n\n"
        "This tool is designed for penetration testing on websites where you have "
        "EXPLICIT PERMISSION to test. Only use this tool on systems you own or "
        "have written authorization to test.\n\n"
        "The crawler performs read-only operations and does not attempt any "
        "destructive actions or brute-force attacks.",
        style="red"
    ))
    
    # Confirm user has permission
    if not click.confirm("Do you have explicit permission to test this website?"):
        console.print("❌ Crawling cancelled. Only test websites you have permission to test.")
        return
    
    # Parse subdomain methods
    subdomain_methods_list = [method.strip() for method in subdomain_methods.split(',')]
    
    # Create configuration
    config = CrawlConfig(
        base_url=url,
        max_depth=max_depth,
        max_pages=max_pages,
        delay=delay,
        concurrent_requests=concurrent,
        respect_robots=respect_robots,
        override_robots=not respect_robots,
        include_subdomains=include_subdomains,
        use_playwright=use_playwright,
        headless=headless,
        enable_subdomain_enumeration=enable_subdomain_enumeration,
        enable_endpoint_guessing=enable_endpoint_guessing,
        enable_hidden_file_scanning=enable_hidden_file_scanning,
        enable_js_analysis=not disable_js_analysis,
        subdomain_wordlist=subdomain_wordlist,
        endpoint_wordlist=endpoint_wordlist,
        hidden_file_wordlist=hidden_file_wordlist,
        subdomain_enumeration_methods=subdomain_methods_list
    )
    
    # Generate output filename
    if output_file is None:
        domain = urlparse(url).netloc
        timestamp = int(time.time())
        output_file = f"crawl_{domain}_{timestamp}"
    
    async def run_crawler():
        async with WebCrawler(config) as crawler:
            report = await crawler.crawl()
            
            # Display report
            crawler.display_report(report)
            
            # Save output
            if output_format in ['json', 'both']:
                crawler.save_to_json(report, f"{output_file}.json")
            
            if output_format in ['sqlite', 'both']:
                crawler.save_to_sqlite(report, f"{output_file}.db")
    
    # Run crawler
    try:
        asyncio.run(run_crawler())
        console.print("✅ Crawling completed successfully!")
    except KeyboardInterrupt:
        console.print("\n⚠️  Crawling interrupted by user")
    except Exception as e:
        console.print(f"❌ Error during crawling: {e}")
        logger.error(f"Crawling error: {e}")

if __name__ == '__main__':
    main() 