#!/usr/bin/env python3
"""
Advanced JavaScript analyzer for extracting links and endpoints.
Analyzes fetch(), XMLHttpRequest, and other JavaScript patterns.
"""

import re
import json
import asyncio
from typing import List, Dict, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table

console = Console()

class JavaScriptAnalyzer:
    """Advanced JavaScript analysis for link and endpoint extraction."""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.extracted_urls = set()
        self.api_endpoints = set()
        self.js_files = set()
        self.ajax_calls = []
        self.fetch_calls = []
        self.websocket_urls = set()
        
    def analyze_javascript(self, js_content: str, source_url: str = "") -> Dict[str, Any]:
        """
        Analyze JavaScript content for URLs and endpoints.
        
        Args:
            js_content: JavaScript content to analyze
            source_url: URL where this JavaScript was found
            
        Returns:
            Dictionary with extracted data
        """
        results = {
            'urls': set(),
            'api_endpoints': set(),
            'ajax_calls': [],
            'fetch_calls': [],
            'websocket_urls': set(),
            'js_files': set(),
            'dynamic_urls': set()
        }
        
        # Extract fetch() calls
        fetch_urls = self._extract_fetch_calls(js_content)
        results['fetch_calls'] = fetch_urls
        results['urls'].update([url for url, _ in fetch_urls])
        results['api_endpoints'].update([url for url, _ in fetch_urls])
        
        # Extract XMLHttpRequest calls
        xhr_urls = self._extract_xmlhttprequest_calls(js_content)
        results['ajax_calls'] = xhr_urls
        results['urls'].update([url for url, _ in xhr_urls])
        results['api_endpoints'].update([url for url, _ in xhr_urls])
        
        # Extract $.ajax calls (jQuery)
        jquery_urls = self._extract_jquery_ajax_calls(js_content)
        results['ajax_calls'].extend(jquery_urls)
        results['urls'].update([url for url, _ in jquery_urls])
        results['api_endpoints'].update([url for url, _ in jquery_urls])
        
        # Extract axios calls
        axios_urls = self._extract_axios_calls(js_content)
        results['fetch_calls'].extend(axios_urls)
        results['urls'].update([url for url, _ in axios_urls])
        results['api_endpoints'].update([url for url, _ in axios_urls])
        
        # Extract WebSocket URLs
        websocket_urls = self._extract_websocket_urls(js_content)
        results['websocket_urls'] = websocket_urls
        results['urls'].update(websocket_urls)
        
        # Extract dynamic URLs (template literals, concatenation)
        dynamic_urls = self._extract_dynamic_urls(js_content)
        results['dynamic_urls'] = dynamic_urls
        results['urls'].update(dynamic_urls)
        
        # Extract JavaScript file references
        js_files = self._extract_js_files(js_content)
        results['js_files'] = js_files
        
        # Normalize URLs
        results['urls'] = self._normalize_urls(results['urls'], source_url)
        results['api_endpoints'] = self._normalize_urls(results['api_endpoints'], source_url)
        results['websocket_urls'] = self._normalize_urls(results['websocket_urls'], source_url)
        results['dynamic_urls'] = self._normalize_urls(results['dynamic_urls'], source_url)
        
        return results
    
    def _extract_fetch_calls(self, js_content: str) -> List[Tuple[str, str]]:
        """Extract URLs from fetch() calls."""
        fetch_patterns = [
            # fetch('url')
            r"fetch\(['\"`]([^'\"`]+)['\"`]",
            # fetch(url)
            r"fetch\(([a-zA-Z_$][a-zA-Z0-9_$]*)\)",
            # fetch(url, options)
            r"fetch\(([^,]+),\s*\{[^}]*\}\)",
            # fetch with template literals
            r"fetch\(`([^`]+)`",
        ]
        
        urls = []
        for pattern in fetch_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                url = match.group(1).strip()
                if self._is_valid_url(url):
                    urls.append((url, 'fetch'))
        
        return urls
    
    def _extract_xmlhttprequest_calls(self, js_content: str) -> List[Tuple[str, str]]:
        """Extract URLs from XMLHttpRequest calls."""
        xhr_patterns = [
            # xhr.open('GET', 'url')
            r"\.open\(['\"`]([A-Z]+)['\"`],\s*['\"`]([^'\"`]+)['\"`]",
            # xhr.open(method, url)
            r"\.open\(([^,]+),\s*([^,)]+)\)",
            # xhr.open with template literals
            r"\.open\(`([^`]+)`,\s*`([^`]+)`",
        ]
        
        urls = []
        for pattern in xhr_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) >= 2:
                    method = match.group(1).strip()
                    url = match.group(2).strip()
                    if self._is_valid_url(url):
                        urls.append((url, f'xhr_{method.lower()}'))
        
        return urls
    
    def _extract_jquery_ajax_calls(self, js_content: str) -> List[Tuple[str, str]]:
        """Extract URLs from jQuery $.ajax calls."""
        jquery_patterns = [
            # $.ajax({url: 'url'})
            r"\$\.ajax\(\s*\{[^}]*url\s*:\s*['\"`]([^'\"`]+)['\"`]",
            # $.ajax({url: url})
            r"\$\.ajax\(\s*\{[^}]*url\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$]*)",
            # $.get('url')
            r"\$\.get\(['\"`]([^'\"`]+)['\"`]",
            # $.post('url')
            r"\$\.post\(['\"`]([^'\"`]+)['\"`]",
            # $.getJSON('url')
            r"\$\.getJSON\(['\"`]([^'\"`]+)['\"`]",
        ]
        
        urls = []
        for pattern in jquery_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                url = match.group(1).strip()
                if self._is_valid_url(url):
                    method = 'get' if '$.get' in pattern else 'post' if '$.post' in pattern else 'ajax'
                    urls.append((url, f'jquery_{method}'))
        
        return urls
    
    def _extract_axios_calls(self, js_content: str) -> List[Tuple[str, str]]:
        """Extract URLs from axios calls."""
        axios_patterns = [
            # axios.get('url')
            r"axios\.(get|post|put|delete|patch)\(['\"`]([^'\"`]+)['\"`]",
            # axios({url: 'url'})
            r"axios\(\s*\{[^}]*url\s*:\s*['\"`]([^'\"`]+)['\"`]",
            # axios.create().get('url')
            r"axios\.create\(\)\.(get|post|put|delete|patch)\(['\"`]([^'\"`]+)['\"`]",
        ]
        
        urls = []
        for pattern in axios_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) >= 2:
                    method = match.group(1)
                    url = match.group(2).strip()
                    if self._is_valid_url(url):
                        urls.append((url, f'axios_{method}'))
        
        return urls
    
    def _extract_websocket_urls(self, js_content: str) -> Set[str]:
        """Extract WebSocket URLs."""
        websocket_patterns = [
            # new WebSocket('url')
            r"new\s+WebSocket\(['\"`]([^'\"`]+)['\"`]",
            # WebSocket('url')
            r"WebSocket\(['\"`]([^'\"`]+)['\"`]",
        ]
        
        urls = set()
        for pattern in websocket_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                url = match.group(1).strip()
                if self._is_valid_url(url):
                    urls.add(url)
        
        return urls
    
    def _extract_dynamic_urls(self, js_content: str) -> Set[str]:
        """Extract dynamically constructed URLs."""
        dynamic_patterns = [
            # Template literals with URLs
            r"`([^`]*https?://[^`]*)`",
            r"`([^`]*\/api\/[^`]*)`",
            r"`([^`]*\/rest\/[^`]*)`",
            # String concatenation with URLs
            r"['\"`]([^'\"`]*https?://[^'\"`]*)['\"`]\s*\+\s*['\"`]([^'\"`]*)['\"`]",
            # URL construction patterns
            r"baseURL\s*\+\s*['\"`]([^'\"`]+)['\"`]",
            r"apiUrl\s*\+\s*['\"`]([^'\"`]+)['\"`]",
        ]
        
        urls = set()
        for pattern in dynamic_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) >= 1:
                    url = match.group(1).strip()
                    if self._is_valid_url(url):
                        urls.add(url)
        
        return urls
    
    def _extract_js_files(self, js_content: str) -> Set[str]:
        """Extract JavaScript file references."""
        js_patterns = [
            # import statements
            r"import\s+.*\s+from\s+['\"`]([^'\"`]+\.js)['\"`]",
            r"import\s+['\"`]([^'\"`]+\.js)['\"`]",
            # require statements
            r"require\(['\"`]([^'\"`]+\.js)['\"`]\)",
            # script src
            r"src\s*=\s*['\"`]([^'\"`]+\.js)['\"`]",
        ]
        
        files = set()
        for pattern in js_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                file_path = match.group(1).strip()
                files.add(file_path)
        
        return files
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid for extraction."""
        # Skip empty or invalid URLs
        if not url or url.startswith('#'):
            return False
        
        # Skip data URLs
        if url.startswith('data:'):
            return False
        
        # Skip mailto and tel URLs
        if url.startswith(('mailto:', 'tel:')):
            return False
        
        # Skip relative paths that are clearly not endpoints
        if url.startswith(('./', '../', '/')) and not any(x in url for x in ['/api/', '/rest/', '/v1/', '/v2/']):
            return False
        
        return True
    
    def _normalize_urls(self, urls: Set[str], source_url: str) -> Set[str]:
        """Normalize URLs relative to source URL."""
        normalized = set()
        
        for url in urls:
            try:
                # If URL is relative, make it absolute
                if url.startswith('/'):
                    parsed_source = urlparse(source_url)
                    normalized_url = f"{parsed_source.scheme}://{parsed_source.netloc}{url}"
                elif not url.startswith(('http://', 'https://')):
                    normalized_url = urljoin(source_url, url)
                else:
                    normalized_url = url
                
                normalized.add(normalized_url)
            except Exception:
                continue
        
        return normalized
    
    def analyze_multiple_scripts(self, scripts: List[Tuple[str, str]]) -> Dict[str, Any]:
        """
        Analyze multiple JavaScript scripts.
        
        Args:
            scripts: List of (content, source_url) tuples
            
        Returns:
            Combined analysis results
        """
        combined_results = {
            'urls': set(),
            'api_endpoints': set(),
            'ajax_calls': [],
            'fetch_calls': [],
            'websocket_urls': set(),
            'js_files': set(),
            'dynamic_urls': set()
        }
        
        for js_content, source_url in scripts:
            results = self.analyze_javascript(js_content, source_url)
            
            # Combine results
            combined_results['urls'].update(results['urls'])
            combined_results['api_endpoints'].update(results['api_endpoints'])
            combined_results['ajax_calls'].extend(results['ajax_calls'])
            combined_results['fetch_calls'].extend(results['fetch_calls'])
            combined_results['websocket_urls'].update(results['websocket_urls'])
            combined_results['js_files'].update(results['js_files'])
            combined_results['dynamic_urls'].update(results['dynamic_urls'])
        
        return combined_results
    
    def display_results(self, results: Dict[str, Any]):
        """Display JavaScript analysis results."""
        
        # Summary table
        table = Table(title="🔍 JavaScript Analysis Results")
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="green")
        
        table.add_row("Total URLs", str(len(results['urls'])))
        table.add_row("API Endpoints", str(len(results['api_endpoints'])))
        table.add_row("AJAX Calls", str(len(results['ajax_calls'])))
        table.add_row("Fetch Calls", str(len(results['fetch_calls'])))
        table.add_row("WebSocket URLs", str(len(results['websocket_urls'])))
        table.add_row("JS Files", str(len(results['js_files'])))
        table.add_row("Dynamic URLs", str(len(results['dynamic_urls'])))
        
        console.print(table)
        
        # Show API endpoints
        if results['api_endpoints']:
            api_table = Table(title="🔗 API Endpoints Found")
            api_table.add_column("Endpoint", style="yellow")
            
            for endpoint in sorted(results['api_endpoints'])[:10]:
                api_table.add_row(endpoint)
            
            if len(results['api_endpoints']) > 10:
                api_table.add_row(f"... and {len(results['api_endpoints']) - 10} more")
            
            console.print(api_table)
        
        # Show AJAX calls
        if results['ajax_calls']:
            ajax_table = Table(title="📡 AJAX Calls")
            ajax_table.add_column("URL", style="yellow")
            ajax_table.add_column("Method", style="cyan")
            
            for url, method in results['ajax_calls'][:10]:
                ajax_table.add_row(url, method)
            
            if len(results['ajax_calls']) > 10:
                ajax_table.add_row(f"... and {len(results['ajax_calls']) - 10} more", "")
            
            console.print(ajax_table)

async def analyze_javascript_from_page(page_content: str, base_url: str) -> Dict[str, Any]:
    """
    Analyze JavaScript from a web page.
    
    Args:
        page_content: HTML content of the page
        base_url: Base URL of the page
        
    Returns:
        JavaScript analysis results
    """
    from bs4 import BeautifulSoup
    
    analyzer = JavaScriptAnalyzer(base_url)
    scripts = []
    
    # Parse HTML and extract script tags
    soup = BeautifulSoup(page_content, 'html.parser')
    
    # Extract inline scripts
    for script in soup.find_all('script'):
        if script.string:
            scripts.append((script.string, base_url))
    
    # Extract external script URLs
    for script in soup.find_all('script', src=True):
        script_url = urljoin(base_url, script['src'])
        # Note: In a real implementation, you'd fetch and analyze external scripts
        scripts.append((f"// External script: {script_url}", base_url))
    
    # Analyze all scripts
    results = analyzer.analyze_multiple_scripts(scripts)
    analyzer.display_results(results)
    
    return results

if __name__ == "__main__":
    # Example usage
    test_js = """
    fetch('/api/users')
    .then(response => response.json())
    .then(data => console.log(data));
    
    $.ajax({
        url: '/api/posts',
        method: 'POST',
        data: {title: 'Test'}
    });
    
    const ws = new WebSocket('wss://example.com/ws');
    """
    
    analyzer = JavaScriptAnalyzer("https://example.com")
    results = analyzer.analyze_javascript(test_js)
    analyzer.display_results(results) 