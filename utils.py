#!/usr/bin/env python3
"""
Utility functions for the web crawler.
Helper functions for URL processing, data normalization, and common operations.
"""

import hashlib
import re
import urllib.parse
from typing import Dict, List, Set, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
from collections import defaultdict

def normalize_url(url: str) -> str:
    """
    Normalize URL to avoid duplicates.
    
    Args:
        url: The URL to normalize
        
    Returns:
        Normalized URL string
    """
    try:
        parsed = urlparse(url)
        
        # Remove fragments
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Normalize query parameters
        if parsed.query:
            # Parse and sort query parameters
            params = parse_qs(parsed.query)
            sorted_params = sorted(params.items())
            query_string = urlencode(sorted_params, doseq=True)
            normalized += f"?{query_string}"
        
        return normalized
    except Exception:
        return url

def is_valid_url(url: str, base_domain: str, include_subdomains: bool = False) -> bool:
    """
    Check if URL is valid for crawling.
    
    Args:
        url: URL to check
        base_domain: Base domain to compare against
        include_subdomains: Whether to include subdomains
        
    Returns:
        True if URL is valid for crawling
    """
    try:
        parsed = urlparse(url)
        base_parsed = urlparse(base_domain)
        
        # Check if URL is within the same domain
        if not include_subdomains:
            if parsed.netloc != base_parsed.netloc:
                return False
        else:
            # Allow subdomains
            if not parsed.netloc.endswith(base_parsed.netloc.split('.', 1)[1]):
                return False
        
        # Check for valid scheme
        if parsed.scheme not in ['http', 'https']:
            return False
        
        return True
    except Exception:
        return False

def filter_urls_by_extension(urls: List[str], ignored_extensions: Set[str], 
                           focused_extensions: Optional[Set[str]] = None) -> List[str]:
    """
    Filter URLs based on file extensions.
    
    Args:
        urls: List of URLs to filter
        ignored_extensions: Extensions to ignore
        focused_extensions: Extensions to focus on (if None, accept all non-ignored)
        
    Returns:
        Filtered list of URLs
    """
    filtered_urls = []
    
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check if URL should be ignored
        if any(path.endswith(ext) for ext in ignored_extensions):
            continue
        
        # Check if URL should be focused on
        if focused_extensions:
            if not any(path.endswith(ext) for ext in focused_extensions):
                continue
        
        filtered_urls.append(url)
    
    return filtered_urls

def extract_domain(url: str) -> str:
    """
    Extract domain from URL.
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain string
    """
    try:
        return urlparse(url).netloc
    except Exception:
        return ""

def extract_path(url: str) -> str:
    """
    Extract path from URL.
    
    Args:
        url: URL to extract path from
        
    Returns:
        Path string
    """
    try:
        return urlparse(url).path
    except Exception:
        return ""

def extract_query_params(url: str) -> Dict[str, List[str]]:
    """
    Extract query parameters from URL.
    
    Args:
        url: URL to extract parameters from
        
    Returns:
        Dictionary of parameter names to values
    """
    try:
        parsed = urlparse(url)
        return parse_qs(parsed.query)
    except Exception:
        return {}

def build_url(base_url: str, path: str, params: Optional[Dict[str, str]] = None) -> str:
    """
    Build a complete URL from components.
    
    Args:
        base_url: Base URL
        path: Path to append
        params: Query parameters
        
    Returns:
        Complete URL string
    """
    url = urljoin(base_url, path)
    
    if params:
        query_string = urlencode(params)
        url += f"?{query_string}"
    
    return url

def deduplicate_urls(urls: List[str]) -> List[str]:
    """
    Remove duplicate URLs while preserving order.
    
    Args:
        urls: List of URLs to deduplicate
        
    Returns:
        List of unique URLs
    """
    seen = set()
    unique_urls = []
    
    for url in urls:
        normalized = normalize_url(url)
        if normalized not in seen:
            seen.add(normalized)
            unique_urls.append(url)
    
    return unique_urls

def extract_api_endpoints_from_js(js_content: str) -> List[str]:
    """
    Extract API endpoints from JavaScript content.
    
    Args:
        js_content: JavaScript content to analyze
        
    Returns:
        List of discovered API endpoints
    """
    endpoints = []
    
    # Common API endpoint patterns
    patterns = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'["\'](/v\d+/[^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        r'\.ajax\(["\']([^"\']+)["\']',
        r'url:\s*["\']([^"\']+)["\']',
        r'endpoint:\s*["\']([^"\']+)["\']',
        r'baseURL:\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                endpoints.extend(match)
            else:
                endpoints.append(match)
    
    return list(set(endpoints))

def extract_forms_from_html(html_content: str) -> List[Dict[str, Any]]:
    """
    Extract forms from HTML content.
    
    Args:
        html_content: HTML content to analyze
        
    Returns:
        List of form dictionaries
    """
    from bs4 import BeautifulSoup
    
    forms = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    for form in soup.find_all('form'):
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        
        fields = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            field_type = inp.get('type', 'text')
            field_name = inp.get('name', '')
            field_value = inp.get('value', '')
            field_id = inp.get('id', '')
            
            fields.append({
                'type': field_type,
                'name': field_name,
                'value': field_value,
                'id': field_id
            })
        
        forms.append({
            'action': action,
            'method': method,
            'fields': fields
        })
    
    return forms

def extract_hidden_fields_from_html(html_content: str) -> List[Dict[str, str]]:
    """
    Extract hidden form fields from HTML content.
    
    Args:
        html_content: HTML content to analyze
        
    Returns:
        List of hidden field dictionaries
    """
    from bs4 import BeautifulSoup
    
    hidden_fields = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    for inp in soup.find_all('input', type='hidden'):
        hidden_fields.append({
            'name': inp.get('name', ''),
            'value': inp.get('value', ''),
            'id': inp.get('id', '')
        })
    
    return hidden_fields

def extract_csrf_tokens_from_html(html_content: str) -> List[str]:
    """
    Extract CSRF tokens from HTML content.
    
    Args:
        html_content: HTML content to analyze
        
    Returns:
        List of CSRF tokens
    """
    from bs4 import BeautifulSoup
    
    csrf_tokens = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Common CSRF token patterns
    csrf_patterns = [
        'input[name*="csrf"]',
        'input[name*="token"]',
        'meta[name*="csrf"]',
        'meta[name*="token"]',
        'input[name*="_token"]',
        'meta[name*="_token"]',
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
    
    return list(set(csrf_tokens))

def calculate_url_hash(url: str) -> str:
    """
    Calculate a hash for a URL to use as a unique identifier.
    
    Args:
        url: URL to hash
        
    Returns:
        Hash string
    """
    return hashlib.md5(url.encode()).hexdigest()

def group_urls_by_pattern(urls: List[str]) -> Dict[str, List[str]]:
    """
    Group URLs by common patterns.
    
    Args:
        urls: List of URLs to group
        
    Returns:
        Dictionary of pattern to URLs
    """
    groups = defaultdict(list)
    
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path
        
        # Extract common patterns
        if '/api/' in path:
            groups['api'].append(url)
        elif '/rest/' in path:
            groups['rest'].append(url)
        elif '/admin/' in path:
            groups['admin'].append(url)
        elif '/user/' in path or '/profile/' in path:
            groups['user'].append(url)
        elif '/login' in path or '/auth' in path:
            groups['auth'].append(url)
        elif path.endswith('.js'):
            groups['javascript'].append(url)
        elif path.endswith('.css'):
            groups['stylesheet'].append(url)
        else:
            groups['other'].append(url)
    
    return dict(groups)

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file system usage.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove or replace unsafe characters
    unsafe_chars = '<>:"/\\|?*'
    for char in unsafe_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename

def create_session_headers(user_agent: Optional[str] = None, 
                         custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Create headers for HTTP session.
    
    Args:
        user_agent: Custom user agent string
        custom_headers: Additional custom headers
        
    Returns:
        Dictionary of headers
    """
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    if user_agent:
        headers['User-Agent'] = user_agent
    
    if custom_headers:
        headers.update(custom_headers)
    
    return headers

def parse_robots_txt_content(content: str) -> Dict[str, Any]:
    """
    Parse robots.txt content and extract rules.
    
    Args:
        content: Robots.txt content
        
    Returns:
        Dictionary with parsed robots.txt data
    """
    lines = content.split('\n')
    disallowed = []
    allowed = []
    crawl_delay = 0
    user_agents = []
    
    current_user_agent = None
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if ':' in line:
            directive, value = line.split(':', 1)
            directive = directive.strip().lower()
            value = value.strip()
            
            if directive == 'user-agent':
                current_user_agent = value
                if value not in user_agents:
                    user_agents.append(value)
            elif directive == 'disallow':
                if current_user_agent in ['*', None] or current_user_agent == '*':
                    disallowed.append(value)
            elif directive == 'allow':
                if current_user_agent in ['*', None] or current_user_agent == '*':
                    allowed.append(value)
            elif directive == 'crawl-delay':
                try:
                    crawl_delay = float(value)
                except ValueError:
                    pass
    
    return {
        'disallowed_paths': disallowed,
        'allowed_paths': allowed,
        'crawl_delay': crawl_delay,
        'user_agents': user_agents
    }

def is_robots_allowed(url: str, robots_data: Dict[str, Any]) -> bool:
    """
    Check if URL is allowed according to robots.txt rules.
    
    Args:
        url: URL to check
        robots_data: Parsed robots.txt data
        
    Returns:
        True if URL is allowed
    """
    parsed = urlparse(url)
    path = parsed.path
    
    # Check disallowed paths
    for disallowed_path in robots_data.get('disallowed_paths', []):
        if path.startswith(disallowed_path):
            return False
    
    # Check allowed paths (if any specific allows exist)
    allowed_paths = robots_data.get('allowed_paths', [])
    if allowed_paths:
        # If there are specific allows, URL must match one
        for allowed_path in allowed_paths:
            if path.startswith(allowed_path):
                return True
        return False
    
    return True 