#!/usr/bin/env python3
"""
Endpoint guessing module for discovering hidden endpoints and API paths.
Uses wordlists to guess potential endpoints and test their existence.
"""

import asyncio
import aiohttp
import os
import time
from typing import List, Dict, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel

console = Console()

class EndpointGuesser:
    """Endpoint guessing using wordlists and common patterns."""
    
    def __init__(self, base_url: str, wordlist_path: Optional[str] = None):
        self.base_url = base_url
        self.wordlist_path = wordlist_path or self._get_default_wordlist()
        self.discovered_endpoints = []
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    def _get_default_wordlist(self) -> str:
        """Get path to default endpoint wordlist."""
        import os
        # Create default wordlist if it doesn't exist
        default_wordlist = "wordlists/endpoints.txt"
        os.makedirs("wordlists", exist_ok=True)
        
        if not os.path.exists(default_wordlist):
            self._create_default_wordlist(default_wordlist)
        
        return default_wordlist
    
    def _create_default_wordlist(self, path: str):
        """Create a default endpoint wordlist."""
        default_endpoints = [
            # API endpoints
            "api", "api/v1", "api/v2", "api/v3", "rest", "rest/v1", "rest/v2",
            "graphql", "graphql/v1", "graphql/v2", "swagger", "swagger.json",
            "openapi", "openapi.json", "docs", "documentation", "redoc",
            
            # Common API paths
            "users", "user", "auth", "login", "logout", "register", "signup",
            "admin", "administrator", "manage", "management", "dashboard",
            "profile", "account", "settings", "config", "configuration",
            "posts", "post", "articles", "article", "blog", "news",
            "products", "product", "items", "item", "catalog", "store",
            "orders", "order", "cart", "checkout", "payment", "billing",
            "files", "file", "upload", "download", "media", "images",
            "search", "find", "query", "filter", "sort", "page",
            
            # Admin and management
            "admin/api", "admin/users", "admin/settings", "admin/dashboard",
            "manage/api", "manage/users", "manage/settings", "manage/dashboard",
            "system", "system/api", "system/users", "system/settings",
            
            # Development and testing
            "dev", "development", "test", "testing", "staging", "beta",
            "debug", "debugger", "console", "log", "logs", "error",
            
            # Authentication and security
            "auth/api", "auth/login", "auth/logout", "auth/register",
            "oauth", "oauth2", "sso", "saml", "jwt", "token",
            "security", "secure", "ssl", "cert", "certificate",
            
            # Data and storage
            "data", "database", "db", "sql", "nosql", "cache",
            "storage", "backup", "archive", "export", "import",
            
            # Monitoring and analytics
            "monitor", "monitoring", "health", "status", "ping",
            "metrics", "analytics", "stats", "statistics", "report",
            
            # Communication
            "mail", "email", "sms", "notification", "webhook",
            "message", "chat", "support", "help", "contact",
            
            # Version control and deployment
            "git", "github", "gitlab", "deploy", "deployment",
            "ci", "cd", "jenkins", "travis", "build", "release",
            
            # Common file extensions
            "robots.txt", "sitemap.xml", "sitemap", "favicon.ico",
            "manifest.json", "service-worker.js", "sw.js",
            
            # Hidden and backup files
            ".git", ".env", ".htaccess", ".htpasswd", "backup",
            "old", "archive", "bak", "tmp", "temp", "cache",
            
            # Common API patterns
            "v1", "v2", "v3", "latest", "current", "stable",
            "public", "private", "internal", "external", "partner",
            
            # RESTful patterns
            "create", "read", "update", "delete", "list", "get",
            "post", "put", "patch", "delete", "head", "options",
            
            # GraphQL patterns
            "query", "mutation", "subscription", "schema", "introspection",
            
            # WebSocket and real-time
            "ws", "websocket", "socket", "stream", "live", "realtime",
            
            # Mobile and app specific
            "mobile", "app", "ios", "android", "native", "hybrid",
            
            # Third-party integrations
            "webhook", "callback", "redirect", "oauth/callback",
            "stripe", "paypal", "google", "facebook", "twitter",
            
            # Development tools
            "phpmyadmin", "adminer", "phpinfo", "info", "test.php",
            "debug.php", "error.php", "config.php", "setup.php"
        ]
        
        with open(path, 'w') as f:
            for endpoint in default_endpoints:
                f.write(f"{endpoint}\n")
        
        console.print(f"✅ Created default endpoint wordlist at {path}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; EndpointGuesser/1.0)',
                'Accept': 'text/html,application/xhtml+xml,application/json,*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def guess_endpoints(self, methods: List[str] = None, 
                            status_codes: List[int] = None,
                            max_concurrent: int = 50) -> List[Dict[str, Any]]:
        """
        Guess endpoints using wordlist and test their existence.
        
        Args:
            methods: HTTP methods to test (default: GET, HEAD)
            status_codes: Status codes to consider as "found" (default: 200, 301, 302, 401, 403)
            max_concurrent: Maximum concurrent requests
            
        Returns:
            List of discovered endpoints with details
        """
        if methods is None:
            methods = ['GET', 'HEAD']
        if status_codes is None:
            status_codes = [200, 201, 301, 302, 401, 403, 405, 500]
        
        # Load wordlist
        with open(self.wordlist_path, 'r') as f:
            endpoints = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        console.print(f"🔍 Guessing endpoints for {self.base_url}")
        console.print(f"📋 Loaded {len(endpoints)} endpoints from wordlist")
        
        discovered = []
        semaphore = asyncio.Semaphore(max_concurrent)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Testing endpoints...", total=len(endpoints))
            
            # Create tasks for all endpoints
            tasks = []
            for endpoint in endpoints:
                task = self._test_endpoint(endpoint, methods, status_codes, semaphore, progress)
                tasks.append(task)
            
            # Run all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, dict) and result.get('found'):
                    discovered.append(result)
            
            progress.update(task, completed=len(endpoints))
        
        # Sort by status code and path
        discovered.sort(key=lambda x: (x['status_code'], x['path']))
        
        return discovered
    
    async def _test_endpoint(self, endpoint: str, methods: List[str], 
                           status_codes: List[int], semaphore: asyncio.Semaphore,
                           progress) -> Dict[str, Any]:
        """Test a single endpoint."""
        async with semaphore:
            url = urljoin(self.base_url, endpoint)
            
            for method in methods:
                try:
                    async with self.session.request(method, url, allow_redirects=False) as response:
                        if response.status in status_codes:
                            result = {
                                'path': endpoint,
                                'url': url,
                                'method': method,
                                'status_code': response.status,
                                'status_text': response.reason,
                                'content_type': response.headers.get('content-type', ''),
                                'content_length': response.headers.get('content-length', ''),
                                'server': response.headers.get('server', ''),
                                'found': True,
                                'timestamp': time.time()
                            }
                            
                            # Try to get response body for analysis
                            try:
                                if response.status == 200:
                                    content = await response.text()
                                    result['content_preview'] = content[:200] + "..." if len(content) > 200 else content
                            except Exception:
                                pass
                            
                            progress.advance(progress.tasks[0].id)
                            return result
                            
                except Exception as e:
                    continue
            
            progress.advance(progress.tasks[0].id)
            return {'path': endpoint, 'found': False}
    
    async def guess_api_endpoints(self) -> List[Dict[str, Any]]:
        """Guess common API endpoints."""
        api_patterns = [
            "api", "api/v1", "api/v2", "api/v3", "rest", "rest/v1", "rest/v2",
            "graphql", "graphql/v1", "swagger", "swagger.json", "openapi", "openapi.json",
            "docs", "documentation", "redoc", "api-docs", "api/docs"
        ]
        
        discovered = []
        for pattern in api_patterns:
            try:
                url = urljoin(self.base_url, pattern)
                async with self.session.get(url, allow_redirects=False) as response:
                    if response.status in [200, 201, 301, 302, 401, 403, 405]:
                        discovered.append({
                            'path': pattern,
                            'url': url,
                            'method': 'GET',
                            'status_code': response.status,
                            'status_text': response.reason,
                            'content_type': response.headers.get('content-type', ''),
                            'found': True
                        })
            except Exception:
                continue
        
        return discovered
    
    async def guess_admin_endpoints(self) -> List[Dict[str, Any]]:
        """Guess common admin endpoints."""
        admin_patterns = [
            "admin", "administrator", "manage", "management", "dashboard",
            "admin/api", "admin/users", "admin/settings", "admin/dashboard",
            "manage/api", "manage/users", "manage/settings", "manage/dashboard",
            "system", "system/api", "system/users", "system/settings",
            "phpmyadmin", "adminer", "webmin", "cpanel", "plesk"
        ]
        
        discovered = []
        for pattern in admin_patterns:
            try:
                url = urljoin(self.base_url, pattern)
                async with self.session.get(url, allow_redirects=False) as response:
                    if response.status in [200, 201, 301, 302, 401, 403, 405]:
                        discovered.append({
                            'path': pattern,
                            'url': url,
                            'method': 'GET',
                            'status_code': response.status,
                            'status_text': response.reason,
                            'content_type': response.headers.get('content-type', ''),
                            'found': True
                        })
            except Exception:
                continue
        
        return discovered
    
    def display_results(self, results: List[Dict[str, Any]]):
        """Display endpoint guessing results."""
        if not results:
            console.print("❌ No endpoints discovered")
            return
        
        # Summary table
        table = Table(title="🎯 Endpoint Guessing Results")
        table.add_column("Path", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Method", style="yellow")
        table.add_column("Content-Type", style="blue")
        table.add_column("Server", style="magenta")
        
        for result in results[:20]:  # Show first 20
            status_color = "green" if result['status_code'] == 200 else "yellow"
            table.add_row(
                result['path'],
                f"[{status_color}]{result['status_code']}[/{status_color}]",
                result['method'],
                result.get('content_type', '')[:30],
                result.get('server', '')[:20]
            )
        
        if len(results) > 20:
            table.add_row(f"... and {len(results) - 20} more", "", "", "", "")
        
        console.print(table)
        
        # Group by status code
        status_groups = {}
        for result in results:
            status = result['status_code']
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(result)
        
        # Show status code summary
        status_table = Table(title="📊 Status Code Summary")
        status_table.add_column("Status Code", style="cyan")
        status_table.add_column("Count", style="green")
        status_table.add_column("Description", style="yellow")
        
        status_descriptions = {
            200: "OK - Endpoint exists",
            201: "Created - Endpoint exists",
            301: "Moved Permanently - Endpoint exists",
            302: "Found - Endpoint exists",
            401: "Unauthorized - Endpoint exists (requires auth)",
            403: "Forbidden - Endpoint exists (access denied)",
            405: "Method Not Allowed - Endpoint exists (wrong method)",
            500: "Internal Server Error - Endpoint exists (server error)"
        }
        
        for status_code, count in sorted(status_groups.items()):
            description = status_descriptions.get(status_code, "Unknown")
            status_table.add_row(str(status_code), str(count), description)
        
        console.print(status_table)

async def guess_endpoints_for_crawler(base_url: str, wordlist_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Guess endpoints for use in the crawler.
    
    Args:
        base_url: Base URL to test
        wordlist_path: Path to custom wordlist
        
    Returns:
        List of discovered endpoints
    """
    async with EndpointGuesser(base_url, wordlist_path) as guesser:
        results = await guesser.guess_endpoints()
        guesser.display_results(results)
        return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python endpoint_guesser.py <base_url> [wordlist_path]")
        sys.exit(1)
    
    base_url = sys.argv[1]
    wordlist_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    asyncio.run(guess_endpoints_for_crawler(base_url, wordlist_path)) 