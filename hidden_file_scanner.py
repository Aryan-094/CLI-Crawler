#!/usr/bin/env python3
"""
Hidden file scanner for discovering sensitive files and directories.
Scans for .git, .env, backup files, and other hidden resources.
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
import re

console = Console()

class HiddenFileScanner:
    """Scanner for hidden files and sensitive resources."""
    
    def __init__(self, base_url: str, wordlist_path: Optional[str] = None):
        self.base_url = base_url
        self.wordlist_path = wordlist_path or self._get_default_wordlist()
        self.discovered_files = []
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    def _get_default_wordlist(self) -> str:
        """Get path to default hidden files wordlist."""
        import os
        # Create default wordlist if it doesn't exist
        default_wordlist = "wordlists/hidden_files.txt"
        os.makedirs("wordlists", exist_ok=True)
        
        if not os.path.exists(default_wordlist):
            self._create_default_wordlist(default_wordlist)
        
        return default_wordlist
    
    def _create_default_wordlist(self, path: str):
        """Create a default hidden files wordlist."""
        hidden_files = [
            # Version control
            ".git", ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
            ".svn", ".svn/entries", ".svn/wc.db", ".svn/format",
            ".hg", ".hg/hgrc", ".hg/requires", ".hg/store",
            
            # Environment and configuration
            ".env", ".env.local", ".env.development", ".env.production", ".env.test",
            ".env.backup", ".env.old", ".env.bak", ".env.save",
            "config.php", "config.ini", "config.json", "config.xml",
            "settings.php", "settings.ini", "settings.json", "settings.xml",
            "database.yml", "database.json", "database.xml",
            "application.yml", "application.json", "application.xml",
            
            # Backup and temporary files
            "backup", "backup/", "backup.zip", "backup.tar", "backup.tar.gz",
            "backup.sql", "backup.db", "backup.bak", "backup.old",
            "bak", "bak/", "old", "old/", "tmp", "tmp/", "temp", "temp/",
            "cache", "cache/", "logs", "logs/", "log", "log/",
            
            # Web server files
            ".htaccess", ".htpasswd", ".htaccess.bak", ".htaccess.old",
            "web.config", "web.config.bak", "web.config.old",
            "robots.txt", "robots.txt.bak", "robots.txt.old",
            "sitemap.xml", "sitemap.xml.bak", "sitemap.xml.old",
            
            # Development and debugging
            "debug", "debug.php", "debug.log", "debug.txt",
            "test", "test.php", "test.html", "test.txt",
            "dev", "dev.php", "dev.html", "dev.txt",
            "info.php", "info.html", "info.txt",
            "phpinfo.php", "phpinfo.html", "phpinfo.txt",
            
            # IDE and editor files
            ".vscode", ".vscode/settings.json", ".vscode/launch.json",
            ".idea", ".idea/workspace.xml", ".idea/modules.xml",
            ".sublime-project", ".sublime-workspace",
            ".vimrc", ".viminfo", ".vim/",
            
            # OS and system files
            ".DS_Store", "Thumbs.db", "desktop.ini",
            ".bash_history", ".bashrc", ".bash_profile",
            ".ssh", ".ssh/config", ".ssh/id_rsa", ".ssh/id_rsa.pub",
            ".ssh/known_hosts", ".ssh/authorized_keys",
            
            # Database files
            "database.sql", "database.sql.bak", "database.sql.old",
            "dump.sql", "dump.sql.bak", "dump.sql.old",
            "backup.sql", "backup.sql.bak", "backup.sql.old",
            "data.sql", "data.sql.bak", "data.sql.old",
            
            # Application specific
            "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
            "config.php", "config.php.bak", "config.php.old",
            "configuration.php", "configuration.php.bak", "configuration.php.old",
            "settings.php", "settings.php.bak", "settings.php.old",
            
            # CMS and framework files
            "composer.json", "composer.lock", "package.json", "package-lock.json",
            "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
            "Pipfile", "Pipfile.lock", "poetry.lock", "Cargo.toml", "Cargo.lock",
            
            # Security and authentication
            ".htaccess", ".htpasswd", ".htaccess.bak", ".htaccess.old",
            "auth.php", "auth.php.bak", "auth.php.old",
            "login.php", "login.php.bak", "login.php.old",
            "admin.php", "admin.php.bak", "admin.php.old",
            
            # API and documentation
            "api", "api/", "api/v1", "api/v2", "api/v3",
            "swagger", "swagger.json", "swagger.yaml", "swagger.yml",
            "openapi", "openapi.json", "openapi.yaml", "openapi.yml",
            "docs", "docs/", "documentation", "documentation/",
            
            # Common file extensions
            ".log", ".log.bak", ".log.old", ".log.1", ".log.2",
            ".sql", ".sql.bak", ".sql.old", ".sql.1", ".sql.2",
            ".bak", ".old", ".backup", ".save", ".tmp", ".temp",
            ".cache", ".session", ".cookie", ".config", ".conf",
            
            # Hidden directories
            ".git/", ".svn/", ".hg/", ".ssh/", ".vim/", ".vscode/",
            ".idea/", ".sublime-project/", ".sublime-workspace/",
            "backup/", "old/", "tmp/", "temp/", "cache/", "logs/",
            "dev/", "test/", "debug/", "api/", "docs/", "admin/",
            
            # Common sensitive paths
            "admin", "admin/", "administrator", "administrator/",
            "manage", "manage/", "management", "management/",
            "system", "system/", "sys", "sys/",
            "internal", "internal/", "private", "private/",
            "secret", "secret/", "hidden", "hidden/",
            
            # Backup patterns
            "*.bak", "*.backup", "*.old", "*.save", "*.tmp", "*.temp",
            "*.log", "*.sql", "*.db", "*.cache", "*.session",
            "*~", "*#", ".#*", ".#*#", "*.swp", "*.swo",
            
            # Configuration files
            "config", "config/", "configuration", "configuration/",
            "settings", "settings/", "setup", "setup/",
            "init", "init/", "bootstrap", "bootstrap/",
            "startup", "startup/", "launch", "launch/",
            
            # Development files
            "dev", "dev/", "development", "development/",
            "test", "test/", "testing", "testing/",
            "staging", "staging/", "beta", "beta/",
            "debug", "debug/", "debugger", "debugger/",
            
            # Database files
            "db", "db/", "database", "database/",
            "data", "data/", "storage", "storage/",
            "dump", "dump/", "backup", "backup/",
            "export", "export/", "import", "import/",
            
            # Log files
            "log", "log/", "logs", "logs/",
            "error", "error/", "errors", "errors/",
            "access", "access/", "access.log", "error.log",
            "debug.log", "info.log", "warn.log", "fatal.log"
        ]
        
        with open(path, 'w') as f:
            for file_path in hidden_files:
                f.write(f"{file_path}\n")
        
        console.print(f"✅ Created default hidden files wordlist at {path}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; HiddenFileScanner/1.0)',
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
    
    async def scan_hidden_files(self, methods: List[str] = None, 
                              status_codes: List[int] = None,
                              max_concurrent: int = 50) -> List[Dict[str, Any]]:
        """
        Scan for hidden files and sensitive resources.
        
        Args:
            methods: HTTP methods to test (default: GET, HEAD)
            status_codes: Status codes to consider as "found" (default: 200, 301, 302, 401, 403)
            max_concurrent: Maximum concurrent requests
            
        Returns:
            List of discovered hidden files with details
        """
        if methods is None:
            methods = ['GET', 'HEAD']
        if status_codes is None:
            status_codes = [200, 201, 301, 302, 401, 403, 405, 500]
        
        # Load wordlist
        with open(self.wordlist_path, 'r') as f:
            hidden_files = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        console.print(f"🔍 Scanning for hidden files on {self.base_url}")
        console.print(f"📋 Loaded {len(hidden_files)} hidden file patterns")
        
        discovered = []
        semaphore = asyncio.Semaphore(max_concurrent)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Scanning hidden files...", total=len(hidden_files))
            
            # Create tasks for all hidden files
            tasks = []
            for hidden_file in hidden_files:
                task = self._test_hidden_file(hidden_file, methods, status_codes, semaphore, progress)
                tasks.append(task)
            
            # Run all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, dict) and result.get('found'):
                    discovered.append(result)
            
            progress.update(task, completed=len(hidden_files))
        
        # Sort by sensitivity level and status code
        discovered.sort(key=lambda x: (self._get_sensitivity_level(x['path']), x['status_code']))
        
        return discovered
    
    def _get_sensitivity_level(self, path: str) -> int:
        """Get sensitivity level of a hidden file (lower = more sensitive)."""
        sensitive_patterns = [
            (r'\.env', 1),  # Environment files
            (r'\.git', 1),  # Git repository
            (r'\.ssh', 1),  # SSH keys
            (r'config\.php', 2),  # Configuration files
            (r'wp-config', 2),  # WordPress config
            (r'backup', 3),  # Backup files
            (r'\.log', 4),  # Log files
            (r'\.bak', 4),  # Backup files
            (r'\.old', 4),  # Old files
        ]
        
        for pattern, level in sensitive_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return level
        
        return 5  # Default level
    
    async def _test_hidden_file(self, hidden_file: str, methods: List[str], 
                               status_codes: List[int], semaphore: asyncio.Semaphore,
                               progress) -> Dict[str, Any]:
        """Test a single hidden file."""
        async with semaphore:
            url = urljoin(self.base_url, hidden_file)
            
            for method in methods:
                try:
                    async with self.session.request(method, url, allow_redirects=False) as response:
                        if response.status in status_codes:
                            result = {
                                'path': hidden_file,
                                'url': url,
                                'method': method,
                                'status_code': response.status,
                                'status_text': response.reason,
                                'content_type': response.headers.get('content-type', ''),
                                'content_length': response.headers.get('content-length', ''),
                                'server': response.headers.get('server', ''),
                                'found': True,
                                'sensitivity_level': self._get_sensitivity_level(hidden_file),
                                'timestamp': time.time()
                            }
                            
                            # Try to get response body for analysis
                            try:
                                if response.status == 200:
                                    content = await response.text()
                                    result['content_preview'] = content[:500] + "..." if len(content) > 500 else content
                                    
                                    # Check for sensitive content
                                    result['sensitive_content'] = self._check_sensitive_content(content)
                            except Exception:
                                pass
                            
                            progress.advance(progress.tasks[0].id)
                            return result
                            
                except Exception as e:
                    continue
            
            progress.advance(progress.tasks[0].id)
            return {'path': hidden_file, 'found': False}
    
    def _check_sensitive_content(self, content: str) -> List[str]:
        """Check for sensitive content in response."""
        sensitive_patterns = [
            (r'password\s*=', 'Password found'),
            (r'secret\s*=', 'Secret found'),
            (r'api_key\s*=', 'API key found'),
            (r'token\s*=', 'Token found'),
            (r'database\s*=', 'Database config found'),
            (r'mysql', 'MySQL reference found'),
            (r'postgresql', 'PostgreSQL reference found'),
            (r'redis', 'Redis reference found'),
            (r'aws', 'AWS reference found'),
            (r'google', 'Google API reference found'),
            (r'facebook', 'Facebook API reference found'),
            (r'twitter', 'Twitter API reference found'),
            (r'private_key', 'Private key found'),
            (r'public_key', 'Public key found'),
            (r'\.env', 'Environment file content'),
            (r'config', 'Configuration content'),
            (r'admin', 'Admin content'),
            (r'root', 'Root access content'),
        ]
        
        found_patterns = []
        for pattern, description in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(description)
        
        return found_patterns
    
    def display_results(self, results: List[Dict[str, Any]]):
        """Display hidden file scanning results."""
        if not results:
            console.print("❌ No hidden files discovered")
            return
        
        # Group by sensitivity level
        sensitivity_groups = {
            1: "🔴 Critical",
            2: "🟡 High", 
            3: "🟠 Medium",
            4: "🟢 Low",
            5: "⚪ Info"
        }
        
        # Summary table
        table = Table(title="🔍 Hidden File Scanning Results")
        table.add_column("Sensitivity", style="cyan")
        table.add_column("Path", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("Content-Type", style="blue")
        table.add_column("Sensitive Content", style="red")
        
        for result in results[:20]:  # Show first 20
            sensitivity = sensitivity_groups.get(result.get('sensitivity_level', 5), "⚪ Info")
            status_color = "green" if result['status_code'] == 200 else "yellow"
            sensitive_content = ", ".join(result.get('sensitive_content', []))[:30]
            
            table.add_row(
                sensitivity,
                result['path'],
                f"[{status_color}]{result['status_code']}[/{status_color}]",
                result.get('content_type', '')[:30],
                sensitive_content
            )
        
        if len(results) > 20:
            table.add_row(f"... and {len(results) - 20} more", "", "", "", "")
        
        console.print(table)
        
        # Group by sensitivity level
        grouped_results = {}
        for result in results:
            level = result.get('sensitivity_level', 5)
            if level not in grouped_results:
                grouped_results[level] = []
            grouped_results[level].append(result)
        
        # Show sensitivity summary
        sensitivity_table = Table(title="📊 Sensitivity Level Summary")
        sensitivity_table.add_column("Level", style="cyan")
        sensitivity_table.add_column("Description", style="yellow")
        sensitivity_table.add_column("Count", style="green")
        sensitivity_table.add_column("Examples", style="blue")
        
        for level in sorted(grouped_results.keys()):
            count = len(grouped_results[level])
            description = sensitivity_groups.get(level, "Unknown")
            examples = ", ".join([r['path'] for r in grouped_results[level][:3]])
            if len(grouped_results[level]) > 3:
                examples += f" (+{len(grouped_results[level]) - 3} more)"
            
            sensitivity_table.add_row(str(level), description, str(count), examples)
        
        console.print(sensitivity_table)

async def scan_hidden_files_for_crawler(base_url: str, wordlist_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Scan for hidden files for use in the crawler.
    
    Args:
        base_url: Base URL to scan
        wordlist_path: Path to custom wordlist
        
    Returns:
        List of discovered hidden files
    """
    async with HiddenFileScanner(base_url, wordlist_path) as scanner:
        results = await scanner.scan_hidden_files()
        scanner.display_results(results)
        return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python hidden_file_scanner.py <base_url> [wordlist_path]")
        sys.exit(1)
    
    base_url = sys.argv[1]
    wordlist_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    asyncio.run(scan_hidden_files_for_crawler(base_url, wordlist_path)) 