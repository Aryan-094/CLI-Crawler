#!/usr/bin/env python3
"""
Subdomain enumeration module for the web crawler.
Integrates with sublist3r, amass, and provides DNS-based enumeration.
"""

import asyncio
import subprocess
import dns.resolver
import dns.reversename
import aiohttp
import re
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

class SubdomainEnumerator:
    """Subdomain enumeration using multiple techniques."""
    
    def __init__(self, domain: str, wordlist_path: Optional[str] = None):
        self.domain = domain
        self.wordlist_path = wordlist_path or self._get_default_wordlist()
        self.discovered_subdomains = set()
        self.enumeration_results = {}
        
    def _get_default_wordlist(self) -> str:
        """Get path to default wordlist."""
        import os
        # Create default wordlist if it doesn't exist
        default_wordlist = "wordlists/subdomains.txt"
        os.makedirs("wordlists", exist_ok=True)
        
        if not os.path.exists(default_wordlist):
            self._create_default_wordlist(default_wordlist)
        
        return default_wordlist
    
    def _create_default_wordlist(self, path: str):
        """Create a default subdomain wordlist."""
        default_subdomains = [
            "www", "mail", "ftp", "admin", "blog", "dev", "test", "staging",
            "api", "cdn", "static", "assets", "img", "images", "media",
            "mobile", "m", "app", "apps", "web", "www2", "ns1", "ns2",
            "dns", "dns1", "dns2", "smtp", "pop", "imap", "webmail",
            "support", "help", "kb", "wiki", "forum", "community",
            "shop", "store", "cart", "checkout", "payment", "billing",
            "secure", "ssl", "vpn", "remote", "ssh", "telnet",
            "monitor", "status", "health", "metrics", "stats",
            "backup", "archive", "old", "legacy", "beta", "alpha",
            "demo", "sandbox", "playground", "lab", "research",
            "corp", "internal", "intranet", "portal", "gateway",
            "proxy", "cache", "loadbalancer", "lb", "router",
            "firewall", "fw", "dmz", "ext", "external", "public"
        ]
        
        with open(path, 'w') as f:
            for subdomain in default_subdomains:
                f.write(f"{subdomain}\n")
        
        console.print(f"✅ Created default wordlist at {path}")
    
    async def enumerate_subdomains(self, methods: List[str] = None) -> Dict[str, Any]:
        """
        Enumerate subdomains using specified methods.
        
        Args:
            methods: List of enumeration methods to use
            
        Returns:
            Dictionary with enumeration results
        """
        if methods is None:
            methods = ['dns', 'wordlist', 'sublist3r', 'amass']
        
        console.print(f"🔍 Enumerating subdomains for {self.domain}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Enumerating subdomains...", total=len(methods))
            
            for method in methods:
                progress.update(task, description=f"Using {method}...")
                
                try:
                    if method == 'dns':
                        await self._dns_enumeration()
                    elif method == 'wordlist':
                        await self._wordlist_enumeration()
                    elif method == 'sublist3r':
                        await self._sublist3r_enumeration()
                    elif method == 'amass':
                        await self._amass_enumeration()
                    
                except Exception as e:
                    console.print(f"❌ {method} enumeration failed: {e}")
                
                progress.advance(task)
        
        return self._compile_results()
    
    async def _dns_enumeration(self):
        """DNS-based subdomain enumeration."""
        try:
            # Common DNS record types to check
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    for answer in answers:
                        if hasattr(answer, 'target'):
                            target = str(answer.target).rstrip('.')
                            if target != self.domain:
                                self.discovered_subdomains.add(target)
                        else:
                            self.discovered_subdomains.add(str(answer))
                except Exception:
                    continue
            
            console.print(f"✅ DNS enumeration found {len(self.discovered_subdomains)} subdomains")
            
        except Exception as e:
            console.print(f"❌ DNS enumeration error: {e}")
    
    async def _wordlist_enumeration(self):
        """Wordlist-based subdomain enumeration."""
        try:
            with open(self.wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            discovered = set()
            
            for subdomain in wordlist:
                full_domain = f"{subdomain}.{self.domain}"
                try:
                    # Try to resolve the subdomain
                    answers = dns.resolver.resolve(full_domain, 'A')
                    if answers:
                        discovered.add(full_domain)
                except Exception:
                    continue
            
            self.discovered_subdomains.update(discovered)
            console.print(f"✅ Wordlist enumeration found {len(discovered)} subdomains")
            
        except Exception as e:
            console.print(f"❌ Wordlist enumeration error: {e}")
    
    async def _sublist3r_enumeration(self):
        """Sublist3r-based subdomain enumeration."""
        try:
            # Check if sublist3r is installed
            result = subprocess.run(['which', 'sublist3r'], 
                                 capture_output=True, text=True)
            
            if result.returncode != 0:
                console.print("⚠️ Sublist3r not found. Skipping sublist3r enumeration.")
                return
            
            # Run sublist3r
            cmd = ['sublist3r', '-d', self.domain, '-o', f"{self.domain}_sublist3r.txt"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Read results
                try:
                    with open(f"{self.domain}_sublist3r.txt", 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                    
                    self.discovered_subdomains.update(subdomains)
                    console.print(f"✅ Sublist3r found {len(subdomains)} subdomains")
                    
                except FileNotFoundError:
                    console.print("⚠️ Sublist3r output file not found")
            else:
                console.print(f"❌ Sublist3r failed: {result.stderr}")
                
        except Exception as e:
            console.print(f"❌ Sublist3r enumeration error: {e}")
    
    async def _amass_enumeration(self):
        """Amass-based subdomain enumeration."""
        try:
            # Check if amass is installed
            result = subprocess.run(['which', 'amass'], 
                                 capture_output=True, text=True)
            
            if result.returncode != 0:
                console.print("⚠️ Amass not found. Skipping amass enumeration.")
                return
            
            # Run amass
            cmd = ['amass', 'enum', '-d', self.domain, '-o', f"{self.domain}_amass.txt"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                # Read results
                try:
                    with open(f"{self.domain}_amass.txt", 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                    
                    self.discovered_subdomains.update(subdomains)
                    console.print(f"✅ Amass found {len(subdomains)} subdomains")
                    
                except FileNotFoundError:
                    console.print("⚠️ Amass output file not found")
            else:
                console.print(f"❌ Amass failed: {result.stderr}")
                
        except Exception as e:
            console.print(f"❌ Amass enumeration error: {e}")
    
    def _compile_results(self) -> Dict[str, Any]:
        """Compile enumeration results."""
        # Convert to list and sort
        subdomains_list = sorted(list(self.discovered_subdomains))
        
        # Group by subdomain level
        subdomain_levels = {}
        for subdomain in subdomains_list:
            parts = subdomain.split('.')
            if len(parts) > 2:
                level = '.'.join(parts[:-2])  # Everything except domain and TLD
                if level not in subdomain_levels:
                    subdomain_levels[level] = []
                subdomain_levels[level].append(subdomain)
        
        return {
            'domain': self.domain,
            'total_subdomains': len(subdomains_list),
            'subdomains': subdomains_list,
            'subdomain_levels': subdomain_levels,
            'methods_used': list(self.enumeration_results.keys())
        }
    
    def display_results(self, results: Dict[str, Any]):
        """Display enumeration results."""
        table = Table(title="🔍 Subdomain Enumeration Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Domain", results['domain'])
        table.add_row("Total Subdomains", str(results['total_subdomains']))
        table.add_row("Methods Used", ", ".join(results['methods_used']))
        
        console.print(table)
        
        if results['subdomains']:
            subdomain_table = Table(title="📋 Discovered Subdomains")
            subdomain_table.add_column("Subdomain", style="yellow")
            subdomain_table.add_column("Level", style="cyan")
            
            for subdomain in results['subdomains'][:20]:  # Show first 20
                level = '.'.join(subdomain.split('.')[:-2]) if len(subdomain.split('.')) > 2 else "root"
                subdomain_table.add_row(subdomain, level)
            
            if len(results['subdomains']) > 20:
                subdomain_table.add_row(f"... and {len(results['subdomains']) - 20} more", "")
            
            console.print(subdomain_table)

async def enumerate_subdomains_for_crawler(domain: str, methods: List[str] = None) -> List[str]:
    """
    Enumerate subdomains for use in the crawler.
    
    Args:
        domain: Domain to enumerate
        methods: Enumeration methods to use
        
    Returns:
        List of discovered subdomains
    """
    enumerator = SubdomainEnumerator(domain)
    results = await enumerator.enumerate_subdomains(methods)
    enumerator.display_results(results)
    
    return results['subdomains']

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python subdomain_enum.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    asyncio.run(enumerate_subdomains_for_crawler(domain)) 