#!/usr/bin/env python3
"""
Configuration module for the web crawler.
Allows users to customize crawler behavior through config files.
"""

import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Set, Optional, Any

@dataclass
class CrawlerConfig:
    """Configuration class for the web crawler."""
    
    # Basic crawling settings
    max_depth: int = 5
    max_pages: int = 1000
    delay: float = 1.0
    concurrent_requests: int = 5
    timeout: int = 30
    
    # Domain settings
    include_subdomains: bool = False
    respect_robots: bool = True
    override_robots: bool = False
    
    # Browser settings
    use_playwright: bool = True
    headless: bool = True
    user_agent: Optional[str] = None
    
    # File filtering
    ignored_extensions: Set[str] = None
    focused_extensions: Set[str] = None
    
    # Authentication
    auth_cookies: Dict[str, str] = None
    auth_headers: Dict[str, str] = None
    custom_headers: Dict[str, str] = None
    
    # Output settings
    output_format: str = 'both'  # 'json', 'sqlite', 'both'
    output_file: Optional[str] = None
    
    def __post_init__(self):
        """Initialize default values for sets and dicts."""
        if self.ignored_extensions is None:
            self.ignored_extensions = {
                '.pdf', '.zip', '.exe', '.dmg', '.mp4', '.mp3', '.avi',
                '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg'
            }
        
        if self.focused_extensions is None:
            self.focused_extensions = {
                '.html', '.htm', '.php', '.asp', '.aspx', '.jsp',
                '.js', '.css', '.xml', '.json'
            }
        
        if self.auth_cookies is None:
            self.auth_cookies = {}
        
        if self.auth_headers is None:
            self.auth_headers = {}
        
        if self.custom_headers is None:
            self.custom_headers = {}
    
    @classmethod
    def from_file(cls, config_path: str) -> 'CrawlerConfig':
        """Load configuration from a JSON file."""
        config_path = Path(config_path)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        # Convert sets from lists
        if 'ignored_extensions' in config_data:
            config_data['ignored_extensions'] = set(config_data['ignored_extensions'])
        if 'focused_extensions' in config_data:
            config_data['focused_extensions'] = set(config_data['focused_extensions'])
        
        return cls(**config_data)
    
    def save_to_file(self, config_path: str):
        """Save configuration to a JSON file."""
        config_data = asdict(self)
        
        # Convert sets to lists for JSON serialization
        config_data['ignored_extensions'] = list(config_data['ignored_extensions'])
        config_data['focused_extensions'] = list(config_data['focused_extensions'])
        
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
    
    @classmethod
    def create_default_config(cls, config_path: str = 'crawler_config.json'):
        """Create a default configuration file."""
        config = cls()
        config.save_to_file(config_path)
        return config

def load_config(config_path: Optional[str] = None) -> CrawlerConfig:
    """Load configuration from file or create default."""
    if config_path is None:
        config_path = 'crawler_config.json'
    
    try:
        return CrawlerConfig.from_file(config_path)
    except FileNotFoundError:
        print(f"Configuration file not found: {config_path}")
        print("Creating default configuration file...")
        return CrawlerConfig.create_default_config(config_path)

def create_example_config():
    """Create an example configuration file with comments."""
    example_config = {
        "max_depth": 5,
        "max_pages": 1000,
        "delay": 1.0,
        "concurrent_requests": 5,
        "timeout": 30,
        "include_subdomains": False,
        "respect_robots": True,
        "override_robots": False,
        "use_playwright": True,
        "headless": True,
        "user_agent": None,
        "ignored_extensions": [
            ".pdf", ".zip", ".exe", ".dmg", ".mp4", ".mp3", ".avi",
            ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg"
        ],
        "focused_extensions": [
            ".html", ".htm", ".php", ".asp", ".aspx", ".jsp",
            ".js", ".css", ".xml", ".json"
        ],
        "auth_cookies": {},
        "auth_headers": {},
        "custom_headers": {},
        "output_format": "both",
        "output_file": None
    }
    
    with open('example_config.json', 'w') as f:
        json.dump(example_config, f, indent=2)
    
    print("Example configuration file created: example_config.json")

if __name__ == '__main__':
    create_example_config() 