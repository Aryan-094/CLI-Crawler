#!/usr/bin/env python3
"""
Test script for the web crawler.
Demonstrates basic functionality and provides examples.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.append(str(Path(__file__).parent))

from crawler import WebCrawler, CrawlConfig
from rich.console import Console

console = Console()

async def test_basic_crawling():
    """Test basic crawling functionality."""
    console.print("🧪 Testing Basic Crawling", style="blue")
    
    # Create a simple configuration for testing
    config = CrawlConfig(
        base_url="https://httpbin.org",
        max_depth=2,
        max_pages=10,
        delay=0.5,
        concurrent_requests=3,
        respect_robots=True,
        use_playwright=False,  # Use requests for faster testing
        headless=True
    )
    
    try:
        async with WebCrawler(config) as crawler:
            # Parse robots.txt
            robots_data = await crawler.parse_robots_txt()
            console.print(f"✅ Robots.txt parsed: {len(robots_data.get('disallowed_paths', []))} disallowed paths")
            
            # Start crawling
            report = await crawler.crawl()
            
            # Display results
            console.print(f"✅ Crawling completed!")
            console.print(f"📊 Pages crawled: {report['crawl_summary']['total_pages_crawled']}")
            console.print(f"📝 Forms found: {report['crawl_summary']['total_forms_found']}")
            console.print(f"🔗 API endpoints: {report['crawl_summary']['total_api_endpoints']}")
            
            # Save results
            crawler.save_to_json(report, "test_crawl_report.json")
            console.print("💾 Results saved to test_crawl_report.json")
            
    except Exception as e:
        console.print(f"❌ Test failed: {e}", style="red")

async def test_robots_parsing():
    """Test robots.txt parsing functionality."""
    console.print("🤖 Testing Robots.txt Parsing", style="blue")
    
    config = CrawlConfig(
        base_url="https://www.google.com",
        max_depth=1,
        max_pages=1,
        delay=1.0,
        use_playwright=False
    )
    
    try:
        async with WebCrawler(config) as crawler:
            robots_data = await crawler.parse_robots_txt()
            
            console.print("📋 Robots.txt Analysis:")
            console.print(f"  - Disallowed paths: {len(robots_data.get('disallowed_paths', []))}")
            console.print(f"  - Allowed paths: {len(robots_data.get('allowed_paths', []))}")
            console.print(f"  - Crawl delay: {robots_data.get('crawl_delay', 0)}")
            
            if 'error' in robots_data:
                console.print(f"  - Error: {robots_data['error']}")
            
    except Exception as e:
        console.print(f"❌ Robots test failed: {e}", style="red")

async def test_config_loading():
    """Test configuration loading from file."""
    console.print("⚙️ Testing Configuration Loading", style="blue")
    
    try:
        from config import CrawlerConfig
        
        # Create a test configuration
        config = CrawlerConfig()
        config.save_to_file("test_config.json")
        console.print("✅ Test configuration saved")
        
        # Load the configuration
        loaded_config = CrawlerConfig.from_file("test_config.json")
        console.print("✅ Configuration loaded successfully")
        
        # Clean up
        Path("test_config.json").unlink()
        console.print("🧹 Test configuration cleaned up")
        
    except Exception as e:
        console.print(f"❌ Config test failed: {e}", style="red")

async def test_utils():
    """Test utility functions."""
    console.print("🔧 Testing Utility Functions", style="blue")
    
    try:
        from utils import normalize_url, is_valid_url, extract_domain
        
        # Test URL normalization
        test_url = "https://example.com/path?b=2&a=1#fragment"
        normalized = normalize_url(test_url)
        console.print(f"✅ URL normalization: {test_url} -> {normalized}")
        
        # Test URL validation
        valid = is_valid_url("https://example.com", "https://example.com")
        console.print(f"✅ URL validation: {valid}")
        
        # Test domain extraction
        domain = extract_domain("https://sub.example.com/path")
        console.print(f"✅ Domain extraction: {domain}")
        
    except Exception as e:
        console.print(f"❌ Utils test failed: {e}", style="red")

def demonstrate_usage():
    """Demonstrate how to use the crawler."""
    console.print("📚 Usage Examples", style="green")
    
    examples = [
        {
            "title": "Basic Crawling",
            "command": "python crawler.py https://example.com",
            "description": "Crawl a website with default settings"
        },
        {
            "title": "Custom Settings",
            "command": "python crawler.py https://example.com --max-depth 3 --delay 2.0",
            "description": "Crawl with custom depth and delay"
        },
        {
            "title": "Override Robots.txt",
            "command": "python crawler.py https://example.com --override-robots",
            "description": "Crawl even disallowed paths (for security testing)"
        },
        {
            "title": "Include Subdomains",
            "command": "python crawler.py https://example.com --include-subdomains",
            "description": "Crawl subdomains as well"
        },
        {
            "title": "JSON Output Only",
            "command": "python crawler.py https://example.com --output-format json",
            "description": "Generate only JSON report"
        }
    ]
    
    for example in examples:
        console.print(f"\n🔹 {example['title']}")
        console.print(f"   Command: {example['command']}")
        console.print(f"   Description: {example['description']}")

async def main():
    """Run all tests."""
    console.print("🚀 Starting Web Crawler Tests", style="green")
    
    # Run tests
    await test_config_loading()
    await test_utils()
    await test_robots_parsing()
    await test_basic_crawling()
    
    # Show usage examples
    demonstrate_usage()
    
    console.print("\n✅ All tests completed!", style="green")
    console.print("\n💡 To run the crawler on your own website:")
    console.print("   python crawler.py https://your-website.com")

if __name__ == "__main__":
    asyncio.run(main()) 