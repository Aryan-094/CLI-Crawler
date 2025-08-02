#!/usr/bin/env python3
"""
Demonstration script for the Ethical Web Crawler.
Shows basic usage and features.
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.append(str(Path(__file__).parent))

from crawler import WebCrawler, CrawlConfig
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

async def demo_crawler():
    """Demonstrate the crawler with a simple example."""
    
    console.print(Panel(
        "🔍 Ethical Web Crawler Demo\n"
        "Testing with httpbin.org (a safe test site)",
        style="blue"
    ))
    
    # Create configuration for demo
    config = CrawlConfig(
        base_url="https://httpbin.org",
        max_depth=2,
        max_pages=5,
        delay=1.0,
        concurrent_requests=2,
        respect_robots=True,
        use_playwright=False,  # Use requests for faster demo
        headless=True
    )
    
    try:
        async with WebCrawler(config) as crawler:
            console.print("🚀 Starting crawler...")
            
            # Parse robots.txt
            robots_data = await crawler.parse_robots_txt()
            console.print(f"📋 Robots.txt analysis completed")
            
            # Start crawling
            console.print("🕷️ Crawling pages...")
            report = await crawler.crawl()
            
            # Display results
            display_results(report)
            
            # Save results
            crawler.save_to_json(report, "demo_results.json")
            console.print("💾 Results saved to demo_results.json")
            
    except Exception as e:
        console.print(f"❌ Demo failed: {e}", style="red")

def display_results(report):
    """Display crawling results in a nice format."""
    
    summary = report['crawl_summary']
    
    # Summary table
    table = Table(title="📊 Crawling Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Base URL", summary['base_url'])
    table.add_row("Pages Crawled", str(summary['total_pages_crawled']))
    table.add_row("Forms Found", str(summary['total_forms_found']))
    table.add_row("API Endpoints", str(summary['total_api_endpoints']))
    table.add_row("JS Files", str(summary['total_js_files']))
    table.add_row("Max Depth Reached", str(summary['crawl_depth_reached']))
    
    console.print(table)
    
    # Show forms if any found
    if report['forms']['all_forms']:
        forms_table = Table(title="📝 Forms Discovered")
        forms_table.add_column("Method", style="cyan")
        forms_table.add_column("Action", style="yellow")
        forms_table.add_column("Fields", style="green")
        
        for form in report['forms']['all_forms']:
            fields_count = len(form['fields'])
            forms_table.add_row(
                form['method'],
                form['action'] or "Same page",
                f"{fields_count} fields"
            )
        
        console.print(forms_table)
    
    # Show API endpoints if any found
    if report['api_endpoints']['all_endpoints']:
        endpoints_table = Table(title="🔗 API Endpoints")
        endpoints_table.add_column("Type", style="cyan")
        endpoints_table.add_column("Count", style="green")
        
        for endpoint_type, endpoints in report['api_endpoints']['by_type'].items():
            endpoints_table.add_row(endpoint_type.title(), str(len(endpoints)))
        
        console.print(endpoints_table)

def show_features():
    """Show the main features of the crawler."""
    
    features = [
        "🔍 Recursive crawling with depth control",
        "🤖 Robots.txt parsing and respect",
        "🌐 JavaScript rendering with Playwright",
        "📝 Form discovery and analysis",
        "🔗 API endpoint detection",
        "🍪 Cookie and header collection",
        "🛡️ Hidden field and CSRF token detection",
        "⚡ Rate limiting and concurrent requests",
        "📊 JSON and SQLite output",
        "⚙️ Configurable settings"
    ]
    
    console.print(Panel(
        "\n".join(features),
        title="✨ Key Features",
        style="green"
    ))

def show_ethical_warning():
    """Display ethical usage warning."""
    
    console.print(Panel(
        "⚠️  ETHICAL USAGE WARNING ⚠️\n\n"
        "This tool is designed for penetration testing on websites where you have "
        "EXPLICIT PERMISSION to test.\n\n"
        "✅ Permitted use cases:\n"
        "   • Testing your own websites\n"
        "   • Testing with written permission\n"
        "   • Educational purposes\n\n"
        "❌ Prohibited use cases:\n"
        "   • Testing without permission\n"
        "   • Attempting destructive actions\n"
        "   • Brute-force or DoS attacks",
        style="red"
    ))

async def main():
    """Main demo function."""
    
    console.print("🎯 Ethical Web Crawler Demo")
    console.print("=" * 50)
    
    # Show features
    show_features()
    
    # Show ethical warning
    show_ethical_warning()
    
    # Run demo
    await demo_crawler()
    
    console.print("\n🎉 Demo completed!")
    console.print("\n💡 To use on your own website:")
    console.print("   python crawler.py https://your-website.com")

if __name__ == "__main__":
    asyncio.run(main()) 