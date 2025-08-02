#!/usr/bin/env python3
"""
Enhanced demonstration script for the web crawler.
Shows all new features including subdomain enumeration, endpoint guessing, and JavaScript analysis.
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

async def enhanced_demo():
    """Demonstrate all enhanced features of the crawler."""
    
    console.print(Panel(
        "🚀 Enhanced Web Crawler Demo\n"
        "Testing with httpbin.org (a safe test site)\n"
        "All new features enabled!",
        style="blue"
    ))
    
    # Create configuration with all new features enabled
    config = CrawlConfig(
        base_url="https://httpbin.org",
        max_depth=2,
        max_pages=10,
        delay=0.5,
        concurrent_requests=3,
        respect_robots=True,
        use_playwright=False,  # Use requests for faster demo
        headless=True,
        
        # Enable all new features
        enable_subdomain_enumeration=True,
        enable_endpoint_guessing=True,
        enable_hidden_file_scanning=True,
        enable_js_analysis=True,
        subdomain_enumeration_methods=['dns', 'wordlist']
    )
    
    try:
        async with WebCrawler(config) as crawler:
            console.print("🚀 Starting enhanced crawler...")
            
            # Parse robots.txt
            robots_data = await crawler.parse_robots_txt()
            console.print(f"📋 Robots.txt analysis completed")
            
            # Start crawling with all features
            console.print("🕷️ Crawling pages with enhanced features...")
            report = await crawler.crawl()
            
            # Display enhanced results
            display_enhanced_results(report)
            
            # Save results
            crawler.save_to_json(report, "enhanced_demo_results.json")
            console.print("💾 Enhanced results saved to enhanced_demo_results.json")
            
    except Exception as e:
        console.print(f"❌ Enhanced demo failed: {e}", style="red")

def display_enhanced_results(report):
    """Display enhanced crawling results."""
    
    summary = report['crawl_summary']
    
    # Enhanced summary table
    table = Table(title="🚀 Enhanced Crawling Results")
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
    
    console.print(table)
    
    # Subdomain enumeration results
    if report['subdomain_enumeration']['enabled'] and report['subdomain_enumeration']['subdomains_found']:
        subdomain_table = Table(title="🔍 Subdomain Enumeration Results")
        subdomain_table.add_column("Subdomain", style="yellow")
        subdomain_table.add_column("Type", style="cyan")
        
        for subdomain in report['subdomain_enumeration']['subdomains_found'][:10]:
            subdomain_type = "DNS" if "dns" in subdomain else "Wordlist"
            subdomain_table.add_row(subdomain, subdomain_type)
        
        if len(report['subdomain_enumeration']['subdomains_found']) > 10:
            subdomain_table.add_row(f"... and {len(report['subdomain_enumeration']['subdomains_found']) - 10} more", "")
        
        console.print(subdomain_table)
    
    # Endpoint guessing results
    if report['endpoint_guessing']['enabled'] and report['endpoint_guessing']['endpoints_found']:
        endpoint_table = Table(title="🎯 Endpoint Guessing Results")
        endpoint_table.add_column("Path", style="cyan")
        endpoint_table.add_column("Status", style="green")
        endpoint_table.add_column("Method", style="yellow")
        endpoint_table.add_column("Content-Type", style="blue")
        
        for endpoint in report['endpoint_guessing']['endpoints_found'][:10]:
            status_color = "green" if endpoint['status_code'] == 200 else "yellow"
            endpoint_table.add_row(
                endpoint['path'],
                f"[{status_color}]{endpoint['status_code']}[/{status_color}]",
                endpoint['method'],
                endpoint.get('content_type', '')[:30]
            )
        
        if len(report['endpoint_guessing']['endpoints_found']) > 10:
            endpoint_table.add_row(f"... and {len(report['endpoint_guessing']['endpoints_found']) - 10} more", "", "", "")
        
        console.print(endpoint_table)
    
    # JavaScript analysis results
    if report['javascript_analysis']['enabled'] and report['javascript_analysis']['analysis_results']:
        js_table = Table(title="🔍 JavaScript Analysis Results")
        js_table.add_column("Page", style="cyan")
        js_table.add_column("URLs Found", style="green")
        js_table.add_column("API Endpoints", style="yellow")
        js_table.add_column("AJAX Calls", style="blue")
        
        for page_url, analysis in report['javascript_analysis']['analysis_results'].items():
            js_table.add_row(
                page_url.split('/')[-1] or page_url,
                str(len(analysis.get('urls', []))),
                str(len(analysis.get('api_endpoints', []))),
                str(len(analysis.get('ajax_calls', [])))
            )
        
        console.print(js_table)
    
    # Forms by method
    if report['forms']['by_method']:
        forms_table = Table(title="📝 Forms Discovered")
        forms_table.add_column("Method", style="cyan")
        forms_table.add_column("Count", style="green")
        
        for method, forms in report['forms']['by_method'].items():
            forms_table.add_row(method.upper(), str(len(forms)))
        
        console.print(forms_table)
    
    # API endpoints by type
    if report['api_endpoints']['by_type']:
        endpoints_table = Table(title="🔗 API Endpoints by Type")
        endpoints_table.add_column("Type", style="cyan")
        endpoints_table.add_column("Count", style="green")
        
        for endpoint_type, endpoints in report['api_endpoints']['by_type'].items():
            endpoints_table.add_row(endpoint_type.title(), str(len(endpoints)))
        
        console.print(endpoints_table)

def show_enhanced_features():
    """Show the enhanced features of the crawler."""
    
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
        "⚙️ Configurable settings",
        "🔍 Subdomain enumeration (DNS + wordlist)",
        "🎯 Endpoint guessing with wordlists",
        "🔍 Advanced JavaScript analysis",
        "📡 AJAX call detection (fetch, XMLHttpRequest)",
        "🌐 WebSocket URL extraction",
        "📄 Dynamic URL construction analysis"
    ]
    
    console.print(Panel(
        "\n".join(features),
        title="✨ Enhanced Features",
        style="green"
    ))

def show_usage_examples():
    """Show usage examples for the new features."""
    
    console.print(Panel(
        "📚 Enhanced Usage Examples",
        style="blue"
    ))
    
    examples = [
        {
            "title": "Basic Enhanced Crawling",
            "command": "python crawler.py https://example.com --enable-subdomain-enumeration --enable-endpoint-guessing",
            "description": "Crawl with all new features enabled"
        },
        {
            "title": "Subdomain Enumeration Only",
            "command": "python crawler.py https://example.com --enable-subdomain-enumeration",
            "description": "Only run subdomain enumeration"
        },
        {
            "title": "Endpoint Guessing Only",
            "command": "python crawler.py https://example.com --enable-endpoint-guessing",
            "description": "Only run endpoint guessing"
        },
        {
            "title": "Custom Wordlists",
            "command": "python crawler.py https://example.com --enable-subdomain-enumeration --subdomain-wordlist custom.txt",
            "description": "Use custom subdomain wordlist"
        },
        {
            "title": "Custom Endpoint Wordlist",
            "command": "python crawler.py https://example.com --enable-endpoint-guessing --endpoint-wordlist api_endpoints.txt",
            "description": "Use custom endpoint wordlist"
        },
        {
            "title": "Disable JavaScript Analysis",
            "command": "python crawler.py https://example.com --disable-js-analysis",
            "description": "Skip JavaScript analysis for faster crawling"
        }
    ]
    
    for example in examples:
        console.print(f"\n🔹 {example['title']}")
        console.print(f"   Command: {example['command']}")
        console.print(f"   Description: {example['description']}")

async def main():
    """Main enhanced demo function."""
    
    console.print("🎯 Enhanced Web Crawler Demo")
    console.print("=" * 50)
    
    # Show enhanced features
    show_enhanced_features()
    
    # Show usage examples
    show_usage_examples()
    
    # Run enhanced demo
    await enhanced_demo()
    
    console.print("\n🎉 Enhanced demo completed!")
    console.print("\n💡 To use enhanced features on your own website:")
    console.print("   python crawler.py https://your-website.com --enable-subdomain-enumeration --enable-endpoint-guessing")

if __name__ == "__main__":
    asyncio.run(main()) 