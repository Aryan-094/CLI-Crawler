# Web Crawler for Penetration Testing

A powerful Python-based web crawler designed for security testing on websites where explicit permission has been granted.

## ⚠️ Ethical Warning

**IMPORTANT**: This tool is designed for penetration testing on websites where you have **EXPLICIT PERMISSION** to test. Only use this tool on systems you own or have written authorization to test.

The crawler performs read-only operations and does not attempt any destructive actions or brute-force attacks.

## Features

### 🔍 Comprehensive Crawling
- **Recursive crawling** within the same domain and subdomains (optional)
- **Intelligent depth limiting** to avoid infinite loops
- **Rate limiting** to prevent denial-of-service
- **Configurable concurrent requests** for optimal performance

### 🤖 Robots.txt Handling
- **Parse and log** all robots.txt entries (Disallow, Allow, Crawl-delay)
- **Respect robots.txt** by default for ethical crawling
- **Optional override** to scan disallowed paths for security testing
- **Detailed robots.txt analysis** in reports

### 🌐 Dynamic Content Support
- **JavaScript rendering** using Playwright for SPAs
- **Dynamic form loading** and AJAX request handling
- **Client-side routing** support
- **Headless browser** option for background operation

### 🔍 Comprehensive Data Collection
- **All internal URLs** with parameters
- **Forms** (method, action, fields, input types)
- **Hidden fields** and CSRF tokens
- **API endpoints** from HTML, JS, and network traffic
- **JavaScript files** and external resources
- **Cookies** and response headers
- **Subdomain enumeration** with DNS and wordlist methods
- **Endpoint guessing** with customizable wordlists
- **Hidden file scanning** for sensitive files (.git, .env, backups, etc.)
- **Advanced JavaScript analysis** for fetch(), XMLHttpRequest, and dynamic URLs

### 🧠 Intelligent Crawling Logic
- **Avoid infinite loops** (pagination traps, session tokens)
- **Deduplication** of endpoints and inputs
- **Normalization** of URLs and parameters
- **Smart filtering** by file extensions

### 📊 Structured Output
- **JSON reports** for easy parsing
- **SQLite database** for complex queries
- **Grouped data** by method and parameter types
- **Ready for vulnerability scanners**

### ⚙️ Configuration Options
- **Delay between requests** (throttling)
- **Max depth and page limits**
- **Ignored or focused file extensions**
- **Custom headers and user-agent**
- **Authentication support** (cookies/session injection)

## Installation

### Prerequisites
- Python 3.8+
- pip

## Usage

### Quick Setup

```bash
git clone https://github.com/Aryan-094/CLI-Crawler.git
```

```bash
cd CLI-Crawler
```

```bash
chmod +x install.sh
```
```bash
# This will setup the tool and install all dependencies
sudo ./install.sh
```

If everything went right, then:

```bash
# Activate the virtual environment:
source venv/bin/activate

# Run the test script:
python test_crawler.py

# Start crawling:
python crawler.py https://your-website.com
```

### Basic Usage

```bash
# Crawl a website with default settings
python crawler.py https://example.com

# Crawl with custom settings
python crawler.py https://example.com --max-depth 3 --delay 2.0 --max-pages 500
```

### Advanced Options

```bash
# Override robots.txt restrictions for security testing
python crawler.py https://example.com --override-robots

# Include subdomains in crawling
python crawler.py https://example.com --include-subdomains

# Use requests instead of Playwright (faster, no JS rendering)
python crawler.py https://example.com --no-playwright

# Custom output format
python crawler.py https://example.com --output-format json --output-file my_crawl

# Enable subdomain enumeration
python crawler.py https://example.com --enable-subdomain-enumeration

# Enable endpoint guessing
python crawler.py https://example.com --enable-endpoint-guessing

# Enable hidden file scanning
python crawler.py https://example.com --enable-hidden-file-scanning

# Use custom wordlists
python crawler.py https://example.com --enable-subdomain-enumeration --subdomain-wordlist custom_subdomains.txt
python crawler.py https://example.com --enable-endpoint-guessing --endpoint-wordlist custom_endpoints.txt
python crawler.py https://example.com --enable-hidden-file-scanning --hidden-file-wordlist custom_hidden_files.txt

# Disable JavaScript analysis
python crawler.py https://example.com --disable-js-analysis
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--max-depth` | Maximum crawling depth | 5 |
| `--max-pages` | Maximum pages to crawl | 1000 |
| `--delay` | Delay between requests (seconds) | 1.0 |
| `--concurrent` | Concurrent requests | 5 |
| `--respect-robots` | Respect robots.txt | True |
| `--override-robots` | Override robots.txt restrictions | False |
| `--include-subdomains` | Include subdomains | False |
| `--use-playwright` | Use Playwright for JS rendering | True |
| `--headless` | Run browser in headless mode | True |
| `--output-format` | Output format (json/sqlite/both) | both |
| `--output-file` | Output filename | auto-generated |
| `--enable-subdomain-enumeration` | Enable subdomain enumeration | False |
| `--enable-endpoint-guessing` | Enable endpoint guessing | False |
| `--enable-hidden-file-scanning` | Enable hidden file scanning | False |
| `--disable-js-analysis` | Disable JavaScript analysis | False |
| `--subdomain-wordlist` | Path to subdomain wordlist | Default |
| `--endpoint-wordlist` | Path to endpoint wordlist | Default |
| `--hidden-file-wordlist` | Path to hidden file wordlist | Default |
| `--subdomain-methods` | Subdomain enumeration methods | dns,wordlist |

## Output

The crawler generates comprehensive reports including:

### JSON Report Structure
```json
{
  "crawl_summary": {
    "base_url": "https://example.com",
    "total_pages_crawled": 150,
    "total_forms_found": 25,
    "total_api_endpoints": 45,
    "total_js_files": 30,
    "crawl_depth_reached": 4,
    "robots_txt_data": {...}
  },
  "forms": {
    "all_forms": [...],
    "by_method": {
      "GET": [...],
      "POST": [...]
    }
  },
  "api_endpoints": {
    "all_endpoints": [...],
    "by_type": {
      "api": [...],
      "rest": [...],
      "versioned": [...]
    }
  },
  "javascript_files": [...],
  "cookies": {...},
  "headers": {...},
  "detailed_results": [...]
}
```

### SQLite Database
The crawler creates a SQLite database with tables for:
- `crawl_summary`: Overall crawling statistics
- `forms`: All discovered forms with fields
- `api_endpoints`: API endpoints grouped by type

## Integration with Vulnerability Scanners

The structured output is designed to feed directly into vulnerability scanners:

### OWASP ZAP Integration
```python
import json
from zapv2 import ZAPv2

# Load crawl results
with open('crawl_report.json', 'r') as f:
    crawl_data = json.load(f)

# Initialize ZAP
zap = ZAPv2()

# Add discovered URLs to ZAP
for result in crawl_data['detailed_results']:
    zap.urlopen(result['url'])

# Add forms for testing
for form in crawl_data['forms']['all_forms']:
    if form['method'] == 'POST':
        # Add form to ZAP for testing
        pass
```

### Burp Suite Integration
The JSON output can be imported into Burp Suite for further analysis and testing.

## Troubleshooting

### Common Issues

1. **Playwright Installation**
   ```bash
   # Reinstall Playwright browsers
   playwright install chromium
   ```

2. **Rate Limiting**
   - Increase `--delay` parameter
   - Reduce `--concurrent` requests

3. **Memory Issues**
   - Reduce `--max-pages` limit
   - Use `--no-playwright` for faster crawling

4. **Permission Errors**
   - Ensure you have permission to test the target
   - Check robots.txt compliance

### Logs
The crawler generates detailed logs in `crawler.log` for debugging and analysis.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any website. The authors are not responsible for any misuse of this tool. 
