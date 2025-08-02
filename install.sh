#!/bin/bash

# Ethical Web Crawler Installation Script
# This script sets up the environment for the web crawler

echo "🚀 Installing Ethical Web Crawler for Penetration Testing"
echo "========================================================"

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "✅ Python $python_version found (>= $required_version required)"
else
    echo "❌ Python 3.8+ is required. Found: $python_version"
    echo "Please install Python 3.8 or higher and try again."
    exit 1
fi

# Check if pip is installed
if command -v pip3 &> /dev/null; then
    echo "✅ pip3 found"
else
    echo "❌ pip3 not found. Please install pip and try again."
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

# Install Playwright browsers
echo "🌐 Installing Playwright browsers..."
playwright install chromium

# Create example configuration
echo "⚙️ Creating example configuration..."
python3 config.py

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run the test script: python test_crawler.py"
echo "3. Start crawling: python crawler.py https://your-website.com"
echo ""
echo "⚠️  Remember: Only test websites you have permission to test!"
echo ""
echo "📖 For more information, see README.md" 