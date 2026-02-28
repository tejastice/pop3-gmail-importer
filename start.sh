#!/bin/bash
# POP3 to Gmail Importer - macOS/Linux Startup Script

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "POP3 to Gmail Importer v3.0"
echo "========================================="
echo ""

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${RED}Error: .env file not found${NC}"
    echo "Please copy .env.example to .env and configure your settings:"
    echo "  cp .env.example .env"
    exit 1
fi

# Check if credentials.json exists
if [ ! -f "credentials.json" ]; then
    echo -e "${YELLOW}Warning: credentials.json not found${NC}"
    echo "You need to set up Google Cloud OAuth credentials first."
    echo "See README.md for instructions."
    echo ""
fi

# Mac用の仮想環境ディレクトリ
VENV_DIR="venv_mac"

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Virtual environment not found. Creating $VENV_DIR ...${NC}"
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create virtual environment${NC}"
        exit 1
    fi
    echo -e "${GREEN}Virtual environment created${NC}"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Check if requirements are installed
if [ ! -f "$VENV_DIR/.requirements_installed" ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install dependencies${NC}"
        exit 1
    fi
    touch "$VENV_DIR/.requirements_installed"
    echo -e "${GREEN}Dependencies installed${NC}"
fi

echo ""
echo "Starting POP3 to Gmail Importer..."
echo "Press Ctrl+C to stop"
echo ""

# Run the main program
python main.py

# Deactivate virtual environment on exit
deactivate
