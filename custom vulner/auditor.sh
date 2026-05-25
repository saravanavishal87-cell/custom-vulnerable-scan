#!/usr/bin/env bash

# Vulcan Security Auditor - Linux Launcher Script
# Usage: ./auditor.sh <target-url> [additional-arguments]

# Ensure Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "\e[31m[!] Error: Python 3 is not installed or not in PATH.\e[0m"
    echo -e "\e[33m[*] Please install it using: sudo apt install python3\e[0m"
    exit 1
fi

# Ensure requirements are satisfied
if [ -f "requirements.txt" ]; then
    # Silently check if rich is installed, if not, offer to install it
    python3 -c "import rich, requests" &> /dev/null
    if [ $? -ne 0 ]; then
        echo -e "\e[33m[*] Missing dependencies. Installing requirements...\e[0m"
        pip3 install -r requirements.txt
    fi
fi

# Run the python auditor passing all arguments
python3 auditor.py "$@"
