#!/bin/bash

# Bug Bounty Automation Script v4 - Enhanced with Skip and Timeout features

# Define colors
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
RED='\e[31m'
NC='\e[0m' # No Color

# Function to run a tool with a skip option (Ctrl+C)
run_tool() (
    echo -e "${GREEN}[+] Running: $@${NC}"
    echo -e "${YELLOW}Press Ctrl+C to skip...${NC}"
    trap 'echo -e "\n${RED}Skipping...${NC}"; exit' SIGINT
    "$@"
)

# Usage: ./bug_bounty_automation.sh <target_domain>

# Check if a target domain is provided
if [ -z "$1" ]; then
    echo -e "${RED}Usage: ./bug_bounty_automation.sh <target_domain>${NC}"
    exit 1
fi

TARGET=$1

# Create a directory for the target
if [ ! -d "$TARGET" ]; then
    mkdir $TARGET
    echo -e "${GREEN}[+] Created directory: $TARGET${NC}"
else
    echo -e "${YELLOW}[!] Directory $TARGET already exists. Using existing directory.${NC}"
fi

# --- Subdomain Enumeration ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting Subdomain Enumeration Phase...${NC}"
echo -e "${YELLOW}This phase discovers subdomains using various passive techniques.${NC}"
echo -e "${BLUE}==================================================${NC}"

if [ ! -s "$TARGET/all_subs.txt" ]; then
    run_tool subfinder -d $TARGET -o $TARGET/subfinder.txt
    run_tool assetfinder --subs-only $TARGET > $TARGET/assetfinder.txt
    run_tool findomain -t $TARGET -u $TARGET/findomain.txt

    echo -e "${GREEN}[+] Subdomain enumeration complete. Results saved to $TARGET/subfinder.txt, $TARGET/assetfinder.txt, $TARGET/findomain.txt${NC}"
else
    echo -e "${YELLOW}[!] Subdomain enumeration already completed (found $TARGET/all_subs.txt). Skipping.${NC}"
fi

# --- Combine and Resolve Subdomains ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting Subdomain Combination and Resolution Phase...${NC}"
echo -e "${YELLOW}This phase combines all found subdomains and resolves them to identify live hosts.${NC}"
echo -e "${BLUE}==================================================${NC}"

if [ ! -s "$TARGET/live_hosts.txt" ]; then
    echo -e "${GREEN}[+] Combining all discovered subdomains into a single list: $TARGET/all_subs.txt${NC}"
    cat $TARGET/subfinder.txt $TARGET/assetfinder.txt $TARGET/findomain.txt | sort -u > $TARGET/all_subs.txt

    echo -e "${GREEN}[+] Resolving live hosts from the combined subdomain list using dnsx. This filters out inactive subdomains.${NC}"
    cat $TARGET/all_subs.txt | run_tool dnsx -silent > $TARGET/live_hosts.txt

    echo -e "${GREEN}[+] Subdomain resolution complete. Live hosts saved to $TARGET/live_hosts.txt${NC}"
else
    echo -e "${YELLOW}[!] Subdomain resolution already completed (found $TARGET/live_hosts.txt). Skipping.${NC}"
fi

# --- Port Scanning and Service Discovery ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting Port Scanning and Service Discovery Phase...${NC}"
echo -e "${YELLOW}This phase identifies open ports and services on the live hosts.${NC}"
echo -e "${BLUE}==================================================${NC}"

if [ ! -s "$TARGET/naabu.txt" ]; then
    echo -e "${GREEN}[+] Running naabu to identify open ports on live hosts. This helps in finding active services quickly.${NC}"
    run_tool naabu -l $TARGET/live_hosts.txt -o $TARGET/naabu.txt

    echo -e "${GREEN}[+] Naabu scan complete. Open ports saved to $TARGET/naabu.txt${NC}"
else
    echo -e "${YELLOW}[!] Port scanning already completed (found $TARGET/naabu.txt). Skipping.${NC}"
fi

# --- HTTP/HTTPS Server Discovery ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting HTTP/HTTPS Server Discovery Phase...${NC}"
echo -e "${YELLOW}This phase probes for active web servers on the discovered open ports.${NC}"
echo -e "${BLUE}==================================================${NC}"

if [ ! -s "$TARGET/live_http_hosts.txt" ]; then
    echo -e "${GREEN}[+] Using httpx to probe for active HTTP/HTTPS services on discovered open ports. This confirms web server presence.${NC}"
    cat $TARGET/naabu.txt | run_tool httpx -silent -o $TARGET/live_http_hosts.txt

    echo -e "${GREEN}[+] HTTP/HTTPS server discovery complete. Live HTTP/HTTPS hosts saved to $TARGET/live_http_hosts.txt${NC}"
else
    echo -e "${YELLOW}[!] HTTP/HTTPS server discovery already completed (found $TARGET/live_http_hosts.txt). Skipping.${NC}"
fi

# --- Web Crawling and URL Discovery ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting Web Crawling and URL Discovery Phase...${NC}"
echo -e "${YELLOW}This phase extracts URLs from various sources for deeper analysis.${NC}"
echo -e "${BLUE}==================================================${NC}"

if [ ! -s "$TARGET/all_urls.txt" ]; then
    run_tool katana -l $TARGET/live_http_hosts.txt -o $TARGET/katana.txt
    cat $TARGET/live_http_hosts.txt | run_tool gau --threads 5 > $TARGET/gau.txt
    cat $TARGET/live_http_hosts.txt | run_tool waybackurls > $TARGET/wayback.txt
    run_tool hakcrawler -subs -url $TARGET -depth 2 -output $TARGET/hakcrawler.txt

    echo -e "${GREEN}[+] Combining all discovered URLs into a single list: $TARGET/all_urls.txt${NC}"
    cat $TARGET/katana.txt $TARGET/gau.txt $TARGET/wayback.txt $TARGET/hakcrawler.txt | sort -u > $TARGET/all_urls.txt
else
    echo -e "${YELLOW}[!] URL discovery already completed (found $TARGET/all_urls.txt). Skipping.${NC}"
fi

# --- Directory and File Enumeration ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting Directory and File Enumeration Phase (Gobuster)...${NC}"
echo -e "${YELLOW}This phase brute-forces common directories and files on the target web server.${NC}"
echo -e "${BLUE}==================================================${NC}"

if [ ! -s "$TARGET/gobuster.txt" ]; then
    echo -e "${GREEN}[+] Running gobuster for brute-forcing directories and files using the common.txt wordlist. This helps discover hidden paths.${NC}"
    run_tool gobuster dir -e -u $TARGET -w /usr/share/wordlists/dirb/common.txt -o $TARGET/gobuster.txt
    
    echo -e "${GREEN}[+] Directory and file enumeration complete. Results saved to $TARGET/gobuster.txt${NC}"
else
    echo -e "${YELLOW}[!] Directory enumeration already completed (found $TARGET/gobuster.txt). Skipping.${NC}"
fi

# --- Parameter Discovery ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting Parameter Discovery Phase...${NC}"
echo -e "${YELLOW}This phase identifies hidden or interesting parameters in the discovered URLs.${NC}"
echo -e "${BLUE}==================================================${NC}"

if [ ! -s "$TARGET/arjun_params.txt" ] || [ ! -s "$TARGET/paramfinder.txt" ] || [ ! -s "$TARGET/secretfinder.txt" ]; then
    echo -e "${GREEN}[+] Running arjun to find hidden HTTP parameters in discovered URLs. This can reveal new attack vectors.${NC}"
    run_tool arjun -i $TARGET/all_urls.txt -o $TARGET/arjun_params.txt

    echo -e "${GREEN}[+] Running paramfinder to identify more parameters. This tool helps in finding request parameters.${NC}"
    run_tool paramfinder -l $TARGET/all_urls.txt -o $TARGET/paramfinder.txt

    echo -e "${GREEN}[+] Running secretfinder to identify sensitive information (secrets) in discovered URLs, including JavaScript files.${NC}"
    run_tool secretfinder -i $TARGET/all_urls.txt -o $TARGET/secretfinder.txt

    echo -e "${GREEN}[+] Parameter discovery complete. Results saved to $TARGET/arjun_params.txt, $TARGET/paramfinder.txt and $TARGET/secretfinder.txt${NC}"
else
    echo -e "${YELLOW}[!] Parameter discovery already completed (found $TARGET/arjun_params.txt, $TARGET/paramfinder.txt, $TARTGET/secretfinder.txt). Skipping.${NC}"
fi

# --- Vulnerability Scanning ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting Vulnerability Scanning Phase...${NC}"
echo -e "${YELLOW}This phase actively scans for various types of vulnerabilities.${NC}"
echo -e "${BLUE}==================================================${NC}"

# XSS Scanning
if [ ! -s "$TARGET/dalfox.txt" ]; then
    echo -e "${GREEN}[+] Running dalfox for XSS vulnerability scanning. This tool automates XSS payload injection and detection.${NC}"
    run_tool timeout 1800 dalfox file $TARGET/all_urls.txt -o $TARGET/dalfox.txt
else
    echo -e "${YELLOW}[!] XSS scanning already completed (found $TARGET/dalfox.txt). Skipping.${NC}"
fi

# Secrets Scanning (placeholder)
echo -e "${YELLOW}[!] Running gitleaks for secrets scanning (manual step required for git repositories).${NC}"
echo -e "${YELLOW}Note: Gitleaks requires a git repository. You need to manually clone the repositories and run gitleaks against them.${NC}"
# gitleaks --repo-path=<path_to_repo> --report-path=$TARGET/gitleaks.json

# General Vulnerability Scanning
if [ ! -s "$TARGET/nuclei_output.json" ]; then
    echo -e "${GREEN}[+] Running Nuclei scanner with templates from /root/nuclei-templates. This scans for a wide range of vulnerabilities.${NC}"
    run_tool nuclei -l $TARGET/all_urls.txt -t /root/nuclei-templates -o $TARGET/nuclei_output.json
else
    echo -e "${YELLOW}[!] Nuclei scanning already completed (found $TARGET/nuclei_output.json). Skipping.${NC}"
fi

# Web Server Scanning
if [ ! -s "$TARGET/nikto.txt" ]; then
    echo -e "${GREEN}[+] Running Nikto scanner for web server vulnerabilities. Nikto performs comprehensive checks for server misconfigurations and known flaws.${NC}"
    run_tool nikto -h $TARGET/live_http_hosts.txt -o $TARGET/nikto.txt
else
    echo -e "${YELLOW}[!] Nikto scanning already completed (found $TARGET/nikto.txt). Skipping.${NC}"
fi

# Subdomain Takeover
if [ ! -s "$TARGET/subjack_takeover.txt" ] || [ ! -s "$TARGET/subzy_takeover.json" ]; then
    echo -e "${GREEN}[+] Running subjack to check for subdomain takeover vulnerabilities. This identifies dangling DNS records.${NC}"
    run_tool subjack -w $TARGET/live_hosts.txt -t 100 -timeout 30 -o $TARGET/subjack_takeover.txt
    echo -e "${GREEN}[+] Running subzy to check for subdomain takeover vulnerabilities. This is another tool for detecting subdomain takeovers.${NC}"
    cat $TARGET/live_hosts.txt | run_tool subzy --hide_fails > $TARGET/subzy_takeover.json

    echo -e "${GREEN}[+] Subdomain takeover checks complete. Results saved to $TARGET/subjack_takeover.txt and $TARGET/subzy_takeover.json${NC}"
else
    echo -e "${YELLOW}[!] Subdomain takeover checks already completed (found $TARGET/subjack_takeover.txt and $TARGET/subzy_takeover.json). Skipping.${NC}"
fi

echo -e "${GREEN}[+] Vulnerability scanning complete. Results saved to respective files.${NC}"

# --- Visual Reconnaissance ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Starting Visual Reconnaissance Phase (Gowitness)...${NC}"
echo -e "${YELLOW}This phase captures screenshots of live web pages for visual inspection.${NC}"
echo -e "${BLUE}==================================================${NC}"

if [ ! -d "$TARGET/screenshots" ]; then
    echo -e "${GREEN}[+] Taking screenshots of live HTTP/HTTPS hosts using gowitness. Screenshots help in quickly identifying interesting targets.${NC}"
    run_tool gowitness file -f $TARGET/live_http_hosts.txt -P $TARGET/screenshots/

    echo -e "${GREEN}[+] Visual reconnaissance complete. Screenshots saved to $TARGET/screenshots/${NC}"
else
    echo -e "${YELLOW}[!] Visual reconnaissance already completed (found $TARGET/screenshots/ directory). Skipping.${NC}"
fi


# --- Manual Testing Placeholders ---
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Manual Testing Suggestions:${NC}"
echo -e "${YELLOW}These are areas that often require manual investigation.${NC}"
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}- SQL Injection: Use sqlmap -l $TARGET/all_urls.txt --batch --random-agent. This tool automates SQL injection detection.${NC}"
echo -e "${YELLOW}- XSS: Use Ghauri -l $TARGET/all_urls.txt -t 10. This tool can help find XSS vulnerabilities.${NC}"

echo -e "${GREEN}[+] Automation script finished for $TARGET. Review the output files in the '$TARGET' directory for findings.${NC}"
