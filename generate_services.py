#!/usr/bin/env python3
"""
Generate service PKL files for SRX Session Analyzer.

This utility generates PKL service definition files from various sources:
- Juniper defaults: From 'show configuration groups junos-defaults applications'
- Custom services: From 'show configuration applications'
- IANA services: Downloaded from official IANA CSV registries

Usage:
    python generate_services.py juniper --input junos-defaults-apps.txt
    python generate_services.py custom --input site-apps.txt
    python generate_services.py iana
    python generate_services.py iana --force-download
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime


# IANA CSV URLs
IANA_SERVICES_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
IANA_PROTOCOLS_URL = "https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv"


def escape_pkl_string(s):
    """Escape special characters for PKL string literals."""
    return s.replace('\\', '\\\\').replace('"', '\\"')


def validate_pkl(pkl_file):
    """Validate PKL file using pkl eval."""
    try:
        result = subprocess.run(
            ['pkl', 'eval', '-f', 'json', pkl_file],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def write_pkl_file(output_path, module_name, header_comments, mappings):
    """
    Write a PKL file with the given mappings.
    
    Args:
        output_path: Path to output PKL file
        module_name: PKL module name (e.g., 'com.juniper.srx.services')
        header_comments: List of comment lines for the header
        mappings: Dict of {mapping_name: {port: service_name, ...}, ...}
    """
    lines = []
    
    # Header comments
    for comment in header_comments:
        lines.append(f'// {comment}')
    lines.append('')
    lines.append(f'module {module_name}')
    lines.append('')
    
    # Write each mapping
    for mapping_name, mapping_dict in mappings.items():
        if not mapping_dict:
            continue
            
        # Determine comment based on mapping type
        entry_count = len(mapping_dict)
        lines.append(f'// {mapping_name.upper()} Services ({entry_count} entries)')
        lines.append(f'{mapping_name}: Mapping<String, String> = new {{')
        
        # Sort by port number (handle ranges by taking first number)
        def sort_key(item):
            port = item[0].split('-')[0]
            return int(port) if port.isdigit() else 999999
        
        for port, service in sorted(mapping_dict.items(), key=sort_key):
            escaped_service = escape_pkl_string(service)
            lines.append(f'  ["{port}"] = "{escaped_service}"')
        
        lines.append('}')
        lines.append('')
    
    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


def parse_junos_applications(input_file, app_prefix=''):
    """
    Parse Junos application configuration.
    
    Handles both simple format and term-based format:
    - Simple: protocol tcp; destination-port 22;
    - Term-based: term X protocol tcp destination-port 80;
    
    Args:
        input_file: Path to Junos config file
        app_prefix: Expected prefix for application names (e.g., 'junos-' or 'svc-')
    
    Returns:
        Tuple of (tcp_services, udp_services) dicts
    """
    tcp_services = {}
    udp_services = {}
    
    with open(input_file, 'r') as f:
        content = f.read()
    
    # Find all application blocks
    # Match both 'application NAME {' and 'application NAME {' with junos- or svc- prefix
    app_pattern = r'application\s+([^\s{]+)\s*\{([^}]+)\}'
    matches = re.findall(app_pattern, content, re.DOTALL)
    
    for app_name, app_body in matches:
        # Skip application-set definitions (they don't have protocol/port)
        if 'application ' in app_body and 'protocol' not in app_body:
            continue
        
        # Check for term-based definitions: term X protocol PROTO destination-port PORT
        term_pattern = r'term\s+\S+\s+protocol\s+(tcp|udp)\s+destination-port\s+(\d+(?:-\d+)?)'
        term_matches = re.findall(term_pattern, app_body)
        
        # Check for simple definitions: protocol tcp; destination-port PORT;
        simple_proto_match = re.search(r'protocol\s+(tcp|udp)\s*;', app_body)
        simple_port_match = re.search(r'destination-port\s+(\d+(?:-\d+)?)\s*;', app_body)
        
        if term_matches:
            for proto, port in term_matches:
                if proto == 'tcp':
                    if port not in tcp_services:
                        tcp_services[port] = app_name
                elif proto == 'udp':
                    if port not in udp_services:
                        udp_services[port] = app_name
        elif simple_proto_match and simple_port_match:
            proto = simple_proto_match.group(1)
            port = simple_port_match.group(1)
            if proto == 'tcp':
                if port not in tcp_services:
                    tcp_services[port] = app_name
            elif proto == 'udp':
                if port not in udp_services:
                    udp_services[port] = app_name
    
    return tcp_services, udp_services


def generate_juniper_services(input_file, output_file):
    """Generate juniper_services.pkl from Junos defaults configuration."""
    print(f"Parsing Juniper defaults from {input_file}...")
    
    tcp_services, udp_services = parse_junos_applications(input_file)
    
    print(f"Found {len(tcp_services)} TCP and {len(udp_services)} UDP services")
    
    header_comments = [
        "Juniper SRX Default Applications",
        "Generated from: show configuration groups junos-defaults applications",
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Format: protocol -> port/port-range -> application name",
    ]
    
    mappings = {
        'tcp': tcp_services,
        'udp': udp_services,
    }
    
    write_pkl_file(output_file, 'com.juniper.srx.services', header_comments, mappings)
    print(f"Generated {output_file}")
    
    # Validate
    if validate_pkl(output_file):
        print("Validated with pkl eval ✓")
    else:
        print("Warning: Could not validate with pkl eval")
    
    total = len(tcp_services) + len(udp_services)
    print(f"Total entries: {total}")
    return True


def generate_custom_services(input_file, output_file):
    """Generate custom_services.pkl from site applications configuration."""
    print(f"Parsing custom applications from {input_file}...")
    
    tcp_services, udp_services = parse_junos_applications(input_file)
    
    print(f"Found {len(tcp_services)} TCP and {len(udp_services)} UDP services")
    
    header_comments = [
        "Custom Services - Site-Specific Applications",
        "Generated from: show configuration applications",
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Priority: After Juniper services, before IANA services",
        "Format: protocol -> port/port-range -> service name",
    ]
    
    mappings = {
        'tcp': tcp_services,
        'udp': udp_services,
    }
    
    write_pkl_file(output_file, 'com.custom.services', header_comments, mappings)
    print(f"Generated {output_file}")
    
    # Validate
    if validate_pkl(output_file):
        print("Validated with pkl eval ✓")
    else:
        print("Warning: Could not validate with pkl eval")
    
    total = len(tcp_services) + len(udp_services)
    print(f"Total entries: {total}")
    return True


def download_file(url, output_path, force=False):
    """Download a file from URL if not cached or force is True."""
    if os.path.exists(output_path) and not force:
        print(f"Using cached {os.path.basename(output_path)}")
        return True
    
    print(f"Downloading {os.path.basename(output_path)}...")
    try:
        urllib.request.urlretrieve(url, output_path)
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False


def generate_iana_services(output_file, force_download=False):
    """Generate iana_services.pkl from IANA CSV registries."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cache_dir = os.path.join(script_dir, '.cache')
    os.makedirs(cache_dir, exist_ok=True)
    
    services_csv = os.path.join(cache_dir, 'service-names-port-numbers.csv')
    protocols_csv = os.path.join(cache_dir, 'protocol-numbers-1.csv')
    
    # Download files
    if not download_file(IANA_SERVICES_URL, services_csv, force_download):
        return False
    if not download_file(IANA_PROTOCOLS_URL, protocols_csv, force_download):
        return False
    
    print("Parsing IANA services...")
    
    # Parse service-names-port-numbers.csv
    tcp_services = {}
    udp_services = {}
    sctp_services = {}
    dccp_services = {}
    
    with open(services_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            service_name = row.get('Service Name', '').strip()
            port = row.get('Port Number', '').strip()
            protocol = row.get('Transport Protocol', '').strip().lower()
            
            # Skip entries without service name or port
            if not service_name or not port:
                continue
            
            # Skip reserved/unassigned
            if service_name.lower() in ('reserved', 'unassigned'):
                continue
            
            if protocol == 'tcp':
                if port not in tcp_services:
                    tcp_services[port] = service_name
            elif protocol == 'udp':
                if port not in udp_services:
                    udp_services[port] = service_name
            elif protocol == 'sctp':
                if port not in sctp_services:
                    sctp_services[port] = service_name
            elif protocol == 'dccp':
                if port not in dccp_services:
                    dccp_services[port] = service_name
    
    # Parse protocol-numbers-1.csv
    protocols = {}
    
    with open(protocols_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            decimal = row.get('Decimal', '').strip()
            keyword = row.get('Keyword', '').strip()
            
            if not decimal or not keyword:
                continue
            
            # Skip ranges like "146-252"
            if '-' in decimal:
                continue
            
            keyword_lower = keyword.lower()
            
            # Skip deprecated entries
            if 'deprecated' in keyword_lower:
                continue
            
            protocols[decimal] = keyword_lower
    
    print(f"Found {len(tcp_services)} TCP, {len(udp_services)} UDP, "
          f"{len(sctp_services)} SCTP, {len(dccp_services)} DCCP services")
    print(f"Found {len(protocols)} protocol numbers")
    
    header_comments = [
        "IANA Standard Services - Complete Registry",
        "Generated from IANA Service Name and Transport Protocol Port Number Registry",
        f"Source: {IANA_SERVICES_URL}",
        f"Source: {IANA_PROTOCOLS_URL}",
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Format: protocol -> port/port-range -> service name",
    ]
    
    mappings = {
        'tcp': tcp_services,
        'udp': udp_services,
        'sctp': sctp_services,
        'dccp': dccp_services,
        'protocols': protocols,
    }
    
    write_pkl_file(output_file, 'com.iana.services', header_comments, mappings)
    print(f"Generated {output_file}")
    
    # Validate
    if validate_pkl(output_file):
        print("Validated with pkl eval ✓")
    else:
        print("Warning: Could not validate with pkl eval")
    
    total = len(tcp_services) + len(udp_services) + len(sctp_services) + len(dccp_services) + len(protocols)
    print(f"Total entries: {total}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Generate service PKL files for SRX Session Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s juniper --input /var/tmp/junos-defaults-apps.txt
  %(prog)s custom --input /var/tmp/site-apps.txt
  %(prog)s iana
  %(prog)s iana --force-download

To collect Juniper defaults from SRX:
  show configuration groups junos-defaults applications | save /var/tmp/junos-defaults-apps.txt

To collect custom applications from SRX:
  show configuration applications | save /var/tmp/site-apps.txt
"""
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Generation commands')
    
    # Juniper subcommand
    juniper_parser = subparsers.add_parser(
        'juniper',
        help='Generate juniper_services.pkl from Junos defaults config'
    )
    juniper_parser.add_argument(
        '--input', '-i',
        required=True,
        help='Path to Junos defaults config file (from: show configuration groups junos-defaults applications)'
    )
    juniper_parser.add_argument(
        '--output', '-o',
        default=None,
        help='Output PKL file path (default: services/juniper_services.pkl)'
    )
    
    # Custom subcommand
    custom_parser = subparsers.add_parser(
        'custom',
        help='Generate custom_services.pkl from site applications config'
    )
    custom_parser.add_argument(
        '--input', '-i',
        required=True,
        help='Path to site applications config file (from: show configuration applications)'
    )
    custom_parser.add_argument(
        '--output', '-o',
        default=None,
        help='Output PKL file path (default: services/custom_services.pkl)'
    )
    
    # IANA subcommand
    iana_parser = subparsers.add_parser(
        'iana',
        help='Generate iana_services.pkl from IANA CSV registries'
    )
    iana_parser.add_argument(
        '--output', '-o',
        default=None,
        help='Output PKL file path (default: services/iana_services.pkl)'
    )
    iana_parser.add_argument(
        '--force-download', '-f',
        action='store_true',
        help='Force download of IANA CSV files (ignore cache)'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Determine script directory for default output paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    services_dir = os.path.join(script_dir, 'services')
    
    if args.command == 'juniper':
        if not os.path.exists(args.input):
            print(f"Error: Input file not found: {args.input}")
            sys.exit(1)
        output = args.output or os.path.join(services_dir, 'juniper_services.pkl')
        success = generate_juniper_services(args.input, output)
        
    elif args.command == 'custom':
        if not os.path.exists(args.input):
            print(f"Error: Input file not found: {args.input}")
            sys.exit(1)
        output = args.output or os.path.join(services_dir, 'custom_services.pkl')
        success = generate_custom_services(args.input, output)
        
    elif args.command == 'iana':
        output = args.output or os.path.join(services_dir, 'iana_services.pkl')
        success = generate_iana_services(output, args.force_download)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
