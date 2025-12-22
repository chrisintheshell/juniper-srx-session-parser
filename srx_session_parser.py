import re
import csv
import sys
import os
from datetime import datetime

# Protocol ID to service name mapping
# Based on IANA Service Name and Transport Protocol Port Number Registry
# Source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
PROTOCOL_SERVICES = {
    # Common TCP Services (IANA-based)
    ('tcp', 20): 'ftp-data',
    ('tcp', 21): 'ftp',
    ('tcp', 22): 'ssh',
    ('tcp', 23): 'telnet',
    ('tcp', 25): 'smtp',
    ('tcp', 53): 'dns',
    ('tcp', 80): 'http',
    ('tcp', 110): 'pop3',
    ('tcp', 143): 'imap',
    ('tcp', 389): 'ldap',
    ('tcp', 443): 'https',
    ('tcp', 465): 'smtps',
    ('tcp', 587): 'submission',
    ('tcp', 636): 'ldaps',
    ('tcp', 993): 'imaps',
    ('tcp', 995): 'pop3s',
    ('tcp', 1433): 'ms-sql-s',
    ('tcp', 3306): 'mysql',
    ('tcp', 3389): 'ms-wbt-server',
    ('tcp', 5432): 'postgresql',
    ('tcp', 5900): 'rfb',
    ('tcp', 8080): 'http-alt',
    ('tcp', 8443): 'https-alt',
    
    # Common UDP Services (IANA-based)
    ('udp', 53): 'dns',
    ('udp', 67): 'bootps',
    ('udp', 68): 'bootpc',
    ('udp', 123): 'ntp',
    ('udp', 161): 'snmp',
    ('udp', 162): 'snmptrap',
    ('udp', 389): 'ldap',
    ('udp', 514): 'syslog',
    ('udp', 1194): 'openvpn',
    ('udp', 3478): 'stun',
    ('udp', 5060): 'sip',
    ('udp', 5061): 'sips',
    
    # Protocol-only services
    'ospf': 'ospf',
    'tcp': 'tcp',
    'udp': 'udp',
    'icmp': 'icmp',
    'igmp': 'igmp',
    'gre': 'gre',
}

def get_service_name(protocol, dest_port):
    """
    Determine service name from protocol and destination port.
    
    Args:
        protocol: Protocol name (tcp, udp, ospf, icmp, etc.)
        dest_port: Destination port number (as string or int)
    
    Returns:
        Service name string, or protocol name if no mapping found
    """
    try:
        # Try protocol + port tuple first
        dest_port_int = int(dest_port) if dest_port else None
        if dest_port_int and (protocol, dest_port_int) in PROTOCOL_SERVICES:
            return PROTOCOL_SERVICES[(protocol, dest_port_int)]
        
        # Fall back to protocol-only lookup
        if protocol in PROTOCOL_SERVICES:
            return PROTOCOL_SERVICES[protocol]
    except (ValueError, TypeError):
        pass
    
    # Default: return protocol as fallback
    return protocol

def is_valid_ip_address(ip):
    """
    Validate IPv4 or IPv6 address format.
    
    Supports:
    - IPv4: 192.168.1.1, 10.0.0.1
    - IPv6: 2001:db8::1, fe80::1, ::1 (including compressed formats)
    
    Args:
        ip: IP address string to validate
    
    Returns:
        True if valid IPv4 or IPv6, False otherwise
    """
    # IPv6 pattern (supports compressed format with ::)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::([0-9a-fA-F]{0,4}:)*[0-9a-fA-F]{0,4}$|^[0-9a-fA-F]{0,4}::$'
    
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    if re.match(ipv6_pattern, ip):
        return True
    if re.match(ipv4_pattern, ip):
        return True
    
    return False

def parse_srx_sessions(input_file, output_file):
    """
    Parse Juniper SRX session table output and convert to CSV format.
    
    Supports both IPv4 and IPv6 addresses (including compressed IPv6 formats).
    
    Args:
        input_file: Path to the text file containing SRX session output
        output_file: Path to the output CSV file
    """
    
    sessions = []
    current_session = {}
    
    # IPv6-aware IP address pattern: matches both IPv4 and IPv6
    # IPv4: 192.168.1.1
    # IPv6: 2001:db8::1, fe80::1, ::1 (compressed and full formats)
    ip_pattern = r'([0-9a-fA-F.:]+)'
    
    with open(input_file, 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and header lines
        if not line or line.startswith('node0:') or line.startswith('---'):
            continue
        
        # Match Session ID line
        # Handles multiple formats:
        # Format 1: Session ID: 967, Policy name: self-traffic-policy/1, Timeout: 60, Session State: Valid
        # Format 2: Session ID: 68719476900, Policy name: default-permit/134, State: Active, Timeout: 10, Valid
        session_match = re.match(r'Session ID: (\d+),\s+Policy name: (.+?)/(\d+),\s+(?:Timeout: (\d+),\s+Session State: (\w+)|State: (\w+),\s+Timeout: (\d+))', line)
        if session_match:
            # Save previous session if it exists
            if current_session:
                sessions.append(current_session)
            
            # Extract groups: handle both format variations
            # Format 1 groups: (id, policy_name, policy_id, timeout, state, None, None)
            # Format 2 groups: (id, policy_name, policy_id, None, None, state, timeout)
            session_id = session_match.group(1)
            policy_name = session_match.group(2)
            policy_id = session_match.group(3)
            
            # Groups 4,5 are from Format 1; groups 6,7 are from Format 2
            if session_match.group(4) is not None:  # Format 1
                timeout = session_match.group(4)
                state = session_match.group(5)
            else:  # Format 2
                state = session_match.group(6)
                timeout = session_match.group(7)
            
            # Start new session
            current_session = {
                'session_id': session_id,
                'policy_name': policy_name,
                'policy_id': policy_id,
                'timeout': timeout,
                'state': state,
                'resource_info': '',
                'service_name': ''
            }
            continue
        
        # Match Resource information line (optional)
        resource_match = re.match(r'Resource information : (.+)', line)
        if resource_match and current_session:
            current_session['resource_info'] = resource_match.group(1)
            continue
        
        # Match In (ingress) line
        # Explicit IPv6-aware pattern: handles both IPv4 and IPv6 addresses
        # Example: In: 10.76.8.99/41641 --> 64.180.20.73/443;tcp, If: irb.1, Pkts: 9, Bytes: 152
        # Example: In: 2001:569:be8e:e801::1/49916 --> 2600:1f14:e33:e801::1/443;tcp, If: irb.1, Pkts: 7, Bytes: 1333
        in_match = re.match(r'In:\s+([0-9a-fA-F.:]+)/(\d+)\s+-->\s+([0-9a-fA-F.:]+)/(\d+);(\w+)', line)
        if in_match and current_session:
            in_src_ip = in_match.group(1)
            in_src_port = in_match.group(2)
            in_dst_ip = in_match.group(3)
            in_dst_port = in_match.group(4)
            protocol = in_match.group(5)
            
            # Validate IP addresses
            if is_valid_ip_address(in_src_ip) and is_valid_ip_address(in_dst_ip):
                current_session['in_src_ip'] = in_src_ip
                current_session['in_src_port'] = in_src_port
                current_session['in_dst_ip'] = in_dst_ip
                current_session['in_dst_port'] = in_dst_port
                current_session['protocol'] = protocol
                
                # Extract service name based on protocol and destination port
                current_session['service_name'] = get_service_name(protocol, in_dst_port)
                
                # Extract additional info from the rest of the line
                if_match = re.search(r'If: ([\w.]+)', line)
                pkts_match = re.search(r'Pkts: (\d+)', line)
                bytes_match = re.search(r'Bytes: (\d+)', line)
                
                current_session['in_interface'] = if_match.group(1) if if_match else ''
                current_session['in_pkts'] = pkts_match.group(1) if pkts_match else ''
                current_session['in_bytes'] = bytes_match.group(1) if bytes_match else ''
            continue
        
        # Match Out (egress) line
        # Explicit IPv6-aware pattern: handles both IPv4 and IPv6 addresses
        out_match = re.match(r'Out:\s+([0-9a-fA-F.:]+)/(\d+)\s+-->\s+([0-9a-fA-F.:]+)/(\d+);(\w+)', line)
        if out_match and current_session:
            out_src_ip = out_match.group(1)
            out_src_port = out_match.group(2)
            out_dst_ip = out_match.group(3)
            out_dst_port = out_match.group(4)
            
            # Validate IP addresses
            if is_valid_ip_address(out_src_ip) and is_valid_ip_address(out_dst_ip):
                current_session['out_src_ip'] = out_src_ip
                current_session['out_src_port'] = out_src_port
                current_session['out_dst_ip'] = out_dst_ip
                current_session['out_dst_port'] = out_dst_port
                
                # Extract additional info from the rest of the line
                if_match = re.search(r'If: ([\w.]+)', line)
                pkts_match = re.search(r'Pkts: (\d+)', line)
                bytes_match = re.search(r'Bytes: (\d+)', line)
                
                current_session['out_interface'] = if_match.group(1) if if_match else ''
                current_session['out_pkts'] = pkts_match.group(1) if pkts_match else ''
                current_session['out_bytes'] = bytes_match.group(1) if bytes_match else ''
            continue
    
    # Don't forget the last session
    if current_session:
        sessions.append(current_session)
    
    # Write to CSV
    if sessions:
        fieldnames = [
            'session_id', 'policy_name', 'policy_id', 'state', 'timeout',
            'protocol', 'service_name',
            'in_src_ip', 'in_src_port', 'in_dst_ip', 'in_dst_port',
            'in_interface', 'in_pkts', 'in_bytes',
            'out_src_ip', 'out_src_port', 'out_dst_ip', 'out_dst_port',
            'out_interface', 'out_pkts', 'out_bytes', 'resource_info'
        ]
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for session in sessions:
                # Ensure all fields exist
                for field in fieldnames:
                    if field not in session:
                        session[field] = ''
                writer.writerow(session)
        
        print(f"Successfully parsed {len(sessions)} sessions")
        print(f"CSV file created: {output_file}")
    else:
        print("No sessions found in the input file")

# Usage example
if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python script.py <input_file> [output_file]")
        print("\nExample:")
        print("  python script.py vpn-sessions-to-psg-burnaby.txt")
        print("  python script.py vpn-sessions-to-psg-burnaby.txt custom_output.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    
    # Use custom output filename if provided, otherwise generate timestamped name
    if len(sys.argv) >= 3:
        output_file = sys.argv[2]
    else:
        # Generate output filename based on input filename
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_file = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print("-" * 50)
    
    parse_srx_sessions(input_file, output_file)
