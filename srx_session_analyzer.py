import re
import csv
import sys
import os
import json
import subprocess
import argparse
import ipaddress
from datetime import datetime

# Service mappings loaded from PKL files via pkl eval
juniper_services = {}
iana_services = {}

def load_services():
    """
    Load service definitions from PKL files using pkl eval.
    
    Tries to load Juniper services and IANA services.
    Falls back to empty dicts if files not found or pkl not available.
    """
    global juniper_services, iana_services
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    juniper_pkl = os.path.join(script_dir, 'services', 'juniper_services.pkl')
    iana_pkl = os.path.join(script_dir, 'services', 'iana_services.pkl')
    
    # Load Juniper services
    if os.path.exists(juniper_pkl):
        try:
            result = subprocess.run(['pkl', 'eval', '-f', 'json', juniper_pkl], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                juniper_services = json.loads(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    
    # Load IANA services
    if os.path.exists(iana_pkl):
        try:
            result = subprocess.run(['pkl', 'eval', '-f', 'json', iana_pkl], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                iana_services = json.loads(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass

def port_in_range(port, port_spec):
    """
    Check if a port is within a port specification (can be single or range).
    
    Args:
        port: Port number as int
        port_spec: Port specification as string (e.g., "443" or "5190-5193")
    
    Returns:
        True if port matches the specification
    """
    if '-' in port_spec:
        try:
            start, end = port_spec.split('-')
            return int(start) <= port <= int(end)
        except (ValueError, IndexError):
            return False
    else:
        try:
            return port == int(port_spec)
        except ValueError:
            return False

def get_service_name(protocol, dest_port):
    """
    Determine service name from protocol and destination port.
    
    Checks Juniper services first (priority), then falls back to IANA services.
    
    Args:
        protocol: Protocol name (tcp, udp, icmp, etc.)
        dest_port: Destination port number (as string or int)
    
    Returns:
        Service name string, or protocol name if no mapping found
    """
    if not protocol or not dest_port:
        return protocol or 'unknown'
    
    try:
        dest_port_int = int(dest_port)
    except (ValueError, TypeError):
        return protocol
    
    protocol_lower = protocol.lower()
    
    # Check Juniper services first (priority)
    if protocol_lower in juniper_services:
        protocol_map = juniper_services[protocol_lower]
        if isinstance(protocol_map, dict):
            # Check exact port match first
            if str(dest_port_int) in protocol_map:
                return protocol_map[str(dest_port_int)]
            
            # Check port ranges
            for port_spec, service_name in protocol_map.items():
                if port_in_range(dest_port_int, port_spec):
                    return service_name
    
    # Fall back to IANA services
    if protocol_lower in iana_services:
        protocol_map = iana_services[protocol_lower]
        if isinstance(protocol_map, dict):
            # Check exact port match first
            if str(dest_port_int) in protocol_map:
                return protocol_map[str(dest_port_int)]
            
            # Check port ranges
            for port_spec, service_name in protocol_map.items():
                if port_in_range(dest_port_int, port_spec):
                    return service_name
    
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

def ip_in_prefix(ip_str, prefix_str):
    """
    Check if an IP address falls within a given prefix/network.
    
    Args:
        ip_str: IP address string (e.g., '10.150.73.5')
        prefix_str: Network prefix in CIDR notation (e.g., '10.150.73.0/24')
    
    Returns:
        True if the IP is within the prefix, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(prefix_str, strict=False)
        return ip in network
    except ValueError:
        return False

def filter_sessions_by_prefix(sessions, prefix, source_only=False, dest_only=False):
    """
    Filter sessions by IP prefix.
    
    Uses ingress flow IPs (in_src_ip, in_dst_ip) which represent the original
    client and destination IPs before NAT translation.
    
    Args:
        sessions: List of session dictionaries
        prefix: Network prefix in CIDR notation (e.g., '10.150.73.0/24')
        source_only: If True, only match client (source) IPs
        dest_only: If True, only match server (destination) IPs
        
    If both source_only and dest_only are False (or both True), 
    matches sessions where either client OR server IP is in the prefix.
    
    Returns:
        Filtered list of sessions
    """
    filtered = []
    
    # If both are False or both are True, match either source or destination
    match_either = (not source_only and not dest_only) or (source_only and dest_only)
    
    for session in sessions:
        # Use ingress flow IPs (original client → destination, pre-NAT)
        client_ip = session.get('in_src_ip', '')
        server_ip = session.get('in_dst_ip', '')
        
        client_match = client_ip and ip_in_prefix(client_ip, prefix)
        server_match = server_ip and ip_in_prefix(server_ip, prefix)
        
        if match_either:
            if client_match or server_match:
                filtered.append(session)
        elif source_only:
            if client_match:
                filtered.append(session)
        elif dest_only:
            if server_match:
                filtered.append(session)
    
    return filtered

def analyze_srx_sessions(input_file, output_file, write_csv=True):
    """
    Analyze Juniper SRX session table output and convert to CSV format.
    
    Supports both IPv4 and IPv6 addresses (including compressed IPv6 formats).
    
    Args:
        input_file: Path to the text file containing SRX session output
        output_file: Path to the output CSV file
        write_csv: Whether to write the CSV file (default: True)
    
    Returns:
        List of analyzed session dictionaries
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
    
    # Write to CSV if requested
    if write_csv and sessions:
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
    elif sessions:
        print(f"Successfully parsed {len(sessions)} sessions")
    else:
        print("No sessions found in the input file")
    
    return sessions

def write_sessions_csv(sessions, output_file, extensive=False):
    """
    Write sessions to a CSV file.
    
    Args:
        sessions: List of session dictionaries
        output_file: Path to the output CSV file
        extensive: If True, use extensive format fieldnames
    """
    if not sessions:
        print("No sessions to write")
        return
    
    if extensive:
        fieldnames = [
            'session_id', 'status', 'state', 'flags',
            'policy_name', 'policy_id', 'source_nat_pool', 'application',
            'dynamic_application', 'encryption', 'url_category',
            'atc_rule_set', 'atc_rule',
            'max_timeout', 'current_timeout', 'session_state',
            'start_time', 'duration', 'client_info',
            'protocol', 'service_name',
            'in_src_ip', 'in_src_port', 'in_dst_ip', 'in_dst_port',
            'in_conn_tag', 'in_interface', 'in_session_token', 'in_flag',
            'in_route', 'in_gateway', 'in_tunnel_id', 'in_tunnel_type',
            'in_port_seq', 'in_fin_seq', 'in_fin_state', 'in_pkts', 'in_bytes',
            'out_src_ip', 'out_src_port', 'out_dst_ip', 'out_dst_port',
            'out_conn_tag', 'out_interface', 'out_session_token', 'out_flag',
            'out_route', 'out_gateway', 'out_tunnel_id', 'out_tunnel_type',
            'out_port_seq', 'out_fin_seq', 'out_fin_state', 'out_pkts', 'out_bytes'
        ]
    else:
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
            row = {}
            for field in fieldnames:
                row[field] = session.get(field, '')
            writer.writerow(row)
    
    print(f"CSV file created: {output_file}")

def get_top_talkers(sessions, limit=10):
    """
    Aggregate and rank bandwidth usage by source and destination IPs.
    
    Uses ingress flow IPs (in_src_ip, in_dst_ip) to identify the original client
    and destination, since egress IPs may be NAT'd. Sums both ingress and egress
    bytes for total bandwidth per IP.
    
    Args:
        sessions: List of session dictionaries
        limit: Number of top talkers to return
    
    Returns:
        Tuple of (src_talkers, dst_talkers) - each a list of (ip, bytes) tuples
    """
    src_bytes = {}  # source IPs (clients initiating connections)
    dst_bytes = {}  # destination IPs (servers receiving connections)
    
    for session in sessions:
        # Sum both directions for total session bandwidth
        in_bytes = int(session.get('in_bytes', 0) or 0)
        out_bytes = int(session.get('out_bytes', 0) or 0)
        total_bytes = in_bytes + out_bytes
        
        # Use ingress flow IPs (original client → destination, pre-NAT)
        if session.get('in_src_ip'):
            src_ip = session['in_src_ip']
            src_bytes[src_ip] = src_bytes.get(src_ip, 0) + total_bytes
        
        if session.get('in_dst_ip'):
            dst_ip = session['in_dst_ip']
            dst_bytes[dst_ip] = dst_bytes.get(dst_ip, 0) + total_bytes
    
    # Sort by bytes descending
    src_talkers = sorted(src_bytes.items(), key=lambda x: x[1], reverse=True)[:limit]
    dst_talkers = sorted(dst_bytes.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    return src_talkers, dst_talkers

def display_top_talkers(sessions, limit=10):
    """Display top bandwidth users."""
    src_talkers, dst_talkers = get_top_talkers(sessions, limit)
    
    print(f"\n{'='*60}")
    print(f"Top {limit} Talkers - Client IPs (Connection Initiators)")
    print(f"{'='*60}")
    for ip, total_bytes in src_talkers:
        gb = total_bytes / (1024**3)
        print(f"{ip:40s} {total_bytes:15,d} bytes ({gb:.2f} GB)")
    
    print(f"\n{'='*60}")
    print(f"Top {limit} Talkers - Server IPs (Connection Destinations)")
    print(f"{'='*60}")
    for ip, total_bytes in dst_talkers:
        gb = total_bytes / (1024**3)
        print(f"{ip:40s} {total_bytes:15,d} bytes ({gb:.2f} GB)")

def get_top_conversations(sessions, limit=10):
    """
    Aggregate and rank bandwidth usage by conversation (src_ip + dst_ip + port + service).
    
    Uses ingress flow IPs (in_src_ip → in_dst_ip) to identify the original client
    and destination, since egress IPs may be NAT'd. Sums both ingress and egress
    bytes for total conversation bandwidth.
    
    Args:
        sessions: List of session dictionaries
        limit: Number of top conversations to return
    
    Returns:
        List of ((src_ip, dst_ip, dst_port, service_name), bytes) tuples sorted by bytes descending
    """
    conversation_bytes = {}
    
    for session in sessions:
        # Sum both directions for total conversation bandwidth
        in_bytes = int(session.get('in_bytes', 0) or 0)
        out_bytes = int(session.get('out_bytes', 0) or 0)
        total_bytes = in_bytes + out_bytes
        
        # Use ingress flow IPs (original client → destination, pre-NAT)
        if session.get('in_src_ip') and session.get('in_dst_ip'):
            src_ip = session['in_src_ip']
            dst_ip = session['in_dst_ip']
            dst_port = session.get('in_dst_port', '') or ''
            service_name = session.get('service_name', '') or 'unknown'
            key = (src_ip, dst_ip, dst_port, service_name)
            conversation_bytes[key] = conversation_bytes.get(key, 0) + total_bytes
    
    # Sort by bytes descending
    conversations = sorted(conversation_bytes.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    return conversations

def display_top_conversations(sessions, limit=10):
    """Display top bandwidth conversations."""
    conversations = get_top_conversations(sessions, limit)
    
    print(f"\n{'='*80}")
    print(f"Top {limit} Conversations (Client → Server)")
    print(f"{'='*80}")
    print(f"{'Client IP':40s} {'Server IP':40s} {'Dst Port':8s} {'Service':20s} {'Bytes':>15s} {'GB':>10s}")
    print(f"{'-'*136}")
    for (src_ip, dst_ip, dst_port, service_name), total_bytes in conversations:
        gb = total_bytes / (1024**3)
        print(f"{src_ip:40s} {dst_ip:40s} {dst_port:8s} {service_name:20s} {total_bytes:15,d} {gb:10.2f}")

def analyze_srx_sessions_extensive(input_file, output_file, write_csv=True):
    """
    Analyze Juniper SRX extensive session table output and convert to CSV format.
    
    Parses the extensive output format from 'show security flow session extensive'.
    Supports both IPv4 and IPv6 addresses (including compressed IPv6 formats).
    
    Args:
        input_file: Path to the text file containing SRX extensive session output
        output_file: Path to the output CSV file
        write_csv: Whether to write the CSV file (default: True)
    
    Returns:
        List of analyzed session dictionaries
    """
    
    sessions = []
    current_session = {}
    current_flow = None  # 'in' or 'out'
    
    with open(input_file, 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and header lines
        if not line or line.startswith('node0:') or line.startswith('---'):
            continue
        
        # Match Session ID line (extensive format)
        # Session ID: 4294967448, Status: Normal, State: Active
        session_match = re.match(r'Session ID: (\d+),\s+Status: (\w+),\s+State: (\w+)', line)
        if session_match:
            # Save previous session if it exists
            if current_session:
                sessions.append(current_session)
            
            current_session = {
                'session_id': session_match.group(1),
                'status': session_match.group(2),
                'state': session_match.group(3),
                'service_name': ''
            }
            current_flow = None
            continue
        
        # Match Flags line
        flags_match = re.match(r'Flags: (.+)', line)
        if flags_match and current_session:
            current_session['flags'] = flags_match.group(1)
            continue
        
        # Match Policy name line
        policy_match = re.match(r'Policy name: (.+?)/(\d+)', line)
        if policy_match and current_session:
            current_session['policy_name'] = policy_match.group(1)
            current_session['policy_id'] = policy_match.group(2)
            continue
        
        # Match Source NAT pool and Application line
        nat_app_match = re.match(r'Source NAT pool: ([^,]+)(?:,\s+Application: (.+))?', line)
        if nat_app_match and current_session:
            current_session['source_nat_pool'] = nat_app_match.group(1)
            if nat_app_match.group(2):
                current_session['application'] = nat_app_match.group(2)
            continue
        
        # Match Dynamic application line
        dyn_app_match = re.match(r'Dynamic application: (.+?)(?:,|$)', line)
        if dyn_app_match and current_session:
            current_session['dynamic_application'] = dyn_app_match.group(1).strip()
            continue
        
        # Match Encryption line
        enc_match = re.match(r'Encryption:\s+(.+)', line)
        if enc_match and current_session:
            current_session['encryption'] = enc_match.group(1).strip()
            continue
        
        # Match Url-category line
        url_match = re.match(r'Url-category:\s+(.+)', line)
        if url_match and current_session:
            current_session['url_category'] = url_match.group(1).strip()
            continue
        
        # Match Application traffic control rule-set line
        atc_match = re.match(r'Application traffic control rule-set: ([^,]+),\s+Rule: (.+)', line)
        if atc_match and current_session:
            current_session['atc_rule_set'] = atc_match.group(1)
            current_session['atc_rule'] = atc_match.group(2)
            continue
        
        # Match Maximum timeout, Current timeout line
        timeout_match = re.match(r'Maximum timeout: (\d+),\s+Current timeout: (\d+)', line)
        if timeout_match and current_session:
            current_session['max_timeout'] = timeout_match.group(1)
            current_session['current_timeout'] = timeout_match.group(2)
            continue
        
        # Match Session State line
        state_match = re.match(r'Session State: (\w+)', line)
        if state_match and current_session:
            current_session['session_state'] = state_match.group(1)
            continue
        
        # Match Start time, Duration line
        time_match = re.match(r'Start time: (\d+),\s+Duration: (\d+)', line)
        if time_match and current_session:
            current_session['start_time'] = time_match.group(1)
            current_session['duration'] = time_match.group(2)
            continue
        
        # Match Client/ALG info line
        client_match = re.match(r'Client: (.+)', line)
        if client_match and current_session:
            current_session['client_info'] = client_match.group(1)
            continue
        
        # Match In (ingress) flow start line
        # In: 10.8.77.18/56591 --> 172.16.6.1/53;udp,
        in_match = re.match(r'In:\s+([0-9a-fA-F.:]+)/(\d+)\s+-->\s+([0-9a-fA-F.:]+)/(\d+);(\w+)', line)
        if in_match and current_session:
            in_src_ip = in_match.group(1)
            in_dst_ip = in_match.group(3)
            
            if is_valid_ip_address(in_src_ip) and is_valid_ip_address(in_dst_ip):
                current_session['in_src_ip'] = in_src_ip
                current_session['in_src_port'] = in_match.group(2)
                current_session['in_dst_ip'] = in_dst_ip
                current_session['in_dst_port'] = in_match.group(4)
                current_session['protocol'] = in_match.group(5)
                current_session['service_name'] = get_service_name(
                    in_match.group(5), in_match.group(4))
                current_flow = 'in'
            continue
        
        # Match Out (egress) flow start line
        out_match = re.match(r'Out:\s+([0-9a-fA-F.:]+)/(\d+)\s+-->\s+([0-9a-fA-F.:]+)/(\d+);(\w+)', line)
        if out_match and current_session:
            out_src_ip = out_match.group(1)
            out_dst_ip = out_match.group(3)
            
            if is_valid_ip_address(out_src_ip) and is_valid_ip_address(out_dst_ip):
                current_session['out_src_ip'] = out_src_ip
                current_session['out_src_port'] = out_match.group(2)
                current_session['out_dst_ip'] = out_dst_ip
                current_session['out_dst_port'] = out_match.group(4)
                current_flow = 'out'
            continue
        
        # Match Conn Tag, Interface line (for current flow)
        conn_match = re.match(r'Conn Tag: ([^,]+),\s+Interface: (.+?)(?:,|$)', line)
        if conn_match and current_session and current_flow:
            prefix = current_flow
            current_session[f'{prefix}_conn_tag'] = conn_match.group(1)
            current_session[f'{prefix}_interface'] = conn_match.group(2).strip()
            continue
        
        # Match Session token, Flag line
        token_match = re.match(r'Session token: ([^,]+),\s+Flag: (.+?)(?:,|$)', line)
        if token_match and current_session and current_flow:
            prefix = current_flow
            current_session[f'{prefix}_session_token'] = token_match.group(1)
            current_session[f'{prefix}_flag'] = token_match.group(2).strip()
            continue
        
        # Match Route, Gateway, Tunnel ID, Tunnel type line
        route_match = re.match(r'Route: ([^,]+),\s+Gateway: ([^,]+),\s+Tunnel ID: ([^,]+),\s+Tunnel type: (.+)', line)
        if route_match and current_session and current_flow:
            prefix = current_flow
            current_session[f'{prefix}_route'] = route_match.group(1)
            current_session[f'{prefix}_gateway'] = route_match.group(2)
            current_session[f'{prefix}_tunnel_id'] = route_match.group(3)
            current_session[f'{prefix}_tunnel_type'] = route_match.group(4)
            continue
        
        # Match Port sequence, FIN sequence line
        seq_match = re.match(r'Port sequence: ([^,]+),\s+FIN sequence: ([^,]+)', line)
        if seq_match and current_session and current_flow:
            prefix = current_flow
            current_session[f'{prefix}_port_seq'] = seq_match.group(1)
            current_session[f'{prefix}_fin_seq'] = seq_match.group(2).strip()
            continue
        
        # Match FIN state line
        fin_match = re.match(r'FIN state: (.+?)(?:,|$)', line)
        if fin_match and current_session and current_flow:
            prefix = current_flow
            current_session[f'{prefix}_fin_state'] = fin_match.group(1).strip()
            continue
        
        # Match Pkts, Bytes line
        pkts_match = re.match(r'Pkts: (\d+),\s+Bytes: (\d+)', line)
        if pkts_match and current_session and current_flow:
            prefix = current_flow
            current_session[f'{prefix}_pkts'] = pkts_match.group(1)
            current_session[f'{prefix}_bytes'] = pkts_match.group(2)
            continue
    
    # Don't forget the last session
    if current_session:
        sessions.append(current_session)
    
    # Write to CSV if requested
    if write_csv and sessions:
        fieldnames = [
            'session_id', 'status', 'state', 'flags',
            'policy_name', 'policy_id', 'source_nat_pool', 'application',
            'dynamic_application', 'encryption', 'url_category',
            'atc_rule_set', 'atc_rule',
            'max_timeout', 'current_timeout', 'session_state',
            'start_time', 'duration', 'client_info',
            'protocol', 'service_name',
            'in_src_ip', 'in_src_port', 'in_dst_ip', 'in_dst_port',
            'in_conn_tag', 'in_interface', 'in_session_token', 'in_flag',
            'in_route', 'in_gateway', 'in_tunnel_id', 'in_tunnel_type',
            'in_port_seq', 'in_fin_seq', 'in_fin_state', 'in_pkts', 'in_bytes',
            'out_src_ip', 'out_src_port', 'out_dst_ip', 'out_dst_port',
            'out_conn_tag', 'out_interface', 'out_session_token', 'out_flag',
            'out_route', 'out_gateway', 'out_tunnel_id', 'out_tunnel_type',
            'out_port_seq', 'out_fin_seq', 'out_fin_state', 'out_pkts', 'out_bytes'
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
        
        print(f"Successfully parsed {len(sessions)} sessions (extensive format)")
        print(f"CSV file created: {output_file}")
    elif sessions:
        print(f"Successfully parsed {len(sessions)} sessions (extensive format)")
    else:
        print("No sessions found in the input file")
    
    return sessions

# Usage example
if __name__ == "__main__":
    # Load service definitions from PKL files
    load_services()
    
    parser = argparse.ArgumentParser(description='Parse Juniper SRX session tables')
    parser.add_argument('input_file', help='SRX session output file')
    parser.add_argument('output_file', nargs='?', help='Output CSV file (optional)')
    parser.add_argument('-E', '--extensive', action='store_true',
                        help='Parse extensive format output (show security flow session extensive)')
    parser.add_argument('-T', '--top-talkers', action='store_true', 
                        help='Display top talkers by bandwidth')
    parser.add_argument('-C', '--conversations', action='store_true', 
                        help='Display top conversations (source to destination)')
    parser.add_argument('-n', '--limit', type=int, default=10, 
                        metavar='N', help='Number of top talkers/conversations to display (default: 10)')
    parser.add_argument('-P', '--prefix', metavar='PREFIX',
                        help='Filter sessions by IP prefix (CIDR notation, e.g., 10.150.73.0/24)')
    parser.add_argument('-s', '--source', action='store_true',
                        help='With -P, only match source IPs')
    parser.add_argument('-d', '--destination', action='store_true',
                        help='With -P, only match destination IPs')
    
    args = parser.parse_args()
    
    # Validate -s and -d require -P
    if (args.source or args.destination) and not args.prefix:
        parser.error('-s and -d options require -P/--prefix')
    
    # Check if input file exists
    if not os.path.exists(args.input_file):
        print(f"Error: Input file '{args.input_file}' not found")
        sys.exit(1)
    
    # Determine if we should write CSV
    # Write CSV if: no -T/-C options, OR explicit output_file provided
    write_csv = (not args.top_talkers and not args.conversations) or args.output_file is not None
    
    # Generate output filename only if we'll write CSV
    if write_csv and args.output_file is None:
        base_name = os.path.splitext(os.path.basename(args.input_file))[0]
        output_file = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    else:
        output_file = args.output_file
    
    if write_csv:
        print(f"Input file: {args.input_file}")
        print(f"Output file: {output_file}")
        print("-" * 50)
    
    # Parse sessions (without writing CSV - we'll write after filtering)
    if args.extensive:
        sessions = analyze_srx_sessions_extensive(args.input_file, None, write_csv=False)
    else:
        sessions = analyze_srx_sessions(args.input_file, None, write_csv=False)
    
    # Apply prefix filter if specified
    if args.prefix:
        original_count = len(sessions)
        sessions = filter_sessions_by_prefix(
            sessions, args.prefix, 
            source_only=args.source, 
            dest_only=args.destination
        )
        filter_type = "source" if args.source and not args.destination else \
                      "destination" if args.destination and not args.source else \
                      "source or destination"
        print(f"Filtered by prefix {args.prefix} ({filter_type}): {len(sessions)} of {original_count} sessions")
    
    # Write CSV after filtering
    if write_csv:
        write_sessions_csv(sessions, output_file, extensive=args.extensive)
    
    # Display top talkers if requested
    if args.top_talkers:
        display_top_talkers(sessions, args.limit)
    
    # Display top conversations if requested
    if args.conversations:
        display_top_conversations(sessions, args.limit)
