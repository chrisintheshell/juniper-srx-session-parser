# AGENTS.md - SRX Session Analyzer

## Overview
This project contains a Juniper SRX session table analyzer that converts raw SRX session output into structured CSV format and provides bandwidth analysis capabilities.

## Commands

### Analyze Session File
```bash
python srx_session_analyzer.py <input_file> [output_file] [options]
```

Analyze a Juniper SRX session table dump with optional bandwidth analysis.

**Arguments:**
- `input_file` - Path to the text file containing SRX session output (required)
- `output_file` - Path to the output CSV file (optional, auto-generated if not provided)

**Options:**
- `-E, --extensive` - Parse extensive format output (`show security flow session extensive`)
- `-T, --top-talkers` - Display top talkers by bandwidth
- `-C, --conversations` - Display top conversations (source to destination)
- `-n, --limit N` - Number of top talkers/conversations to display (default: 10, use with `-T` or `-C`)

**Output Modes:**
- **Default (no options)**: Creates a CSV file with session data
- **With `-T` only**: Displays top talkers to stdout, no CSV created
- **With `-C` only**: Displays top conversations to stdout, no CSV created
- **With `-T` and/or `-C` and explicit output file**: Displays analysis AND writes CSV

**CSV Output Fields (Standard Format):**
- Session metadata: `session_id`, `policy_name`, `policy_id`, `state`, `timeout`
- Protocol info: `protocol`, `service_name` (IANA standard service names, e.g., https, ssh, dns)
- Ingress: `in_src_ip`, `in_src_port`, `in_dst_ip`, `in_dst_port`, `in_interface`, `in_pkts`, `in_bytes`
- Egress: `out_src_ip`, `out_src_port`, `out_dst_ip`, `out_dst_port`, `out_interface`, `out_pkts`, `out_bytes`
- Other: `resource_info`

**CSV Output Fields (Extensive Format with `-E`):**
- Session metadata: `session_id`, `status`, `state`, `flags`, `policy_name`, `policy_id`
- NAT/App info: `source_nat_pool`, `application`, `dynamic_application`, `encryption`, `url_category`
- Traffic control: `atc_rule_set`, `atc_rule`
- Timing: `max_timeout`, `current_timeout`, `session_state`, `start_time`, `duration`
- Client info: `client_info` (ALG information)
- Protocol info: `protocol`, `service_name`
- Ingress flow: `in_src_ip`, `in_src_port`, `in_dst_ip`, `in_dst_port`, `in_conn_tag`, `in_interface`, `in_session_token`, `in_flag`, `in_route`, `in_gateway`, `in_tunnel_id`, `in_tunnel_type`, `in_port_seq`, `in_fin_seq`, `in_fin_state`, `in_pkts`, `in_bytes`
- Egress flow: `out_src_ip`, `out_src_port`, `out_dst_ip`, `out_dst_port`, `out_conn_tag`, `out_interface`, `out_session_token`, `out_flag`, `out_route`, `out_gateway`, `out_tunnel_id`, `out_tunnel_type`, `out_port_seq`, `out_fin_seq`, `out_fin_state`, `out_pkts`, `out_bytes`

**Examples:**
```bash
# Default: analyze and write CSV
python srx_session_analyzer.py vpn-sessions.txt
python srx_session_analyzer.py vpn-sessions.txt output.csv

# Show top 10 talkers only (no CSV)
python srx_session_analyzer.py vpn-sessions.txt -T

# Show top 20 talkers only
python srx_session_analyzer.py vpn-sessions.txt -T -n 20

# Show top 10 conversations only (no CSV)
python srx_session_analyzer.py vpn-sessions.txt -C

# Show top 15 conversations only
python srx_session_analyzer.py vpn-sessions.txt -C -n 15

# Show both talkers and conversations (no CSV)
python srx_session_analyzer.py vpn-sessions.txt -T -C

# Show top talkers AND write CSV
python srx_session_analyzer.py vpn-sessions.txt output.csv -T -n 15

# Show talkers and conversations AND write CSV
python srx_session_analyzer.py vpn-sessions.txt output.csv -T -C -n 20

# Parse extensive format output
python srx_session_analyzer.py sessions-extensive.txt -E
python srx_session_analyzer.py sessions-extensive.txt output.csv -E

# Parse extensive format with top talkers
python srx_session_analyzer.py sessions-extensive.txt -E -T -n 15
```

## Code Structure

- `analyze_srx_sessions(input_file, output_file, write_csv=True)` - Main analysis function
  - Regex-based line-by-line parsing of SRX session table format (IPv4 and IPv6)
  - Builds session dictionaries with ingress/egress flow information
  - Writes structured CSV output with service name mapping (optional)
  - Returns analyzed sessions list for further analysis

- `analyze_srx_sessions_extensive(input_file, output_file, write_csv=True)` - Extensive format parser
  - Parses output from `show security flow session extensive`
  - Captures all extended fields: NAT pools, applications, tunnels, routing, flags
  - Tracks flow state for ingress/egress with session tokens and FIN states
  - Returns analyzed sessions list compatible with top talkers/conversations analysis

- `get_top_talkers(sessions, limit=10)` - Bandwidth aggregation function
  - Aggregates egress bytes by source IP (data sent) and destination IP (data received)
  - Sorts and returns top N talkers for each direction
  - Returns tuple of (src_talkers, dst_talkers) lists

- `display_top_talkers(sessions, limit=10)` - Top talkers display function
  - Formats and displays top bandwidth users
  - Shows data in bytes and gigabytes for readability
  - Displays both source and destination IP rankings

- `get_top_conversations(sessions, limit=10)` - Conversation aggregation function
  - Aggregates egress bytes by (source IP, destination IP) pairs
  - Sorts and returns top N conversations by bandwidth
  - Returns list of ((src_ip, dst_ip), bytes) tuples

- `display_top_conversations(sessions, limit=10)` - Top conversations display function
  - Formats and displays top bandwidth conversations
  - Shows source → destination pairs with bytes and gigabytes
  - Identifies the actual communication flows between IPs

- `get_service_name(protocol, dest_port)` - Protocol/port to service name lookup
  - Maps protocol + destination port to IANA standard service names
  - Supports TCP, UDP, and protocol-only services (ospf, icmp, etc.)
  - Falls back to protocol name if no mapping found
  - Based on IANA Service Name and Transport Protocol Port Number Registry

- `is_valid_ip_address(ip)` - IP address validation
  - Validates both IPv4 and IPv6 address formats
  - Supports IPv6 compressed notation (e.g., `::1`, `2001:db8::1`)

## Input Format
Parser expects SRX session table output with the following structure:
- Session headers: `Session ID: X, Policy name: NAME/ID, Timeout: N, Session State: STATE`
- Ingress lines: `In: SRC_IP/PORT --> DST_IP/PORT;PROTOCOL, If: IFACE, Pkts: N, Bytes: N`
- Egress lines: `Out: SRC_IP/PORT --> DST_IP/PORT;PROTOCOL, If: IFACE, Pkts: N, Bytes: N`
- Optional: `Resource information: ...`

## Features

- **IPv4 and IPv6 Support**: Handles both IPv4 and compressed IPv6 address formats
- **IANA Service Name Mapping**: Automatically maps protocol + destination port to IANA standard service names (e.g., tcp/443 → https)
- **IP Validation**: Validates IP addresses before including in output
- **Flexible Output**: Generates timestamped CSV files or custom output filenames
- **Top Talkers Analysis**: Identifies and displays top bandwidth consumers by source and destination IP
- **Configurable Output**: Switch between CSV export and stdout analysis modes
