# AGENTS.md - SRX Session Parser

## Overview
This project contains a Juniper SRX session table parser that converts raw SRX session output into structured CSV format.

## Commands

### Parse Session File
```bash
python srx_session_parser.py <input_file> [output_file]
```

Parse a Juniper SRX session table dump and output to CSV.

**Arguments:**
- `input_file` - Path to the text file containing SRX session output (required)
- `output_file` - Path to the output CSV file (optional, auto-generated if not provided)

**Examples:**
```bash
python srx_session_parser.py vpn-sessions.txt
python srx_session_parser.py vpn-sessions.txt output.csv
```

**Output:** Creates a CSV with the following fields:
- Session metadata: `session_id`, `policy_name`, `policy_id`, `state`, `timeout`
- Protocol info: `protocol`, `service_name` (IANA standard service names, e.g., https, ssh, dns)
- Ingress: `in_src_ip`, `in_src_port`, `in_dst_ip`, `in_dst_port`, `in_interface`, `in_pkts`, `in_bytes`
- Egress: `out_src_ip`, `out_src_port`, `out_dst_ip`, `out_dst_port`, `out_interface`, `out_pkts`, `out_bytes`
- Other: `resource_info`

## Code Structure

- `parse_srx_sessions(input_file, output_file)` - Main parsing function
  - Regex-based line-by-line parsing of SRX session table format (IPv4 and IPv6)
  - Builds session dictionaries with ingress/egress flow information
  - Writes structured CSV output with service name mapping

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
