# Juniper SRX Session Analyzer

Analyze Juniper SRX session table dumps with optional top talkers and conversation analysis.

## Features

- **Session Parsing**: Converts raw SRX session table output to structured CSV format
- **Extensive Format Support**: Parse detailed output from `show security flow session extensive`
- **IPv4 & IPv6 Support**: Handles both IPv4 and compressed IPv6 address formats
- **IP Prefix Filtering**: Filter sessions by source/destination IP prefix (CIDR notation)
- **Service Name Mapping**: Automatically maps protocol + port to IANA standard and Juniper application names
- **Top Talkers Analysis**: Identify top bandwidth consumers by source and destination IP
- **Conversation Analysis**: Display top communication flows (source to destination pairs)
- **Flexible Output**: Export to CSV, analyze via stdout, or both

## Requirements

- Python 3.6+
- pkl (Pickle Language) - install via Homebrew: `brew install pkl`

## Installation

1. Clone or download the repository
2. Ensure pkl is installed: `which pkl`
3. No additional Python dependencies required (uses standard library only)

## Usage

### Basic Analysis (CSV Export)

```bash
# Analyze session dump and create timestamped CSV
python srx_session_analyzer.py vpn-sessions.txt

# Analyze with custom output filename
python srx_session_analyzer.py vpn-sessions.txt output.csv
```

### Top Talkers Analysis

```bash
# Display top 10 talkers (no CSV created)
python srx_session_analyzer.py vpn-sessions.txt -T

# Display top 20 talkers
python srx_session_analyzer.py vpn-sessions.txt -T -n 20

# Display top talkers AND create CSV
python srx_session_analyzer.py vpn-sessions.txt output.csv -T -n 15
```

### Conversation Analysis

```bash
# Display top 10 conversations (no CSV created)
python srx_session_analyzer.py vpn-sessions.txt -C

# Display top 20 conversations
python srx_session_analyzer.py vpn-sessions.txt -C -n 20

# Display both talkers and conversations (no CSV)
python srx_session_analyzer.py vpn-sessions.txt -T -C
```

### Combined Analysis

```bash
# Show top 15 talkers and conversations, plus write CSV
python srx_session_analyzer.py vpn-sessions.txt output.csv -T -C -n 15
```

### Extensive Format Parsing

```bash
# Parse extensive format output from SRX
python srx_session_analyzer.py sessions-extensive.txt -E

# Extensive format with top talkers
python srx_session_analyzer.py sessions-extensive.txt -E -T -n 15
```

### IP Prefix Filtering

```bash
# Filter by IP prefix (matches source OR destination)
python srx_session_analyzer.py vpn-sessions.txt -P 10.150.73.0/24

# Filter by prefix, only match source IPs
python srx_session_analyzer.py vpn-sessions.txt -P 10.150.73.0/24 -s

# Filter by prefix, only match destination IPs
python srx_session_analyzer.py vpn-sessions.txt -P 10.150.73.0/24 -d

# Combine prefix filter with top talkers
python srx_session_analyzer.py vpn-sessions.txt -P 10.150.0.0/16 -T -n 10
```

## Command-Line Options

```
positional arguments:
  input_file                    SRX session output file (required)
  output_file                   Output CSV file (optional)

optional arguments:
  -E, --extensive               Parse extensive format output
  -T, --top-talkers             Display top talkers by bandwidth
  -C, --conversations           Display top conversations (source → destination)
  -n, --limit N                 Number of top items to display (default: 10)
  -P, --prefix PREFIX           Filter by IP prefix (CIDR notation)
  -s, --source                  With -P, only match source IPs
  -d, --destination             With -P, only match destination IPs
  -h, --help                    Show help message
```

## Output

### CSV Format

The CSV output contains the following fields:

**Session Metadata**: `session_id`, `policy_name`, `policy_id`, `state`, `timeout`

**Protocol Info**: `protocol`, `service_name`

**Ingress Flow**: `in_src_ip`, `in_src_port`, `in_dst_ip`, `in_dst_port`, `in_interface`, `in_pkts`, `in_bytes`

**Egress Flow**: `out_src_ip`, `out_src_port`, `out_dst_ip`, `out_dst_port`, `out_interface`, `out_pkts`, `out_bytes`

**Other**: `resource_info`

### Top Talkers Output

```
============================================================
Top 10 Talkers - Source IPs (Data Sent)
============================================================
10.1.2.100                               5000000000 bytes (4.66 GB)
192.168.1.50                             3000000000 bytes (2.79 GB)
...
```

### Top Conversations Output

```
============================================================
Top 10 Conversations (Source → Destination)
============================================================
Source IP                       Destination IP                        Bytes          GB
---------------------------------------------
10.1.2.100                      172.16.0.10                      5000000000      4.66
192.168.1.50                    8.8.8.8                          3000000000      2.79
...
```

## Service Mapping

The parser uses two service definition files:

- **juniper_services.pkl**: Juniper SRX default applications (checked first for priority)
- **iana_services.pkl**: IANA standard service names (fallback)

Service lookups follow this priority:
1. Juniper application name (protocol + port match)
2. IANA service name (protocol + port match)
3. Protocol name (fallback)

Port ranges are supported (e.g., `5190-5193` for AOL).

## Input Format

The parser expects SRX session table output with this structure:

```
Session ID: 967, Policy name: policy-name/1, Timeout: 60, Session State: Valid
In: 10.76.8.99/41641 --> 64.180.20.73/443;tcp, If: irb.1, Pkts: 9, Bytes: 152
Out: 10.76.8.99/41641 --> 64.180.20.73/443;tcp, If: irb.1, Pkts: 10, Bytes: 1024
Resource information: resource-data
```

## Examples

### Example 1: Quick Analysis
```bash
python srx_session_analyzer.py sessions.txt -T -n 5
```
Shows the top 5 bandwidth talkers without creating a CSV file.

### Example 2: Full Report
```bash
python srx_session_analyzer.py sessions.txt report.csv -T -C -n 20
```
Creates a CSV file and displays top 20 talkers and conversations.

### Example 3: Network Forensics
```bash
python srx_session_analyzer.py suspicious.txt -C -n 50
```
Display top 50 communication flows for forensic investigation.

## Troubleshooting

**Error: pkl not found**
- Install pkl: `brew install pkl`
- Verify installation: `which pkl`

**Missing service names in output**
- Service definitions are loaded from PKL files via `pkl eval -f json`
- Ensure `services/juniper_services.pkl` and `services/iana_services.pkl` exist
- If pkl fails, service lookups fall back to protocol names

**No sessions parsed**
- Verify input file format matches SRX session table output
- Check that sessions include both `In:` and `Out:` flow lines

## Project Structure

```
juniper-srx-session-analyzer/
├── README.md
├── AGENTS.md
├── srx_session_analyzer.py
└── services/
    ├── juniper_services.pkl
    └── iana_services.pkl
```

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]
