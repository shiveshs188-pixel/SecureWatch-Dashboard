import csv
import re

# Strict pattern: "2026-06-10 Login Failed 192.168.1.15" or with time "2026-06-10 12:00:00 Login Failed 192.168.1.15"
# Extracts timestamp, action, and IP
LOG_PATTERN = re.compile(
    r'^(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)\s+(.*?)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
)

# Fallback regex patterns to search within unstructured lines
IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
TIMESTAMP_PATTERN = re.compile(r'(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)')

def parse_log_line(line):
    """
    Parses a single text line to extract (timestamp, action, ip_address).
    Returns a tuple, or None if it doesn't match standard log patterns.
    """
    line = line.strip()
    if not line:
        return None
        
    # 1. Try strict parsing pattern
    match = LOG_PATTERN.match(line)
    if match:
        timestamp, action, ip = match.groups()
        return timestamp.strip(), action.strip(), ip.strip()
        
    # 2. Try loose extraction fallback
    ips = IP_PATTERN.findall(line)
    timestamps = TIMESTAMP_PATTERN.findall(line)
    
    if ips and timestamps:
        ip = ips[0]
        timestamp = timestamps[0]
        # Clean the line of ip and timestamp to determine the action
        action_candidate = line.replace(ip, "").replace(timestamp, "").strip()
        action = action_candidate if action_candidate else "Unknown Action"
        return timestamp, action, ip
        
    return None

def parse_csv_content(file_content):
    """
    Parses CSV content, mapping column headers or using column positions.
    Returns a list of (timestamp, action, ip) tuples.
    """
    parsed = []
    lines = file_content.splitlines()
    if not lines:
        return parsed
        
    reader = csv.reader(lines)
    header = next(reader, None)
    if not header:
        return parsed
        
    # Find matching indices for timestamp, action, and IP
    ts_idx, action_idx, ip_idx = None, None, None
    for idx, col in enumerate(header):
        col_lower = col.lower().strip()
        if 'time' in col_lower or 'date' in col_lower:
            ts_idx = idx
        elif 'action' in col_lower or 'event' in col_lower or 'status' in col_lower or 'msg' in col_lower:
            action_idx = idx
        elif 'ip' in col_lower or 'host' in col_lower or 'address' in col_lower:
            ip_idx = idx
            
    # Default fallbacks if headers don't match standard words
    if ts_idx is None:
        ts_idx = 0
    if action_idx is None:
        action_idx = 1
    if ip_idx is None:
        ip_idx = min(2, len(header) - 1) if len(header) > 2 else 1
        
    for row in reader:
        if not row or len(row) <= max(ts_idx, action_idx, ip_idx):
            continue
        timestamp = row[ts_idx].strip()
        action = row[action_idx].strip()
        ip_val = row[ip_idx].strip()
        
        # Verify IP format
        ip_match = IP_PATTERN.search(ip_val)
        if timestamp and action and ip_match:
            parsed.append((timestamp, action, ip_match.group(0)))
            
    return parsed

def parse_file(filename, file_content):
    """
    Routes file content to correct parser based on extension.
    Returns list of (timestamp, action, ip_address) tuples.
    """
    if filename.endswith('.csv'):
        return parse_csv_content(file_content)
    else:
        parsed_logs = []
        for line in file_content.splitlines():
            res = parse_log_line(line)
            if res:
                parsed_logs.append(res)
        return parsed_logs
