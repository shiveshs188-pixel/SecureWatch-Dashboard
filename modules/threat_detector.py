from datetime import datetime
import config
from modules import database_manager

def parse_timestamp(ts_str):
    """Parses a timestamp string into a datetime object with fallback formats."""
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return datetime.now()

def detect_threats(parsed_logs):
    """
    Analyzes the parsed logs, runs threat detection rules,
    saves the logs and generated alerts into the database, and returns analysis stats.
    
    parsed_logs: list of (timestamp, action, ip_address)
    """
    if not parsed_logs:
        return {
            'total_parsed': 0,
            'alerts_created': 0,
            'high_risk_alerts': 0,
            'medium_risk_alerts': 0,
            'low_risk_alerts': 0
        }

    # Fetch existing failed logins from the DB to combine history (makes detection persistent and realistic)
    conn = database_manager.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, ip_address FROM logs WHERE action LIKE '%Failed%'")
    db_failed_logs = cursor.fetchall()
    conn.close()
    
    # Organize existing failed logins by IP address
    ip_history_failed = {}
    for row in db_failed_logs:
        ip = row['ip_address']
        ts = row['timestamp']
        if ip not in ip_history_failed:
            ip_history_failed[ip] = []
        ip_history_failed[ip].append(parse_timestamp(ts))

    # Separate parsed logs by IP for the current file upload
    ip_current_failed = {}
    unique_ips = set()
    latest_timestamp_per_ip = {}
    
    for ts_str, action, ip in parsed_logs:
        unique_ips.add(ip)
        ts_dt = parse_timestamp(ts_str)
        
        # Track the latest timestamp to associate alerts
        if ip not in latest_timestamp_per_ip:
            latest_timestamp_per_ip[ip] = ts_str
        else:
            if ts_dt > parse_timestamp(latest_timestamp_per_ip[ip]):
                latest_timestamp_per_ip[ip] = ts_str
                
        if 'failed' in action.lower():
            if ip not in ip_current_failed:
                ip_current_failed[ip] = []
            ip_current_failed[ip].append(ts_dt)

    alerts_to_create = [] # tuples of (threat_type, ip_address, risk_level, status, created_at)

    # Apply detection rules for each IP in the uploaded file
    for ip in unique_ips:
        alert_time = latest_timestamp_per_ip.get(ip, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        # 1. Unknown IP Detection
        if ip not in config.WHITELISTED_IPS:
            alerts_to_create.append((
                'Suspicious IP Alert',
                ip,
                'Medium',
                'Open',
                alert_time
            ))
            
        # Combine historical and current failed logins for failed counts
        current_failed_times = ip_current_failed.get(ip, [])
        historical_failed_times = ip_history_failed.get(ip, [])
        all_failed_times = sorted(current_failed_times + historical_failed_times)
        
        total_failed_count = len(all_failed_times)
        
        # 2. Brute Force Detection (10 failed logins within 5 minutes)
        is_brute_force = False
        for i in range(len(all_failed_times)):
            if i + 9 < len(all_failed_times):
                window_start = all_failed_times[i]
                window_end = all_failed_times[i + 9]
                time_diff = (window_end - window_start).total_seconds()
                if time_diff <= 300: # 300 seconds = 5 minutes
                    is_brute_force = True
                    break
                    
        if is_brute_force:
            alerts_to_create.append((
                'Potential Brute Force Attack',
                ip,
                'High',
                'Open',
                alert_time
            ))
            
        # 3. Failed Login Threshold Threat Detection (evaluated on total combined logs)
        if total_failed_count >= 10:
            alerts_to_create.append((
                'High Threat - Multiple Failed Logins',
                ip,
                'High',
                'Open',
                alert_time
            ))
        elif total_failed_count >= 5:
            alerts_to_create.append((
                'Medium Threat - Multiple Failed Logins',
                ip,
                'Medium',
                'Open',
                alert_time
            ))
        elif total_failed_count >= 3:
            alerts_to_create.append((
                'Low Threat - Multiple Failed Logins',
                ip,
                'Low',
                'Open',
                alert_time
            ))

    # Determine individual log risk levels for storage in database
    logs_to_insert = []
    for ts_str, action, ip in parsed_logs:
        # Calculate failures for this IP including history
        current_failed_times = ip_current_failed.get(ip, [])
        historical_failed_times = ip_history_failed.get(ip, [])
        total_failed_count = len(current_failed_times) + len(historical_failed_times)
        
        if 'success' in action.lower():
            risk_level = 'Safe'
        else:
            # Login Failed
            if total_failed_count >= 10:
                risk_level = 'High'
            elif total_failed_count >= 5:
                risk_level = 'Medium'
            elif total_failed_count >= 3:
                risk_level = 'Low'
            else:
                risk_level = 'Low' # Any single failure is a minor risk
                
        logs_to_insert.append((ts_str, action, ip, risk_level))

    # Bulk insert parsed logs
    database_manager.insert_logs_bulk(logs_to_insert)
    
    # Bulk insert alerts
    database_manager.insert_alerts_bulk(alerts_to_create)
    
    # Compile statistics of analysis
    high_count = len([a for a in alerts_to_create if a[2] == 'High'])
    med_count = len([a for a in alerts_to_create if a[2] == 'Medium'])
    low_count = len([a for a in alerts_to_create if a[2] == 'Low'])
    
    return {
        'total_parsed': len(parsed_logs),
        'alerts_created': len(alerts_to_create),
        'high_risk_alerts': high_count,
        'medium_risk_alerts': med_count,
        'low_risk_alerts': low_count
    }
