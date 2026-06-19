import sqlite3
import os
from datetime import datetime
import config

def get_db_connection():
    """Returns a connection to the SQLite database with Row factory enabled."""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # 2. Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            risk_level TEXT NOT NULL
        )
    ''')
    
    # 3. Alerts Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

# --- User Management ---

def create_user(name, email, username, hashed_password):
    """Inserts a new user into the database. Returns True if successful, False if duplicate."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)',
            (name, email, username, hashed_password)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user_by_username(username):
    """Retrieves a user record by username."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    """Retrieves a user record by email."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

# --- Logs Management ---

def insert_log(timestamp, action, ip_address, risk_level):
    """Inserts a single log record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO logs (timestamp, action, ip_address, risk_level) VALUES (?, ?, ?, ?)',
        (timestamp, action, ip_address, risk_level)
    )
    conn.commit()
    conn.close()

def insert_logs_bulk(logs_list):
    """Bulk inserts a list of log tuples: (timestamp, action, ip_address, risk_level)."""
    if not logs_list:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.executemany(
        'INSERT INTO logs (timestamp, action, ip_address, risk_level) VALUES (?, ?, ?, ?)',
        logs_list
    )
    conn.commit()
    conn.close()

def get_all_logs(search_query=None, risk_filter=None, limit=1000):
    """Retrieves logs based on optional search criteria and filters."""
    conn = get_db_connection()
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    
    if search_query:
        query += " AND (ip_address LIKE ? OR action LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
        
    if risk_filter:
        query += " AND risk_level = ?"
        params.append(risk_filter)
        
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    logs = conn.execute(query, params).fetchall()
    conn.close()
    return logs

# --- Alerts Management ---

def insert_alert(threat_type, ip_address, risk_level, status='Open', created_at=None):
    """Inserts an alert record."""
    if not created_at:
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO alerts (threat_type, ip_address, risk_level, status, created_at) VALUES (?, ?, ?, ?, ?)',
        (threat_type, ip_address, risk_level, status, created_at)
    )
    conn.commit()
    conn.close()

def insert_alerts_bulk(alerts_list):
    """Bulk inserts a list of alerts tuples: (threat_type, ip_address, risk_level, status, created_at)."""
    if not alerts_list:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.executemany(
        'INSERT INTO alerts (threat_type, ip_address, risk_level, status, created_at) VALUES (?, ?, ?, ?, ?)',
        alerts_list
    )
    conn.commit()
    conn.close()

def get_all_alerts(search_query=None, status_filter=None, risk_filter=None):
    """Retrieves alerts based on search query, risk filters, and status filters."""
    conn = get_db_connection()
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if search_query:
        query += " AND (ip_address LIKE ? OR threat_type LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
        
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)
        
    if risk_filter:
        query += " AND risk_level = ?"
        params.append(risk_filter)
        
    query += " ORDER BY created_at DESC"
    
    alerts = conn.execute(query, params).fetchall()
    conn.close()
    return alerts

def update_alert_status(alert_id, new_status):
    """Updates the resolution status of an alert."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE alerts SET status = ? WHERE id = ?',
        (new_status, alert_id)
    )
    conn.commit()
    conn.close()

# --- Aggregation & Dashboard Statistics ---

def get_dashboard_stats():
    """Calculates high-level metrics for dashboard cards and charts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Total logs analyzed
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    
    # 2. Total threats (Total alert items)
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_threats = cursor.fetchone()[0]
    
    # 3. High risk threats (Alerts with 'High' risk)
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE risk_level = 'High'")
    high_risk_threats = cursor.fetchone()[0]
    
    # 4. Safe events (Logs that are 'Safe')
    cursor.execute("SELECT COUNT(*) FROM logs WHERE risk_level = 'Safe'")
    safe_events = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_logs': total_logs,
        'total_threats': total_threats,
        'high_risk_threats': high_risk_threats,
        'safe_events': safe_events
    }

def get_threat_distribution():
    """Gets alert counts grouped by risk level for the distribution pie chart."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # We aggregate counts of alerts for Low, Medium, High.
    # Safe logs are calculated from logs table where risk_level = 'Safe'.
    cursor.execute("SELECT risk_level, COUNT(*) FROM alerts GROUP BY risk_level")
    threat_counts = dict(cursor.fetchall())
    
    cursor.execute("SELECT COUNT(*) FROM logs WHERE risk_level = 'Safe'")
    safe_count = cursor.fetchone()[0]
    
    conn.close()
    
    # Build complete dict with all categories
    return {
        'Safe': safe_count,
        'Low': threat_counts.get('Low', 0),
        'Medium': threat_counts.get('Medium', 0),
        'High': threat_counts.get('High', 0)
    }

def get_failed_logins_per_ip():
    """Gets the count of failed logins per IP address (for Bar Chart)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Find action matching 'Login Failed' and group by IP address, sorting by count descending
    cursor.execute("""
        SELECT ip_address, COUNT(*) as failed_count 
        FROM logs 
        WHERE action LIKE '%Failed%' 
        GROUP BY ip_address 
        ORDER BY failed_count DESC 
        LIMIT 10
    """)
    results = cursor.fetchall()
    conn.close()
    
    return [{'ip_address': row['ip_address'], 'failed_count': row['failed_count']} for row in results]
