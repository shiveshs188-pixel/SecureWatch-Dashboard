import os
import sys

# Ensure current path is resolved for modules import
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from modules import database_manager, authentication, log_parser, threat_detector, report_generator
import config

def verify():
    print("====================================================")
    print("Z+ SECURITY - SYSTEM INTEGRATION VERIFICATION")
    print("====================================================")
    
    # 1. Initialize SQLite tables
    print("\n[STEP 1] Initializing Database Schema...")
    try:
        database_manager.init_db()
        print(" -> SUCCESS: Database schema loaded.")
    except Exception as e:
        print(f" -> ERROR: Failed schema init: {str(e)}")
        return False
        
    # 2. Test user authentication flows
    print("\n[STEP 2] Testing User Authentication Flows...")
    test_user = "test_analyst"
    test_pass = "securityPass321"
    
    # Clear existing test user if present
    conn = database_manager.get_db_connection()
    conn.execute("DELETE FROM users WHERE username = ?", (test_user,))
    conn.commit()
    conn.close()
    
    # Register test user
    reg_ok, reg_msg = authentication.register_user(
        name="Security Auditor", 
        email="auditor@zplus.com", 
        username=test_user, 
        password=test_pass
    )
    if reg_ok:
        print(f" -> SUCCESS: Registration test user: {reg_msg}")
    else:
        print(f" -> ERROR: Registration failed: {reg_msg}")
        return False
        
    # Verify login
    user_row = authentication.login_user(test_user, test_pass)
    if user_row:
        print(f" -> SUCCESS: Authenticated analyst: {user_row['name']} ({user_row['email']})")
    else:
        print(" -> ERROR: Credential validation failed.")
        return False

    # 3. Log file parsing test
    print("\n[STEP 3] Testing Logfile Parsing Engine...")
    sample_log_path = os.path.join(config.LOGS_FOLDER, 'sample_logs.log')
    if not os.path.exists(sample_log_path):
        print(f" -> ERROR: Test sample logs file missing at: {sample_log_path}")
        return False
        
    with open(sample_log_path, 'r', encoding='utf-8') as f:
        log_content = f.read()
        
    parsed = log_parser.parse_file('sample_logs.log', log_content)
    print(f" -> SUCCESS: Parsed {len(parsed)} log entries from sample_logs.log.")
    if len(parsed) == 0:
        print(" -> ERROR: No log lines parsed.")
        return False
        
    # 4. Threat detection evaluation
    print("\n[STEP 4] Testing Threat Rules Detection Engine...")
    try:
        # Run rules evaluation and DB store
        results = threat_detector.detect_threats(parsed)
        print(" -> SUCCESS: Threat classification execution completed.")
        print(f"    - Total Parsed Lines: {results['total_parsed']}")
        print(f"    - Alerts Generated: {results['alerts_created']}")
        print(f"    - Critical Risks (High): {results['high_risk_alerts']}")
        print(f"    - Warnings (Medium): {results['medium_risk_alerts']}")
        print(f"    - Notices (Low): {results['low_risk_alerts']}")
    except Exception as e:
        print(f" -> ERROR: Threat evaluation failure: {str(e)}")
        return False

    # 5. Database totals validation
    print("\n[STEP 5] Validating Database Storage Indices...")
    try:
        stats = database_manager.get_dashboard_stats()
        print(f"    - Logs inserted into DB: {stats['total_logs']}")
        print(f"    - Incident alerts in DB: {stats['total_threats']}")
        if stats['total_logs'] == 0 or stats['total_threats'] == 0:
            print(" -> ERROR: Database records verify empty.")
            return False
        else:
            print(" -> SUCCESS: Database records matched parsed logs.")
    except Exception as e:
        print(f" -> ERROR: Database stats retrieval failed: {str(e)}")
        return False

    # 6. Report generation test
    print("\n[STEP 6] Testing PDF & CSV Reports Compiler...")
    test_pdf = os.path.join(config.REPORTS_FOLDER, 'verify_report.pdf')
    test_csv = os.path.join(config.REPORTS_FOLDER, 'verify_ledger.csv')
    
    # Remove old verify files
    for p in (test_pdf, test_csv):
        if os.path.exists(p):
            os.remove(p)
            
    try:
        report_generator.generate_pdf_report(test_pdf)
        print(" -> SUCCESS: PDF Threat Report compiled.")
        report_generator.generate_csv_report(test_csv)
        print(" -> SUCCESS: CSV Alerts Ledger exported.")
        
        if os.path.exists(test_pdf) and os.path.exists(test_csv):
            print("\n====================================================")
            print("VERIFICATION COMPLETED: ALL COMPONENT TESTS PASSED!")
            print("====================================================")
            return True
        else:
            print(" -> ERROR: Output reports could not be found.")
            return False
    except Exception as e:
        print(f" -> ERROR: Reports compilation failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = verify()
    sys.exit(0 if success else 1)
