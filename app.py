import os
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.utils import secure_filename

import config
from modules import database_manager, authentication, log_parser, threat_detector, report_generator

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY

# Initialize SQLite database schema at boot-up
database_manager.init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Authentication required. Access denied.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    stats = database_manager.get_dashboard_stats()
    pie_data = database_manager.get_threat_distribution()
    bar_data = database_manager.get_failed_logins_per_ip()
    # Fetch top 10 recent alerts to display
    recent_alerts = database_manager.get_all_alerts()[:10]
    
    return render_template(
        'dashboard.html',
        stats=stats,
        pie_data=pie_data,
        bar_data=bar_data,
        recent_alerts=recent_alerts
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = authentication.login_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['name'] = user['name']
            flash(f"Access granted. Welcome back, {user['name']}.", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Access denied.", 'error')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        success, msg = authentication.register_user(name, email, username, password)
        if success:
            flash(msg, 'success')
            return redirect(url_for('login'))
        else:
            flash(msg, 'error')
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Analyst session ended.", 'success')
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_logs():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            flash("No file selected.", 'error')
            return redirect(request.url)
            
        file = request.files['logfile']
        if file.filename == '':
            flash("No file selected.", 'error')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(config.UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            try:
                # Read upload contents
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Parse logs
                parsed_logs = log_parser.parse_file(filename, content)
                
                # Run threat rules engine
                results = threat_detector.detect_threats(parsed_logs)
                
                flash(
                    f"Successfully parsed {results['total_parsed']} log records. "
                    f"Generated {results['alerts_created']} warnings "
                    f"({results['high_risk_alerts']} High Risk, {results['medium_risk_alerts']} Medium Risk, {results['low_risk_alerts']} Low Risk).",
                    'success'
                )
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash(f"Error parsing logfile: {str(e)}", 'error')
                return redirect(request.url)
        else:
            flash("Unsupported file extension. Please select a .log, .txt, or .csv file.", 'error')
            
    return render_template('upload.html')

@app.route('/alerts')
@login_required
def alerts_page():
    search_query = request.args.get('search', '').strip()
    risk_filter = request.args.get('risk', '').strip()
    status_filter = request.args.get('status', '').strip()
    
    alerts = database_manager.get_all_alerts(
        search_query=search_query if search_query else None,
        risk_filter=risk_filter if risk_filter else None,
        status_filter=status_filter if status_filter else None
    )
    
    return render_template(
        'alerts.html',
        alerts=alerts,
        search_query=search_query,
        risk_filter=risk_filter,
        status_filter=status_filter
    )

@app.route('/alerts/update_status', methods=['POST'])
@login_required
def update_status():
    alert_id = request.form.get('alert_id')
    status = request.form.get('status')
    
    if alert_id and status in ['Open', 'Investigating', 'Resolved']:
        try:
            database_manager.update_alert_status(int(alert_id), status)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
            
    return jsonify({'success': False, 'error': 'Invalid inputs'})

@app.route('/reports')
@login_required
def reports_page():
    stats = database_manager.get_dashboard_stats()
    return render_template('reports.html', stats=stats)

@app.route('/reports/pdf')
@login_required
def export_pdf():
    filepath = os.path.join(config.REPORTS_FOLDER, 'executive_threat_report.pdf')
    try:
        report_generator.generate_pdf_report(filepath)
        time_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        return send_file(
            filepath,
            as_attachment=True,
            download_name=f"ZPlus_Security_Report_{time_str}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        flash(f"Error compiling PDF report: {str(e)}", 'error')
        return redirect(url_for('reports_page'))

@app.route('/reports/csv')
@login_required
def export_csv():
    filepath = os.path.join(config.REPORTS_FOLDER, 'security_alert_ledger.csv')
    try:
        report_generator.generate_csv_report(filepath)
        time_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        return send_file(
            filepath,
            as_attachment=True,
            download_name=f"ZPlus_Security_Ledger_{time_str}.csv",
            mimetype='text/csv'
        )
    except Exception as e:
        flash(f"Error compiling CSV report: {str(e)}", 'error')
        return redirect(url_for('reports_page'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
