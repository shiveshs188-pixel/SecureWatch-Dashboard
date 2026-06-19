import os

# Base directory of the application
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Flask configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'securewatch_super_secret_key_987654')
DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'securewatch.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
LOGS_FOLDER = os.path.join(BASE_DIR, 'logs')
REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')

# Upload constraints
ALLOWED_EXTENSIONS = {'log', 'txt', 'csv'}

# Whitelisted IPs for suspicious IP detection
WHITELISTED_IPS = {
    '127.0.0.1',
    'localhost',
    '192.168.1.1',
    '192.168.1.20',
    '10.0.0.1'
}

# Automatically ensure required directories exist
for folder in [os.path.join(BASE_DIR, 'database'), UPLOAD_FOLDER, LOGS_FOLDER, REPORTS_FOLDER]:
    os.makedirs(folder, exist_ok=True)
