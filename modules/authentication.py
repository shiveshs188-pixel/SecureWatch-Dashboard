import re
from werkzeug.security import generate_password_hash, check_password_hash
from modules import database_manager

def validate_registration_fields(name, email, username, password):
    """
    Validates registration fields.
    Returns: (is_valid: bool, error_message: str or None)
    """
    if not name or not name.strip():
        return False, "Full Name is required."
    
    if not email or not email.strip():
        return False, "Email is required."
    
    # Simple email regex
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return False, "Invalid email address format."
        
    if not username or not username.strip():
        return False, "Username is required."
        
    if len(username.strip()) < 3:
        return False, "Username must be at least 3 characters long."
        
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters long."
        
    return True, None

def register_user(name, email, username, password):
    """
    Registers a new user after validation.
    Returns: (success: bool, message: str)
    """
    name = name.strip()
    email = email.strip().lower()
    username = username.strip().lower()
    
    # Validate fields
    is_valid, err = validate_registration_fields(name, email, username, password)
    if not is_valid:
        return False, err
        
    # Check duplicate user
    if database_manager.get_user_by_username(username):
        return False, "Username is already taken."
        
    if database_manager.get_user_by_email(email):
        return False, "Email is already registered."
        
    # Password hashing
    hashed_pwd = generate_password_hash(password)
    
    success = database_manager.create_user(name, email, username, hashed_pwd)
    if success:
        return True, "Registration successful!"
    else:
        return False, "Database error. Registration failed."

def login_user(username, password):
    """
    Verifies user credentials.
    Returns: user Row if successful, else None.
    """
    username = username.strip().lower()
    user = database_manager.get_user_by_username(username)
    if user and check_password_hash(user['password'], password):
        return user
    return None
