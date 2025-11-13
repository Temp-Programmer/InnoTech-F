# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta
import re
import traceback
import os
import logging
from mysql.connector.pooling import MySQLConnectionPool
import urllib.parse

# Optional dev .env loader
from dotenv import load_dotenv
load_dotenv()  # safe: only loads if .env exists (local dev convenience)

# Optional server-side session (Redis) support
from flask_session import Session
import redis

# Use environment variables for secrets/config
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or 'change-me-in-prod'

# Configure session (override safely in prod)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=int(os.getenv('SESSION_DAYS', '7')))
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')

# Configure server-side sessions when REDIS_URL is present (recommended on Railway)
redis_url = os.getenv('REDIS_URL') or os.getenv('REDISTLS_URL')  # Railway may expose REDISTLS_URL
if redis_url:
    try:
        redis_client = redis.from_url(redis_url, decode_responses=False)
        app.config['SESSION_TYPE'] = 'redis'
        app.config['SESSION_REDIS'] = redis_client
        app.config['SESSION_PERMANENT'] = True
        # Keep small server-side cookie
        app.config['SESSION_USE_SIGNER'] = True
        Session(app)
        app.logger.info("Configured Redis-backed sessions")
    except Exception as e:
        app.logger.exception("Failed to configure Redis sessions, falling back to filesystem: %s", e)
        app.config['SESSION_TYPE'] = 'filesystem'
        Session(app)
else:
    # Fallback: filesystem session store (not ideal for multi-instance production)
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)

# Database Configuration from env (keeps backwards compatibility with DB_* vars)
DATABASE_URL = os.getenv('DATABASE_URL')  # Railway typically provides a single URL
if DATABASE_URL:
    # Example DATABASE_URL: mysql://user:password@host:3306/dbname
    parsed = urllib.parse.urlparse(DATABASE_URL)
    DB_CONFIG = {
        'host': parsed.hostname,
        'user': parsed.username,
        'password': parsed.password,
        'database': parsed.path.lstrip('/') if parsed.path else '',
        'port': parsed.port or 3306,
        'charset': 'utf8mb4'
    }
else:
    DB_CONFIG = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'user': os.getenv('DB_USER', 'root'),
        'password': os.getenv('DB_PASSWORD', ''),
        'database': os.getenv('DB_NAME', 'innotech'),
        'port': int(os.getenv('DB_PORT', '3306')),
        'charset': 'utf8mb4'
    }

# Configure logging to inherit Gunicorn logger if present
if 'gunicorn.error' in logging.root.manager.loggerDict:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers[:]
    app.logger.setLevel(gunicorn_logger.level)
else:
    logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))

# Connection pool (singleton)
_db_pool = None

def _ensure_pool():
    global _db_pool
    if _db_pool is None:
        pool_size = int(os.getenv('DB_POOL_SIZE', '5'))
        try:
            _db_pool = MySQLConnectionPool(
                pool_name = os.getenv('DB_POOL_NAME', 'app_pool'),
                pool_size = pool_size,
                **DB_CONFIG
            )
            app.logger.info("DB pool created (size=%d)", pool_size)
        except Exception as e:
            app.logger.exception("Failed to create DB pool: %s", e)
            raise

def get_db_connection():
    """Create database connection using a connection pool with debug info"""
    try:
        _ensure_pool()
        conn = _db_pool.get_connection()
        # ensure autocommit OFF to control transactions explicitly
        conn.autocommit = False
        return conn
    except Exception as e:
        app.logger.exception("Database connection error")
        return None

# ==================== DATABASE FUNCTIONS ====================

def get_user_by_email(email):
    """Fetch user by email"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT UID, name, email, password_hash FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()
        return user
    except Error as e:
        print(f"Database query error: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_user_by_uid(uid):
    """Fetch user by UID"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT UID, name, email, password_hash FROM users WHERE UID = %s",
            (uid,)
        )
        user = cursor.fetchone()
        return user
    except Error as e:
        print(f"Database query error: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def create_user(uid, name, email, password_hash):
    """Insert new user into database with improved debug"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"
    
    cursor = None
    try:
        cursor = conn.cursor()
        sql = "INSERT INTO users (UID, name, email, password_hash) VALUES (%s, %s, %s, %s)"
        params = (uid, name, email, password_hash)
        print(f"DEBUG: Running SQL -> {sql} params={params}")
        cursor.execute(sql, params)

        # verify affected rows before commit
        if getattr(cursor, "rowcount", None) in (None, -1):
            # Some MySQL drivers don't populate rowcount until commit
            conn.commit()
            print("DEBUG: Commit executed (rowcount unknown).")
        else:
            if cursor.rowcount == 1:
                conn.commit()
                print("DEBUG: Insert committed, rowcount=1")
            else:
                conn.rollback()
                print(f"DEBUG: Unexpected rowcount after insert: {cursor.rowcount}; rolled back")
                return False, "Insert failed (unexpected rowcount)"

        return True, "User created successfully"
    except mysql.connector.IntegrityError as ie:
        conn.rollback()
        print(f"DEBUG: IntegrityError during insert: {ie}")
        if "Duplicate" in str(ie):
            # try to be specific
            msg = str(ie).lower()
            if "email" in msg:
                return False, "Email already registered"
            if "uid" in msg or "uid" in msg:
                return False, "UID already registered"
        return False, f"Integrity error: {ie}"
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"DEBUG: Exception during create_user: {e}")
        traceback.print_exc()
        return False, f"Database error: {e}"
    finally:
        if cursor:
            try:
                cursor.close()
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass

# ==================== VALIDATION FUNCTIONS ====================

def validate_email(email):
    """Validate email format and domain - ONLY @kiet.edu allowed"""
    email = email.strip().lower()
    
    if not email:
        return False, "Email is required"
    
    if not email.endswith('@kiet.edu'):
        return False, "Only KIET email addresses (@kiet.edu) are allowed"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@kiet\.edu$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format. Use: firstname.lastname@kiet.edu"
    
    return True, email

def validate_uid(uid):
    """Validate UID format"""
    uid = uid.strip().upper()
    
    if not uid:
        return False, "UID is required"
    
    # Accept format like K123456 or any alphanumeric format
    uid_pattern = r'^[A-Z0-9]{6,20}$'
    if not re.match(uid_pattern, uid):
        return False, "UID must be 6-20 alphanumeric characters (e.g., K123456)"
    
    return True, uid

def validate_password(password):
    """Validate password strength"""
    if not password:
        return False, "Password is required"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    
    if len(password) > 100:
        return False, "Password is too long"
    
    return True, password

def validate_name(name):
    """Validate user name"""
    name = name.strip()
    
    if not name:
        return False, "Name is required"
    
    if len(name) < 2:
        return False, "Name must be at least 2 characters long"
    
    if len(name) > 50:
        return False, "Name is too long"
    
    return True, name

# ==================== DECORATORS ====================

def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_uid'):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def logout_required(f):
    """Decorator to check if user is not logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_uid'):
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ROUTES ====================

@app.route('/')
def index():
    """Home route - serve base1.html as default"""
    return render_template('base1.html')

@app.route('/register', methods=['GET', 'POST'])
@logout_required
def register():
    """User registration route"""
    if request.method == 'POST':
        print("DEBUG: POST request received at /register")
        print(f"DEBUG: Form data: {request.form}")
        
        uid = request.form.get('uid', '').strip().upper()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password2', '')

        print(f"DEBUG: Extracted values - UID: {uid}, Name: {name}, Email: {email}")

        # Validate UID
        is_valid, uid_msg = validate_uid(uid)
        if not is_valid:
            flash(uid_msg, "danger")
            return render_template('register.html', uid=uid, name=name, email=email)

        # Validate name
        is_valid, name_msg = validate_name(name)
        if not is_valid:
            flash(name_msg, "danger")
            return render_template('register.html', uid=uid, name=name, email=email)

        # Validate email - KIET ONLY
        is_valid, email_msg = validate_email(email)
        if not is_valid:
            flash(f"⚠️ {email_msg}", "danger")
            print(f"DEBUG: Invalid email format - {email}")
            return render_template('register.html', uid=uid, name=name, email=email)

        # Validate password
        is_valid, pwd_msg = validate_password(password)
        if not is_valid:
            flash(pwd_msg, "danger")
            return render_template('register.html', uid=uid, name=name, email=email)

        # Check if passwords match
        if password != password_confirm:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', uid=uid, name=name, email=email)

        # Check if UID already exists
        if get_user_by_uid(uid):
            flash("UID already registered.", "danger")
            print(f"DEBUG: UID already exists - {uid}")
            return render_template('register.html', uid=uid, name=name, email=email)

        # Check if email already exists
        if get_user_by_email(email):
            flash("Email already registered. Please log in.", "info")
            print(f"DEBUG: Email already exists - {email}")
            return redirect(url_for('login'))

        # Hash password and create user
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        success, message = create_user(uid, name, email, password_hash)

        if success:
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash(message, "danger")
            return render_template('register.html', uid=uid, name=name, email=email)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@logout_required
def login():
    """User login route"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        print(f"DEBUG: Login attempt - Email: {email}")

        # Validate inputs
        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template('login.html', email=email)

        # Validate email format - KIET ONLY
        is_valid, email_msg = validate_email(email)
        if not is_valid:
            flash(f"⚠️ {email_msg}", "danger")
            print(f"DEBUG: Invalid email domain - {email}")
            return render_template('login.html', email=email)

        # Get user from database
        user = get_user_by_email(email)
        if not user:
            print(f"DEBUG: User not found - {email}")
            flash("Invalid email or password.", "danger")
            return render_template('login.html', email=email)

        # Check password
        if not check_password_hash(user['password_hash'], password):
            print(f"DEBUG: Invalid password for - {email}")
            flash("Invalid email or password.", "danger")
            return render_template('login.html', email=email)

        # Set session
        session.permanent = True
        session['user_uid'] = user['UID']
        session['user_name'] = user['name']
        session['user_email'] = user['email']

        print(f"DEBUG: Login successful - UID: {user['UID']}, Name: {user['name']}")
        flash(f"Welcome back, {user['name']}!", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard route - requires login"""
    user = get_user_by_uid(session.get('user_uid'))
    if not user:
        session.clear()
        flash("User not found.", "danger")
        return redirect(url_for('login'))
    
    return render_template('dashboard1.html', user=user, name=user['name'])

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    """User profile route"""
    user = get_user_by_uid(session.get('user_uid'))
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('profile.html', user=user)

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    flash("Page not found.", "danger")
    if session.get('user_uid'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    flash("An error occurred. Please try again.", "danger")
    if session.get('user_uid'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ==================== CONTEXT PROCESSORS ====================

@app.context_processor
def inject_user():
    """Make user info available to all templates"""
    user = None
    if session.get('user_uid'):
        user = get_user_by_uid(session.get('user_uid'))
    return {'current_user': user}

# Add a simple health-check endpoint
@app.route('/health')
def health():
    try:
        conn = get_db_connection()
        if not conn:
            return {"status":"fail","reason":"db_conn"}, 503
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return {"status":"ok"}
    except Exception:
        app.logger.exception("Health check failed")
        return {"status":"fail"}, 500

# Ensure app.run is only for local debug; disable debug via env
if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'False') == 'True'
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    # Use Railway's PORT if present
    port = int(os.getenv('PORT', os.getenv('FLASK_PORT', '5000')))
    app.run(debug=debug_mode, host=host, port=port)