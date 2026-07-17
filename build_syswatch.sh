#!/bin/bash
# ======================================================================
# SysWatch v1.2.0 Complete Builder (Linux/macOS)
# ======================================================================
set -e

echo "========================================"
echo "  SysWatch v1.2.0 Project Builder       "
echo "========================================"

TARGET_DIR="syswatch_v1.2.0"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

# ----------------------------------------------------------------------
# Directory Structure
# ----------------------------------------------------------------------
mkdir -p core modules/authentication modules/web_ui/templates modules/web_ui/static modules/api modules/monitoring_checks modules/alert_engine modules/ai modules/ldap modules/winrm modules/remote_exec modules/discovery modules/remediation agents scripts keys

# ----------------------------------------------------------------------
# 2. CORE FILES
# ----------------------------------------------------------------------
cat > core/__init__.py <<'CORE_INIT_END'
# core/__init__.py
CORE_INIT_END

cat > core/config.py <<'CONFIG_END'
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_USER = os.getenv("DB_USER", "monitor")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "monitoring")
    API_KEY = os.getenv("API_KEY", "change-me-api-key")
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")
    TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")

    DISCOVERY_SUBNET = os.getenv("DISCOVERY_SUBNET", "192.168.1.0/24")

    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions")
    DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_API_URL = os.getenv("GEMINI_API_URL", "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent")

    SSH_USER = os.getenv("SSH_USER", "syswatch")
    SSH_PRIVATE_KEY_PATH = os.getenv("SSH_PRIVATE_KEY_PATH", "/opt/syswatch/keys/syswatch_key")
    SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", 10))
    WINRM_USER = os.getenv("WINRM_USER", "syswatch")
    WINRM_PASSWORD = os.getenv("WINRM_PASSWORD", "")
    WINRM_USE_SSL = os.getenv("WINRM_USE_SSL", "true").lower() == "true"
    WINRM_USE_KERBEROS = os.getenv("WINRM_USE_KERBEROS", "false").lower() == "true"

    LDAP_SERVER = os.getenv("LDAP_SERVER", "")
    LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "")
    LDAP_USER_DN = os.getenv("LDAP_USER_DN", "")
    LDAP_GROUP_DN = os.getenv("LDAP_GROUP_DN", "")
    LDAP_BIND_USER = os.getenv("LDAP_BIND_USER", "")
    LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "")
    LDAP_ROLE_MAPPING = os.getenv("LDAP_ROLE_MAPPING", "")
CONFIG_END

cat > core/database.py <<'DATABASE_END'
import pymysql
from flask import g
from werkzeug.security import generate_password_hash
from core.config import Config

db_config = {
    "host": Config.DB_HOST,
    "user": Config.DB_USER,
    "password": Config.DB_PASSWORD,
    "database": Config.DB_NAME,
    "autocommit": True,
    "auth_plugin_map": {'caching_sha2_password': 'caching_sha2_password'}
}

def get_db():
    if "db" not in g:
        g.db = pymysql.connect(**db_config)
    else:
        try:
            g.db.ping(reconnect=True)
        except Exception:
            g.db = pymysql.connect(**db_config)
    return g.db

def close_db(exception=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = pymysql.connect(**db_config)
    cur = db.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            hostname VARCHAR(128) PRIMARY KEY,
            agent_id VARCHAR(64) DEFAULT NULL,
            ip VARCHAR(45),
            last_seen DATETIME,
            status VARCHAR(16) DEFAULT 'UP',
            group_id INT DEFAULT NULL,
            discovered_by VARCHAR(32) DEFAULT 'manual',
            discovery_time DATETIME DEFAULT NULL,
            os_type VARCHAR(20) DEFAULT 'linux'
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(128) NOT NULL,
            ip VARCHAR(45),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu FLOAT,
            memory FLOAT,
            disk FLOAT,
            network_sent BIGINT,
            network_recv BIGINT,
            services JSON,
            network_devices JSON,
            uptime BIGINT,
            INDEX idx_hostname (hostname),
            INDEX idx_timestamp (timestamp)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(128),
            metric VARCHAR(32),
            threshold FLOAT,
            operator VARCHAR(2),
            severity VARCHAR(16),
            cooldown INT DEFAULT 300,
            cause TEXT,
            action TEXT,
            enabled TINYINT DEFAULT 1,
            duration INT DEFAULT 1,
            template VARCHAR(32) DEFAULT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(128),
            metric VARCHAR(32),
            value FLOAT,
            threshold FLOAT,
            severity VARCHAR(16),
            cause TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved INT DEFAULT 0,
            resolved_at DATETIME,
            status VARCHAR(16) DEFAULT 'OPEN',
            acknowledged_by VARCHAR(64) DEFAULT NULL,
            acknowledged_at DATETIME DEFAULT NULL,
            INDEX idx_alert_status (status),
            INDEX idx_alert_host_metric (hostname, metric)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS host_groups (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) UNIQUE NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            role VARCHAR(16) NOT NULL DEFAULT 'manager',
            ldap_dn VARCHAR(256) DEFAULT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) UNIQUE NOT NULL,
            description VARCHAR(200)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS group_permissions (
            group_id INT NOT NULL,
            permission_id INT NOT NULL,
            PRIMARY KEY (group_id, permission_id),
            FOREIGN KEY (group_id) REFERENCES host_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ssl_certificates (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(128) NOT NULL,
            port INT DEFAULT 443,
            expiry_date DATE NOT NULL,
            last_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_host_port (hostname, port)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_insights (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(128),
            metric VARCHAR(32),
            current_value FLOAT,
            baseline_mean FLOAT,
            baseline_std FLOAT,
            deviation FLOAT,
            severity VARCHAR(16),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(16) DEFAULT 'OPEN',
            details JSON
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(128) NOT NULL,
            event_type VARCHAR(64) NOT NULL,
            event_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            source VARCHAR(64),
            user VARCHAR(64),
            details JSON,
            INDEX idx_hostname (hostname),
            INDEX idx_event_type (event_type),
            INDEX idx_event_time (event_time)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_ranges (
            id INT AUTO_INCREMENT PRIMARY KEY,
            subnet VARCHAR(32) NOT NULL,
            description VARCHAR(128),
            enabled TINYINT DEFAULT 1
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pending_hosts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            os_type VARCHAR(20) DEFAULT 'linux',
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'pending',
            approved_at DATETIME,
            deployed_at DATETIME
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS remediation_tasks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            alert_id INT NOT NULL,
            action_type VARCHAR(50),
            action_command TEXT NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            dry_run_output TEXT,
            execution_output TEXT,
            executed_at DATETIME,
            executed_by VARCHAR(80),
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        )
    """)

    cur.execute("SELECT COUNT(*) FROM network_ranges")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO network_ranges (subnet, description) VALUES (%s, %s)", (Config.DISCOVERY_SUBNET, 'Default subnet'))

    default_perms = [
        ('dashboard:view', 'View dashboard'),
        ('hosts:view', 'View hosts'),
        ('hosts:manage', 'Manage hosts'),
        ('hosts:deploy', 'Deploy agents'),
        ('events:view', 'View events'),
        ('alerts:view', 'View alerts'),
        ('alerts:ack', 'Acknowledge alerts'),
        ('alerts:remediate', 'Execute remediation'),
        ('exec:run', 'Run remote commands'),
        ('users:manage', 'Manage users'),
        ('windows:view', 'View Windows hosts'),
        ('windows:manage', 'Manage Windows hosts'),
        ('settings:manage', 'Manage settings')
    ]
    for name, desc in default_perms:
        cur.execute("INSERT IGNORE INTO permissions (name, description) VALUES (%s, %s)", (name, desc))

    groups = {
        'Admin': [
            'dashboard:view','hosts:view','hosts:manage','hosts:deploy',
            'events:view','alerts:view','alerts:ack','alerts:remediate',
            'exec:run','users:manage','windows:view','windows:manage','settings:manage'
        ],
        'Operator': [
            'dashboard:view','hosts:view','events:view','alerts:view',
            'alerts:ack','exec:run','windows:view'
        ],
        'Viewer': [
            'dashboard:view','hosts:view','events:view','alerts:view'
        ]
    }
    for gname, perms in groups.items():
        cur.execute("INSERT IGNORE INTO host_groups (name) VALUES (%s)", (gname,))
        cur.execute("SELECT id FROM host_groups WHERE name = %s", (gname,))
        gid = cur.fetchone()[0]
        for pname in perms:
            cur.execute("SELECT id FROM permissions WHERE name = %s", (pname,))
            pid = cur.fetchone()[0]
            cur.execute("INSERT IGNORE INTO group_permissions (group_id, permission_id) VALUES (%s, %s)", (gid, pid))

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        admin_user = Config.ADMIN_USER
        admin_pass = Config.ADMIN_PASSWORD
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
            (admin_user, generate_password_hash(admin_pass))
        )
        db.commit()

    cur.execute("SELECT COUNT(*) FROM alert_rules")
    if cur.fetchone()[0] == 0:
        default_rules = [
            ('%', 'cpu', 90, '>', 'CRITICAL', 300, 'CPU usage exceeded 90%', 'Check top processes', 'high_cpu'),
            ('%', 'cpu', 75, '>', 'WARNING', 300, 'CPU usage exceeded 75%', 'Monitor trends', 'high_cpu'),
            ('%', 'memory', 90, '>', 'CRITICAL', 300, 'Memory usage exceeded 90%', 'Check for memory leaks', 'high_memory'),
            ('%', 'memory', 75, '>', 'WARNING', 300, 'Memory usage exceeded 75%', 'Monitor growth', 'high_memory'),
            ('%', 'disk', 95, '>', 'CRITICAL', 300, 'Disk usage exceeded 95%', 'Clean up logs', 'disk_full'),
            ('%', 'disk', 80, '>', 'WARNING', 300, 'Disk usage exceeded 80%', 'Review retention', 'disk_full'),
        ]
        for rule in default_rules:
            cur.execute(
                "INSERT INTO alert_rules (hostname, metric, threshold, operator, severity, cooldown, cause, action, template) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                rule
            )
        db.commit()

    cur.close()
    db.close()
DATABASE_END

cat > core/scheduler.py <<'SCHEDULER_END'
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

def start_scheduler(app):
    with app.app_context():
        from modules.monitoring_checks.status_updater import compute_status
        from modules.monitoring_checks.ssl_expiry import check_all_certificates
        from modules.ai.anomaly import run_anomaly_detection, run_predictions, send_daily_briefing
        from modules.alert_engine.auto_resolve import auto_resolve_stale_alerts
        from modules.discovery.sweep import run_discovery_sweep

        scheduler.add_job(compute_status, 'interval', seconds=30, id='status_updater')
        scheduler.add_job(check_all_certificates, 'cron', hour=8, minute=0, id='ssl_expiry')
        scheduler.add_job(run_anomaly_detection, 'interval', minutes=5, id='anomaly')
        scheduler.add_job(run_predictions, 'interval', hours=6, id='predictions')
        scheduler.add_job(auto_resolve_stale_alerts, 'interval', minutes=10, id='auto_resolve')
        scheduler.add_job(send_daily_briefing, 'cron', hour=8, minute=0, id='briefing')
        scheduler.add_job(run_discovery_sweep, 'cron', hour=2, minute=0, id='discovery')

        if not scheduler.running:
            scheduler.start()
            print("✅ Scheduler started with 7 jobs.")

def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        print("🛑 Scheduler stopped.")
SCHEDULER_END

cat > core/app.py <<'APP_END'
from flask import Flask
from flask_login import LoginManager
from core.config import Config
from core.database import close_db, init_db
from core.scheduler import start_scheduler

app = Flask(__name__, template_folder='../modules/web_ui/templates')
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.teardown_appcontext(close_db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "authentication.login"

from modules.authentication.models import load_user
login_manager.user_loader(load_user)

from modules.authentication.routes import auth_bp
from modules.web_ui.routes import ui_bp
from modules.api.routes import api_bp

app.register_blueprint(auth_bp)
app.register_blueprint(ui_bp)
app.register_blueprint(api_bp, url_prefix='/api')

with app.app_context():
    init_db()

start_scheduler(app)

print("🚀 SysWatch v1.2.0 Core initialized.")
APP_END

# ----------------------------------------------------------------------
# 3. MODULES – AUTHENTICATION
# ----------------------------------------------------------------------
cat > modules/authentication/__init__.py <<'AUTH_INIT_END'
# modules/authentication/__init__.py
AUTH_INIT_END

cat > modules/authentication/models.py <<'AUTH_MODELS_END'
from flask_login import UserMixin
from core.database import get_db

class User(UserMixin):
    def __init__(self, id, username, role, ldap_dn=None):
        self.id = id
        self.username = username
        self.role = role
        self.ldap_dn = ldap_dn

    def has_permission(self, perm_name):
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT 1 FROM group_permissions gp
            JOIN host_groups g ON gp.group_id = g.id
            JOIN permissions p ON gp.permission_id = p.id
            JOIN users u ON u.role = g.name
            WHERE u.id = %s AND p.name = %s
        """, (self.id, perm_name))
        exists = cur.fetchone() is not None
        cur.close()
        return exists

    @property
    def is_admin(self):
        return self.has_permission('users:manage')

def load_user(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, role, ldap_dn FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    if row:
        return User(row[0], row[1], row[2], row[3])
    return None
AUTH_MODELS_END

cat > modules/authentication/routes.py <<'AUTH_ROUTES_END'
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from core.database import get_db
from core.config import Config
from modules.authentication.models import User
import pymysql
import ldap3

bp = Blueprint('authentication', __name__)

def _ldap_authenticate(username, password):
    server = Config.LDAP_SERVER
    base_dn = Config.LDAP_BASE_DN
    user_dn = Config.LDAP_USER_DN
    bind_user = Config.LDAP_BIND_USER
    bind_pass = Config.LDAP_BIND_PASSWORD
    mapping_str = Config.LDAP_ROLE_MAPPING

    if not server or not bind_user:
        return None, None

    try:
        conn = ldap3.Connection(server, user=bind_user, password=bind_pass, auto_bind=True)
        search_filter = f'(sAMAccountName={username})'
        conn.search(search_base=user_dn, search_filter=search_filter, attributes=['memberOf'])
        if not conn.entries:
            return None, None
        entry = conn.entries[0]
        user_dn_full = entry.entry_dn

        user_conn = ldap3.Connection(server, user=user_dn_full, password=password, auto_bind=True)
        user_conn.unbind()

        groups = []
        for member_of in entry.memberOf.values:
            groups.append(str(member_of))

        mapping = {}
        if mapping_str:
            for pair in mapping_str.split(','):
                if ':' in pair:
                    ldap_group, sw_group = pair.split(':', 1)
                    mapping[ldap_group.strip()] = sw_group.strip()

        matched_groups = []
        for g in groups:
            if g in mapping:
                matched_groups.append(mapping[g])
        return user_dn_full, matched_groups
    except Exception as e:
        print(f"LDAP error: {e}")
        return None, None

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('web_ui.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db()
        cur = db.cursor()

        ldap_dn, ldap_roles = _ldap_authenticate(username, password)
        if ldap_dn:
            cur.execute("SELECT id, username, role, ldap_dn FROM users WHERE username = %s", (username,))
            user_row = cur.fetchone()
            if user_row:
                user = User(user_row[0], user_row[1], user_row[2], user_row[3])
            else:
                role = ldap_roles[0] if ldap_roles else 'Viewer'
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, ldap_dn) VALUES (%s, '', %s, %s)",
                    (username, role, ldap_dn)
                )
                db.commit()
                cur.execute("SELECT id, username, role, ldap_dn FROM users WHERE username = %s", (username,))
                user_row = cur.fetchone()
                user = User(user_row[0], user_row[1], user_row[2], user_row[3])
            login_user(user)
            cur.close()
            return redirect(url_for('web_ui.dashboard'))

        cur.execute("SELECT id, username, password_hash, role, ldap_dn FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close()
        if row and check_password_hash(row[2], password):
            user = User(row[0], row[1], row[3], row[4])
            login_user(user)
            return redirect(url_for('web_ui.dashboard'))

        flash('Invalid credentials', 'danger')

    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('authentication.login'))

@bp.route('/api/users', methods=['GET'])
@login_required
def list_users():
    if not current_user.has_permission('users:manage'):
        return jsonify({"error": "Forbidden"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, role, ldap_dn FROM users ORDER BY username")
    users = [{"id": r[0], "username": r[1], "role": r[2], "ldap": bool(r[3])} for r in cur.fetchall()]
    cur.close()
    return jsonify(users)

@bp.route('/api/users', methods=['POST'])
@login_required
def create_user():
    if not current_user.has_permission('users:manage'):
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'Viewer')
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, generate_password_hash(password), role)
        )
        db.commit()
        return jsonify({"status": "ok", "id": cur.lastrowid})
    except pymysql.IntegrityError:
        return jsonify({"error": "User already exists"}), 409
    finally:
        cur.close()

@bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.has_permission('users:manage'):
        return jsonify({"error": "Forbidden"}), 403
    if user_id == current_user.id:
        return jsonify({"error": "Cannot delete yourself"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})
AUTH_ROUTES_END

# ----------------------------------------------------------------------
# 4. MODULES – WEB UI
# ----------------------------------------------------------------------
cat > modules/web_ui/__init__.py <<'WEBUI_INIT_END'
# modules/web_ui/__init__.py
WEBUI_INIT_END

cat > modules/web_ui/routes.py <<'WEBUI_ROUTES_END'
from flask import Blueprint, render_template
from flask_login import login_required

bp = Blueprint('web_ui', __name__)

@bp.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')
WEBUI_ROUTES_END

cat > modules/web_ui/templates/dashboard.html <<'DASHBOARD_HTML_END'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SysWatch v1.2.0</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2"></script>
    <style>
        :root { --bg: #f4f6f9; --sidebar-bg: #2c3e50; --sidebar-text: #ecf0f1; --card-bg: #ffffff; --text: #2c3e50; --border: #dce1e8; --primary: #3498db; --success: #27ae60; --warning: #f39c12; --danger: #e74c3c; }
        body.dark { --bg: #1a1a2e; --sidebar-bg: #16213e; --sidebar-text: #e0e0e0; --card-bg: #22223b; --text: #e0e0e0; --border: #3a3a5a; --primary: #4a9eff; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); display: flex; min-height: 100vh; }
        .sidebar { width: 220px; background: var(--sidebar-bg); color: var(--sidebar-text); padding: 20px 0; position: fixed; height: 100vh; overflow-y: auto; }
        .sidebar h2 { text-align: center; padding: 10px 0; border-bottom: 1px solid #3a3a5a; }
        .sidebar .brand { font-size: 1.2em; font-weight: bold; }
        .sidebar ul { list-style: none; padding: 0; margin-top: 20px; }
        .sidebar ul li { padding: 12px 20px; cursor: pointer; border-left: 3px solid transparent; transition: 0.2s; }
        .sidebar ul li:hover { background: #1a1a2e; border-left-color: var(--primary); }
        .sidebar ul li.active { background: #1a1a2e; border-left-color: var(--primary); }
        .main { margin-left: 220px; padding: 20px; flex: 1; }
        .topbar { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
        .topbar .user { display: flex; align-items: center; gap: 15px; }
        .summary-cards { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); padding: 15px 20px; border-radius: 8px; flex: 1; min-width: 120px; text-align: center; }
        .card h4 { font-weight: normal; color: #7f8c8d; margin-bottom: 5px; }
        .card .value { font-size: 2em; font-weight: bold; }
        .card .value.up { color: var(--success); }
        .card .value.warning { color: var(--warning); }
        .card .value.down { color: var(--danger); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 8px 12px; border: 1px solid var(--border); text-align: left; }
        th { background: var(--card-bg); font-weight: 600; }
        tr:nth-child(even) { background: rgba(0,0,0,0.02); }
        .btn { background: var(--primary); color: #fff; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; }
        .btn-sm { padding: 3px 8px; font-size: 0.8em; }
        .btn-danger { background: var(--danger); }
        .btn-success { background: var(--success); }
        .btn-warning { background: var(--warning); }
        .btn-secondary { background: #6c757d; color: #fff; }
        .inline-form { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
        .status-OPEN { color: var(--danger); font-weight: bold; }
        .status-ACKNOWLEDGED { color: var(--warning); font-weight: bold; }
        .status-RESOLVED { color: var(--success); font-weight: bold; }
        .filter-bar { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px; }
        .filter-bar select, .filter-bar input { padding: 5px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--card-bg); color: var(--text); }
        .chart-box { margin-top: 20px; background: var(--card-bg); padding: 15px; border: 1px solid var(--border); border-radius: 8px; }
        .chart-box canvas { max-height: 300px; width: 100%; }
        .progress-bar { width: 100%; background: #ddd; border-radius: 4px; margin-top: 8px; }
        .progress-bar .progress { height: 20px; background: var(--primary); border-radius: 4px; transition: width 0.3s; }
        @media (max-width: 768px) { .sidebar { width: 60px; } .sidebar span { display: none; } .main { margin-left: 60px; } }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2><span class="brand">SysWatch</span></h2>
        <ul id="menu">
            <li class="active" data-tab="dashboard"><span>📊 Dashboard</span></li>
            <li data-tab="monitoring"><span>🖥️ Hosts</span></li>
            <li data-tab="events"><span>📋 Events</span></li>
            <li data-tab="alerts"><span>🔔 Alerts</span></li>
            <li data-tab="windows"><span>🪟 Windows</span></li>
            <li data-tab="rules"><span>⚙️ Rules</span></li>
            <li data-tab="admin"><span>👤 Admin</span></li>
            <li data-tab="ai"><span>🤖 AI Insights</span></li>
            <li><a href="/logout" style="color:inherit; text-decoration:none;"><span>🚪 Logout</span></a></li>
        </ul>
    </div>
    <div class="main">
        <div class="topbar">
            <h1 id="pageTitle">Dashboard</h1>
            <div class="user">
                <button onclick="toggleDarkMode()">🌓</button>
                <span>{{ current_user.username }}</span>
            </div>
        </div>

        <div id="tab-dashboard" class="tab-content active">
            <div class="summary-cards" id="summaryCards">
                <div class="card"><h4>Total Hosts</h4><div class="value" id="totalHosts">-</div></div>
                <div class="card"><h4>UP</h4><div class="value up" id="upHosts">-</div></div>
                <div class="card"><h4>WARNING</h4><div class="value warning" id="warnHosts">-</div></div>
                <div class="card"><h4>DOWN</h4><div class="value down" id="downHosts">-</div></div>
                <div class="card"><h4>Open Alerts</h4><div class="value down" id="openAlerts">-</div></div>
            </div>
            <div class="filter-bar">
                <label>Group: <select id="groupFilter"><option value="">All</option></select></label>
                <label>Status: <select id="statusFilter"><option value="">All</option><option value="UP">UP</option><option value="WARNING">WARNING</option><option value="DOWN">DOWN</option></select></label>
                <button onclick="fetchDevices()" class="btn">Refresh</button>
            </div>
            <table id="devicesTable"><thead><tr><th>Hostname</th><th>IP</th><th>Status</th><th>Group</th><th>OS</th><th>CPU%</th><th>Mem%</th><th>Disk%</th></tr></thead><tbody></tbody></table>
            <div class="chart-box">
                <div class="inline-form">
                    <label>Range: <select id="trendRange" onchange="loadChart()"><option value="1h">1h</option><option value="6h">6h</option><option value="12h">12h</option><option value="24h">24h</option><option value="7d">7d</option><option value="30d">30d</option></select></label>
                    <label>Metric: <select id="trendMetric" onchange="loadChart()"><option value="cpu">CPU</option><option value="memory">Memory</option><option value="disk">Disk</option></select></label>
                    <label>Hosts: <select id="trendHosts" multiple size="2" onchange="loadChart()"></select></label>
                    <button onclick="loadChart()" class="btn">Update</button>
                </div>
                <canvas id="trendChart"></canvas>
            </div>
        </div>

        <div id="tab-monitoring" class="tab-content">
            <h3>Hosts & Devices</h3>
            <div style="background:var(--card-bg);padding:15px;border:1px solid var(--border);border-radius:8px;margin-bottom:15px;">
                <h4>Add Host</h4>
                <div class="inline-form">
                    <input type="text" id="newHostname" placeholder="Hostname">
                    <input type="text" id="newHostIP" placeholder="IP">
                    <select id="newHostGroup"><option value="">No Group</option></select>
                    <select id="newHostOS"><option value="linux">Linux</option><option value="windows">Windows</option></select>
                    <button class="btn" onclick="addHost()">Add</button>
                </div>
                <div id="addHostMessage"></div>
            </div>
            <div style="background:var(--card-bg);padding:15px;border:1px solid var(--border);border-radius:8px;margin-bottom:15px;">
                <h4>Auto-Discovery</h4>
                <div class="inline-form">
                    <button class="btn btn-success" onclick="startDiscovery()">Scan Network</button>
                    <span id="discoveryStatus">Idle</span>
                </div>
                <div class="progress-bar"><div class="progress" id="discoveryProgress" style="width:0%;"></div></div>
                <div id="discoveryMessage"></div>
            </div>
            <div class="filter-bar">
                <label>Type: <select id="monitoringType"><option value="hosts">Hosts</option><option value="devices">Devices</option></select></label>
                <button onclick="fetchMonitoring()" class="btn">Refresh</button>
            </div>
            <table id="monitoringTable"><thead><tr><th>Name</th><th>IP</th><th>Status</th><th>Type</th></tr></thead><tbody></tbody></table>
        </div>

        <div id="tab-events" class="tab-content">
            <h3>Events</h3>
            <div class="filter-bar">
                <input type="text" id="eventHost" placeholder="Hostname">
                <input type="text" id="eventUser" placeholder="Username">
                <select id="eventType"><option value="">All</option><option value="login">Login</option><option value="logout">Logout</option><option value="file_change">File Change</option></select>
                <input type="date" id="eventStart">
                <input type="date" id="eventEnd">
                <button onclick="fetchEvents()" class="btn">Filter</button>
            </div>
            <table id="eventsTable"><thead><tr><th>Time</th><th>Host</th><th>User</th><th>Type</th><th>Details</th></tr></thead><tbody></tbody></table>
        </div>

        <div id="tab-alerts" class="tab-content">
            <h3>Alerts</h3>
            <div class="filter-bar">
                <select id="alertSeverity"><option value="">All</option><option value="WARNING">WARNING</option><option value="CRITICAL">CRITICAL</option></select>
                <select id="alertStatus"><option value="">All</option><option value="OPEN">OPEN</option><option value="ACKNOWLEDGED">ACKNOWLEDGED</option><option value="RESOLVED">RESOLVED</option></select>
                <button onclick="fetchAlerts()" class="btn">Refresh</button>
            </div>
            <table id="alertsTable"><thead><tr><th>Host</th><th>Metric</th><th>Value</th><th>Severity</th><th>Time</th><th>Status</th><th>Actions</th></tr></thead><tbody></tbody></table>
        </div>

        <div id="tab-windows" class="tab-content">
            <h3>Windows Hosts</h3>
            <table id="windowsTable"><thead><tr><th>Hostname</th><th>IP</th><th>Status</th><th>Action</th></tr></thead><tbody></tbody></table>
            <div style="margin-top:20px;">
                <h4>Execute Command</h4>
                <div class="inline-form">
                    <input type="text" id="winCommand" placeholder="Command (e.g., Get-Service)" style="width:400px;">
                    <button onclick="execWinCommand()" class="btn">Run</button>
                </div>
                <pre id="winOutput" style="background:var(--card-bg);padding:10px;border:1px solid var(--border);border-radius:4px;margin-top:10px;"></pre>
            </div>
        </div>

        <div id="tab-rules" class="tab-content">
            <h3>Alert Rules</h3>
            <div style="background:var(--card-bg);padding:15px;border:1px solid var(--border);border-radius:8px;margin-bottom:15px;">
                <h4>Add Rule</h4>
                <div class="inline-form">
                    <input type="text" id="ruleHost" placeholder="Host (or %)" value="%">
                    <input type="text" id="ruleMetric" placeholder="Metric">
                    <input type="number" id="ruleThreshold" placeholder="Threshold">
                    <select id="ruleOp"><option value=">">&gt;</option><option value="<">&lt;</option></select>
                    <select id="ruleSev"><option value="WARNING">WARNING</option><option value="CRITICAL">CRITICAL</option></select>
                    <button class="btn" onclick="createRule()">Add</button>
                </div>
            </div>
            <table id="rulesTable"><thead><tr><th>ID</th><th>Host</th><th>Metric</th><th>Threshold</th><th>Severity</th><th>Enabled</th><th>Actions</th></tr></thead><tbody></tbody></table>
        </div>

        <div id="tab-admin" class="tab-content">
            <h3>Admin</h3>
            <div style="background:var(--card-bg);padding:15px;border:1px solid var(--border);border-radius:8px;margin-bottom:15px;">
                <h4>Create User</h4>
                <div class="inline-form">
                    <input type="text" id="newUname" placeholder="Username">
                    <input type="password" id="newPass" placeholder="Password">
                    <select id="newRole"><option value="Viewer">Viewer</option><option value="Operator">Operator</option><option value="Admin">Admin</option></select>
                    <button class="btn" onclick="createUser()">Create</button>
                </div>
            </div>
            <table id="usersTable"><thead><tr><th>ID</th><th>Username</th><th>Role</th><th>LDAP</th><th>Actions</th></tr></thead><tbody></tbody></table>
            <h3>Groups</h3>
            <div class="inline-form"><input type="text" id="newGroupName" placeholder="Group name"><button class="btn" onclick="createGroup()">Create</button></div>
            <table id="groupsTable"><thead><tr><th>ID</th><th>Name</th><th>Actions</th></tr></thead><tbody></tbody></table>
        </div>

        <div id="tab-ai" class="tab-content">
            <h3>AI Insights & Predictions</h3>
            <table id="aiTable"><thead><tr><th>Host</th><th>Metric</th><th>Value</th><th>Baseline</th><th>Deviation</th><th>Severity</th><th>Time</th><th>Details</th></tr></thead><tbody></tbody></table>
        </div>
    </div>

    <script>
        let trendChart = null;
        function toggleDarkMode() { document.body.classList.toggle('dark'); }

        document.querySelectorAll('#menu li[data-tab]').forEach(el => {
            el.addEventListener('click', function() {
                document.querySelectorAll('#menu li').forEach(l => l.classList.remove('active'));
                this.classList.add('active');
                const tab = this.dataset.tab;
                document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
                document.getElementById('tab-' + tab).classList.add('active');
                document.getElementById('pageTitle').innerText = this.innerText.trim();
                if (tab === 'dashboard') { fetchSummary(); fetchDevices(); loadTrendHosts(); }
                else if (tab === 'monitoring') { fetchMonitoring(); loadGroupsForAddHost(); }
                else if (tab === 'events') { fetchEvents(); }
                else if (tab === 'alerts') { fetchAlerts(); }
                else if (tab === 'windows') { fetchWindows(); }
                else if (tab === 'rules') { fetchRules(); }
                else if (tab === 'admin') { loadAdmin(); }
                else if (tab === 'ai') { fetchAI(); }
            });
        });

        async function fetchSummary() {
            const r = await fetch('/api/summary'); const d = await r.json();
            document.getElementById('totalHosts').textContent = d.total; document.getElementById('upHosts').textContent = d.up;
            document.getElementById('warnHosts').textContent = d.warning; document.getElementById('downHosts').textContent = d.down;
            document.getElementById('openAlerts').textContent = d.open_alerts;
        }
        async function fetchDevices() {
            const r = await fetch('/api/latest'); const data = await r.json();
            const tbody = document.querySelector('#devicesTable tbody'); tbody.innerHTML = '';
            data.forEach(d => {
                tbody.innerHTML += `<tr><td>${d.hostname}</td><td>${d.ip}</td><td class="status-${d.status}">${d.status}</td><td>${d.group_name}</td><td>${d.os_type}</td><td>${d.cpu || 'N/A'}</td><td>${d.memory || 'N/A'}</td><td>${d.disk || 'N/A'}</td></tr>`;
            });
            await loadGroupFilterOptions();
        }
        async function loadGroupFilterOptions() {
            const r = await fetch('/api/groups'); const g = await r.json();
            const sel = document.getElementById('groupFilter'); sel.innerHTML = '<option value="">All</option>';
            g.forEach(gr => sel.innerHTML += `<option value="${gr.id}">${gr.name}</option>`);
        }
        async function loadTrendHosts() {
            const r = await fetch('/api/hosts'); const h = await r.json();
            const sel = document.getElementById('trendHosts'); sel.innerHTML = '';
            h.forEach(host => sel.innerHTML += `<option value="${host.hostname}">${host.hostname}</option>`);
            if (sel.options.length > 0) { sel.options[0].selected = true; loadChart(); }
        }
        async function loadChart() {
            const range = document.getElementById('trendRange').value;
            const metric = document.getElementById('trendMetric').value;
            const sel = document.getElementById('trendHosts');
            const hosts = [];
            for (let i=0; i<sel.options.length; i++) if (sel.options[i].selected) hosts.push(sel.options[i].value);
            if (hosts.length === 0) return;
            if (trendChart) trendChart.destroy();
            const datasets = [];
            const colors = ['#e74c3c','#3498db','#2ecc71','#f39c12','#9b59b6'];
            for (let idx=0; idx<hosts.length; idx++) {
                const resp = await fetch('/api/trends/' + hosts[idx] + '?range=' + range);
                const data = await resp.json();
                if (data.length === 0) continue;
                datasets.push({
                    label: hosts[idx] + ' (' + metric + ')',
                    data: data.map(p => p[metric] || 0),
                    borderColor: colors[idx % colors.length],
                    fill: false, tension: 0.1, pointRadius: 1
                });
            }
            if (datasets.length === 0) return;
            trendChart = new Chart(document.getElementById('trendChart'), {
                type: 'line',
                data: { labels: datasets[0].data.map((_,i) => i), datasets: datasets },
                options: { responsive: true, plugins: { zoom: { pan: { enabled: true, mode: 'x' }, zoom: { wheel: { enabled: true } } } } }
            });
        }

        async function loadGroupsForAddHost() {
            const r = await fetch('/api/groups'); const g = await r.json();
            const sel = document.getElementById('newHostGroup'); sel.innerHTML = '<option value="">No Group</option>';
            g.forEach(gr => sel.innerHTML += `<option value="${gr.id}">${gr.name}</option>`);
        }
        async function addHost() {
            const hostname = document.getElementById('newHostname').value.trim();
            const ip = document.getElementById('newHostIP').value.trim();
            const group = document.getElementById('newHostGroup').value;
            const os = document.getElementById('newHostOS').value;
            if (!hostname || !ip) { alert('Hostname and IP required'); return; }
            const r = await fetch('/api/hosts', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({hostname, ip, group_id: group||null, os_type: os}) });
            const data = await r.json();
            document.getElementById('addHostMessage').innerHTML = r.ok ? '<span style="color:green;">✅ Added</span>' : '<span style="color:red;">❌ ' + data.error + '</span>';
            fetchMonitoring();
        }
        async function startDiscovery() {
            await fetch('/api/discover/start', { method:'POST' });
            document.getElementById('discoveryStatus').innerText = 'Running...';
            const interval = setInterval(async () => {
                const r = await fetch('/api/discover/status'); const d = await r.json();
                document.getElementById('discoveryProgress').style.width = d.progress + '%';
                document.getElementById('discoveryMessage').innerText = d.message;
                if (!d.running) { clearInterval(interval); document.getElementById('discoveryStatus').innerText = 'Idle'; fetchMonitoring(); }
            }, 1000);
        }
        async function fetchMonitoring() {
            const r = await fetch('/api/hosts'); const data = await r.json();
            const tbody = document.querySelector('#monitoringTable tbody'); tbody.innerHTML = '';
            data.forEach(d => tbody.innerHTML += `<tr><td>${d.hostname}</td><td>${d.ip}</td><td class="status-${d.status}">${d.status}</td><td>Host (${d.os_type})</td></tr>`);
        }

        async function fetchEvents() {
            const host = document.getElementById('eventHost').value;
            const user = document.getElementById('eventUser').value;
            const type = document.getElementById('eventType').value;
            const start = document.getElementById('eventStart').value;
            const end = document.getElementById('eventEnd').value;
            let url = '/api/events?';
            if (host) url += 'hostname=' + host + '&';
            if (user) url += 'username=' + user + '&';
            if (type) url += 'event_type=' + type + '&';
            if (start) url += 'start=' + start + '&';
            if (end) url += 'end=' + end + '&';
            const r = await fetch(url); const data = await r.json();
            const tbody = document.querySelector('#eventsTable tbody'); tbody.innerHTML = '';
            data.forEach(e => tbody.innerHTML += `<tr><td>${e.event_time}</td><td>${e.hostname}</td><td>${e.user}</td><td>${e.event_type}</td><td>${e.details ? JSON.stringify(e.details) : ''}</td></tr>`);
        }

        async function fetchAlerts() {
            const sev = document.getElementById('alertSeverity').value;
            const status = document.getElementById('alertStatus').value;
            let url = '/api/alerts?';
            if (sev) url += 'severity=' + sev + '&';
            if (status) url += 'status=' + status + '&';
            const r = await fetch(url); const data = await r.json();
            const tbody = document.querySelector('#alertsTable tbody'); tbody.innerHTML = '';
            data.forEach(a => {
                let actions = `<button class="btn btn-sm btn-info" onclick="ackAlert(${a.id})">Ack</button>`;
                if (a.status === 'OPEN') actions += ` <button class="btn btn-sm btn-warning" onclick="suggest(${a.id})">Suggest</button>`;
                tbody.innerHTML += `<tr><td>${a.hostname}</td><td>${a.metric}</td><td>${a.value}</td><td>${a.severity}</td><td>${a.timestamp}</td><td class="status-${a.status}">${a.status}</td><td>${actions}</td></tr>`;
            });
        }
        async function ackAlert(id) { await fetch('/api/alerts/' + id + '/acknowledge', { method:'POST' }); fetchAlerts(); }
        async function suggest(id) { await fetch('/api/alerts/' + id + '/suggest', { method:'POST' }); fetchAlerts(); }

        async function fetchWindows() {
            const r = await fetch('/api/winrm/hosts'); const data = await r.json();
            const tbody = document.querySelector('#windowsTable tbody'); tbody.innerHTML = '';
            data.forEach(h => tbody.innerHTML += `<tr><td>${h.hostname}</td><td>${h.ip}</td><td class="status-${h.status}">${h.status}</td><td><button class="btn btn-sm btn-primary" onclick="execWinHost('${h.hostname}')">Exec</button></td></tr>`);
        }
        async function execWinCommand() {
            const cmd = document.getElementById('winCommand').value;
            const host = prompt('Enter Windows hostname:');
            if (!host || !cmd) return;
            const r = await fetch('/api/winrm/' + host + '/exec', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({command: cmd}) });
            const d = await r.json();
            document.getElementById('winOutput').innerText = d.output || d.error || 'Done.';
        }
        async function execWinHost(host) {
            const cmd = prompt('Enter command for ' + host + ':');
            if (!cmd) return;
            const r = await fetch('/api/winrm/' + host + '/exec', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({command: cmd}) });
            const d = await r.json();
            alert(d.output || d.error || 'Done.');
        }

        async function fetchRules() {
            const r = await fetch('/api/rules'); const data = await r.json();
            const tbody = document.querySelector('#rulesTable tbody'); tbody.innerHTML = '';
            data.forEach(rule => tbody.innerHTML += `<tr><td>${rule.id}</td><td>${rule.hostname}</td><td>${rule.metric}</td><td>${rule.threshold}</td><td>${rule.severity}</td><td>${rule.enabled ? '✅' : '❌'}</td><td><button class="btn btn-sm btn-warning" onclick="toggleRule(${rule.id})">Toggle</button> <button class="btn btn-sm btn-danger" onclick="delRule(${rule.id})">Del</button></td></tr>`);
        }
        async function createRule() {
            const data = {
                hostname: document.getElementById('ruleHost').value,
                metric: document.getElementById('ruleMetric').value,
                threshold: parseFloat(document.getElementById('ruleThreshold').value) || 0,
                operator: document.getElementById('ruleOp').value,
                severity: document.getElementById('ruleSev').value,
                cooldown: 300
            };
            await fetch('/api/rules', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) });
            fetchRules();
        }
        async function toggleRule(id) { await fetch('/api/rules/' + id + '/toggle', { method:'POST' }); fetchRules(); }
        async function delRule(id) { if (confirm('Delete?')) { await fetch('/api/rules/' + id, { method:'DELETE' }); fetchRules(); } }

        async function loadAdmin() {
            const r = await fetch('/api/users'); const users = await r.json();
            const tbody = document.querySelector('#usersTable tbody'); tbody.innerHTML = '';
            users.forEach(u => tbody.innerHTML += `<tr><td>${u.id}</td><td>${u.username}</td><td>${u.role}</td><td>${u.ldap ? 'Yes' : 'No'}</td><td><button class="btn btn-sm btn-danger" onclick="delUser(${u.id})">Del</button></td></tr>`);
            const gr = await fetch('/api/groups'); const groups = await gr.json();
            const gt = document.querySelector('#groupsTable tbody'); gt.innerHTML = '';
            groups.forEach(g => gt.innerHTML += `<tr><td>${g.id}</td><td>${g.name}</td><td><button class="btn btn-sm btn-danger" onclick="delGroup(${g.id})">Del</button></td></tr>`);
        }
        async function createUser() {
            const username = document.getElementById('newUname').value;
            const password = document.getElementById('newPass').value;
            const role = document.getElementById('newRole').value;
            await fetch('/api/users', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username, password, role}) });
            loadAdmin();
        }
        async function delUser(id) { if (confirm('Delete?')) { await fetch('/api/users/' + id, { method:'DELETE' }); loadAdmin(); } }
        async function createGroup() {
            const name = document.getElementById('newGroupName').value;
            await fetch('/api/groups', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name}) });
            loadAdmin();
        }
        async function delGroup(id) { if (confirm('Delete?')) { await fetch('/api/groups/' + id, { method:'DELETE' }); loadAdmin(); } }

        async function fetchAI() {
            const r = await fetch('/api/ai_insights'); const data = await r.json();
            const tbody = document.querySelector('#aiTable tbody'); tbody.innerHTML = '';
            data.forEach(item => {
                let details = '';
                if (item.details) {
                    try { const d = JSON.parse(item.details); details = d.days_remaining ? 'Full in ' + d.days_remaining.toFixed(1) + ' days' : d.slope ? 'Slope: ' + d.slope.toFixed(3) : ''; } catch(e) {}
                }
                tbody.innerHTML += `<tr><td>${item.hostname}</td><td>${item.metric}</td><td>${item.current_value}</td><td>${item.baseline_mean.toFixed(2)}±${item.baseline_std.toFixed(2)}</td><td>${item.deviation.toFixed(2)}</td><td class="status-${item.severity}">${item.severity}</td><td>${item.timestamp}</td><td>${details}</td></tr>`;
            });
        }

        fetchSummary(); fetchDevices(); loadTrendHosts(); fetchMonitoring(); fetchEvents(); fetchAlerts(); fetchWindows(); fetchRules(); loadAdmin(); fetchAI();
        setInterval(() => { if (document.getElementById('tab-dashboard').classList.contains('active')) { fetchDevices(); fetchSummary(); } }, 30000);
    </script>
</body>
</html>
DASHBOARD_HTML_END

cat > modules/web_ui/templates/login.html <<'LOGIN_HTML_END'
<!DOCTYPE html>
<html><head><title>SysWatch Login</title></head>
<body style="font-family:sans-serif;background:#f0f4f8;display:flex;justify-content:center;align-items:center;height:100vh;">
<div style="background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.1);width:320px;">
    <h2 style="text-align:center;">🔐 SysWatch</h2>
    {% if error %}<p style="color:red;text-align:center;">{{ error }}</p>{% endif %}
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required style="width:100%;padding:10px;margin-bottom:10px;border:1px solid #ccc;border-radius:6px;">
        <input type="password" name="password" placeholder="Password" required style="width:100%;padding:10px;margin-bottom:10px;border:1px solid #ccc;border-radius:6px;">
        <button type="submit" style="width:100%;padding:10px;background:#3498db;color:#fff;border:none;border-radius:6px;font-weight:bold;cursor:pointer;">Log in</button>
    </form>
</div>
</body>
</html>
LOGIN_HTML_END

# ----------------------------------------------------------------------
# 5. MODULES – API
# ----------------------------------------------------------------------
cat > modules/api/__init__.py <<'API_INIT_END'
# modules/api/__init__.py
API_INIT_END

cat > modules/api/routes.py <<'API_ROUTES_END'
import json, datetime, pymysql, ipaddress, subprocess, threading, socket
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from core.config import Config
from core.database import get_db
from modules.monitoring_checks.status_updater import update_host_status
from modules.alert_engine.lifecycle import evaluate_alerts
from modules.remote_exec.executor import ssh_exec, winrm_exec
from modules.discovery.sweep import run_discovery_sweep

bp = Blueprint('api', __name__)

@bp.route('/report', methods=['POST'])
def report():
    if request.headers.get('X-API-Key') != Config.API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(force=True)
    hostname = data['hostname']
    agent_id = data.get('agent_id', '')
    ip = data['ip']
    group_id = data.get('group_id', None)
    os_type = data.get('os_type', 'linux')
    update_host_status(hostname, agent_id, ip, group_id, os_type)

    db = get_db()
    cur = db.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cur.execute(
        "INSERT INTO metrics (hostname, ip, timestamp, cpu, memory, disk, "
        "network_sent, network_recv, services, network_devices, uptime) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (hostname, ip, now, data['cpu'], data['memory'], data['disk'],
         data.get('network_sent', 0), data.get('network_recv', 0),
         json.dumps(data.get('services', {})), json.dumps(data.get('network_devices', [])),
         data['uptime'])
    )
    db.commit()
    evaluate_alerts(hostname, data)
    cur.close()
    return jsonify({"status": "ok"})

@bp.route('/latest')
@login_required
def latest():
    group_filter = request.args.get('group', '')
    status_filter = request.args.get('status', '')
    db = get_db()
    cur = db.cursor()
    query = """
        SELECT h.hostname, h.agent_id, h.ip, h.status, h.last_seen,
               h.group_id, g.name as group_name, h.os_type,
               m.cpu, m.memory, m.disk, m.network_sent, m.network_recv,
               m.services, m.network_devices
        FROM hosts h
        LEFT JOIN host_groups g ON h.group_id = g.id
        LEFT JOIN (
            SELECT hostname, MAX(timestamp) as max_ts FROM metrics GROUP BY hostname
        ) latest ON h.hostname = latest.hostname
        LEFT JOIN metrics m ON m.hostname = latest.hostname AND m.timestamp = latest.max_ts
        WHERE 1=1
    """
    params = []
    if group_filter:
        query += " AND h.group_id = %s"
        params.append(group_filter)
    if status_filter:
        query += " AND h.status = %s"
        params.append(status_filter)
    query += " ORDER BY h.hostname"
    cur.execute(query, params)
    rows = cur.fetchall()
    result = []
    for r in rows:
        result.append({
            "hostname": r[0], "agent_id": r[1], "ip": r[2], "status": r[3],
            "last_seen": r[4].isoformat() if r[4] else None,
            "group_id": r[5], "group_name": r[6] or "None", "os_type": r[7],
            "cpu": r[8], "memory": r[9], "disk": r[10],
            "network_sent": r[11], "network_recv": r[12],
            "services": json.loads(r[13]) if r[13] else {},
            "network_devices": json.loads(r[14]) if r[14] else []
        })
    cur.close()
    return jsonify(result)

@bp.route('/trends/<hostname>')
@login_required
def trends(hostname):
    range_ = request.args.get('range', '1h')
    db = get_db()
    cur = db.cursor()
    intervals = {'1h':"1 HOUR",'6h':"6 HOUR",'12h':"12 HOUR",'24h':"24 HOUR",'7d':"7 DAY",'30d':"30 DAY"}
    if range_ in intervals:
        cur.execute(f"SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL {intervals[range_]} ORDER BY timestamp ASC", (hostname,))
    else:
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s ORDER BY timestamp ASC LIMIT 100", (hostname,))
    rows = cur.fetchall()
    data = [{"timestamp": r[0].isoformat(), "cpu": r[1], "memory": r[2], "disk": r[3]} for r in rows]
    cur.close()
    return jsonify(data)

@bp.route('/alerts')
@login_required
def alerts_api():
    status_filter = request.args.get('status', '')
    host_filter = request.args.get('host', '')
    db = get_db()
    cur = db.cursor()
    query = "SELECT id, hostname, metric, value, severity, timestamp, status FROM alerts"
    params = []
    if status_filter:
        query += " WHERE status = %s"
        params.append(status_filter)
    if host_filter:
        query += " AND hostname = %s" if 'WHERE' in query else " WHERE hostname = %s"
        params.append(host_filter)
    query += " ORDER BY timestamp DESC LIMIT 500"
    cur.execute(query, params)
    rows = cur.fetchall()
    alerts = [{"id": r[0], "hostname": r[1], "metric": r[2], "value": r[3],
               "severity": r[4], "timestamp": r[5].isoformat(), "status": r[6]} for r in rows]
    cur.close()
    return jsonify(alerts)

@bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    if not current_user.has_permission('alerts:ack'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE alerts SET status = 'ACKNOWLEDGED', acknowledged_by = %s, acknowledged_at = NOW() WHERE id = %s",
                (current_user.username, alert_id))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

@bp.route('/events')
@login_required
def events_api():
    if not current_user.has_permission('events:view'):
        return jsonify({"error": "Permission denied"}), 403
    hostname = request.args.get('hostname', '')
    username = request.args.get('username', '')
    event_type = request.args.get('event_type', '')
    start = request.args.get('start', '')
    end = request.args.get('end', '')
    db = get_db()
    cur = db.cursor()
    query = "SELECT id, hostname, event_type, event_time, source, user, details FROM events WHERE 1=1"
    params = []
    if hostname:
        query += " AND hostname LIKE %s"
        params.append(f'%{hostname}%')
    if username:
        query += " AND user LIKE %s"
        params.append(f'%{username}%')
    if event_type:
        query += " AND event_type = %s"
        params.append(event_type)
    if start:
        query += " AND event_time >= %s"
        params.append(start)
    if end:
        query += " AND event_time <= %s"
        params.append(end + ' 23:59:59')
    query += " ORDER BY event_time DESC LIMIT 500"
    cur.execute(query, params)
    rows = cur.fetchall()
    events = [{"id": r[0], "hostname": r[1], "event_type": r[2], "event_time": r[3].isoformat(),
               "source": r[4], "user": r[5], "details": json.loads(r[6]) if r[6] else {}} for r in rows]
    cur.close()
    return jsonify(events)

@bp.route('/groups')
@login_required
def list_groups():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, name FROM host_groups ORDER BY name")
    groups = [{"id": r[0], "name": r[1]} for r in cur.fetchall()]
    cur.close()
    return jsonify(groups)

@bp.route('/groups', methods=['POST'])
@login_required
def create_group():
    if not current_user.has_permission('users:manage'):
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({"error": "Group name required"}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO host_groups (name) VALUES (%s)", (name,))
        db.commit()
        return jsonify({"id": cur.lastrowid, "name": name})
    except pymysql.IntegrityError:
        return jsonify({"error": "Group already exists"}), 409
    finally:
        cur.close()

@bp.route('/groups/<int:group_id>', methods=['DELETE'])
@login_required
def delete_group(group_id):
    if not current_user.has_permission('users:manage'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM host_groups WHERE id = %s", (group_id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

@bp.route('/summary')
@login_required
def summary():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*), SUM(status='UP'), SUM(status='WARNING'), SUM(status='DOWN') FROM hosts")
    row = cur.fetchone()
    total, up, warning, down = row[0], row[1] or 0, row[2] or 0, row[3] or 0
    cur.execute("SELECT COUNT(*) FROM alerts WHERE status = 'OPEN'")
    open_alerts = cur.fetchone()[0]
    cur.close()
    return jsonify({"total": total, "up": up, "warning": warning, "down": down, "open_alerts": open_alerts})

@bp.route('/rules', methods=['GET'])
@login_required
def list_rules():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, hostname, metric, threshold, operator, severity, cooldown, enabled FROM alert_rules ORDER BY hostname, metric")
    rows = cur.fetchall()
    rules = [{"id": r[0], "hostname": r[1], "metric": r[2], "threshold": r[3],
              "operator": r[4], "severity": r[5], "cooldown": r[6], "enabled": bool(r[7])} for r in rows]
    cur.close()
    return jsonify(rules)

@bp.route('/rules', methods=['POST'])
@login_required
def create_rule():
    if not current_user.has_permission('settings:manage'):
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    required = ['hostname', 'metric', 'threshold', 'operator', 'severity', 'cooldown']
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "INSERT INTO alert_rules (hostname, metric, threshold, operator, severity, cooldown, cause, action, enabled) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (data['hostname'], data['metric'], data['threshold'], data['operator'],
             data['severity'], data['cooldown'], data.get('cause', ''), data.get('action', ''), 1)
        )
        db.commit()
        return jsonify({"status": "ok", "id": cur.lastrowid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()

@bp.route('/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
def toggle_rule(rule_id):
    if not current_user.has_permission('settings:manage'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE alert_rules SET enabled = NOT enabled WHERE id = %s", (rule_id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

@bp.route('/rules/<int:rule_id>', methods=['DELETE'])
@login_required
def delete_rule(rule_id):
    if not current_user.has_permission('settings:manage'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM alert_rules WHERE id = %s", (rule_id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

@bp.route('/hosts', methods=['GET'])
@login_required
def list_hosts():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname, ip, status, group_id, os_type, last_seen FROM hosts ORDER BY hostname")
    rows = cur.fetchall()
    hosts = [{"hostname": r[0], "ip": r[1], "status": r[2], "group_id": r[3], "os_type": r[4], "last_seen": r[5].isoformat() if r[5] else None} for r in rows]
    cur.close()
    return jsonify(hosts)

@bp.route('/hosts', methods=['POST'])
@login_required
def add_host():
    if not current_user.has_permission('hosts:manage'):
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    hostname = data.get('hostname')
    ip = data.get('ip')
    group_id = data.get('group_id')
    os_type = data.get('os_type', 'linux')
    if not hostname or not ip:
        return jsonify({"error": "Hostname and IP required"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname FROM hosts WHERE hostname = %s", (hostname,))
    if cur.fetchone():
        return jsonify({"error": "Host already exists"}), 409
    cur.execute(
        "INSERT INTO hosts (hostname, ip, last_seen, status, group_id, os_type, discovered_by, discovery_time) "
        "VALUES (%s, %s, NOW(), 'UP', %s, %s, 'manual', NOW())",
        (hostname, ip, group_id, os_type)
    )
    db.commit()
    cur.close()
    return jsonify({"status": "ok", "hostname": hostname})

@bp.route('/hosts/<hostname>/exec', methods=['POST'])
@login_required
def execute_command(hostname):
    if not current_user.has_permission('exec:run'):
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    command = data.get('command')
    if not command:
        return jsonify({"error": "Command required"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip, os_type FROM hosts WHERE hostname = %s", (hostname,))
    row = cur.fetchone()
    cur.close()
    if not row:
        return jsonify({"error": "Host not found"}), 404
    ip, os_type = row
    try:
        if os_type == 'windows':
            stdout, stderr = winrm_exec(ip, command)
        else:
            stdout, stderr = ssh_exec(ip, command)
        return jsonify({"status": "ok", "output": stdout, "error": stderr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route('/ai_insights')
@login_required
def ai_insights():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname, metric, current_value, baseline_mean, baseline_std, deviation, severity, timestamp, details FROM ai_insights ORDER BY timestamp DESC LIMIT 100")
    rows = cur.fetchall()
    insights = [{"hostname": r[0], "metric": r[1], "current_value": r[2],
                 "baseline_mean": r[3], "baseline_std": r[4], "deviation": r[5],
                 "severity": r[6], "timestamp": r[7].isoformat() if r[7] else None, "details": r[8]} for r in rows]
    cur.close()
    return jsonify(insights)

@bp.route('/pending')
@login_required
def pending_hosts():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, ip_address, os_type, detected_at, status FROM pending_hosts WHERE status = 'pending'")
    rows = cur.fetchall()
    pending = [{"id": r[0], "ip": r[1], "os_type": r[2], "detected_at": r[3].isoformat(), "status": r[4]} for r in rows]
    cur.close()
    return jsonify(pending)

@bp.route('/pending/<int:id>/approve', methods=['POST'])
@login_required
def approve_pending(id):
    if not current_user.has_permission('hosts:deploy'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip_address, os_type FROM pending_hosts WHERE id = %s AND status = 'pending'", (id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "No pending host found"}), 404
    ip, os_type = row
    from modules.remote_exec.executor import deploy_agent
    success, msg = deploy_agent(ip, os_type)
    if success:
        cur.execute("UPDATE pending_hosts SET status = 'approved', approved_at = NOW() WHERE id = %s", (id,))
        db.commit()
        return jsonify({"status": "ok", "message": "Agent deployment initiated"})
    else:
        return jsonify({"error": msg}), 500

@bp.route('/pending/<int:id>/reject', methods=['POST'])
@login_required
def reject_pending(id):
    if not current_user.has_permission('hosts:manage'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE pending_hosts SET status = 'rejected' WHERE id = %s", (id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

discovery_status = {"running": False, "progress": 0, "total": 0, "found": 0, "message": ""}

@bp.route('/discover/start', methods=['POST'])
@login_required
def start_discovery():
    if not current_user.has_permission('hosts:manage'):
        return jsonify({"error": "Permission denied"}), 403
    if discovery_status["running"]:
        return jsonify({"error": "Discovery already running"}), 409
    threading.Thread(target=run_discovery_sweep).start()
    return jsonify({"status": "started"})

@bp.route('/discover/status')
@login_required
def discovery_status_endpoint():
    return jsonify(discovery_status)

@bp.route('/alerts/<int:alert_id>/suggest', methods=['POST'])
@login_required
def suggest_remediation(alert_id):
    if not current_user.has_permission('alerts:remediate'):
        return jsonify({"error": "Permission denied"}), 403
    from modules.remediation.suggest import generate_suggestion
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname, metric, value, threshold, severity, cause FROM alerts WHERE id = %s", (alert_id,))
    alert = cur.fetchone()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    hostname, metric, value, threshold, severity, cause = alert
    suggestion, command = generate_suggestion(hostname, metric, value, threshold, severity, cause)
    if suggestion:
        cur.execute("UPDATE alerts SET ai_suggestion = %s, ai_suggestion_id = %s WHERE id = %s",
                    (suggestion, command, alert_id))
        db.commit()
        cur.close()
        return jsonify({"suggestion": suggestion, "command": command})
    cur.close()
    return jsonify({"error": "No suggestion available"}), 404

@bp.route('/alerts/<int:alert_id>/dryrun', methods=['POST'])
@login_required
def dryrun_remediation(alert_id):
    if not current_user.has_permission('alerts:remediate'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname, ai_suggestion_id FROM alerts WHERE id = %s", (alert_id,))
    alert = cur.fetchone()
    if not alert or not alert[1]:
        return jsonify({"error": "No suggestion to dry-run"}), 404
    hostname, command = alert
    cur.execute("SELECT ip, os_type FROM hosts WHERE hostname = %s", (hostname,))
    host = cur.fetchone()
    if not host:
        return jsonify({"error": "Host not found"}), 404
    ip, os_type = host
    try:
        if os_type == 'windows':
            stdout, stderr = winrm_exec(ip, f"echo 'DRY RUN: {command}' && {command} --dry-run")
        else:
            stdout, stderr = ssh_exec(ip, f"echo 'DRY RUN: {command}' && {command} --dry-run")
        cur.execute("INSERT INTO remediation_tasks (alert_id, action_type, action_command, status, dry_run_output) "
                    "VALUES (%s, 'dry_run', %s, 'dry_run', %s)", (alert_id, command, stdout + stderr))
        db.commit()
        cur.close()
        return jsonify({"output": stdout, "error": stderr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route('/alerts/<int:alert_id>/execute', methods=['POST'])
@login_required
def execute_remediation(alert_id):
    if not current_user.has_permission('alerts:remediate'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname, ai_suggestion_id FROM alerts WHERE id = %s", (alert_id,))
    alert = cur.fetchone()
    if not alert or not alert[1]:
        return jsonify({"error": "No suggestion to execute"}), 404
    hostname, command = alert
    cur.execute("SELECT ip, os_type FROM hosts WHERE hostname = %s", (hostname,))
    host = cur.fetchone()
    if not host:
        return jsonify({"error": "Host not found"}), 404
    ip, os_type = host
    try:
        if os_type == 'windows':
            stdout, stderr = winrm_exec(ip, command)
        else:
            stdout, stderr = ssh_exec(ip, command)
        cur.execute("INSERT INTO remediation_tasks (alert_id, action_type, action_command, status, execution_output, executed_at, executed_by) "
                    "VALUES (%s, 'execution', %s, 'executed', %s, NOW(), %s)", (alert_id, command, stdout + stderr, current_user.username))
        if not stderr:
            cur.execute("UPDATE alerts SET status = 'RESOLVED', resolved_at = NOW() WHERE id = %s", (alert_id,))
        db.commit()
        cur.close()
        return jsonify({"output": stdout, "error": stderr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route('/winrm/hosts')
@login_required
def winrm_hosts():
    if not current_user.has_permission('windows:view'):
        return jsonify({"error": "Permission denied"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname, ip, status FROM hosts WHERE os_type = 'windows'")
    rows = cur.fetchall()
    hosts = [{"hostname": r[0], "ip": r[1], "status": r[2]} for r in rows]
    cur.close()
    return jsonify(hosts)

@bp.route('/winrm/<hostname>/exec', methods=['POST'])
@login_required
def winrm_execute(hostname):
    if not current_user.has_permission('windows:manage'):
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    command = data.get('command')
    if not command:
        return jsonify({"error": "Command required"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip FROM hosts WHERE hostname = %s AND os_type = 'windows'", (hostname,))
    row = cur.fetchone()
    cur.close()
    if not row:
        return jsonify({"error": "Windows host not found"}), 404
    ip = row[0]
    try:
        stdout, stderr = winrm_exec(ip, command)
        return jsonify({"status": "ok", "output": stdout, "error": stderr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
API_ROUTES_END

# ----------------------------------------------------------------------
# 6. MODULES – MONITORING CHECKS
# ----------------------------------------------------------------------
cat > modules/monitoring_checks/__init__.py <<'MON_INIT_END'
# modules/monitoring_checks/__init__.py
MON_INIT_END

cat > modules/monitoring_checks/status_updater.py <<'STATUS_UPDATER_END'
import datetime
from core.database import get_db
from core.app import app

STATUS_THRESHOLDS = {"UP": 90, "WARNING": 300}

def update_host_status(hostname, agent_id, ip, group_id=None, os_type='linux'):
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cur.execute(
            "INSERT INTO hosts (hostname, agent_id, ip, last_seen, status, group_id, os_type) "
            "VALUES (%s, %s, %s, %s, 'UP', %s, %s) "
            "ON DUPLICATE KEY UPDATE agent_id = VALUES(agent_id), ip = VALUES(ip), "
            "last_seen = VALUES(last_seen), group_id = VALUES(group_id), os_type = VALUES(os_type)",
            (hostname, agent_id, ip, now, group_id, os_type)
        )
        db.commit()
        cur.close()

def compute_status():
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT hostname, last_seen FROM hosts")
        rows = cur.fetchall()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        for hostname, last_seen in rows:
            if last_seen is None:
                status = "DOWN"
            else:
                delta = (now - last_seen).total_seconds()
                if delta < STATUS_THRESHOLDS["UP"]:
                    status = "UP"
                elif delta < STATUS_THRESHOLDS["WARNING"]:
                    status = "WARNING"
                else:
                    status = "DOWN"
            cur.execute("UPDATE hosts SET status = %s WHERE hostname = %s", (status, hostname))
        db.commit()
        cur.close()
STATUS_UPDATER_END

cat > modules/monitoring_checks/ssl_expiry.py <<'SSL_EXPIRY_END'
import ssl, socket, datetime, OpenSSL.crypto
from core.database import get_db
from core.app import app
from modules.alert_engine.notifiers import dispatch_alert

def fetch_cert_expiry(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                expiry_bytes = cert.get_notAfter()
                expiry_str = expiry_bytes.decode('ascii')
                expiry_date = datetime.datetime.strptime(expiry_str, '%Y%m%d%H%M%SZ').date()
                return expiry_date
    except Exception as e:
        print(f"SSL fetch error: {e}")
        return None

def check_all_certificates():
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT DISTINCT hostname, ip FROM hosts WHERE ip IS NOT NULL AND ip != '127.0.0.1'")
        hosts = cur.fetchall()
        today = datetime.date.today()
        for hostname, ip in hosts:
            cur.execute("SELECT expiry_date FROM ssl_certificates WHERE hostname = %s AND port = 443", (hostname,))
            row = cur.fetchone()
            if row:
                stored_expiry = row[0]
                days_remaining = (stored_expiry - today).days
                if 0 <= days_remaining <= 7:
                    severity = "WARNING" if days_remaining > 2 else "CRITICAL"
                    dispatch_alert(hostname, "ssl_expiry", days_remaining, 7, severity,
                                   f"SSL expires in {days_remaining} days", "Renew the certificate.")
                elif days_remaining < 0:
                    dispatch_alert(hostname, "ssl_expiry", days_remaining, 0, "CRITICAL",
                                   f"SSL expired on {stored_expiry}", "Renew immediately.")
                cur.execute("UPDATE ssl_certificates SET last_checked = NOW() WHERE hostname = %s AND port = 443", (hostname,))
                db.commit()
            else:
                expiry_date = fetch_cert_expiry(hostname, 443)
                if expiry_date:
                    cur.execute("INSERT INTO ssl_certificates (hostname, port, expiry_date, last_checked) VALUES (%s, 443, %s, NOW())",
                                (hostname, expiry_date))
                    db.commit()
        cur.close()
SSL_EXPIRY_END

# ----------------------------------------------------------------------
# 7. MODULES – ALERT ENGINE
# ----------------------------------------------------------------------
cat > modules/alert_engine/__init__.py <<'ALERT_ENGINE_INIT_END'
# modules/alert_engine/__init__.py
ALERT_ENGINE_INIT_END

cat > modules/alert_engine/lifecycle.py <<'LIFECYCLE_END'
import datetime, logging
from core.database import get_db
from modules.alert_engine.notifiers import dispatch_alert

logger = logging.getLogger(__name__)

def evaluate_alerts(hostname, data):
    try:
        db = get_db()
        cur = db.cursor()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cur.execute("SELECT * FROM alert_rules WHERE (hostname = %s OR hostname = '%' OR hostname IS NULL) AND enabled=1", (hostname,))
        rules = cur.fetchall()
        if not rules:
            return
        for rule in rules:
            metric = rule[2]
            if metric not in data:
                continue
            value = data[metric]
            op = rule[4]
            threshold = rule[3]
            severity = rule[5]
            cooldown = rule[6]
            cause = rule[7] if len(rule) > 7 else None
            action = rule[8] if len(rule) > 8 else None
            violated = False
            if op == ">" and value > threshold:
                violated = True
            elif op == "<" and value < threshold:
                violated = True
            if violated:
                cur.execute("SELECT id, timestamp, status FROM alerts WHERE hostname=%s AND metric=%s AND status IN ('OPEN','ACKNOWLEDGED') ORDER BY timestamp DESC LIMIT 1", (hostname, metric))
                existing = cur.fetchone()
                fire = True
                if existing:
                    last_time = existing[1]
                    if (now - last_time).total_seconds() < cooldown:
                        fire = False
                if fire:
                    cur.execute("INSERT INTO alerts (hostname, metric, value, threshold, severity, cause, action, status) VALUES (%s, %s, %s, %s, %s, %s, %s, 'OPEN')",
                                (hostname, metric, value, threshold, severity, cause, action))
                    db.commit()
                    dispatch_alert(hostname, metric, value, threshold, severity, cause, action)
            else:
                cur.execute("UPDATE alerts SET status = 'RESOLVED', resolved = 1, resolved_at = %s WHERE hostname = %s AND metric = %s AND status IN ('OPEN','ACKNOWLEDGED')",
                            (now, hostname, metric))
                db.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Error in evaluate_alerts: {e}", exc_info=True)
LIFECYCLE_END

cat > modules/alert_engine/auto_resolve.py <<'AUTO_RESOLVE_END'
import datetime, logging
from core.database import get_db

logger = logging.getLogger(__name__)

def auto_resolve_stale_alerts():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT id, hostname, metric, threshold, operator
        FROM alerts
        WHERE status = 'ACKNOWLEDGED'
        AND acknowledged_at IS NOT NULL
        AND acknowledged_at < NOW() - INTERVAL 10 MINUTE
    """)
    alerts = cur.fetchall()
    for alert in alerts:
        alert_id, hostname, metric, threshold, operator = alert
        cur.execute(f"SELECT {metric} FROM metrics WHERE hostname = %s ORDER BY timestamp DESC LIMIT 1", (hostname,))
        row = cur.fetchone()
        if row:
            current_value = row[0]
            violated = False
            if operator == ">" and current_value > threshold:
                violated = True
            elif operator == "<" and current_value < threshold:
                violated = True
            if not violated:
                cur.execute("UPDATE alerts SET status = 'RESOLVED', resolved = 1, resolved_at = NOW() WHERE id = %s", (alert_id,))
                db.commit()
                logger.info(f"Auto-resolved alert {alert_id}")
    cur.close()
AUTO_RESOLVE_END

cat > modules/alert_engine/notifiers.py <<'NOTIFIERS_END'
import smtplib, requests, datetime
from email.mime.text import MIMEText
from core.config import Config

def send_email(subject, body):
    if not Config.SMTP_USER or not Config.SMTP_PASSWORD:
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = Config.SMTP_USER
        msg['To'] = Config.ALERT_EMAIL_TO
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as s:
            s.starttls()
            s.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
            s.sendmail(Config.SMTP_USER, [Config.ALERT_EMAIL_TO], msg.as_string())
    except Exception as e:
        print(f"Email error: {e}")

def send_teams(title, text):
    if not Config.TEAMS_WEBHOOK_URL:
        return
    try:
        requests.post(Config.TEAMS_WEBHOOK_URL, json={"title": title, "text": text, "themeColor": "FF0000"})
    except Exception as e:
        print(f"Teams error: {e}")

def dispatch_alert(hostname, metric, value, threshold, severity, cause, action):
    subject = f"{severity.upper()}: {hostname} {metric} = {value:.1f}%"
    body = f"""Host: {hostname}
Metric: {metric}
Value: {value:.1f}%
Threshold: {threshold}
Severity: {severity}
Cause: {cause or 'N/A'}
Action: {action or 'N/A'}
Time: {datetime.datetime.utcnow().isoformat()}"""
    send_email(subject, body)
    send_teams(subject, body)
NOTIFIERS_END

# ----------------------------------------------------------------------
# 8. MODULES – AI
# ----------------------------------------------------------------------
cat > modules/ai/__init__.py <<'AI_INIT_END'
# modules/ai/__init__.py
AI_INIT_END

cat > modules/ai/deepseek.py <<'DEEPSEEK_END'
import json, requests, logging
from core.config import Config

logger = logging.getLogger(__name__)

DEEPSEEK_API_KEY = Config.DEEPSEEK_API_KEY
DEEPSEEK_API_URL = Config.DEEPSEEK_API_URL
DEEPSEEK_MODEL = Config.DEEPSEEK_MODEL
GEMINI_API_KEY = Config.GEMINI_API_KEY
GEMINI_API_URL = Config.GEMINI_API_URL

def analyze_with_deepseek(analysis_type, context):
    if not DEEPSEEK_API_KEY and not GEMINI_API_KEY:
        logger.info("No AI API key configured.")
        return None

    system_prompt = "You are SysWatch AI. Respond in JSON format with keys: analysis_type, severity, summary, details, recommendation, confidence."
    user_prompt = f"Analysis Type: {analysis_type}\nContext: {json.dumps(context, indent=2)}"

    if DEEPSEEK_API_KEY:
        try:
            payload = {
                "model": DEEPSEEK_MODEL,
                "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                "temperature": 0.3,
                "response_format": {"type": "json_object"}
            }
            resp = requests.post(DEEPSEEK_API_URL, headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}, json=payload, timeout=30)
            if resp.status_code == 200:
                content = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
                return json.loads(content)
            else:
                logger.warning(f"DeepSeek error: {resp.status_code}")
        except Exception as e:
            logger.warning(f"DeepSeek exception: {e}")

    if GEMINI_API_KEY:
        try:
            payload = {"contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}]}
            resp = requests.post(f"{GEMINI_API_URL}?key={GEMINI_API_KEY}", json=payload, timeout=30)
            if resp.status_code == 200:
                text = resp.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                import re
                json_match = re.search(r'\{.*\}', text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(0))
                return {"summary": text[:200], "recommendation": "Check Gemini response."}
            else:
                logger.warning(f"Gemini error: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Gemini exception: {e}")

    logger.info("All AI providers failed.")
    return None
DEEPSEEK_END

cat > modules/ai/anomaly.py <<'ANOMALY_END'
import statistics, logging, datetime, json
from core.database import get_db
from core.app import app
from modules.alert_engine.notifiers import dispatch_alert
from modules.ai.deepseek import analyze_with_deepseek

logger = logging.getLogger(__name__)

def run_anomaly_detection():
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT DISTINCT hostname FROM hosts WHERE status != 'DOWN'")
        hosts = cur.fetchall()
        if not hosts: return
        for (hostname,) in hosts:
            for metric in ['cpu', 'memory', 'disk']:
                cur.execute(f"SELECT {metric} FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL 7 DAY AND {metric} IS NOT NULL ORDER BY timestamp DESC LIMIT 100", (hostname,))
                rows = cur.fetchall()
                if len(rows) < 10: continue
                values = [r[0] for r in rows]
                mean = statistics.mean(values)
                std = statistics.stdev(values) if len(values) > 1 else 0
                if std == 0: continue
                cur.execute(f"SELECT {metric} FROM metrics WHERE hostname = %s AND {metric} IS NOT NULL ORDER BY timestamp DESC LIMIT 1", (hostname,))
                current_row = cur.fetchone()
                if not current_row: continue
                current_value = current_row[0]
                if current_value > mean + (2 * std):
                    deviation = (current_value - mean) / std
                    severity = "WARNING" if deviation < 3 else "CRITICAL"
                    details = {"deviation": deviation, "mean": mean, "std": std}
                    ai_analysis = analyze_with_deepseek("anomaly", {"hostname": hostname, "metric": metric, "current_value": current_value, "baseline_mean": mean, "baseline_std": std})
                    if ai_analysis:
                        details["ai_summary"] = ai_analysis.get("summary", "")
                        details["ai_recommendation"] = ai_analysis.get("recommendation", "")
                    cur.execute("INSERT INTO ai_insights (hostname, metric, current_value, baseline_mean, baseline_std, deviation, severity, details) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                                (hostname, metric, current_value, mean, std, deviation, severity, json.dumps(details)))
                    db.commit()
                    dispatch_alert(hostname, f"ai_{metric}", current_value, round(mean + 2*std, 2), severity,
                                   f"AI anomaly: {metric} exceeded baseline. {ai_analysis.get('summary', '') if ai_analysis else ''}",
                                   ai_analysis.get("recommendation", "Investigate recent changes.") if ai_analysis else "Investigate recent changes.")
        cur.close()

def run_predictions():
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT hostname FROM hosts WHERE status != 'DOWN'")
        hosts = cur.fetchall()
        for (hostname,) in hosts:
            cur.execute("SELECT disk, UNIX_TIMESTAMP(timestamp) as ts FROM metrics WHERE hostname = %s AND disk IS NOT NULL AND timestamp >= NOW() - INTERVAL 7 DAY ORDER BY timestamp ASC", (hostname,))
            rows = cur.fetchall()
            if len(rows) >= 2:
                values = [r[0] for r in rows]; times = [r[1] for r in rows]
                n = len(times); sum_x = sum(times); sum_y = sum(values); sum_xy = sum([t*v for t,v in zip(times, values)]); sum_x2 = sum([t**2 for t in times])
                denom = n*sum_x2 - sum_x**2
                if denom != 0:
                    slope = (n*sum_xy - sum_x*sum_y) / denom
                    if slope > 0:
                        last_value = values[-1]
                        if last_value < 95:
                            days_to_full = (95 - last_value) / (slope * 86400)
                            if days_to_full < 30:
                                severity = "WARNING" if days_to_full > 7 else "CRITICAL"
                                details = {"days_remaining": days_to_full}
                                ai_analysis = analyze_with_deepseek("prediction", {"hostname": hostname, "metric": "disk", "days_to_full": days_to_full})
                                if ai_analysis:
                                    details["ai_summary"] = ai_analysis.get("summary", "")
                                    details["ai_recommendation"] = ai_analysis.get("recommendation", "")
                                cur.execute("INSERT INTO ai_insights (hostname, metric, current_value, baseline_mean, baseline_std, deviation, severity, details) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                                            (hostname, "prediction_disk_full", days_to_full, 0, 0, 0, severity, json.dumps(details)))
                                db.commit()
                                dispatch_alert(hostname, "prediction_disk_full", days_to_full, 0, severity,
                                               f"Disk full in {days_to_full:.1f} days. {ai_analysis.get('summary', '') if ai_analysis else ''}",
                                               ai_analysis.get("recommendation", "Extend volume or clean up.") if ai_analysis else "Extend volume or clean up.")
            cur.execute("SELECT memory, UNIX_TIMESTAMP(timestamp) as ts FROM metrics WHERE hostname = %s AND memory IS NOT NULL AND timestamp >= NOW() - INTERVAL 7 DAY ORDER BY timestamp ASC", (hostname,))
            rows = cur.fetchall()
            if len(rows) >= 2:
                values = [r[0] for r in rows]; times = [r[1] for r in rows]
                n = len(times); sum_x = sum(times); sum_y = sum(values); sum_xy = sum([t*v for t,v in zip(times, values)]); sum_x2 = sum([t**2 for t in times])
                denom = n*sum_x2 - sum_x**2
                if denom != 0:
                    slope = (n*sum_xy - sum_x*sum_y) / denom
                    if slope > 0.1:
                        severity = "WARNING" if slope < 0.2 else "CRITICAL"
                        details = {"slope": slope}
                        ai_analysis = analyze_with_deepseek("prediction", {"hostname": hostname, "metric": "memory", "slope": slope})
                        if ai_analysis:
                            details["ai_summary"] = ai_analysis.get("summary", "")
                            details["ai_recommendation"] = ai_analysis.get("recommendation", "")
                        cur.execute("INSERT INTO ai_insights (hostname, metric, current_value, baseline_mean, baseline_std, deviation, severity, details) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                                    (hostname, "memory_leak_detected", slope, 0, 0, 0, severity, json.dumps(details)))
                        db.commit()
                        dispatch_alert(hostname, "memory_leak_detected", slope, 0, severity,
                                       f"Memory increasing (slope {slope:.2f}). {ai_analysis.get('summary', '') if ai_analysis else ''}",
                                       ai_analysis.get("recommendation", "Check for memory leaks.") if ai_analysis else "Check for memory leaks.")
        cur.close()

def send_daily_briefing():
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= NOW() - INTERVAL 1 DAY")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= NOW() - INTERVAL 1 DAY AND status='OPEN'")
        open_ = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM hosts WHERE discovery_time >= NOW() - INTERVAL 1 DAY")
        new = cur.fetchone()[0]
        context = {"total_alerts": total, "open_alerts": open_, "new_hosts": new}
        ai_analysis = analyze_with_deepseek("briefing", context)
        if ai_analysis:
            body = f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\n\n{ai_analysis.get('summary', 'No changes.')}"
            dispatch_alert("SysWatch", "daily_briefing", 0, 0, "INFO", body, "Review briefing.")
        else:
            body = f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\nTotal: {total}\nOpen: {open_}\nNew Hosts: {new}"
            dispatch_alert("SysWatch", "daily_briefing", 0, 0, "INFO", body, "Review briefing.")
        cur.close()
ANOMALY_END

# ----------------------------------------------------------------------
# 9. MODULES – REMOTE EXEC, DISCOVERY, REMEDIATION
# ----------------------------------------------------------------------
cat > modules/remote_exec/__init__.py <<'REMOTE_INIT_END'
# modules/remote_exec/__init__.py
REMOTE_INIT_END

cat > modules/remote_exec/executor.py <<'EXECUTOR_END'
import os, paramiko, winrm
from core.config import Config

def ssh_exec(ip, command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key_path = Config.SSH_PRIVATE_KEY_PATH
    ssh.connect(ip, username=Config.SSH_USER, key_filename=key_path, timeout=Config.SSH_TIMEOUT)
    stdin, stdout, stderr = ssh.exec_command(command)
    out = stdout.read().decode()
    err = stderr.read().decode()
    ssh.close()
    return out, err

def winrm_exec(ip, command):
    endpoint = f"{'https' if Config.WINRM_USE_SSL else 'http'}://{ip}:5986/wsman"
    session = winrm.Session(
        endpoint,
        auth=(Config.WINRM_USER, Config.WINRM_PASSWORD),
        transport='kerberos' if Config.WINRM_USE_KERBEROS else 'basic',
        server_cert_validation='ignore'
    )
    result = session.run_cmd(command)
    return result.std_out.decode(), result.std_err.decode()

def deploy_agent(ip, os_type):
    if os_type == 'linux':
        cmd = "curl -s https://your-server/agent/installer.sh | bash"
        out, err = ssh_exec(ip, cmd)
        if err: return False, err
        return True, "Deployed"
    elif os_type == 'windows':
        cmd = "powershell -Command \"Invoke-WebRequest -Uri https://your-server/agent/installer.ps1 -OutFile $env:TEMP\\install.ps1; & $env:TEMP\\install.ps1\""
        out, err = winrm_exec(ip, cmd)
        if err: return False, err
        return True, "Deployed"
    return False, "Unsupported OS"
EXECUTOR_END

cat > modules/discovery/__init__.py <<'DISCOVERY_INIT_END'
# modules/discovery/__init__.py
DISCOVERY_INIT_END

cat > modules/discovery/sweep.py <<'SWEEP_END'
import ipaddress, subprocess, socket
from core.database import get_db
from core.app import app
from modules.api.routes import discovery_status

def run_discovery_sweep():
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT subnet FROM network_ranges WHERE enabled=1")
        subnets = [r[0] for r in cur.fetchall()]
        if not subnets: return

        discovery_status["running"] = True
        discovery_status["progress"] = 0
        discovery_status["message"] = "Starting discovery..."
        total_hosts = 0
        for subnet in subnets:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                total_hosts += sum(1 for _ in network.hosts())
            except: pass
        discovery_status["total"] = total_hosts
        processed = 0
        found = 0

        for subnet in subnets:
            network = ipaddress.ip_network(subnet, strict=False)
            for ip in network.hosts():
                ip_str = str(ip)
                ret = subprocess.call(["ping", "-c", "1", "-W", "1", ip_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if ret == 0:
                    try:
                        hostname = socket.gethostbyaddr(ip_str)[0]
                    except:
                        hostname = ip_str
                    cur.execute("SELECT hostname FROM hosts WHERE ip = %s", (ip_str,))
                    if not cur.fetchone():
                        is_win = subprocess.call(["nmap", "-p", "5986", ip_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
                        cur.execute("INSERT INTO pending_hosts (ip_address, os_type, detected_at) VALUES (%s, %s, NOW())",
                                    (ip_str, 'windows' if is_win else 'linux'))
                        found += 1
                        db.commit()
                processed += 1
                discovery_status["progress"] = int((processed / total_hosts) * 100) if total_hosts > 0 else 0
                discovery_status["found"] = found
                discovery_status["message"] = f"Scanning {ip_str}..."
        discovery_status["running"] = False
        discovery_status["message"] = f"Discovery complete. Found {found} new hosts."
        cur.close()
SWEEP_END

cat > modules/remediation/__init__.py <<'REMEDIATION_INIT_END'
# modules/remediation/__init__.py
REMEDIATION_INIT_END

cat > modules/remediation/suggest.py <<'SUGGEST_END'
def generate_suggestion(hostname, metric, value, threshold, severity, cause):
    if metric == 'cpu' and value > 85:
        return "High CPU detected. Consider restarting heavy services.", "systemctl restart $(systemctl list-units --type=service --state=running | head -5 | tail -1 | awk '{print $1}')"
    elif metric == 'memory' and value > 85:
        return "High memory usage. Clear cache.", "sync && echo 3 > /proc/sys/vm/drop_caches"
    elif metric == 'disk' and value > 90:
        return "Disk space critical. Clean old logs.", "find /var/log -type f -mtime +7 -delete"
    return None, None
SUGGEST_END

# ----------------------------------------------------------------------
# 10. AGENT
# ----------------------------------------------------------------------
cat > agents/__init__.py <<'AGENT_INIT_END'
# agents/__init__.py
AGENT_INIT_END

cat > agents/client.py <<'AGENT_CLIENT_END'
#!/usr/bin/env python3
import os, time, json, socket, subprocess, uuid, logging, platform
import requests, psutil
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

load_dotenv()

SERVER_URL = os.getenv("SERVER_URL", "https://your-domain.com/api/report")
API_KEY = os.getenv("API_KEY", "")
GROUP_ID = os.getenv("GROUP_ID")
AGENT_ID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_id")

logger = logging.getLogger("syswatch-agent")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
logger.addHandler(handler)

def get_agent_id():
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE) as f:
            return f.read().strip()
    new_id = str(uuid.uuid4())
    with open(AGENT_ID_FILE, "w") as f:
        f.write(new_id)
    return new_id

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_file:
            self._send_event("file_change", event.src_path, "modified")
    def on_created(self, event):
        if event.is_file:
            self._send_event("file_change", event.src_path, "created")
    def _send_event(self, ev_type, path, detail):
        try:
            payload = {"events": [{"event_type": ev_type, "user": "system", "details": {"path": path, "action": detail}}]}
            requests.post(SERVER_URL, json=payload, headers={"X-API-Key": API_KEY}, timeout=5)
        except:
            pass

def collect_metrics():
    hostname = socket.gethostname()
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    net = psutil.net_io_counters()
    services = {}
    for svc in ["sshd", "nginx", "mysql", "docker"]:
        try:
            rc = subprocess.call(["systemctl", "is-active", "--quiet", svc])
            services[svc] = "running" if rc == 0 else "stopped"
        except:
            services[svc] = "unknown"
    return {
        "hostname": hostname,
        "agent_id": get_agent_id(),
        "ip": get_ip(),
        "os_type": "windows" if platform.system() == "Windows" else "linux",
        "cpu": cpu, "memory": mem, "disk": disk,
        "uptime": int(time.time() - psutil.boot_time()),
        "network_sent": net.bytes_sent, "network_recv": net.bytes_recv,
        "services": services,
        "network_devices": [],
        "group_id": int(GROUP_ID) if GROUP_ID else None
    }

def main():
    logger.info("SysWatch Agent v1.2.0 starting...")
    path = "/etc" if platform.system() != "Windows" else "C:\\Windows\\System32\\config"
    observer = Observer()
    observer.schedule(FileChangeHandler(), path, recursive=True)
    observer.start()

    while True:
        try:
            data = collect_metrics()
            resp = requests.post(SERVER_URL, json=data, headers={"X-API-Key": API_KEY}, timeout=10)
            if resp.status_code == 200:
                logger.info("Metrics sent")
            else:
                logger.error(f"Metrics error: {resp.status_code}")
        except Exception as e:
            logger.error(f"Error: {e}")
        time.sleep(60)

if __name__ == "__main__":
    main()
AGENT_CLIENT_END

# ----------------------------------------------------------------------
# 11. SCRIPTS
# ----------------------------------------------------------------------
cat > scripts/deploy_agent.sh <<'DEPLOY_AGENT_END'
#!/bin/bash
if [ $# -lt 1 ]; then echo "Usage: $0 <hostname_or_ip>"; exit 1; fi
HOST=$1
scp -i /opt/syswatch/keys/syswatch_key agents/client.py "$HOST":/tmp/client.py
ssh -i /opt/syswatch/keys/syswatch_key "$HOST" "sudo mv /tmp/client.py /opt/syswatch-agent/ && sudo chmod +x /opt/syswatch-agent/client.py"
DEPLOY_AGENT_END
chmod +x scripts/deploy_agent.sh

# ----------------------------------------------------------------------
# 12. TOP LEVEL FILES
# ----------------------------------------------------------------------
cat > wsgi.py <<'WSGI_END'
from core.app import app
if __name__ == "__main__":
    app.run()
WSGI_END

cat > requirements.txt <<'REQ_END'
flask
flask-login
pymysql
python-dotenv
requests
psutil
gunicorn
apscheduler
pyOpenSSL
paramiko
pywinrm
ldap3
watchdog
REQ_END

cat > .env.example <<'ENV_EXAMPLE_END'
SECRET_KEY=your-secret-key
DB_HOST=127.0.0.1
DB_USER=monitor
DB_PASSWORD=your-db-password
DB_NAME=monitoring
API_KEY=your-api-key
ADMIN_USER=admin
ADMIN_PASSWORD=admin123
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=recipient@example.com
TEAMS_WEBHOOK_URL=https://your.webhook.url
DISCOVERY_SUBNET=192.168.1.0/24
DEEPSEEK_API_KEY=your-deepseek-key
DEEPSEEK_API_URL=https://api.deepseek.com/v1/chat/completions
DEEPSEEK_MODEL=deepseek-chat
GEMINI_API_KEY=your-gemini-key
GEMINI_API_URL=https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent
SSH_USER=syswatch
SSH_PRIVATE_KEY_PATH=/opt/syswatch/keys/syswatch_key
SSH_TIMEOUT=10
WINRM_USER=syswatch
WINRM_PASSWORD=your-windows-password
WINRM_USE_SSL=true
WINRM_USE_KERBEROS=false
LDAP_SERVER=ldap://your-domain-controller:389
LDAP_BASE_DN=DC=yourdomain,DC=com
LDAP_USER_DN=CN=Users,DC=yourdomain,DC=com
LDAP_GROUP_DN=CN=Groups,DC=yourdomain,DC=com
LDAP_BIND_USER=CN=svc_syswatch,CN=Users,DC=yourdomain,DC=com
LDAP_BIND_PASSWORD=your_svc_password
LDAP_ROLE_MAPPING=CN=SysWatchAdmins,OU=Groups,DC=yourdomain,DC=com:Admin
ENV_EXAMPLE_END

cat > README.md <<'README_END'
# SysWatch v1.2.0
Simple Monitoring. Smarter Operations.

## Features
- Events UI with filters
- Granular RBAC (Admin, Operator, Viewer)
- LDAP (AD/Azure) + local fallback
- WinRM + dedicated Windows page
- Auto-discovery + admin-approved deployment
- AI remediation (DeepSeek + Gemini) with Dry-Run & Execute
- Remote command execution

## Installation (Linux)
```bash
sudo bash install.sh