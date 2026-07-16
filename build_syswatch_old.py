#!/usr/bin/env python3
"""
SysWatch v1.1.0 – Complete Project Builder
Generates the entire SysWatch project with AI Studio‑inspired UI.
Run this script on any platform (Windows/Linux) to create the project.
"""

import os
import stat
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "syswatch_v1.1.0")

# ----------------------------------------------------------------------
# FILE CONTENTS – Defined as multiline strings
# ----------------------------------------------------------------------

FILES = {
    # ---------- CORE ----------
    "core/__init__.py": '''# core/__init__.py
''',

    "core/config.py": '''# core/config.py
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
    # Gemini fallback
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_API_URL = os.getenv("GEMINI_API_URL", "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent")
''',

    "core/database.py": '''# core/database.py
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

    # Hosts
    cur.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            hostname VARCHAR(128) PRIMARY KEY,
            agent_id VARCHAR(64) DEFAULT NULL,
            ip VARCHAR(45),
            last_seen DATETIME,
            status VARCHAR(16) DEFAULT 'UP',
            group_id INT DEFAULT NULL,
            discovered_by VARCHAR(32) DEFAULT 'manual',
            discovery_time DATETIME DEFAULT NULL
        )
    """)
    # Metrics
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
    # Alert rules
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
    # Alerts
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
    # Host groups
    cur.execute("""
        CREATE TABLE IF NOT EXISTS host_groups (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) UNIQUE NOT NULL
        )
    """)
    # Users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            role VARCHAR(16) NOT NULL DEFAULT 'manager'
        )
    """)
    # SSL certificates
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
    # AI insights
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
    # Events
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
    # Network ranges
    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_ranges (
            id INT AUTO_INCREMENT PRIMARY KEY,
            subnet VARCHAR(32) NOT NULL,
            description VARCHAR(128),
            enabled TINYINT DEFAULT 1
        )
    """)
    cur.execute("SELECT COUNT(*) FROM network_ranges")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO network_ranges (subnet, description) VALUES (%s, %s)", (Config.DISCOVERY_SUBNET, 'Default subnet'))

    # Migrations
    try:
        cur.execute("ALTER TABLE alerts ADD COLUMN status VARCHAR(16) DEFAULT 'OPEN'")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE alerts ADD COLUMN acknowledged_by VARCHAR(64) DEFAULT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at DATETIME DEFAULT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN agent_id VARCHAR(64) DEFAULT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN group_id INT DEFAULT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN discovered_by VARCHAR(32) DEFAULT 'manual'")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN discovery_time DATETIME DEFAULT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE ai_insights ADD COLUMN details JSON")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE alert_rules ADD COLUMN enabled TINYINT DEFAULT 1")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE alert_rules ADD COLUMN duration INT DEFAULT 1")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE alert_rules ADD COLUMN template VARCHAR(32) DEFAULT NULL")
    except Exception:
        pass

    db.commit()

    # Bootstrap admin
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        admin_user = Config.ADMIN_USER
        admin_pass = Config.ADMIN_PASSWORD
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
            (admin_user, generate_password_hash(admin_pass))
        )
        db.commit()

    # Default alert rules
    cur.execute("SELECT COUNT(*) FROM alert_rules")
    if cur.fetchone()[0] == 0:
        default_rules = [
            ('%', 'cpu', 90, '>', 'CRITICAL', 300,
             'CPU usage exceeded 90%', 'Check top processes and reduce load.', 'high_cpu'),
            ('%', 'cpu', 75, '>', 'WARNING', 300,
             'CPU usage exceeded 75%', 'Monitor trends; consider scaling.', 'high_cpu'),
            ('%', 'memory', 90, '>', 'CRITICAL', 300,
             'Memory usage exceeded 90%', 'Check for memory leaks; add swap or RAM.', 'high_memory'),
            ('%', 'memory', 75, '>', 'WARNING', 300,
             'Memory usage exceeded 75%', 'Monitor growth; plan capacity.', 'high_memory'),
            ('%', 'disk', 95, '>', 'CRITICAL', 300,
             'Disk usage exceeded 95%', 'Clean up logs; extend volume.', 'disk_full'),
            ('%', 'disk', 80, '>', 'WARNING', 300,
             'Disk usage exceeded 80%', 'Review retention; archive old data.', 'disk_full'),
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
''',

    "core/scheduler.py": '''# core/scheduler.py
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

def start_scheduler(app):
    with app.app_context():
        from modules.monitoring_checks.status_updater import compute_status
        from modules.monitoring_checks.ssl_expiry import check_all_certificates
        from modules.ai.anomaly import run_anomaly_detection, run_predictions, send_daily_briefing
        from modules.alert_engine.auto_resolve import auto_resolve_stale_alerts

        scheduler.add_job(
            func=compute_status,
            trigger='interval',
            seconds=30,
            id='status_updater',
            replace_existing=True
        )
        scheduler.add_job(
            func=check_all_certificates,
            trigger='cron',
            hour=8,
            minute=0,
            id='ssl_expiry_check',
            replace_existing=True
        )
        scheduler.add_job(
            func=run_anomaly_detection,
            trigger='interval',
            minutes=5,
            id='anomaly_detection',
            replace_existing=True
        )
        scheduler.add_job(
            func=run_predictions,
            trigger='interval',
            hours=6,
            id='predictions',
            replace_existing=True
        )
        scheduler.add_job(
            func=auto_resolve_stale_alerts,
            trigger='interval',
            minutes=10,
            id='auto_resolve',
            replace_existing=True
        )
        scheduler.add_job(
            func=send_daily_briefing,
            trigger='cron',
            hour=8,
            minute=0,
            id='daily_briefing',
            replace_existing=True
        )

        if not scheduler.running:
            scheduler.start()
            print("✅ Scheduler started with 6 jobs.")

def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        print("🛑 Scheduler stopped.")
''',

    "core/app.py": '''# core/app.py
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

print("🚀 SysWatch Core initialized successfully.")
''',

    # ---------- MODULES ----------
    "modules/__init__.py": '''

    "modules/authentication/__init__.py": '''

    "modules/authentication/models.py": '''# modules/authentication/models.py
from flask_login import UserMixin
from core.database import get_db

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

def load_user(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    if row:
        return User(row[0], row[1], row[2])
    return None
''',

    "modules/authentication/routes.py": '''# modules/authentication/routes.py
from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from core.database import get_db
from modules.authentication.models import User
import pymysql

auth_bp = Blueprint('authentication', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        if user and check_password_hash(user[2], password):
            login_user(User(user[0], user[1], user[3]))
            return redirect(url_for('web_ui.dashboard'))
        error = "Invalid credentials"
    return render_template('login.html', error=error)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('authentication.login'))

@auth_bp.route('/api/users', methods=['GET'])
@login_required
def list_users():
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, role FROM users ORDER BY username")
    users = [{"id": r[0], "username": r[1], "role": r[2]} for r in cur.fetchall()]
    cur.close()
    return jsonify(users)

@auth_bp.route('/api/users', methods=['POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'manager')
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

@auth_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    if user_id == current_user.id:
        return jsonify({"error": "Cannot delete yourself"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})
''',

    "modules/web_ui/__init__.py": '''

    "modules/web_ui/routes.py": '''# modules/web_ui/routes.py
from flask import Blueprint, render_template
from flask_login import login_required

ui_bp = Blueprint('web_ui', __name__)

@ui_bp.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')
''',

    # ---------- dashboard.html (AI Studio Inspired UI) ----------
    "modules/web_ui/templates/dashboard.html": '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SysWatch</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* ===== CSS Variables (Light & Dark) ===== */
        :root {
            --bg-primary: #f0f4f8;
            --bg-secondary: #ffffff;
            --bg-sidebar: #0a1628;
            --bg-sidebar-hover: #1a2a4a;
            --text-primary: #1a2332;
            --text-secondary: #5a6a7a;
            --text-sidebar: #b0c4de;
            --text-sidebar-active: #ffffff;
            --border-color: #e2e8f0;
            --card-shadow: 0 4px 20px rgba(0,0,0,0.06);
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --accent-light: #eff6ff;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --radius: 12px;
            --transition: 0.3s ease;
            --sidebar-width: 260px;
        }

        body.dark {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-sidebar: #020617;
            --bg-sidebar-hover: #1a2a4a;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --card-shadow: 0 4px 20px rgba(0,0,0,0.3);
            --accent-light: #1e293b;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            display: flex;
            min-height: 100vh;
            transition: background var(--transition), color var(--transition);
        }

        /* ===== Sidebar ===== */
        .sidebar {
            width: var(--sidebar-width);
            background: var(--bg-sidebar);
            padding: 20px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            transition: transform 0.3s ease;
            z-index: 100;
        }

        .sidebar-brand {
            padding: 0 24px 24px 24px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .sidebar-brand .logo {
            font-size: 28px;
            font-weight: 800;
            color: #fff;
            letter-spacing: -0.5px;
        }
        .sidebar-brand .logo span { color: var(--accent); }

        .sidebar-nav {
            flex: 1;
            padding: 20px 12px;
        }

        .sidebar-nav .nav-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: rgba(255,255,255,0.3);
            padding: 8px 12px;
            margin-top: 8px;
        }

        .sidebar-nav a {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 16px;
            margin: 2px 0;
            border-radius: 8px;
            color: var(--text-sidebar);
            text-decoration: none;
            transition: all var(--transition);
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }

        .sidebar-nav a:hover {
            background: var(--bg-sidebar-hover);
            color: var(--text-sidebar-active);
        }

        .sidebar-nav a.active {
            background: var(--accent);
            color: #fff;
            box-shadow: 0 4px 12px rgba(59,130,246,0.3);
        }

        .sidebar-nav a .icon { font-size: 18px; width: 24px; text-align: center; }

        .sidebar-footer {
            padding: 16px 24px;
            border-top: 1px solid rgba(255,255,255,0.06);
        }

        .sidebar-footer a {
            color: var(--text-sidebar);
            text-decoration: none;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            border-radius: 8px;
            transition: all var(--transition);
        }

        .sidebar-footer a:hover {
            background: var(--bg-sidebar-hover);
            color: #fff;
        }

        /* ===== Main Content ===== */
        .main {
            margin-left: var(--sidebar-width);
            flex: 1;
            padding: 24px 32px 40px;
            min-height: 100vh;
        }

        /* ===== Top Bar ===== */
        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0 20px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .topbar-left h1 {
            font-size: 24px;
            font-weight: 700;
            letter-spacing: -0.3px;
        }
        .topbar-left .subtitle {
            font-size: 14px;
            color: var(--text-secondary);
            margin-top: 2px;
        }

        .topbar-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .topbar-right .theme-toggle {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 8px 12px;
            cursor: pointer;
            font-size: 18px;
            transition: all var(--transition);
            color: var(--text-primary);
        }

        .topbar-right .theme-toggle:hover {
            background: var(--accent-light);
        }

        .topbar-right .user-badge {
            display: flex;
            align-items: center;
            gap: 10px;
            background: var(--bg-secondary);
            padding: 6px 16px 6px 12px;
            border-radius: 100px;
            border: 1px solid var(--border-color);
        }

        .topbar-right .user-badge .avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--accent);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 14px;
        }

        /* ===== Cards ===== */
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }

        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 18px 20px;
            box-shadow: var(--card-shadow);
            transition: all var(--transition);
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.08);
        }

        .stat-card .label {
            font-size: 13px;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }

        .stat-card .value {
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }

        .stat-card .value.up { color: var(--success); }
        .stat-card .value.warning { color: var(--warning); }
        .stat-card .value.down { color: var(--danger); }
        .stat-card .value.primary { color: var(--accent); }

        /* ===== Filters ===== */
        .filter-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 16px;
            align-items: center;
        }

        .filter-bar select,
        .filter-bar input {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 8px 14px;
            color: var(--text-primary);
            font-size: 13px;
            font-family: inherit;
            transition: all var(--transition);
        }

        .filter-bar select:focus,
        .filter-bar input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(59,130,246,0.15);
        }

        .btn {
            background: var(--accent);
            color: #fff;
            border: none;
            padding: 8px 18px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all var(--transition);
            font-family: inherit;
        }

        .btn:hover {
            background: var(--accent-hover);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59,130,246,0.3);
        }

        .btn-success { background: var(--success); }
        .btn-success:hover { background: #16a34a; }

        .btn-danger { background: var(--danger); }
        .btn-danger:hover { background: #dc2626; }

        .btn-warning { background: var(--warning); color: #1a2332; }
        .btn-warning:hover { background: #d97706; color: #fff; }

        .btn-sm { padding: 4px 12px; font-size: 12px; }
        .btn-secondary { background: var(--text-secondary); }

        /* ===== Tables ===== */
        .table-container {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            overflow: hidden;
            box-shadow: var(--card-shadow);
            margin-bottom: 24px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }

        th {
            background: var(--bg-primary);
            font-weight: 600;
            color: var(--text-secondary);
            padding: 12px 16px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }

        tr:last-child td { border-bottom: none; }
        tr:hover { background: var(--accent-light); }

        .status-badge {
            display: inline-block;
            padding: 3px 12px;
            border-radius: 100px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-badge.up { background: #dcfce7; color: #16a34a; }
        .status-badge.warning { background: #fef3c7; color: #d97706; }
        .status-badge.down { background: #fee2e2; color: #dc2626; }
        .status-badge.critical { background: #fee2e2; color: #dc2626; }

        body.dark .status-badge.up { background: #064e3b; color: #4ade80; }
        body.dark .status-badge.warning { background: #78350f; color: #fbbf24; }
        body.dark .status-badge.down { background: #7f1d1d; color: #f87171; }
        body.dark .status-badge.critical { background: #7f1d1d; color: #f87171; }

        /* ===== Charts ===== */
        .chart-box {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 20px;
            margin-top: 24px;
            box-shadow: var(--card-shadow);
        }

        .chart-box canvas { max-height: 280px; width: 100%; }

        .chart-controls {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 16px;
            align-items: center;
        }

        .chart-controls select {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 6px 12px;
            color: var(--text-primary);
            font-size: 13px;
        }

        /* ===== Forms ===== */
        .form-section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: var(--card-shadow);
        }

        .form-section h4 {
            font-size: 15px;
            font-weight: 600;
            margin-bottom: 12px;
        }

        .inline-form {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }

        .inline-form input,
        .inline-form select {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-primary);
            font-size: 13px;
            font-family: inherit;
            min-width: 120px;
        }

        .inline-form input:focus,
        .inline-form select:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(59,130,246,0.15);
        }

        /* ===== Tab Content ===== */
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* ===== Responsive ===== */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
                width: 280px;
            }
            .sidebar.open { transform: translateX(0); }
            .main { margin-left: 0; padding: 16px; }

            .hamburger {
                display: flex !important;
                background: var(--bg-secondary);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 8px 12px;
                cursor: pointer;
                font-size: 20px;
            }

            .summary-cards { grid-template-columns: repeat(2, 1fr); }
            .topbar-left h1 { font-size: 20px; }
        }

        .hamburger { display: none; }

        /* ===== Overlay ===== */
        .overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.4);
            z-index: 99;
        }
        .overlay.active { display: block; }

        /* ===== Progress Bar ===== */
        .progress-bar {
            width: 100%;
            background: var(--bg-primary);
            border-radius: 6px;
            height: 8px;
            margin-top: 8px;
            overflow: hidden;
        }
        .progress-bar .progress {
            height: 100%;
            background: var(--accent);
            border-radius: 6px;
            transition: width 0.3s ease;
        }

        /* ===== Messages ===== */
        .msg-success { color: var(--success); }
        .msg-error { color: var(--danger); }
        .msg-info { color: var(--accent); }

        .mt-8 { margin-top: 8px; }
        .mb-8 { margin-bottom: 8px; }
    </style>
</head>
<body>

    <!-- Overlay for mobile -->
    <div class="overlay" id="mobileOverlay" onclick="toggleSidebar()"></div>

    <!-- ===== SIDEBAR ===== -->
    <nav class="sidebar" id="sidebar">
        <div class="sidebar-brand">
            <div class="logo">Sys<span>Watch</span></div>
        </div>

        <div class="sidebar-nav">
            <div class="nav-label">Main</div>
            <a class="active" data-tab="dashboard"><span class="icon">📊</span> Dashboard</a>
            <a data-tab="monitoring"><span class="icon">🖥️</span> Monitoring</a>
            <a data-tab="rules"><span class="icon">⚙️</span> Alert Rules</a>
            <a data-tab="admin"><span class="icon">👤</span> Admin</a>

            <div class="nav-label" style="margin-top:20px;">Insights</div>
            <a data-tab="ai"><span class="icon">🤖</span> AI Insights</a>
            <a data-tab="alerts_history"><span class="icon">📜</span> Alerts History</a>
        </div>

        <div class="sidebar-footer">
            <a href="/logout"><span class="icon">🚪</span> Logout</a>
        </div>
    </nav>

    <!-- ===== MAIN ===== -->
    <div class="main">
        <!-- Top Bar -->
        <header class="topbar">
            <div class="topbar-left">
                <div style="display:flex;align-items:center;gap:12px;">
                    <button class="hamburger" onclick="toggleSidebar()">☰</button>
                    <div>
                        <h1 id="pageTitle">Dashboard</h1>
                        <div class="subtitle" id="pageSubtitle">Real‑time infrastructure overview</div>
                    </div>
                </div>
            </div>
            <div class="topbar-right">
                <button class="theme-toggle" onclick="toggleDarkMode()">🌓</button>
                <div class="user-badge">
                    <span class="avatar">{{ current_user.username[0]|upper }}</span>
                    <span>{{ current_user.username }}</span>
                </div>
            </div>
        </header>

        <!-- ============================================================ -->
        <!-- TAB: Dashboard -->
        <!-- ============================================================ -->
        <div id="tab-dashboard" class="tab-content active">
            <div class="summary-cards" id="summaryCards">
                <div class="stat-card"><div class="label">Total Hosts</div><div class="value primary" id="totalHosts">-</div></div>
                <div class="stat-card"><div class="label">UP</div><div class="value up" id="upHosts">-</div></div>
                <div class="stat-card"><div class="label">WARNING</div><div class="value warning" id="warnHosts">-</div></div>
                <div class="stat-card"><div class="label">DOWN</div><div class="value down" id="downHosts">-</div></div>
                <div class="stat-card"><div class="label">Open Alerts</div><div class="value down" id="openAlerts">-</div></div>
            </div>

            <div class="filter-bar">
                <select id="groupFilter"><option value="">All Groups</option></select>
                <select id="statusFilter"><option value="">All Status</option><option value="UP">UP</option><option value="WARNING">WARNING</option><option value="DOWN">DOWN</option></select>
                <button class="btn" onclick="fetchDevices()">🔄 Refresh</button>
            </div>

            <div class="table-container">
                <table>
                    <thead><tr><th>Hostname</th><th>IP</th><th>Status</th><th>Group</th><th>Last Seen</th><th>CPU%</th><th>Mem%</th><th>Disk%</th><th>Services</th></tr></thead>
                    <tbody id="devicesTableBody"></tbody>
                </table>
            </div>

            <div class="chart-box">
                <div class="chart-controls">
                    <label>Range: <select id="trendRange" onchange="loadChart()">
                        <option value="1h">Last Hour</option><option value="6h">Last 6 Hours</option>
                        <option value="12h">Last 12 Hours</option><option value="24h">Last 24 Hours</option>
                        <option value="7d">Last Week</option><option value="30d">Last Month</option>
                    </select></label>
                    <label>Metric: <select id="trendMetric" onchange="loadChart()">
                        <option value="cpu">CPU</option><option value="memory">Memory</option><option value="disk">Disk</option>
                    </select></label>
                    <label>Hosts: <select id="trendHosts" multiple size="2" onchange="loadChart()"></select></label>
                    <button class="btn btn-sm" onclick="loadChart()">Update Chart</button>
                </div>
                <canvas id="trendChart"></canvas>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- TAB: Monitoring -->
        <!-- ============================================================ -->
        <div id="tab-monitoring" class="tab-content">
            <h2 style="margin-bottom:16px;font-weight:600;">Hosts & Devices</h2>

            <div class="form-section">
                <h4>➕ Add Host Manually</h4>
                <div class="inline-form">
                    <input type="text" id="newHostname" placeholder="Hostname">
                    <input type="text" id="newHostIP" placeholder="IP Address">
                    <select id="newHostGroup"><option value="">No Group</option></select>
                    <button class="btn" onclick="addHost()">Add Host</button>
                </div>
                <div id="addHostMessage" class="mt-8"></div>
            </div>

            <div class="form-section">
                <h4>🔍 Auto‑Discovery</h4>
                <div class="inline-form">
                    <button class="btn btn-success" onclick="startDiscovery()">Scan Network</button>
                    <span id="discoveryStatus" style="font-size:14px;">Idle</span>
                </div>
                <div class="progress-bar"><div class="progress" id="discoveryProgress" style="width:0%;"></div></div>
                <div id="discoveryMessage" class="mt-8"></div>
            </div>

            <div class="filter-bar">
                <select id="monitoringType"><option value="hosts">Hosts</option><option value="devices">Devices</option></select>
                <button class="btn" onclick="fetchMonitoring()">Refresh</button>
            </div>

            <div class="table-container">
                <table>
                    <thead><tr><th>Name</th><th>IP</th><th>Status</th><th>Type</th></tr></thead>
                    <tbody id="monitoringTableBody"></tbody>
                </table>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- TAB: Alert Rules -->
        <!-- ============================================================ -->
        <div id="tab-rules" class="tab-content">
            <h2 style="margin-bottom:16px;font-weight:600;">Alert Rules Management</h2>

            <div class="form-section">
                <h4>➕ Add New Rule</h4>
                <div class="inline-form">
                    <input type="text" id="ruleHostname" placeholder="Hostname (or %)" value="%">
                    <input type="text" id="ruleMetric" placeholder="Metric">
                    <input type="number" id="ruleThreshold" placeholder="Threshold">
                    <select id="ruleOperator"><option value=">">&gt;</option><option value="<">&lt;</option></select>
                    <select id="ruleSeverity"><option value="WARNING">WARNING</option><option value="CRITICAL">CRITICAL</option></select>
                    <input type="number" id="ruleCooldown" placeholder="Cooldown (sec)" value="300">
                    <button class="btn" onclick="createRule()">Add Rule</button>
                </div>
                <div class="inline-form" style="margin-top:10px;">
                    <label style="font-size:13px;color:var(--text-secondary);">Template:</label>
                    <select id="ruleTemplate">
                        <option value="">None</option><option value="high_cpu">High CPU</option>
                        <option value="high_memory">High Memory</option><option value="disk_full">Disk Full</option>
                        <option value="service_down">Service Down</option>
                    </select>
                    <button class="btn btn-sm btn-secondary" onclick="applyTemplate()">Apply</button>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead><tr><th>ID</th><th>Host</th><th>Metric</th><th>Threshold</th><th>Op</th><th>Severity</th><th>Cooldown</th><th>Enabled</th><th>Actions</th></tr></thead>
                    <tbody id="rulesTableBody"></tbody>
                </table>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- TAB: Admin -->
        <!-- ============================================================ -->
        <div id="tab-admin" class="tab-content">
            <h2 style="margin-bottom:16px;font-weight:600;">User Management</h2>

            <div class="form-section">
                <h4>➕ Create New User</h4>
                <div class="inline-form">
                    <input type="text" id="newUsername" placeholder="Username">
                    <input type="password" id="newPassword" placeholder="Password">
                    <select id="newRole"><option value="manager">Manager</option><option value="admin">Admin</option></select>
                    <button class="btn" onclick="createUser()">Create</button>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Actions</th></tr></thead>
                    <tbody id="usersTableBody"></tbody>
                </table>
            </div>

            <h3 style="margin:24px 0 12px;font-weight:600;">Host Groups</h3>
            <div class="form-section">
                <div class="inline-form">
                    <input type="text" id="newGroupName" placeholder="Group name">
                    <button class="btn" onclick="createGroup()">Create</button>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead><tr><th>ID</th><th>Name</th><th>Actions</th></tr></thead>
                    <tbody id="groupsTableBody"></tbody>
                </table>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- TAB: AI Insights -->
        <!-- ============================================================ -->
        <div id="tab-ai" class="tab-content">
            <h2 style="margin-bottom:16px;font-weight:600;">AI Insights & Predictions</h2>
            <div class="table-container">
                <table>
                    <thead><tr><th>Host</th><th>Metric</th><th>Value</th><th>Baseline</th><th>Deviation</th><th>Severity</th><th>Time</th><th>Details</th></tr></thead>
                    <tbody id="aiInsightsTableBody"></tbody>
                </table>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- TAB: Alerts History -->
        <!-- ============================================================ -->
        <div id="tab-alerts_history" class="tab-content">
            <h2 style="margin-bottom:16px;font-weight:600;">Alerts History</h2>

            <div class="filter-bar">
                <select id="historyStatusFilter"><option value="">All Status</option><option value="OPEN">OPEN</option><option value="ACKNOWLEDGED">ACKNOWLEDGED</option><option value="RESOLVED">RESOLVED</option></select>
                <input type="text" id="historyHostFilter" placeholder="Filter by host...">
                <button class="btn" onclick="fetchAlertHistory()">Refresh</button>
            </div>

            <div class="table-container">
                <table>
                    <thead><tr><th>Host</th><th>Metric</th><th>Value</th><th>Severity</th><th>Time</th><th>Status</th></tr></thead>
                    <tbody id="alertHistoryTableBody"></tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- ==================== JAVASCRIPT ==================== -->
    <script>
        // =========================== GLOBALS ===========================
        let currentUserRole = "{{ current_user.role }}";
        let trendChart = null;
        let discoveryInterval = null;

        // =========================== DARK MODE ===========================
        function toggleDarkMode() {
            document.body.classList.toggle('dark');
            localStorage.setItem('darkMode', document.body.classList.contains('dark'));
        }
        if (localStorage.getItem('darkMode') === 'true') document.body.classList.add('dark');

        // =========================== SIDEBAR ===========================
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('open');
            document.getElementById('mobileOverlay').classList.toggle('active');
        }

        // =========================== MENU ===========================
        document.addEventListener('DOMContentLoaded', function() {
            // Attach menu click handlers
            document.querySelectorAll('.sidebar-nav a[data-tab]').forEach(function(el) {
                el.addEventListener('click', function(e) {
                    e.preventDefault();
                    // Update active state
                    document.querySelectorAll('.sidebar-nav a').forEach(function(a) { a.classList.remove('active'); });
                    this.classList.add('active');

                    // Switch tabs
                    const tabId = this.dataset.tab;
                    document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
                    const target = document.getElementById('tab-' + tabId);
                    if (target) target.classList.add('active');

                    // Update title
                    document.getElementById('pageTitle').innerText = this.innerText.trim();

                    // Load data
                    if (tabId === 'dashboard') { fetchSummary(); fetchDevices(); loadTrendHosts(); }
                    else if (tabId === 'monitoring') { fetchMonitoring(); loadGroupsForAddHost(); }
                    else if (tabId === 'rules') { fetchRules(); }
                    else if (tabId === 'admin') { loadAdmin(); }
                    else if (tabId === 'ai') { fetchAIInsights(); }
                    else if (tabId === 'alerts_history') { fetchAlertHistory(); }

                    // Close sidebar on mobile
                    if (window.innerWidth <= 768) { toggleSidebar(); }
                });
            });

            // Initial load
            fetchSummary(); fetchDevices(); loadTrendHosts();
            fetchMonitoring(); loadGroupsForAddHost();
            fetchRules(); loadAdmin(); fetchAIInsights(); fetchAlertHistory();

            // Auto refresh dashboard every 30s
            setInterval(function() {
                if (document.getElementById('tab-dashboard').classList.contains('active')) {
                    fetchDevices(); fetchSummary();
                }
            }, 30000);
        });

        // =========================== API HELPER ===========================
        async function apiFetch(url, options) {
            const resp = await fetch(url, options);
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return resp.json();
        }

        // =========================== DASHBOARD ===========================
        async function fetchSummary() {
            try {
                const data = await apiFetch('/api/summary');
                document.getElementById('totalHosts').textContent = data.total || 0;
                document.getElementById('upHosts').textContent = data.up || 0;
                document.getElementById('warnHosts').textContent = data.warning || 0;
                document.getElementById('downHosts').textContent = data.down || 0;
                document.getElementById('openAlerts').textContent = data.open_alerts || 0;
            } catch (e) { console.error('fetchSummary:', e); }
        }

        async function fetchDevices() {
            try {
                const gf = document.getElementById('groupFilter').value;
                const sf = document.getElementById('statusFilter').value;
                let url = '/api/latest?';
                if (gf) url += 'group=' + gf + '&';
                if (sf) url += 'status=' + sf + '&';
                const data = await apiFetch(url);
                const tbody = document.getElementById('devicesTableBody');
                tbody.innerHTML = '';
                data.forEach(function(d) {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td><strong>${d.hostname}</strong></td>
                        <td>${d.ip}</td>
                        <td><span class="status-badge ${d.status.toLowerCase()}">${d.status}</span></td>
                        <td>${d.group_name || 'None'}</td>
                        <td>${d.last_seen ? new Date(d.last_seen).toLocaleString() : 'Never'}</td>
                        <td>${d.cpu != null ? d.cpu + '%' : 'N/A'}</td>
                        <td>${d.memory != null ? d.memory + '%' : 'N/A'}</td>
                        <td>${d.disk != null ? d.disk + '%' : 'N/A'}</td>
                        <td>${formatServices(d.services)}</td>
                    `;
                });
                await loadGroupFilterOptions();
                fetchSummary();
            } catch (e) {
                console.error('fetchDevices:', e);
                document.getElementById('devicesTableBody').innerHTML = '<tr><td colspan="9" style="color:red;text-align:center;">Failed to load devices.</td></tr>';
            }
        }

        function formatServices(s) {
            if (!s || Object.keys(s).length === 0) return 'N/A';
            return Object.entries(s).map(function(arr) { return arr[0] + ':' + arr[1]; }).join(', ');
        }

        async function loadGroupFilterOptions() {
            try {
                const groups = await apiFetch('/api/groups');
                const sel = document.getElementById('groupFilter');
                const current = sel.value;
                sel.innerHTML = '<option value="">All Groups</option>';
                groups.forEach(function(g) {
                    sel.innerHTML += '<option value="' + g.id + '" ' + (g.id == current ? 'selected' : '') + '>' + g.name + '</option>';
                });
            } catch (e) { console.error('loadGroupFilterOptions:', e); }
        }

        async function loadTrendHosts() {
            try {
                const hosts = await apiFetch('/api/hosts');
                const sel = document.getElementById('trendHosts');
                sel.innerHTML = '';
                hosts.forEach(function(h) {
                    sel.innerHTML += '<option value="' + h.hostname + '">' + h.hostname + '</option>';
                });
                // Select first two
                for (let i = 0; i < Math.min(2, sel.options.length); i++) {
                    sel.options[i].selected = true;
                }
                loadChart();
            } catch (e) { console.error('loadTrendHosts:', e); }
        }

        async function loadChart() {
            const range = document.getElementById('trendRange').value;
            const metric = document.getElementById('trendMetric').value;
            const sel = document.getElementById('trendHosts');
            const hosts = Array.from(sel.options).filter(o => o.selected).map(o => o.value);
            if (hosts.length === 0) return;

            const ctx = document.getElementById('trendChart').getContext('2d');
            if (trendChart) trendChart.destroy();

            const datasets = [];
            const colors = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];

            try {
                for (let idx = 0; idx < hosts.length; idx++) {
                    const data = await apiFetch('/api/trends/' + hosts[idx] + '?range=' + range);
                    if (data.length === 0) continue;
                    const values = data.map(function(d) { return d[metric] || 0; });
                    const labels = data.map(function(d) { return d.timestamp; });
                    datasets.push({
                        label: hosts[idx] + ' (' + metric.toUpperCase() + ')',
                        data: values,
                        borderColor: colors[idx % colors.length],
                        fill: false,
                        tension: 0.2,
                        pointRadius: 1
                    });
                }

                if (datasets.length === 0) {
                    document.querySelector('#trendChart').innerHTML = '<p style="color:var(--text-secondary);text-align:center;">No data available.</p>';
                    return;
                }

                trendChart = new Chart(ctx, {
                    type: 'line',
                    data: { labels: datasets[0].labels || [], datasets: datasets },
                    options: {
                        responsive: true,
                        plugins: {
                            zoom: {
                                pan: { enabled: true, mode: 'x' },
                                zoom: { wheel: { enabled: true, speed: 0.1 }, pinch: { enabled: true }, mode: 'x' }
                            }
                        },
                        scales: { y: { beginAtZero: true } }
                    }
                });
            } catch (e) {
                console.error('loadChart:', e);
                document.querySelector('#trendChart').innerHTML = '<p style="color:red;text-align:center;">Failed to load chart.</p>';
            }
        }

        // =========================== MONITORING ===========================
        async function loadGroupsForAddHost() {
            try {
                const groups = await apiFetch('/api/groups');
                const sel = document.getElementById('newHostGroup');
                sel.innerHTML = '<option value="">No Group</option>';
                groups.forEach(function(g) {
                    sel.innerHTML += '<option value="' + g.id + '">' + g.name + '</option>';
                });
            } catch (e) { console.error('loadGroupsForAddHost:', e); }
        }

        async function addHost() {
            const hostname = document.getElementById('newHostname').value.trim();
            const ip = document.getElementById('newHostIP').value.trim();
            const group = document.getElementById('newHostGroup').value;
            if (!hostname || !ip) { alert('Hostname and IP are required.'); return; }

            try {
                const resp = await fetch('/api/hosts', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hostname: hostname, ip: ip, group_id: group || null })
                });
                const data = await resp.json();
                const msg = document.getElementById('addHostMessage');
                if (resp.ok) {
                    msg.innerHTML = '<span class="msg-success">✅ Host ' + hostname + ' added.</span>';
                    fetchMonitoring();
                } else {
                    msg.innerHTML = '<span class="msg-error">❌ ' + (data.error || 'Unknown error') + '</span>';
                }
            } catch (e) {
                console.error('addHost:', e);
                document.getElementById('addHostMessage').innerHTML = '<span class="msg-error">❌ Network error.</span>';
            }
        }

        async function startDiscovery() {
            const statusDiv = document.getElementById('discoveryStatus');
            const progressDiv = document.getElementById('discoveryProgress');
            const msgDiv = document.getElementById('discoveryMessage');
            statusDiv.innerText = 'Starting...';
            progressDiv.style.width = '0%';
            msgDiv.innerText = '';

            try {
                const resp = await fetch('/api/discover/start', { method: 'POST' });
                if (!resp.ok) throw new Error('Failed to start discovery');
                if (discoveryInterval) clearInterval(discoveryInterval);
                discoveryInterval = setInterval(async function() {
                    try {
                        const st = await apiFetch('/api/discover/status');
                        statusDiv.innerText = st.running ? 'Running...' : 'Idle';
                        progressDiv.style.width = st.progress + '%';
                        msgDiv.innerText = st.message || '';
                        if (!st.running) {
                            clearInterval(discoveryInterval);
                            discoveryInterval = null;
                            fetchMonitoring();
                        }
                    } catch (e) {
                        console.error('Discovery status:', e);
                        clearInterval(discoveryInterval);
                        discoveryInterval = null;
                        statusDiv.innerText = 'Error';
                        msgDiv.innerText = 'Failed to get status.';
                    }
                }, 1000);
            } catch (e) {
                console.error('startDiscovery:', e);
                statusDiv.innerText = 'Error';
                msgDiv.innerText = 'Discovery failed: ' + e.message;
            }
        }

        async function fetchMonitoring() {
            try {
                const type = document.getElementById('monitoringType').value;
                const hosts = await apiFetch('/api/hosts');
                const tbody = document.getElementById('monitoringTableBody');
                tbody.innerHTML = '';

                if (type === 'hosts') {
                    hosts.forEach(function(d) {
                        const row = tbody.insertRow();
                        row.innerHTML = '<td><strong>' + d.hostname + '</strong></td><td>' + d.ip + '</td><td><span class="status-badge ' + d.status.toLowerCase() + '">' + d.status + '</span></td><td>Host</td>';
                    });
                } else {
                    const latest = await apiFetch('/api/latest');
                    latest.forEach(function(d) {
                        if (d.network_devices && d.network_devices.length) {
                            d.network_devices.forEach(function(dev) {
                                const row = tbody.insertRow();
                                const status = dev.reachable ? 'UP' : 'DOWN';
                                row.innerHTML = '<td><strong>' + dev.name + '</strong></td><td>' + dev.ip + '</td><td><span class="status-badge ' + status.toLowerCase() + '">' + status + '</span></td><td>' + (dev.type || 'Device') + '</td>';
                            });
                        }
                    });
                }
            } catch (e) {
                console.error('fetchMonitoring:', e);
                document.getElementById('monitoringTableBody').innerHTML = '<tr><td colspan="4" style="color:red;text-align:center;">Failed to load data.</td></tr>';
            }
        }

        // =========================== ALERT RULES ===========================
        async function fetchRules() {
            try {
                const data = await apiFetch('/api/rules');
                const tbody = document.getElementById('rulesTableBody');
                tbody.innerHTML = '';
                data.forEach(function(r) {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${r.id}</td>
                        <td>${r.hostname}</td>
                        <td>${r.metric}</td>
                        <td>${r.threshold}</td>
                        <td>${r.operator}</td>
                        <td><span class="status-badge ${r.severity.toLowerCase()}">${r.severity}</span></td>
                        <td>${r.cooldown}s</td>
                        <td>${r.enabled ? '✅' : '❌'}</td>
                        <td>
                            <button class="btn btn-sm btn-warning" onclick="toggleRule(${r.id})">Toggle</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteRule(${r.id})">🗑️</button>
                        </td>
                    `;
                });
            } catch (e) {
                console.error('fetchRules:', e);
                document.getElementById('rulesTableBody').innerHTML = '<tr><td colspan="9" style="color:red;text-align:center;">Failed to load rules.</td></tr>';
            }
        }

        function applyTemplate() {
            const template = document.getElementById('ruleTemplate').value;
            const presets = {
                'high_cpu': { metric: 'cpu', threshold: 85, operator: '>', severity: 'CRITICAL', cause: 'CPU usage exceeded 85%', action: 'Check top processes' },
                'high_memory': { metric: 'memory', threshold: 90, operator: '>', severity: 'CRITICAL', cause: 'Memory usage exceeded 90%', action: 'Check for memory leaks' },
                'disk_full': { metric: 'disk', threshold: 90, operator: '>', severity: 'WARNING', cause: 'Disk usage exceeded 90%', action: 'Clean up logs' },
                'service_down': { metric: 'service:nginx', threshold: 0, operator: '=', severity: 'CRITICAL', cause: 'Service nginx is down', action: 'Restart service' }
            };
            if (template && presets[template]) {
                const p = presets[template];
                document.getElementById('ruleMetric').value = p.metric;
                document.getElementById('ruleThreshold').value = p.threshold;
                document.getElementById('ruleOperator').value = p.operator;
                document.getElementById('ruleSeverity').value = p.severity;
                document.getElementById('ruleCause').value = p.cause;
                document.getElementById('ruleAction').value = p.action;
            }
        }

        async function createRule() {
            const data = {
                hostname: document.getElementById('ruleHostname').value || '%',
                metric: document.getElementById('ruleMetric').value,
                threshold: parseFloat(document.getElementById('ruleThreshold').value) || 0,
                operator: document.getElementById('ruleOperator').value,
                severity: document.getElementById('ruleSeverity').value,
                cooldown: parseInt(document.getElementById('ruleCooldown').value) || 300,
                cause: document.getElementById('ruleCause').value || '',
                action: document.getElementById('ruleAction').value || ''
            };
            try {
                const resp = await fetch('/api/rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (resp.ok) { fetchRules(); } else { alert('Failed to create rule'); }
            } catch (e) { console.error('createRule:', e); alert('Network error.'); }
        }

        async function toggleRule(id) {
            try {
                await fetch('/api/rules/' + id + '/toggle', { method: 'POST' });
                fetchRules();
            } catch (e) { console.error('toggleRule:', e); alert('Failed to toggle rule.'); }
        }

        async function deleteRule(id) {
            if (!confirm('Delete this rule?')) return;
            try {
                await fetch('/api/rules/' + id, { method: 'DELETE' });
                fetchRules();
            } catch (e) { console.error('deleteRule:', e); alert('Failed to delete rule.'); }
        }

        // =========================== ADMIN ===========================
        async function loadAdmin() {
            if (currentUserRole !== 'admin') {
                document.querySelector('#tab-admin .form-section').style.display = 'none';
                document.querySelector('#tab-admin .table-container').style.display = 'none';
                return;
            }
            try {
                const users = await apiFetch('/api/users');
                const uTbody = document.getElementById('usersTableBody');
                uTbody.innerHTML = '';
                users.forEach(function(u) {
                    const row = uTbody.insertRow();
                    row.innerHTML = '<td>' + u.id + '</td><td>' + u.username + '</td><td>' + u.role + '</td><td><button class="btn btn-sm btn-danger" onclick="deleteUser(' + u.id + ')">Delete</button></td>';
                });

                const groups = await apiFetch('/api/groups');
                const gTbody = document.getElementById('groupsTableBody');
                gTbody.innerHTML = '';
                groups.forEach(function(g) {
                    const row = gTbody.insertRow();
                    row.innerHTML = '<td>' + g.id + '</td><td>' + g.name + '</td><td><button class="btn btn-sm btn-danger" onclick="deleteGroup(' + g.id + ')">Delete</button></td>';
                });
            } catch (e) { console.error('loadAdmin:', e); }
        }

        async function createUser() {
            const username = document.getElementById('newUsername').value;
            const password = document.getElementById('newPassword').value;
            const role = document.getElementById('newRole').value;
            try {
                await fetch('/api/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username, password: password, role: role })
                });
                loadAdmin();
            } catch (e) { console.error('createUser:', e); alert('Failed to create user.'); }
        }

        async function deleteUser(id) {
            if (!confirm('Delete user?')) return;
            try {
                await fetch('/api/users/' + id, { method: 'DELETE' });
                loadAdmin();
            } catch (e) { console.error('deleteUser:', e); alert('Failed to delete user.'); }
        }

        async function createGroup() {
            const name = document.getElementById('newGroupName').value;
            try {
                await fetch('/api/groups', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: name })
                });
                loadAdmin();
            } catch (e) { console.error('createGroup:', e); alert('Failed to create group.'); }
        }

        async function deleteGroup(id) {
            if (!confirm('Delete group?')) return;
            try {
                await fetch('/api/groups/' + id, { method: 'DELETE' });
                loadAdmin();
            } catch (e) { console.error('deleteGroup:', e); alert('Failed to delete group.'); }
        }

        // =========================== AI INSIGHTS ===========================
        async function fetchAIInsights() {
            try {
                const data = await apiFetch('/api/ai_insights');
                const tbody = document.getElementById('aiInsightsTableBody');
                tbody.innerHTML = '';
                data.forEach(function(item) {
                    let details = '';
                    if (item.details) {
                        try {
                            const d = JSON.parse(item.details);
                            if (item.metric === 'prediction_disk_full' && d.days_remaining !== undefined) {
                                details = 'Full in ' + d.days_remaining.toFixed(1) + ' days';
                            } else if (item.metric === 'memory_leak_detected') {
                                details = 'Slope: ' + d.slope.toFixed(3);
                            } else {
                                details = 'Anomaly detected';
                            }
                        } catch (e) { details = 'Error parsing details'; }
                    }
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td><strong>${item.hostname}</strong></td>
                        <td>${item.metric}</td>
                        <td>${item.current_value}</td>
                        <td>${item.baseline_mean.toFixed(2)} ± ${item.baseline_std.toFixed(2)}</td>
                        <td>${item.deviation.toFixed(2)}</td>
                        <td><span class="status-badge ${item.severity.toLowerCase()}">${item.severity}</span></td>
                        <td>${item.timestamp ? new Date(item.timestamp).toLocaleString() : ''}</td>
                        <td>${details}</td>
                    `;
                });
            } catch (e) {
                console.error('fetchAIInsights:', e);
                document.getElementById('aiInsightsTableBody').innerHTML = '<tr><td colspan="8" style="color:red;text-align:center;">Failed to load AI insights.</td></tr>';
            }
        }

        // =========================== ALERTS HISTORY ===========================
        async function fetchAlertHistory() {
            try {
                const status = document.getElementById('historyStatusFilter').value;
                const host = document.getElementById('historyHostFilter').value;
                let url = '/api/alerts?';
                if (status) url += 'status=' + status + '&';
                if (host) url += 'host=' + host + '&';
                const data = await apiFetch(url);
                const tbody = document.getElementById('alertHistoryTableBody');
                tbody.innerHTML = '';
                data.forEach(function(a) {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td><strong>${a.hostname}</strong></td>
                        <td>${a.metric}</td>
                        <td>${a.value}</td>
                        <td><span class="status-badge ${a.severity.toLowerCase()}">${a.severity}</span></td>
                        <td>${a.timestamp ? new Date(a.timestamp).toLocaleString() : ''}</td>
                        <td><span class="status-badge ${a.status.toLowerCase()}">${a.status}</span></td>
                    `;
                });
            } catch (e) {
                console.error('fetchAlertHistory:', e);
                document.getElementById('alertHistoryTableBody').innerHTML = '<tr><td colspan="6" style="color:red;text-align:center;">Failed to load alerts history.</td></tr>';
            }
        }
    </script>
</body>
</html>
''',

    "modules/web_ui/templates/login.html": '''<h1 style="font-family:Inter,sans-serif;text-align:center;margin-bottom:20px;">🔐 SysWatch Login</h1>
{% if error %}<p style="color:red;text-align:center;">{{ error }}</p>{% endif %}
<form method="POST" style="max-width:320px;margin:0 auto;">
    <input type="text" name="username" placeholder="Username" required style="width:100%;padding:10px;margin-bottom:10px;border:1px solid #ccc;border-radius:6px;"><br>
    <input type="password" name="password" placeholder="Password" required style="width:100%;padding:10px;margin-bottom:10px;border:1px solid #ccc;border-radius:6px;"><br>
    <button type="submit" style="width:100%;padding:10px;background:#3b82f6;color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer;">Log in</button>
</form>
''',

    # ---------- API ----------
    "modules/api/__init__.py": ''',

    "modules/api/routes.py": '''# modules/api/routes.py
import json, datetime, pymysql, ipaddress, subprocess, threading, socket
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from core.config import Config
from core.database import get_db
from modules.monitoring_checks.status_updater import update_host_status
from modules.alert_engine.lifecycle import evaluate_alerts

api_bp = Blueprint('api', __name__)

@api_bp.route('/report', methods=['POST'])
def report():
    if request.headers.get('X-API-Key') != Config.API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(force=True)
    hostname = data['hostname']
    agent_id = data.get('agent_id', '')
    ip = data['ip']
    group_id = data.get('group_id', None)
    update_host_status(hostname, agent_id, ip, group_id)

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

@api_bp.route('/latest')
@login_required
def latest():
    group_filter = request.args.get('group', '')
    status_filter = request.args.get('status', '')
    db = get_db()
    cur = db.cursor()
    query = """
        SELECT h.hostname, h.agent_id, h.ip, h.status, h.last_seen,
               h.group_id, g.name as group_name,
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
            "group_id": r[5], "group_name": r[6] or "None",
            "cpu": r[7], "memory": r[8], "disk": r[9],
            "network_sent": r[10], "network_recv": r[11],
            "services": json.loads(r[12]) if r[12] else {},
            "network_devices": json.loads(r[13]) if r[13] else []
        })
    cur.close()
    return jsonify(result)

@api_bp.route('/trends/<hostname>')
@login_required
def trends(hostname):
    range_ = request.args.get('range', '1h')
    db = get_db()
    cur = db.cursor()
    intervals = {
        '1h': "1 HOUR", '6h': "6 HOUR", '12h': "12 HOUR",
        '24h': "24 HOUR", '7d': "7 DAY", '30d': "30 DAY"
    }
    if range_ in intervals:
        cur.execute(f"SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL {intervals[range_]} ORDER BY timestamp ASC", (hostname,))
    else:
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s ORDER BY timestamp ASC LIMIT 100", (hostname,))
    rows = cur.fetchall()
    data = [{"timestamp": r[0].isoformat(), "cpu": r[1], "memory": r[2], "disk": r[3]} for r in rows]
    cur.close()
    return jsonify(data)

@api_bp.route('/alerts')
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
    query += " ORDER BY timestamp DESC LIMIT 200"
    cur.execute(query, params)
    rows = cur.fetchall()
    alerts = [{"id": r[0], "hostname": r[1], "metric": r[2], "value": r[3],
               "severity": r[4], "timestamp": r[5].isoformat(), "status": r[6]} for r in rows]
    cur.close()
    return jsonify(alerts)

@api_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE alerts SET status = 'ACKNOWLEDGED', acknowledged_by = %s, acknowledged_at = NOW() WHERE id = %s",
                (current_user.username, alert_id))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

@api_bp.route('/groups')
@login_required
def list_groups():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, name FROM host_groups ORDER BY name")
    groups = [{"id": r[0], "name": r[1]} for r in cur.fetchall()]
    cur.close()
    return jsonify(groups)

@api_bp.route('/groups', methods=['POST'])
@login_required
def create_group():
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
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

@api_bp.route('/groups/<int:group_id>', methods=['DELETE'])
@login_required
def delete_group(group_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM host_groups WHERE id = %s", (group_id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

@api_bp.route('/summary')
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

@api_bp.route('/rules', methods=['GET'])
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

@api_bp.route('/rules', methods=['POST'])
@login_required
def create_rule():
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
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

@api_bp.route('/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
def toggle_rule(rule_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE alert_rules SET enabled = NOT enabled WHERE id = %s", (rule_id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

@api_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
@login_required
def delete_rule(rule_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM alert_rules WHERE id = %s", (rule_id,))
    db.commit()
    cur.close()
    return jsonify({"status": "ok"})

@api_bp.route('/hosts', methods=['GET'])
@login_required
def list_hosts():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname, ip, status, group_id, last_seen FROM hosts ORDER BY hostname")
    rows = cur.fetchall()
    hosts = [{"hostname": r[0], "ip": r[1], "status": r[2], "group_id": r[3], "last_seen": r[4].isoformat() if r[4] else None} for r in rows]
    cur.close()
    return jsonify(hosts)

@api_bp.route('/hosts', methods=['POST'])
@login_required
def add_host():
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json()
    hostname = data.get('hostname')
    ip = data.get('ip')
    group_id = data.get('group_id')
    if not hostname or not ip:
        return jsonify({"error": "Hostname and IP required"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT hostname FROM hosts WHERE hostname = %s", (hostname,))
    if cur.fetchone():
        return jsonify({"error": "Host already exists"}), 409
    cur.execute(
        "INSERT INTO hosts (hostname, ip, last_seen, status, group_id, discovered_by, discovery_time) "
        "VALUES (%s, %s, NOW(), 'UP', %s, 'manual', NOW())",
        (hostname, ip, group_id)
    )
    db.commit()
    cur.close()
    return jsonify({"status": "ok", "hostname": hostname})

@api_bp.route('/ai_insights')
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

# ---- Discovery ----
discovery_status = {"running": False, "progress": 0, "total": 0, "found": 0, "message": ""}

@api_bp.route('/discover/start', methods=['POST'])
@login_required
def start_discovery():
    if current_user.role != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    if discovery_status["running"]:
        return jsonify({"error": "Discovery already running"}), 409
    threading.Thread(target=run_discovery).start()
    return jsonify({"status": "started"})

@api_bp.route('/discover/status')
@login_required
def discovery_status_endpoint():
    return jsonify(discovery_status)

def run_discovery():
    global discovery_status
    discovery_status["running"] = True
    discovery_status["progress"] = 0
    discovery_status["message"] = "Starting discovery..."
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT subnet FROM network_ranges WHERE enabled=1")
    subnets = [r[0] for r in cur.fetchall()]
    if not subnets:
        discovery_status["message"] = "No enabled subnets found."
        discovery_status["running"] = False
        return
    total_hosts = 0
    for subnet in subnets:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            total_hosts += sum(1 for _ in network.hosts())
        except Exception:
            continue
    discovery_status["total"] = total_hosts
    processed = 0
    found_hosts = 0
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
                cur.execute("SELECT hostname FROM hosts WHERE ip=%s", (ip_str,))
                if cur.fetchone():
                    cur.execute("UPDATE hosts SET last_seen=NOW(), status='UP' WHERE ip=%s", (ip_str,))
                else:
                    cur.execute(
                        "INSERT INTO hosts (hostname, ip, last_seen, status, discovered_by, discovery_time) "
                        "VALUES (%s, %s, NOW(), 'UP', 'discovery', NOW())",
                        (hostname, ip_str)
                    )
                    found_hosts += 1
                db.commit()
            processed += 1
            discovery_status["progress"] = int((processed / total_hosts) * 100) if total_hosts > 0 else 0
            discovery_status["found"] = found_hosts
            discovery_status["message"] = f"Scanning {ip_str}..."
    discovery_status["running"] = False
    discovery_status["message"] = f"Discovery complete. Found {found_hosts} new hosts."
''',

    # ---------- MONITORING CHECKS ----------
    "modules/monitoring_checks/__init__.py": ''',

    "modules/monitoring_checks/status_updater.py": '''# modules/monitoring_checks/status_updater.py
import datetime
from core.database import get_db
from core.app import app

STATUS_THRESHOLDS = {"UP": 90, "WARNING": 300}

def update_host_status(hostname, agent_id, ip, group_id=None):
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cur.execute(
            "INSERT INTO hosts (hostname, agent_id, ip, last_seen, status, group_id) "
            "VALUES (%s, %s, %s, %s, 'UP', %s) "
            "ON DUPLICATE KEY UPDATE agent_id = VALUES(agent_id), ip = VALUES(ip), "
            "last_seen = VALUES(last_seen), group_id = VALUES(group_id)",
            (hostname, agent_id, ip, now, group_id)
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
''',

    "modules/monitoring_checks/ssl_expiry.py": '''# modules/monitoring_checks/ssl_expiry.py
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
        print(f"SSL fetch error for {hostname}:{port} - {e}")
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
                    dispatch_alert(
                        hostname=hostname, metric="ssl_expiry", value=days_remaining, threshold=7,
                        severity=severity,
                        cause=f"SSL certificate expires in {days_remaining} days on {stored_expiry}",
                        action="Renew the certificate and update it on the server."
                    )
                elif days_remaining < 0:
                    dispatch_alert(
                        hostname=hostname, metric="ssl_expiry", value=days_remaining, threshold=0,
                        severity="CRITICAL",
                        cause=f"SSL certificate expired on {stored_expiry}",
                        action="Renew the certificate immediately."
                    )
                cur.execute("UPDATE ssl_certificates SET last_checked = NOW() WHERE hostname = %s AND port = 443", (hostname,))
                db.commit()
            else:
                expiry_date = fetch_cert_expiry(hostname, 443)
                if expiry_date:
                    cur.execute(
                        "INSERT INTO ssl_certificates (hostname, port, expiry_date, last_checked) VALUES (%s, 443, %s, NOW())",
                        (hostname, expiry_date)
                    )
                    db.commit()
        cur.close()
''',

    # ---------- ALERT ENGINE ----------
    "modules/alert_engine/__init__.py": ''',

    "modules/alert_engine/lifecycle.py": '''# modules/alert_engine/lifecycle.py
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
                cur.execute(
                    "SELECT id, timestamp, status FROM alerts WHERE hostname=%s AND metric=%s "
                    "AND status IN ('OPEN','ACKNOWLEDGED') ORDER BY timestamp DESC LIMIT 1",
                    (hostname, metric)
                )
                existing = cur.fetchone()
                fire = True
                if existing:
                    last_time = existing[1]
                    if (now - last_time).total_seconds() < cooldown:
                        fire = False
                if fire:
                    cur.execute(
                        "INSERT INTO alerts (hostname, metric, value, threshold, severity, cause, action, status) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, 'OPEN')",
                        (hostname, metric, value, threshold, severity, cause, action)
                    )
                    db.commit()
                    dispatch_alert(hostname, metric, value, threshold, severity, cause, action)
            else:
                cur.execute(
                    "UPDATE alerts SET status = 'RESOLVED', resolved = 1, resolved_at = %s "
                    "WHERE hostname = %s AND metric = %s AND status IN ('OPEN','ACKNOWLEDGED')",
                    (now, hostname, metric)
                )
                db.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Error in evaluate_alerts: {e}", exc_info=True)
''',

    "modules/alert_engine/auto_resolve.py": '''# modules/alert_engine/auto_resolve.py
import datetime, logging
from core.database import get_db

logger = logging.getLogger(__name__)

def auto_resolve_stale_alerts():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT id, hostname, metric, threshold, operator, timestamp
        FROM alerts
        WHERE status = 'ACKNOWLEDGED'
        AND acknowledged_at IS NOT NULL
        AND acknowledged_at < NOW() - INTERVAL 10 MINUTE
    """)
    alerts = cur.fetchall()
    for alert in alerts:
        alert_id, hostname, metric, threshold, operator, alert_time = alert
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
                logger.info(f"Auto-resolved alert {alert_id} for {hostname} {metric}")
    cur.close()
''',

    "modules/alert_engine/notifiers.py": '''# modules/alert_engine/notifiers.py
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
''',

    # ---------- AI ----------
    "modules/ai/__init__.py": ''',

    "modules/ai/anomaly.py": '''# modules/ai/anomaly.py
import statistics, logging, datetime, json
from core.database import get_db
from core.app import app
from modules.alert_engine.notifiers import dispatch_alert
from modules.ai.deepseek import analyze_with_deepseek

logger = logging.getLogger(__name__)

def run_anomaly_detection():
    from core.app import app
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT DISTINCT hostname FROM hosts WHERE status != 'DOWN'")
        hosts = cur.fetchall()
        if not hosts:
            return
        for (hostname,) in hosts:
            for metric in ['cpu', 'memory', 'disk']:
                cur.execute(
                    f"SELECT {metric} FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL 7 DAY "
                    f"AND {metric} IS NOT NULL ORDER BY timestamp DESC LIMIT 100",
                    (hostname,)
                )
                rows = cur.fetchall()
                if len(rows) < 10:
                    continue
                values = [r[0] for r in rows]
                mean = statistics.mean(values)
                std = statistics.stdev(values) if len(values) > 1 else 0
                if std == 0:
                    continue
                cur.execute(
                    f"SELECT {metric} FROM metrics WHERE hostname = %s AND {metric} IS NOT NULL ORDER BY timestamp DESC LIMIT 1",
                    (hostname,)
                )
                current_row = cur.fetchone()
                if not current_row:
                    continue
                current_value = current_row[0]
                if current_value > mean + (2 * std):
                    deviation = (current_value - mean) / std
                    severity = "WARNING" if deviation < 3 else "CRITICAL"
                    details = {"deviation": deviation, "mean": mean, "std": std}
                    ai_analysis = analyze_with_deepseek(
                        analysis_type="anomaly",
                        context={
                            "hostname": hostname,
                            "metric": metric,
                            "current_value": current_value,
                            "baseline_mean": mean,
                            "baseline_std": std,
                            "deviation": deviation
                        }
                    )
                    if ai_analysis:
                        details["ai_summary"] = ai_analysis.get("summary", "")
                        details["ai_recommendation"] = ai_analysis.get("recommendation", "")
                    cur.execute(
                        "INSERT INTO ai_insights (hostname, metric, current_value, baseline_mean, baseline_std, deviation, severity, details) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (hostname, metric, current_value, mean, std, deviation, severity, json.dumps(details))
                    )
                    db.commit()
                    dispatch_alert(hostname, f"ai_{metric}", current_value, round(mean + 2*std, 2), severity,
                                   f"AI anomaly: {metric} exceeded baseline. {ai_analysis.get('summary', '')}" if ai_analysis else f"AI anomaly: {metric} exceeded baseline.",
                                   ai_analysis.get("recommendation", "Investigate recent changes.") if ai_analysis else "Investigate recent changes.")
        cur.close()

def run_predictions():
    from core.app import app
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT hostname FROM hosts WHERE status != 'DOWN'")
        hosts = cur.fetchall()
        for (hostname,) in hosts:
            # Disk full prediction
            cur.execute("""
                SELECT disk, UNIX_TIMESTAMP(timestamp) as ts FROM metrics WHERE hostname = %s AND disk IS NOT NULL 
                AND timestamp >= NOW() - INTERVAL 7 DAY ORDER BY timestamp ASC
            """, (hostname,))
            rows = cur.fetchall()
            if len(rows) >= 2:
                values = [r[0] for r in rows]
                times = [r[1] for r in rows]
                n = len(times)
                sum_x = sum(times)
                sum_y = sum(values)
                sum_xy = sum([t*v for t,v in zip(times, values)])
                sum_x2 = sum([t**2 for t in times])
                denom = n*sum_x2 - sum_x**2
                if denom != 0:
                    slope = (n*sum_xy - sum_x*sum_y) / denom
                    if slope > 0:
                        last_value = values[-1]
                        if last_value < 95:
                            days_to_full = (95 - last_value) / (slope * 86400)
                            if days_to_full < 30:
                                severity = "WARNING" if days_to_full > 7 else "CRITICAL"
                                details = {"estimated_full_date": (datetime.datetime.now() + datetime.timedelta(days=days_to_full)).isoformat(),
                                           "days_remaining": days_to_full}
                                ai_analysis = analyze_with_deepseek(
                                    analysis_type="prediction",
                                    context={
                                        "hostname": hostname,
                                        "metric": "disk",
                                        "current_usage": last_value,
                                        "days_to_full": days_to_full
                                    }
                                )
                                if ai_analysis:
                                    details["ai_summary"] = ai_analysis.get("summary", "")
                                    details["ai_recommendation"] = ai_analysis.get("recommendation", "")
                                cur.execute(
                                    "INSERT INTO ai_insights (hostname, metric, current_value, baseline_mean, baseline_std, deviation, severity, details) "
                                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                                    (hostname, "prediction_disk_full", days_to_full, 0, 0, 0, severity, json.dumps(details))
                                )
                                db.commit()
                                dispatch_alert(hostname, "prediction_disk_full", days_to_full, 0, severity,
                                               f"Disk will be full in {days_to_full:.1f} days. {ai_analysis.get('summary', '')}" if ai_analysis else f"Disk will be full in {days_to_full:.1f} days.",
                                               ai_analysis.get("recommendation", "Extend volume or clean up files.") if ai_analysis else "Extend volume or clean up files.")
            # Memory leak detection
            cur.execute("""
                SELECT memory, UNIX_TIMESTAMP(timestamp) as ts FROM metrics WHERE hostname = %s AND memory IS NOT NULL 
                AND timestamp >= NOW() - INTERVAL 7 DAY ORDER BY timestamp ASC
            """, (hostname,))
            rows = cur.fetchall()
            if len(rows) >= 2:
                values = [r[0] for r in rows]
                times = [r[1] for r in rows]
                n = len(times)
                sum_x = sum(times)
                sum_y = sum(values)
                sum_xy = sum([t*v for t,v in zip(times, values)])
                sum_x2 = sum([t**2 for t in times])
                denom = n*sum_x2 - sum_x**2
                if denom != 0:
                    slope = (n*sum_xy - sum_x*sum_y) / denom
                    if slope > 0.1:
                        severity = "WARNING" if slope < 0.2 else "CRITICAL"
                        details = {"slope": slope}
                        ai_analysis = analyze_with_deepseek(
                            analysis_type="prediction",
                            context={
                                "hostname": hostname,
                                "metric": "memory",
                                "slope": slope,
                                "current_memory": values[-1]
                            }
                        )
                        if ai_analysis:
                            details["ai_summary"] = ai_analysis.get("summary", "")
                            details["ai_recommendation"] = ai_analysis.get("recommendation", "")
                        cur.execute(
                            "INSERT INTO ai_insights (hostname, metric, current_value, baseline_mean, baseline_std, deviation, severity, details) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                            (hostname, "memory_leak_detected", slope, 0, 0, 0, severity, json.dumps(details))
                        )
                        db.commit()
                        dispatch_alert(hostname, "memory_leak_detected", slope, 0, severity,
                                       f"Memory usage increasing steadily (slope {slope:.2f}% per second). {ai_analysis.get('summary', '')}" if ai_analysis else f"Memory usage increasing steadily (slope {slope:.2f}% per second).",
                                       ai_analysis.get("recommendation", "Check for memory leaks.") if ai_analysis else "Check for memory leaks.")
        cur.close()

def send_daily_briefing():
    from core.app import app
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= NOW() - INTERVAL 1 DAY")
        total_alerts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= NOW() - INTERVAL 1 DAY AND status='OPEN'")
        open_alerts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= NOW() - INTERVAL 1 DAY AND status='RESOLVED'")
        resolved_alerts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM hosts WHERE discovery_time >= NOW() - INTERVAL 1 DAY")
        new_hosts = cur.fetchone()[0]
        context = {
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "resolved_alerts": resolved_alerts,
            "new_hosts": new_hosts,
            "timestamp": datetime.datetime.now().isoformat()
        }
        ai_analysis = analyze_with_deepseek("briefing", context)
        if ai_analysis:
            subject = "[SysWatch] Daily Briefing"
            body = f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\\n\\n"
            body += ai_analysis.get("summary", "No significant changes.")
            body += "\\n\\n" + ai_analysis.get("details", "")
            dispatch_alert(None, "daily_briefing", 0, 0, "INFO", body, "Review the daily briefing.")
        else:
            subject = "[SysWatch] Daily Briefing"
            body = f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\\n"
            body += f"Total Alerts (24h): {total_alerts}\\n"
            body += f"Open Alerts: {open_alerts}\\n"
            body += f"Resolved Alerts: {resolved_alerts}\\n"
            body += f"New Hosts Discovered: {new_hosts}\\n"
            dispatch_alert(None, "daily_briefing", 0, 0, "INFO", body, "Review the daily briefing.")
''',

    "modules/ai/deepseek.py": '''# modules/ai/deepseek.py
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
        logger.info("No AI API key configured – skipping AI analysis.")
        return None

    system_prompt = """
    You are SysWatch AI, an expert infrastructure monitoring assistant.
    Respond in JSON format with keys: analysis_type, severity, summary, details, recommendation, confidence.
    """
    user_prompt = f"""
    Analysis Type: {analysis_type}
    Context: {json.dumps(context, indent=2)}
    """

    # Try DeepSeek first
    if DEEPSEEK_API_KEY:
        try:
            payload = {
                "model": DEEPSEEK_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.3,
                "response_format": {"type": "json_object"}
            }
            resp = requests.post(
                DEEPSEEK_API_URL,
                headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"},
                json=payload,
                timeout=30
            )
            if resp.status_code == 200:
                result = resp.json()
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                return json.loads(content)
            else:
                logger.warning(f"DeepSeek API error: {resp.status_code}")
        except Exception as e:
            logger.warning(f"DeepSeek connection error: {e}")

    # Fallback to Gemini if available
    if GEMINI_API_KEY:
        try:
            payload = {
                "contents": [{
                    "parts": [{
                        "text": f"{system_prompt}\\n\\n{user_prompt}"
                    }]
                }]
            }
            resp = requests.post(
                f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
                json=payload,
                timeout=30
            )
            if resp.status_code == 200:
                result = resp.json()
                text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                # Try to parse JSON from the response
                import re
                json_match = re.search(r'\\{.*\\}', text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(0))
                return {"summary": text[:200], "recommendation": "Check Gemini response for details."}
            else:
                logger.warning(f"Gemini API error: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Gemini connection error: {e}")

    logger.info("All AI providers failed – falling back to statistical analysis.")
    return None
''',

    # ---------- AGENT ----------
    "agents/__init__.py": ''',

    "agents/client.py": '''#!/usr/bin/env python3
"""
SysWatch Agent v1.1.0
Collects metrics, services, device health, system events, and file changes.
"""
import os, sys, time, json, socket, subprocess, platform, uuid, threading, logging, hashlib
import requests, psutil
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

SERVER_URL = os.getenv("SERVER_URL", "https://your-domain.com/api/report")
EVENT_URL = os.getenv("EVENT_URL", "https://your-domain.com/api/events")
API_KEY = os.getenv("API_KEY", "")
GROUP_ID = os.getenv("GROUP_ID")
AGENT_ID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_id")

SERVICES_TO_CHECK = ["sshd", "nginx", "mysql", "docker", "systemd-logind"]
NETWORK_DEVICES = []

logger = logging.getLogger("syswatch-agent")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
logger.addHandler(handler)

def get_agent_id():
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, "r") as f:
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
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def collect_metrics():
    hostname = socket.gethostname()
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    net = psutil.net_io_counters()
    services = {}
    for svc in SERVICES_TO_CHECK:
        try:
            rc = subprocess.call(["systemctl", "is-active", "--quiet", svc])
            services[svc] = "running" if rc == 0 else "stopped"
        except:
            services[svc] = "unknown"
    devices = []
    for dev in NETWORK_DEVICES:
        reachable = subprocess.call(["ping", "-c", "1", dev["ip"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        devices.append({"name": dev["name"], "ip": dev["ip"], "type": dev.get("type", "device"), "reachable": reachable})
    payload = {
        "hostname": hostname,
        "agent_id": get_agent_id(),
        "ip": get_ip(),
        "uptime": int(time.time() - psutil.boot_time()),
        "cpu": cpu, "memory": mem, "disk": disk,
        "network_sent": net.bytes_sent, "network_recv": net.bytes_recv,
        "services": services, "network_devices": devices,
    }
    if GROUP_ID:
        payload["group_id"] = int(GROUP_ID)
    return payload

def collect_login_events():
    events = []
    try:
        output = subprocess.check_output(["last", "-n", "20"], text=True)
        lines = output.splitlines()
        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 3:
                user = parts[0]
                if user in ("reboot", "wtmp", "shutdown"):
                    continue
                events.append({
                    "event_type": "login",
                    "user": user,
                    "source": "last",
                    "details": {"line": line}
                })
    except Exception as e:
        logger.error(f"Login event error: {e}")
    return events

def collect_update_events():
    events = []
    if platform.system() == "Linux":
        try:
            with open("/var/log/dpkg.log", "r") as f:
                lines = f.readlines()[-20:]
                for line in lines:
                    if "status installed" in line or "upgrade" in line:
                        events.append({
                            "event_type": "package_update",
                            "source": "dpkg",
                            "details": {"line": line.strip()}
                        })
        except FileNotFoundError:
            pass
    return events

def send_events(events):
    if not events:
        return
    try:
        payload = {"events": events}
        resp = requests.post(EVENT_URL, json=payload, headers={"X-API-Key": API_KEY}, timeout=10)
        if resp.status_code != 200:
            logger.error(f"Event send failed: {resp.status_code}")
    except Exception as e:
        logger.error(f"Event send error: {e}")

def main():
    logger.info("SysWatch Agent v1.1.0 starting...")
    while True:
        try:
            data = collect_metrics()
            resp = requests.post(SERVER_URL, json=data, headers={"X-API-Key": API_KEY}, timeout=10)
            if resp.status_code == 200:
                logger.info("Metrics sent")
            else:
                logger.error(f"Metrics error: {resp.status_code}")
            if int(time.time()) % 300 == 0:
                events = collect_login_events() + collect_update_events()
                send_events(events)
        except Exception as e:
            logger.error(f"Error: {e}")
        time.sleep(60)

if __name__ == "__main__":
    main()
''',

    # ---------- TOP LEVEL ----------
    "wsgi.py": '''from core.app import app
if __name__ == "__main__":
    app.run()
''',

    "requirements.txt": '''flask
flask-login
pymysql
python-dotenv
requests
psutil
gunicorn
apscheduler
pyOpenSSL
''',

    ".env.example": '''SECRET_KEY=your-secret-key-here
DB_HOST=127.0.0.1
DB_USER=monitor
DB_PASSWORD=your-db-password
DB_NAME=monitoring
API_KEY=your-api-key-here
ADMIN_PASSWORD=admin123
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=recipient@example.com
TEAMS_WEBHOOK_URL=https://your.webhook.url
DISCOVERY_SUBNET=192.168.1.0/24
DEEPSEEK_API_KEY=your-deepseek-api-key
DEEPSEEK_API_URL=https://api.deepseek.com/v1/chat/completions
DEEPSEEK_MODEL=deepseek-chat
GEMINI_API_KEY=your-gemini-api-key
''',

    "README.md": '''# SysWatch v1.1.0
Simple Monitoring. Smarter Operations.

## Features
- Modern, responsive dashboard (AI Studio inspired UI)
- DeepSeek AI integration (with Gemini fallback) for root cause analysis, predictions, and daily briefings
- Full-featured sidebar menu with: Dashboard, Monitoring, Alert Rules, Admin, AI Insights, Alerts History
- Auto-discovery of hosts via ping sweep
- Cross-platform agent with event collection
- Alert lifecycle (OPEN, ACKNOWLEDGED, RESOLVED)
- Installers for Linux and Windows

## Quick Install

### Linux
```bash
sudo bash install.sh