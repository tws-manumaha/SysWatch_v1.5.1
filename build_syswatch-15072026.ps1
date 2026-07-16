# SysWatch v1.1.0 Complete Builder (Windows)
# Run: powershell -ExecutionPolicy Bypass -File build_syswatch.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SysWatch v1.1.0 Project Builder       " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$TARGET_DIR = "syswatch_v1.1.0"
New-Item -ItemType Directory -Path $TARGET_DIR -Force | Out-Null
Set-Location $TARGET_DIR

# Create directory structure
$folders = @(
    "core",
    "modules",
    "modules\authentication",
    "modules\web_ui",
    "modules\web_ui\templates",
    "modules\web_ui\static",
    "modules\api",
    "modules\monitoring_checks",
    "modules\alert_engine",
    "modules\ai",
    "modules\rules",
    "modules\dashboard",
    "agents",
    "scripts"
)
foreach ($folder in $folders) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

function Write-File {
    param($Path, $Content)
    $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

# ------------------- CORE FILES -------------------
Write-File "core\__init__.py" "# core/__init__.py"

Write-File "core\config.py" @'
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
'@

Write-File "core\database.py" @'
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
'@

Write-File "core\scheduler.py" @'
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
'@

Write-File "core\app.py" @'
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
'@

# ------------------- MODULES: Authentication -------------------
Write-File "modules\authentication\__init__.py" ""
Write-File "modules\authentication\models.py" @'
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
'@

Write-File "modules\authentication\routes.py" @'
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
'@

# ------------------- MODULES: Web UI -------------------
Write-File "modules\web_ui\__init__.py" ""
Write-File "modules\web_ui\routes.py" @'
from flask import Blueprint, render_template
from flask_login import login_required

ui_bp = Blueprint('web_ui', __name__)

@ui_bp.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')
'@

# dashboard.html (full content) – we use a here-string with no escaping issues
Write-File "modules\web_ui\templates\dashboard.html" @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SysWatch v1.1.0</title>
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
        .ack-btn { background: var(--warning); border: none; padding: 2px 8px; border-radius: 4px; cursor: pointer; color: #fff; }
        .rule-form-section { background: var(--card-bg); padding: 15px; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; }
        .rule-form-section h4 { margin-bottom: 10px; }
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
            <li data-tab="monitoring"><span>🖥️ Monitoring</span></li>
            <li data-tab="rules"><span>⚙️ Rules</span></li>
            <li data-tab="admin"><span>👤 Admin</span></li>
            <li data-tab="ai"><span>🤖 AI Insights</span></li>
            <li data-tab="alerts_history"><span>📜 Alerts History</span></li>
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

        <!-- Dashboard Tab -->
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
            <table id="devicesTable">
                <thead><tr><th>Hostname</th><th>IP</th><th>Status</th><th>Group</th><th>Last Seen</th><th>CPU%</th><th>Mem%</th><th>Disk%</th><th>Services</th></tr></thead>
                <tbody></tbody>
            </table>
            <div class="chart-box">
                <div class="inline-form">
                    <label>Range: <select id="trendRange" onchange="loadChart()">
                        <option value="1h">Last Hour</option>
                        <option value="6h">Last 6 Hours</option>
                        <option value="12h">Last 12 Hours</option>
                        <option value="24h">Last 24 Hours</option>
                        <option value="7d">Last Week</option>
                        <option value="30d">Last Month</option>
                    </select></label>
                    <label>Metric: <select id="trendMetric" onchange="loadChart()">
                        <option value="cpu">CPU</option>
                        <option value="memory">Memory</option>
                        <option value="disk">Disk</option>
                    </select></label>
                    <label>Hosts: <select id="trendHosts" multiple size="2" onchange="loadChart()"></select></label>
                    <button onclick="loadChart()" class="btn">Update Chart</button>
                </div>
                <canvas id="trendChart"></canvas>
            </div>
        </div>

        <!-- Monitoring Tab -->
        <div id="tab-monitoring" class="tab-content">
            <h3>Hosts & Devices</h3>
            <div class="rule-form-section" style="margin-bottom:15px;">
                <h4>Add Host Manually</h4>
                <div class="inline-form">
                    <input type="text" id="newHostname" placeholder="Hostname">
                    <input type="text" id="newHostIP" placeholder="IP Address">
                    <select id="newHostGroup"><option value="">No Group</option></select>
                    <button class="btn" onclick="addHost()">Add Host</button>
                </div>
                <div id="addHostMessage" style="margin-top:5px;"></div>
            </div>
            <div class="rule-form-section">
                <h4>Auto‑Discovery</h4>
                <div class="inline-form">
                    <button class="btn btn-success" onclick="startDiscovery()">🔍 Scan Network</button>
                    <span id="discoveryStatus" style="margin-left:10px;">Idle</span>
                </div>
                <div class="progress-bar"><div class="progress" id="discoveryProgress" style="width:0%;"></div></div>
                <div id="discoveryMessage" style="margin-top:5px;"></div>
            </div>
            <div class="filter-bar">
                <label>Type: <select id="monitoringType"><option value="hosts">Hosts</option><option value="devices">Devices</option></select></label>
                <button onclick="fetchMonitoring()" class="btn">Refresh</button>
            </div>
            <table id="monitoringTable">
                <thead><tr><th>Name</th><th>IP</th><th>Status</th><th>Type</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>

        <!-- Rules Tab -->
        <div id="tab-rules" class="tab-content">
            <h3>Alert Rules Management</h3>
            <div class="rule-form-section">
                <h4>Add New Rule</h4>
                <div class="inline-form">
                    <input type="text" id="ruleHostname" placeholder="Hostname (or % for all)" value="%">
                    <input type="text" id="ruleMetric" placeholder="Metric (cpu, memory, disk, uptime, etc.)">
                    <input type="number" id="ruleThreshold" placeholder="Threshold">
                    <select id="ruleOperator"><option value=">">&gt;</option><option value="<">&lt;</option></select>
                    <select id="ruleSeverity"><option value="WARNING">WARNING</option><option value="CRITICAL">CRITICAL</option></select>
                    <input type="number" id="ruleCooldown" placeholder="Cooldown (sec)" value="300">
                    <input type="text" id="ruleCause" placeholder="Cause (optional)">
                    <input type="text" id="ruleAction" placeholder="Action (optional)">
                    <button class="btn" onclick="createRule()">Add Rule</button>
                </div>
                <div class="inline-form" style="margin-top:8px;">
                    <label>Template:</label>
                    <select id="ruleTemplate" onchange="applyTemplate()">
                        <option value="">None</option>
                        <option value="high_cpu">High CPU</option>
                        <option value="high_memory">High Memory</option>
                        <option value="disk_full">Disk Full</option>
                        <option value="service_down">Service Down</option>
                    </select>
                    <button class="btn btn-sm btn-secondary" onclick="applyTemplate()">Apply</button>
                </div>
            </div>
            <table id="rulesTable">
                <thead><tr><th>ID</th><th>Host</th><th>Metric</th><th>Threshold</th><th>Op</th><th>Severity</th><th>Cooldown</th><th>Enabled</th><th>Actions</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>

        <!-- Admin Tab -->
        <div id="tab-admin" class="tab-content">
            <h3>User Management</h3>
            <div class="rule-form-section">
                <h4>Create New User</h4>
                <div class="inline-form">
                    <input type="text" id="newUsername" placeholder="Username">
                    <input type="password" id="newPassword" placeholder="Password">
                    <select id="newRole"><option value="manager">Manager</option><option value="admin">Admin</option></select>
                    <button class="btn" onclick="createUser()">Create</button>
                </div>
            </div>
            <table id="usersTable">
                <thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Actions</th></tr></thead>
                <tbody></tbody>
            </table>
            <h3>Host Groups</h3>
            <div class="inline-form">
                <input type="text" id="newGroupName" placeholder="Group name">
                <button class="btn" onclick="createGroup()">Create</button>
            </div>
            <table id="groupsTable">
                <thead><tr><th>ID</th><th>Name</th><th>Actions</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>

        <!-- AI Insights Tab -->
        <div id="tab-ai" class="tab-content">
            <h3>AI Insights & Predictions</h3>
            <table id="aiInsightsTable">
                <thead><tr><th>Host</th><th>Metric</th><th>Value</th><th>Baseline</th><th>Deviation</th><th>Severity</th><th>Time</th><th>Details</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>

        <!-- Alerts History Tab -->
        <div id="tab-alerts_history" class="tab-content">
            <h3>Alerts History</h3>
            <div class="filter-bar">
                <label>Status: <select id="historyStatusFilter"><option value="">All</option><option value="OPEN">OPEN</option><option value="ACKNOWLEDGED">ACKNOWLEDGED</option><option value="RESOLVED">RESOLVED</option></select></label>
                <label>Host: <input type="text" id="historyHostFilter" placeholder="Hostname"></label>
                <button onclick="fetchAlertHistory()" class="btn">Refresh</button>
            </div>
            <table id="alertHistoryTable">
                <thead><tr><th>Host</th><th>Metric</th><th>Value</th><th>Severity</th><th>Time</th><th>Status</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <script>
        // ======================== GLOBAL ========================
        let currentUserRole = "{{ current_user.role }}";
        let selectedHosts = [];
        let trendChart = null;
        let discoveryInterval = null;

        function toggleDarkMode() {
            document.body.classList.toggle('dark');
            localStorage.setItem('darkMode', document.body.classList.contains('dark'));
        }
        if (localStorage.getItem('darkMode') === 'true') document.body.classList.add('dark');

        // ======================== MENU ========================
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('#menu li[data-tab]').forEach(function(el) {
                el.addEventListener('click', function() {
                    try {
                        document.querySelectorAll('#menu li').forEach(function(li) { li.classList.remove('active'); });
                        this.classList.add('active');
                        const tab = this.dataset.tab;
                        document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
                        document.getElementById('tab-' + tab).classList.add('active');
                        document.getElementById('pageTitle').innerText = this.innerText.trim();
                        if (tab === 'dashboard') { fetchSummary(); fetchDevices(); loadTrendHosts(); }
                        else if (tab === 'monitoring') { fetchMonitoring(); loadGroupsForAddHost(); }
                        else if (tab === 'rules') { fetchRules(); }
                        else if (tab === 'admin') { loadAdmin(); }
                        else if (tab === 'ai') { fetchAIInsights(); }
                        else if (tab === 'alerts_history') { fetchAlertHistory(); }
                    } catch (e) {
                        console.error('Menu click error:', e);
                    }
                });
            });
            // Initial load
            fetchSummary(); fetchDevices(); loadTrendHosts();
            fetchMonitoring(); loadGroupsForAddHost();
            fetchRules(); loadAdmin(); fetchAIInsights(); fetchAlertHistory();
            setInterval(function() {
                if (document.getElementById('tab-dashboard').classList.contains('active')) {
                    fetchDevices(); fetchSummary();
                }
            }, 30000);
        });

        // ======================== DASHBOARD ========================
        async function fetchSummary() {
            try {
                const resp = await fetch('/api/summary');
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const data = await resp.json();
                document.getElementById('totalHosts').textContent = data.total || 0;
                document.getElementById('upHosts').textContent = data.up || 0;
                document.getElementById('warnHosts').textContent = data.warning || 0;
                document.getElementById('downHosts').textContent = data.down || 0;
                document.getElementById('openAlerts').textContent = data.open_alerts || 0;
            } catch (e) {
                console.error('fetchSummary error:', e);
                document.querySelector('#summaryCards').innerHTML += '<div style="color:red;">Failed to load summary.</div>';
            }
        }

        async function fetchDevices() {
            try {
                const gf = document.getElementById('groupFilter').value;
                const sf = document.getElementById('statusFilter').value;
                let url = '/api/latest?';
                if (gf) url += 'group=' + gf + '&';
                if (sf) url += 'status=' + sf + '&';
                const resp = await fetch(url);
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const data = await resp.json();
                const tbody = document.querySelector('#devicesTable tbody');
                tbody.innerHTML = '';
                data.forEach(function(d) {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${d.hostname}</td>
                        <td>${d.ip}</td>
                        <td class="status-${d.status}">${d.status}</td>
                        <td>${d.group_name}</td>
                        <td>${d.last_seen || ''}</td>
                        <td>${d.cpu != null ? d.cpu + '%' : 'N/A'}</td>
                        <td>${d.memory != null ? d.memory + '%' : 'N/A'}</td>
                        <td>${d.disk != null ? d.disk + '%' : 'N/A'}</td>
                        <td>${formatServices(d.services)}</td>
                    `;
                });
                await loadGroupFilterOptions();
                fetchSummary();
            } catch (e) {
                console.error('fetchDevices error:', e);
                document.querySelector('#devicesTable tbody').innerHTML = '<tr><td colspan="9" style="color:red;">Failed to load devices. Please refresh.</td></tr>';
            }
        }

        function formatServices(s) {
            if (!s || Object.keys(s).length === 0) return 'N/A';
            return Object.entries(s).map(function(arr) { return arr[0] + ':' + arr[1]; }).join(', ');
        }

        async function loadGroupFilterOptions() {
            try {
                const sel = document.getElementById('groupFilter');
                const resp = await fetch('/api/groups');
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const groups = await resp.json();
                const current = sel.value;
                sel.innerHTML = '<option value="">All</option>';
                groups.forEach(function(g) {
                    sel.innerHTML += '<option value="' + g.id + '" ' + (g.id == current ? 'selected' : '') + '>' + g.name + '</option>';
                });
            } catch (e) {
                console.error('loadGroupFilterOptions error:', e);
            }
        }

        async function loadTrendHosts() {
            try {
                const resp = await fetch('/api/hosts');
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const hosts = await resp.json();
                const sel = document.getElementById('trendHosts');
                sel.innerHTML = '';
                hosts.forEach(function(h) {
                    sel.innerHTML += '<option value="' + h.hostname + '">' + h.hostname + '</option>';
                });
                const options = sel.options;
                for (let i = 0; i < Math.min(2, options.length); i++) {
                    options[i].selected = true;
                }
                loadChart();
            } catch (e) {
                console.error('loadTrendHosts error:', e);
            }
        }

        async function loadChart() {
            const range = document.getElementById('trendRange').value;
            const metric = document.getElementById('trendMetric').value;
            const sel = document.getElementById('trendHosts');
            const hosts = [];
            for (let i = 0; i < sel.options.length; i++) {
                if (sel.options[i].selected) hosts.push(sel.options[i].value);
            }
            if (hosts.length === 0) return;
            const ctx = document.getElementById('trendChart');
            if (!ctx) return;
            if (trendChart) trendChart.destroy();
            const datasets = [];
            const colors = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c'];
            try {
                for (let idx = 0; idx < hosts.length; idx++) {
                    const host = hosts[idx];
                    const resp = await fetch('/api/trends/' + host + '?range=' + range);
                    if (!resp.ok) throw new Error('HTTP ' + resp.status);
                    const data = await resp.json();
                    if (data.length === 0) continue;
                    const values = data.map(function(d) { return d[metric] || 0; });
                    const labels = data.map(function(d) { return d.timestamp; });
                    datasets.push({
                        label: host + ' (' + metric.toUpperCase() + ')',
                        data: values,
                        borderColor: colors[idx % colors.length],
                        fill: false,
                        tension: 0.1,
                        pointRadius: 1
                    });
                }
                if (datasets.length === 0) {
                    document.querySelector('#trendChart').innerHTML = '<p>No data available for the selected range.</p>';
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
                console.error('loadChart error:', e);
                document.querySelector('#trendChart').innerHTML = '<p style="color:red;">Failed to load chart.</p>';
            }
        }

        // ======================== MONITORING ========================
        async function loadGroupsForAddHost() {
            try {
                const resp = await fetch('/api/groups');
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const groups = await resp.json();
                const sel = document.getElementById('newHostGroup');
                sel.innerHTML = '<option value="">No Group</option>';
                groups.forEach(function(g) {
                    sel.innerHTML += '<option value="' + g.id + '">' + g.name + '</option>';
                });
            } catch (e) {
                console.error('loadGroupsForAddHost error:', e);
            }
        }

        async function addHost() {
            const hostname = document.getElementById('newHostname').value.trim();
            const ip = document.getElementById('newHostIP').value.trim();
            const group = document.getElementById('newHostGroup').value;
            if (!hostname || !ip) { alert('Hostname and IP required'); return; }
            try {
                const resp = await fetch('/api/hosts', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hostname: hostname, ip: ip, group_id: group || null })
                });
                const data = await resp.json();
                const msg = document.getElementById('addHostMessage');
                if (resp.ok) {
                    msg.innerHTML = '<span style="color:green;">✅ Host ' + hostname + ' added.</span>';
                    fetchMonitoring();
                } else {
                    msg.innerHTML = '<span style="color:red;">❌ ' + (data.error || 'Unknown error') + '</span>';
                }
            } catch (e) {
                console.error('addHost error:', e);
                document.getElementById('addHostMessage').innerHTML = '<span style="color:red;">❌ Network error.</span>';
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
                        const stResp = await fetch('/api/discover/status');
                        if (!stResp.ok) throw new Error('HTTP ' + stResp.status);
                        const st = await stResp.json();
                        statusDiv.innerText = st.running ? 'Running...' : 'Idle';
                        progressDiv.style.width = st.progress + '%';
                        msgDiv.innerText = st.message || '';
                        if (!st.running) {
                            clearInterval(discoveryInterval);
                            discoveryInterval = null;
                            fetchMonitoring();
                        }
                    } catch (e) {
                        console.error('Discovery status error:', e);
                        clearInterval(discoveryInterval);
                        discoveryInterval = null;
                        statusDiv.innerText = 'Error';
                        msgDiv.innerText = 'Failed to get status.';
                    }
                }, 1000);
            } catch (e) {
                console.error('startDiscovery error:', e);
                statusDiv.innerText = 'Error';
                msgDiv.innerText = 'Discovery failed: ' + e.message;
            }
        }

        async function fetchMonitoring() {
            try {
                const type = document.getElementById('monitoringType').value;
                const resp = await fetch('/api/hosts');
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const data = await resp.json();
                const tbody = document.querySelector('#monitoringTable tbody');
                tbody.innerHTML = '';
                if (type === 'hosts') {
                    data.forEach(function(d) {
                        const row = tbody.insertRow();
                        row.innerHTML = '<td>' + d.hostname + '</td><td>' + d.ip + '</td><td class="status-' + d.status + '">' + d.status + '</td><td>Host</td>';
                    });
                } else {
                    const resp2 = await fetch('/api/latest');
                    if (!resp2.ok) throw new Error('HTTP ' + resp2.status);
                    const latest = await resp2.json();
                    latest.forEach(function(d) {
                        if (d.network_devices && d.network_devices.length) {
                            d.network_devices.forEach(function(dev) {
                                const row = tbody.insertRow();
                                row.innerHTML = '<td>' + dev.name + '</td><td>' + dev.ip + '</td><td class="status-' + (dev.reachable ? 'UP' : 'DOWN') + '">' + (dev.reachable ? 'UP' : 'DOWN') + '</td><td>' + (dev.type || 'Device') + '</td>';
                            });
                        }
                    });
                }
            } catch (e) {
                console.error('fetchMonitoring error:', e);
                document.querySelector('#monitoringTable tbody').innerHTML = '<tr><td colspan="4" style="color:red;">Failed to load data.</td></tr>';
            }
        }

        // ======================== RULES ========================
        async function fetchRules() {
            try {
                const resp = await fetch('/api/rules');
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const data = await resp.json();
                const tbody = document.querySelector('#rulesTable tbody');
                tbody.innerHTML = '';
                data.forEach(function(r) {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${r.id}</td>
                        <td>${r.hostname}</td>
                        <td>${r.metric}</td>
                        <td>${r.threshold}</td>
                        <td>${r.operator}</td>
                        <td>${r.severity}</td>
                        <td>${r.cooldown}</td>
                        <td>${r.enabled ? '✅' : '❌'}</td>
                        <td>
                            <button class="btn btn-sm btn-warning" onclick="toggleRule(${r.id})">Toggle</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteRule(${r.id})">🗑️</button>
                        </td>
                    `;
                });
            } catch (e) {
                console.error('fetchRules error:', e);
                document.querySelector('#rulesTable tbody').innerHTML = '<tr><td colspan="9" style="color:red;">Failed to load rules.</td></tr>';
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
                hostname: document.getElementById('ruleHostname').value,
                metric: document.getElementById('ruleMetric').value,
                threshold: parseFloat(document.getElementById('ruleThreshold').value) || 0,
                operator: document.getElementById('ruleOperator').value,
                severity: document.getElementById('ruleSeverity').value,
                cooldown: parseInt(document.getElementById('ruleCooldown').value) || 300,
                cause: document.getElementById('ruleCause').value,
                action: document.getElementById('ruleAction').value,
                enabled: 1
            };
            try {
                const resp = await fetch('/api/rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (resp.ok) { fetchRules(); } else { alert('Failed to create rule'); }
            } catch (e) {
                console.error('createRule error:', e);
                alert('Network error.');
            }
        }

        async function toggleRule(id) {
            try {
                await fetch('/api/rules/' + id + '/toggle', { method: 'POST' });
                fetchRules();
            } catch (e) {
                console.error('toggleRule error:', e);
                alert('Failed to toggle rule.');
            }
        }

        async function deleteRule(id) {
            if (!confirm('Delete this rule?')) return;
            try {
                await fetch('/api/rules/' + id, { method: 'DELETE' });
                fetchRules();
            } catch (e) {
                console.error('deleteRule error:', e);
                alert('Failed to delete rule.');
            }
        }

        // ======================== ADMIN ========================
        async function loadAdmin() {
            if (currentUserRole !== 'admin') {
                document.querySelector('#tab-admin .rule-form-section').style.display = 'none';
                document.querySelector('#tab-admin #usersTable').style.display = 'none';
                document.querySelector('#tab-admin #groupsTable').style.display = 'none';
                return;
            }
            try {
                const uResp = await fetch('/api/users');
                if (!uResp.ok) throw new Error('HTTP ' + uResp.status);
                const users = await uResp.json();
                const uTbody = document.querySelector('#usersTable tbody');
                uTbody.innerHTML = '';
                users.forEach(function(u) {
                    const row = uTbody.insertRow();
                    row.innerHTML = '<td>' + u.id + '</td><td>' + u.username + '</td><td>' + u.role + '</td><td><button class="btn btn-sm btn-danger" onclick="deleteUser(' + u.id + ')">Delete</button></td>';
                });
                const gResp = await fetch('/api/groups');
                if (!gResp.ok) throw new Error('HTTP ' + gResp.status);
                const groups = await gResp.json();
                const gTbody = document.querySelector('#groupsTable tbody');
                gTbody.innerHTML = '';
                groups.forEach(function(g) {
                    const row = gTbody.insertRow();
                    row.innerHTML = '<td>' + g.id + '</td><td>' + g.name + '</td><td><button class="btn btn-sm btn-danger" onclick="deleteGroup(' + g.id + ')">Delete</button></td>';
                });
            } catch (e) {
                console.error('loadAdmin error:', e);
            }
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
            } catch (e) {
                console.error('createUser error:', e);
                alert('Failed to create user.');
            }
        }

        async function deleteUser(id) {
            if (!confirm('Delete user?')) return;
            try {
                await fetch('/api/users/' + id, { method: 'DELETE' });
                loadAdmin();
            } catch (e) {
                console.error('deleteUser error:', e);
                alert('Failed to delete user.');
            }
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
            } catch (e) {
                console.error('createGroup error:', e);
                alert('Failed to create group.');
            }
        }

        async function deleteGroup(id) {
            if (!confirm('Delete group?')) return;
            try {
                await fetch('/api/groups/' + id, { method: 'DELETE' });
                loadAdmin();
            } catch (e) {
                console.error('deleteGroup error:', e);
                alert('Failed to delete group.');
            }
        }

        // ======================== AI INSIGHTS ========================
        async function fetchAIInsights() {
            try {
                const resp = await fetch('/api/ai_insights');
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const data = await resp.json();
                const tbody = document.querySelector('#aiInsightsTable tbody');
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
                        <td>${item.hostname}</td>
                        <td>${item.metric}</td>
                        <td>${item.current_value}</td>
                        <td>${item.baseline_mean.toFixed(2)} ± ${item.baseline_std.toFixed(2)}</td>
                        <td>${item.deviation.toFixed(2)}</td>
                        <td class="status-${item.severity}">${item.severity}</td>
                        <td>${item.timestamp}</td>
                        <td>${details}</td>
                    `;
                });
            } catch (e) {
                console.error('fetchAIInsights error:', e);
                document.querySelector('#aiInsightsTable tbody').innerHTML = '<tr><td colspan="8" style="color:red;">Failed to load AI insights.</td></tr>';
            }
        }

        // ======================== ALERTS HISTORY ========================
        async function fetchAlertHistory() {
            try {
                const status = document.getElementById('historyStatusFilter').value;
                const host = document.getElementById('historyHostFilter').value;
                let url = '/api/alerts?';
                if (status) url += 'status=' + status + '&';
                if (host) url += 'host=' + host + '&';
                const resp = await fetch(url);
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const data = await resp.json();
                const tbody = document.querySelector('#alertHistoryTable tbody');
                tbody.innerHTML = '';
                data.forEach(function(a) {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${a.hostname}</td>
                        <td>${a.metric}</td>
                        <td>${a.value}</td>
                        <td>${a.severity}</td>
                        <td>${a.timestamp}</td>
                        <td class="status-${a.status}">${a.status}</td>
                    `;
                });
            } catch (e) {
                console.error('fetchAlertHistory error:', e);
                document.querySelector('#alertHistoryTable tbody').innerHTML = '<tr><td colspan="6" style="color:red;">Failed to load alerts history.</td></tr>';
            }
        }
    </script>
</body>
</html>
'@

Write-File "modules\web_ui\templates\login.html" @'
<h1>🔐 SysWatch Login</h1>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="POST">
    <input type="text" name="username" placeholder="Username" required><br>
    <input type="password" name="password" placeholder="Password" required><br>
    <button type="submit">Log in</button>
</form>
'@

# ------------------- MODULES: API -------------------
Write-File "modules\api\__init__.py" ""
Write-File "modules\api\routes.py" @'
import json, datetime, pymysql, ipaddress, subprocess, threading, socket
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from core.config import Config
from core.database import get_db
from modules.monitoring_checks.status_updater import update_host_status
from modules.alert_engine.lifecycle import evaluate_alerts

api_bp = Blueprint('api', __name__)

# ---- Agent Ingest ----
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

# ---- Latest Hosts ----
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
            "hostname": r[0],
            "agent_id": r[1],
            "ip": r[2],
            "status": r[3],
            "last_seen": r[4].isoformat() if r[4] else None,
            "group_id": r[5],
            "group_name": r[6] or "None",
            "cpu": r[7],
            "memory": r[8],
            "disk": r[9],
            "network_sent": r[10],
            "network_recv": r[11],
            "services": json.loads(r[12]) if r[12] else {},
            "network_devices": json.loads(r[13]) if r[13] else []
        })
    cur.close()
    return jsonify(result)

# ---- Trends ----
@api_bp.route('/trends/<hostname>')
@login_required
def trends(hostname):
    range_ = request.args.get('range', '1h')
    db = get_db()
    cur = db.cursor()
    if range_ == '1h':
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL 1 HOUR ORDER BY timestamp ASC", (hostname,))
    elif range_ == '6h':
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL 6 HOUR ORDER BY timestamp ASC", (hostname,))
    elif range_ == '12h':
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL 12 HOUR ORDER BY timestamp ASC", (hostname,))
    elif range_ == '24h':
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL 24 HOUR ORDER BY timestamp ASC", (hostname,))
    elif range_ == '7d':
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL 7 DAY ORDER BY timestamp ASC", (hostname,))
    elif range_ == '30d':
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s AND timestamp >= NOW() - INTERVAL 30 DAY ORDER BY timestamp ASC", (hostname,))
    else:
        cur.execute("SELECT timestamp, cpu, memory, disk FROM metrics WHERE hostname = %s ORDER BY timestamp ASC LIMIT 100", (hostname,))
    rows = cur.fetchall()
    data = [{"timestamp": r[0].isoformat(), "cpu": r[1], "memory": r[2], "disk": r[3]} for r in rows]
    cur.close()
    return jsonify(data)

# ---- Alerts ----
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

# ---- Groups ----
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

# ---- Summary ----
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

# ---- Alert Rules CRUD ----
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

# ---- Hosts ----
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

# ---- AI Insights ----
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
'@

# ------------------- MODULES: Monitoring Checks -------------------
Write-File "modules\monitoring_checks\__init__.py" ""
Write-File "modules\monitoring_checks\status_updater.py" @'
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
'@

Write-File "modules\monitoring_checks\ssl_expiry.py" @'
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
'@

# ------------------- MODULES: ALERT ENGINE -------------------
Write-File "modules\alert_engine\__init__.py" ""
Write-File "modules\alert_engine\lifecycle.py" @'
import datetime, logging
from core.database import get_db
from modules.alert_engine.notifiers import dispatch_alert

logger = logging.getLogger(__name__)

def evaluate_alerts(hostname, data):
    try:
        db = get_db()
        cur = db.cursor()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        # Get enabled rules only
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
                # Check for existing OPEN or ACKNOWLEDGED alert
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
'@

Write-File "modules\alert_engine\auto_resolve.py" @'
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
'@

Write-File "modules\alert_engine\notifiers.py" @'
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
'@

# ------------------- MODULES: AI -------------------
Write-File "modules\ai\__init__.py" ""
Write-File "modules\ai\anomaly.py" @'
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
                    # Use DeepSeek if available
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
        # Get alerts from last 24h
        cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= NOW() - INTERVAL 1 DAY")
        total_alerts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= NOW() - INTERVAL 1 DAY AND status='OPEN'")
        open_alerts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= NOW() - INTERVAL 1 DAY AND status='RESOLVED'")
        resolved_alerts = cur.fetchone()[0]
        # Get new hosts
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
            body = f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\n\n"
            body += ai_analysis.get("summary", "No significant changes.")
            body += "\n\n" + ai_analysis.get("details", "")
            dispatch_alert(None, "daily_briefing", 0, 0, "INFO", body, "Review the daily briefing.")
        else:
            # Fallback: send a simple summary
            subject = "[SysWatch] Daily Briefing"
            body = f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\n"
            body += f"Total Alerts (24h): {total_alerts}\n"
            body += f"Open Alerts: {open_alerts}\n"
            body += f"Resolved Alerts: {resolved_alerts}\n"
            body += f"New Hosts Discovered: {new_hosts}\n"
            dispatch_alert(None, "daily_briefing", 0, 0, "INFO", body, "Review the daily briefing.")
'@

Write-File "modules\ai\deepseek.py" @'
import json, requests, logging
from core.config import Config

logger = logging.getLogger(__name__)

DEEPSEEK_API_KEY = Config.DEEPSEEK_API_KEY
DEEPSEEK_API_URL = Config.DEEPSEEK_API_URL
DEEPSEEK_MODEL = Config.DEEPSEEK_MODEL

def analyze_with_deepseek(analysis_type, context):
    """Send context to DeepSeek and return structured analysis."""
    if not DEEPSEEK_API_KEY:
        logger.info("DeepSeek API key not configured – skipping AI analysis.")
        return None
    system_prompt = """
    You are SysWatch AI, an expert infrastructure monitoring assistant.
    Respond in JSON format with keys: analysis_type, severity, summary, details, recommendation, confidence.
    """
    user_prompt = f"""
    Analysis Type: {analysis_type}
    Context: {json.dumps(context, indent=2)}
    """
    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.3,
        "response_format": {"type": "json_object"}
    }
    try:
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
            logger.error(f"DeepSeek API error: {resp.status_code} – {resp.text}")
            return None
    except Exception as e:
        logger.error(f"DeepSeek connection error: {e}")
        return None
'@

# ------------------- AGENT -------------------
Write-File "agents\__init__.py" ""
Write-File "agents\client.py" @'
#!/usr/bin/env python3
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
'@

# ------------------- TOP LEVEL FILES -------------------
Write-File "wsgi.py" @'
from core.app import app
if __name__ == "__main__":
    app.run()
'@

Write-File "requirements.txt" @'
flask
flask-login
pymysql
python-dotenv
requests
psutil
gunicorn
apscheduler
pyOpenSSL
'@

Write-File ".env.example" @'
SECRET_KEY=your-secret-key-here
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
'@

# ------------------- INSTALLER SCRIPTS -------------------
Write-File "install.sh" @'
#!/bin/bash
# SysWatch v1.1.0 Linux Installer (Full)
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
echo "========================================"
echo "  SysWatch v1.1.0 Installation (Linux)  "
echo "========================================"
if [ "$EUID" -ne 0 ]; then echo -e "${RED}Please run as root (sudo).${NC}"; exit 1; fi

# OS detection
if [ -f /etc/debian_version ]; then OS="debian"; INSTALL_CMD="apt install -y"; UPDATE_CMD="apt update"; MYSQL_SERVICE="mysql"; NGINX_SERVICE="nginx"
elif [ -f /etc/redhat-release ]; then
    if command -v dnf &> /dev/null; then OS="redhat"; INSTALL_CMD="dnf install -y"; UPDATE_CMD="dnf check-update || true"; MYSQL_SERVICE="mysqld"; NGINX_SERVICE="nginx"
    else OS="redhat"; INSTALL_CMD="yum install -y"; UPDATE_CMD="yum check-update || true"; MYSQL_SERVICE="mysqld"; NGINX_SERVICE="nginx"; fi
else echo -e "${RED}Unsupported OS.${NC}"; exit 1; fi

echo -e "\n${GREEN}Checking required packages...${NC}"
REQUIRED_PKGS="python3 python3-pip python3-venv mysql-server nginx certbot python3-certbot-nginx openssl"
if [ "$OS" = "debian" ]; then
    $UPDATE_CMD
    for pkg in $REQUIRED_PKGS; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            echo -e "${YELLOW}Installing $pkg...${NC}"; $INSTALL_CMD "$pkg"
        else echo -e "${GREEN}✔ $pkg already installed.${NC}"; fi
    done
    $INSTALL_CMD libmysqlclient-dev build-essential
else
    $INSTALL_CMD epel-release
    for pkg in $REQUIRED_PKGS; do
        if ! rpm -q "$pkg" >/dev/null 2>&1; then
            echo -e "${YELLOW}Installing $pkg...${NC}"; $INSTALL_CMD "$pkg"
        else echo -e "${GREEN}✔ $pkg already installed.${NC}"; fi
    done
    $INSTALL_CMD mysql-devel gcc
fi

echo -e "\n${GREEN}Starting MySQL...${NC}"
if ! systemctl is-active --quiet "$MYSQL_SERVICE"; then
    systemctl start "$MYSQL_SERVICE"; systemctl enable "$MYSQL_SERVICE"
fi

echo -e "\n${GREEN}Configuration:${NC}"
read -p "Enter database name [monitoring]: " DB_NAME; DB_NAME=${DB_NAME:-monitoring}
read -p "Enter database user [monitor]: " DB_USER; DB_USER=${DB_USER:-monitor}
read -s -p "Enter database password: " DB_PASSWORD; echo
read -s -p "Confirm database password: " DB_PASSWORD_CONFIRM; echo
if [ "$DB_PASSWORD" != "$DB_PASSWORD_CONFIRM" ]; then echo -e "${RED}Passwords do not match.${NC}"; exit 1; fi
read -s -p "Enter SysWatch admin password [admin123]: " ADMIN_PASS; ADMIN_PASS=${ADMIN_PASS:-admin123}; echo
read -p "Enter SMTP server [smtp.gmail.com]: " SMTP_SERVER; SMTP_SERVER=${SMTP_SERVER:-smtp.gmail.com}
read -p "Enter SMTP port [587]: " SMTP_PORT; SMTP_PORT=${SMTP_PORT:-587}
read -p "Enter SMTP username (email): " SMTP_USER
read -s -p "Enter SMTP password: " SMTP_PASSWORD; echo
read -p "Enter alert recipient email: " ALERT_EMAIL_TO
read -p "Enter Teams webhook URL (leave blank to skip): " TEAMS_WEBHOOK
read -p "Enter domain for SysWatch (e.g., syswatch.example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then echo -e "${RED}Domain required.${NC}"; exit 1; fi
read -p "Enter discovery subnet (e.g., 192.168.1.0/24) [192.168.1.0/24]: " DISCOVERY_SUBNET; DISCOVERY_SUBNET=${DISCOVERY_SUBNET:-192.168.1.0/24}
read -p "Enter DeepSeek API key (leave blank to skip): " DEEPSEEK_API_KEY

echo -e "\n${GREEN}Checking existing database and user...${NC}"
DB_EXISTS=$(mysql -s -N -e "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='$DB_NAME';" 2>/dev/null || echo "0")
if [ "$DB_EXISTS" -gt 0 ]; then
    echo -e "${YELLOW}Database '$DB_NAME' already exists.${NC}"
    read -p "Drop and recreate? (y/n) [n]: " DROP_DB; DROP_DB=${DROP_DB:-n}
    if [[ "$DROP_DB" =~ ^[Yy]$ ]]; then mysql -e "DROP DATABASE $DB_NAME;"; echo -e "${GREEN}Dropped.${NC}"; else SKIP_DB_INIT=1; fi
fi
USER_EXISTS=$(mysql -s -N -e "SELECT COUNT(*) FROM mysql.user WHERE User='$DB_USER' AND Host='localhost';" 2>/dev/null || echo "0")
if [ "$USER_EXISTS" -gt 0 ]; then
    echo -e "${YELLOW}User '$DB_USER' already exists.${NC}"
    read -p "Drop and recreate? (y/n) [n]: " DROP_USER; DROP_USER=${DROP_USER:-n}
    if [[ "$DROP_USER" =~ ^[Yy]$ ]]; then mysql -e "DROP USER '$DB_USER'@'localhost';"; echo -e "${GREEN}Dropped.${NC}"; fi
fi

[ "$DB_EXISTS" -eq 0 ] || [[ "$DROP_DB" =~ ^[Yy]$ ]] && mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
if [ "$USER_EXISTS" -eq 0 ] || [[ "$DROP_USER" =~ ^[Yy]$ ]]; then
    mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
else
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost'; FLUSH PRIVILEGES;"
fi

echo -e "\n${GREEN}Checking DNS for $DOMAIN...${NC}"
SERVER_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "")
if [ -n "$SERVER_IP" ]; then
    DOMAIN_IP=$(dig +short "$DOMAIN" | head -1)
    if [ "$DOMAIN_IP" != "$SERVER_IP" ]; then
        echo -e "${YELLOW}Warning: Domain doesn't resolve to this IP.${NC}"
        read -p "Continue anyway? (y/n) [n]: " CONTINUE_DNS; CONTINUE_DNS=${CONTINUE_DNS:-n}
        if [[ ! "$CONTINUE_DNS" =~ ^[Yy]$ ]]; then echo -e "${RED}Aborting.${NC}"; exit 1; fi
    else echo -e "${GREEN}✔ Domain resolves.${NC}"; fi
fi

echo -e "\n${GREEN}Setting up Nginx...${NC}"
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN"
if [ -f "$NGINX_CONF" ]; then
    echo -e "${YELLOW}Config exists.${NC}"
    read -p "Overwrite? (y/n) [n]: " OVERWRITE_NGINX; OVERWRITE_NGINX=${OVERWRITE_NGINX:-n}
    if [[ ! "$OVERWRITE_NGINX" =~ ^[Yy]$ ]]; then SKIP_NGINX=1; fi
fi
if [ -z "$SKIP_NGINX" ]; then
    cat > "$NGINX_CONF" <<NGINX_EOL
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}
server {
    listen 443 ssl;
    http2 on;
    server_name $DOMAIN;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX_EOL
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl reload nginx
    echo -e "${GREEN}Nginx configured.${NC}"

    read -p "Obtain SSL with Let's Encrypt? (y/n) [y]: " DO_LETSENCRYPT; DO_LETSENCRYPT=${DO_LETSENCRYPT:-y}
    if [[ "$DO_LETSENCRYPT" =~ ^[Yy]$ ]]; then
        read -p "Email for Let's Encrypt: " LETSENCRYPT_EMAIL
        if [ -n "$LETSENCRYPT_EMAIL" ]; then
            echo -e "${GREEN}Obtaining certificate...${NC}"
            if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "$LETSENCRYPT_EMAIL"; then
                echo -e "${GREEN}SSL installed.${NC}"; systemctl reload nginx
            else
                echo -e "${RED}SSL failed. Falling back to HTTP.${NC}"
                cat > "$NGINX_CONF" <<NGINX_HTTP
server { listen 80; server_name $DOMAIN; location / { proxy_pass http://127.0.0.1:5000; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; } }
NGINX_HTTP
                nginx -t && systemctl reload nginx
            fi
        else echo -e "${YELLOW}Email required. Skipping SSL.${NC}"; fi
    else echo -e "${YELLOW}Skipping SSL.${NC}"; fi
fi

PROJECT_DIR="/opt/syswatch"
echo -e "\n${GREEN}Installing to $PROJECT_DIR...${NC}"
if [ -d "$PROJECT_DIR" ]; then
    BACKUP_DIR="/opt/syswatch_backup_$(date +%s)"
    echo -e "${YELLOW}Backing up to $BACKUP_DIR${NC}"
    mv "$PROJECT_DIR" "$BACKUP_DIR"
fi
mkdir -p "$PROJECT_DIR"
cp -r . "$PROJECT_DIR/"
chown -R $(whoami):$(whoami) "$PROJECT_DIR"
cd "$PROJECT_DIR"

echo -e "\n${GREEN}Setting up Python venv...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

API_KEY=$(openssl rand -base64 32)
SECRET_KEY=$(openssl rand -base64 32)
cat > .env <<ENV_EOL
SECRET_KEY=$SECRET_KEY
DB_HOST=127.0.0.1
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME
API_KEY=$API_KEY
ADMIN_PASSWORD=$ADMIN_PASS
SMTP_SERVER=$SMTP_SERVER
SMTP_PORT=$SMTP_PORT
SMTP_USER=$SMTP_USER
SMTP_PASSWORD=$SMTP_PASSWORD
ALERT_EMAIL_TO=$ALERT_EMAIL_TO
TEAMS_WEBHOOK_URL=$TEAMS_WEBHOOK
DISCOVERY_SUBNET=$DISCOVERY_SUBNET
DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY
DEEPSEEK_API_URL=https://api.deepseek.com/v1/chat/completions
DEEPSEEK_MODEL=deepseek-chat
ENV_EOL

if [ -z "$SKIP_DB_INIT" ]; then
    echo -e "\n${GREEN}Initializing database...${NC}"
    python3 <<DB_INIT
from core.app import app
from core.database import init_db
with app.app_context():
    init_db()
DB_INIT
else echo -e "${YELLOW}Skipping DB init.${NC}"; fi

SERVICE_FILE="/etc/systemd/system/syswatch.service"
[ -f "$SERVICE_FILE" ] && systemctl stop syswatch || true
[ -f "$SERVICE_FILE" ] && systemctl disable syswatch || true
[ -f "$SERVICE_FILE" ] && rm -f "$SERVICE_FILE"
cat > "$SERVICE_FILE" <<SERVICE_EOL
[Unit]
Description=SysWatch Monitoring Server
After=network.target $MYSQL_SERVICE.service
Wants=$MYSQL_SERVICE.service

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 wsgi:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE_EOL

systemctl daemon-reload
systemctl enable syswatch
systemctl start syswatch

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}✅ SysWatch installation complete!${NC}"
echo -e "${GREEN}========================================${NC}"
if [[ "$DO_LETSENCRYPT" =~ ^[Yy]$ ]] && [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo -e "Access URL: https://$DOMAIN"
else
    echo -e "Access URL: http://$DOMAIN"
fi
echo -e "Username: admin"
echo -e "Password: $ADMIN_PASS"
echo -e "API Key: $API_KEY"
echo -e "\nService status:"
systemctl status syswatch --no-pager
echo -e "\nTo view logs: sudo journalctl -u syswatch -f"
'@

Write-File "install.ps1" @'
# SysWatch v1.1.0 Windows Installer
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SysWatch v1.1.0 Installation (Windows) " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Please run as Administrator." -ForegroundColor Red; exit 1
}
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "🐍 Python not found. Downloading..." -ForegroundColor Yellow
    $pythonUrl = "https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe"
    $installerPath = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath
    Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    Remove-Item $installerPath -Force
    Write-Host "✅ Python installed. Please restart PowerShell and re-run." -ForegroundColor Green
    exit 0
} else { Write-Host "✅ Python found: $(python --version)" -ForegroundColor Green }
$mysql = Get-Command mysql -ErrorAction SilentlyContinue
if (-not $mysql) {
    Write-Host "📦 MySQL not found. Installing via Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install mysql -y
    Start-Service MySQL
}
Write-Host "`n⚙️  Configuration:" -ForegroundColor Green
$DB_NAME = Read-Host -Prompt "Enter database name [monitoring]"
if (-not $DB_NAME) { $DB_NAME = "monitoring" }
$DB_USER = Read-Host -Prompt "Enter database user [monitor]"
if (-not $DB_USER) { $DB_USER = "monitor" }
$DB_PASSWORD = Read-Host -Prompt "Enter database password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($DB_PASSWORD)
$DB_PASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$ADMIN_PASS = Read-Host -Prompt "Enter SysWatch admin password [admin123]"
if (-not $ADMIN_PASS) { $ADMIN_PASS = "admin123" }
$SMTP_SERVER = Read-Host -Prompt "Enter SMTP server [smtp.gmail.com]"
if (-not $SMTP_SERVER) { $SMTP_SERVER = "smtp.gmail.com" }
$SMTP_PORT = Read-Host -Prompt "Enter SMTP port [587]"
if (-not $SMTP_PORT) { $SMTP_PORT = "587" }
$SMTP_USER = Read-Host -Prompt "Enter SMTP username (email)"
$SMTP_PASSWORD = Read-Host -Prompt "Enter SMTP password" -AsSecureString
$BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SMTP_PASSWORD)
$SMTP_PASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
$ALERT_EMAIL_TO = Read-Host -Prompt "Enter alert recipient email"
$TEAMS_WEBHOOK = Read-Host -Prompt "Enter Teams webhook URL (leave blank to skip)"
$DISCOVERY_SUBNET = Read-Host -Prompt "Enter discovery subnet (e.g., 192.168.1.0/24) [192.168.1.0/24]"
if (-not $DISCOVERY_SUBNET) { $DISCOVERY_SUBNET = "192.168.1.0/24" }
$DEEPSEEK_API_KEY = Read-Host -Prompt "Enter DeepSeek API key (leave blank to skip)"

Write-Host "`n📊 Setting up MySQL database..." -ForegroundColor Green
$mysqlCmd = "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
$mysqlCmd += "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';"
$mysqlCmd += "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
$mysqlCmd += "FLUSH PRIVILEGES;"
mysql -u root -e $mysqlCmd

$PROJECT_DIR = "C:\SysWatch"
Write-Host "`n📁 Installing to $PROJECT_DIR..." -ForegroundColor Green
if (Test-Path $PROJECT_DIR) {
    $backup = "C:\SysWatch_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Move-Item $PROJECT_DIR $backup
}
New-Item -ItemType Directory -Path $PROJECT_DIR -Force | Out-Null
Copy-Item -Path ".\*" -Destination $PROJECT_DIR -Recurse
Set-Location $PROJECT_DIR

Write-Host "🐍 Setting up Python venv..." -ForegroundColor Green
python -m venv venv
& .\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt

$API_KEY = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Guid]::NewGuid().ToString()))
$SECRET_KEY = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Guid]::NewGuid().ToString()))
@"
SECRET_KEY=$SECRET_KEY
DB_HOST=127.0.0.1
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME
API_KEY=$API_KEY
ADMIN_PASSWORD=$ADMIN_PASS
SMTP_SERVER=$SMTP_SERVER
SMTP_PORT=$SMTP_PORT
SMTP_USER=$SMTP_USER
SMTP_PASSWORD=$SMTP_PASSWORD
ALERT_EMAIL_TO=$ALERT_EMAIL_TO
TEAMS_WEBHOOK_URL=$TEAMS_WEBHOOK
DISCOVERY_SUBNET=$DISCOVERY_SUBNET
DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY
DEEPSEEK_API_URL=https://api.deepseek.com/v1/chat/completions
DEEPSEEK_MODEL=deepseek-chat
"@ | Out-File -FilePath .\.env -Encoding UTF8

Write-Host "`n🗄️  Initializing database..." -ForegroundColor Green
python -c "from core.app import app; from core.database import init_db; with app.app_context(): init_db()"

Write-Host "`n⏰ Setting up Windows Scheduled Task..." -ForegroundColor Green
$venvPython = "$PROJECT_DIR\venv\Scripts\python.exe"
$action = New-ScheduledTaskAction -Execute $venvPython -Argument "$PROJECT_DIR\venv\Scripts\gunicorn --workers 2 --bind 127.0.0.1:5000 wsgi:app" -WorkingDirectory $PROJECT_DIR
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "SysWatch" -Action $action -Trigger $trigger -Settings $settings -User $env:USERNAME -RunLevel Highest -Force
Start-ScheduledTask -TaskName "SysWatch"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "✅ SysWatch installation complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
$ip = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content
Write-Host "Access URL: http://$($ip):5000 (or localhost:5000)"
Write-Host "Username: admin"
Write-Host "Password: $ADMIN_PASS"
Write-Host "API Key: $API_KEY"
Write-Host "`nTo manage, use Task Scheduler (Task: SysWatch)."
'@

# ------------------- DOCUMENTATION -------------------
Write-File "README.md" @'
# SysWatch v1.1.0
Simple Monitoring. Smarter Operations.

## Features
- DeepSeek AI integration for root cause analysis, predictions, and daily briefings.
- Full-featured dashboard with sidebar menu, zoomable charts, and alert rule management.
- Auto-discovery of hosts via ping sweep.
- Cross-platform agent with event collection.
- Installers for Linux and Windows.

## Quick Install
**Linux:**
```bash
sudo bash install.sh