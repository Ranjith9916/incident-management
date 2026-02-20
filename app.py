from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from functools import wraps
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incidents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ── Email Config ──────────────────────────────────────────────────────────────
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS']  = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'noreply@incidents.com')

db   = SQLAlchemy(app)
mail = Mail(app)

# ══════════════════════════════════════════════════════════════════════════════
# MODELS
# ══════════════════════════════════════════════════════════════════════════════

class User(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80),  unique=True, nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(200), nullable=False)
    role       = db.Column(db.String(20),  default='viewer')   # admin | engineer | viewer
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)

class Incident(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text,        nullable=False)
    severity    = db.Column(db.String(20),  nullable=False)   # critical | high | medium | low
    status      = db.Column(db.String(20),  default='open')   # open | in_progress | resolved | closed
    created_by  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    creator  = db.relationship('User', foreign_keys=[created_by],  backref='created_incidents')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_incidents')

class Comment(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'),     nullable=False)
    content     = db.Column(db.Text, nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    incident = db.relationship('Incident', backref='comments')
    author   = db.relationship('User',     backref='comments')

# ══════════════════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user = User.query.get(session['user_id'])
            if user.role not in roles:
                flash('Access denied: insufficient permissions.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL HELPER
# ══════════════════════════════════════════════════════════════════════════════

def send_notification(subject, recipients, body):
    try:
        msg = Message(subject, recipients=recipients, body=body)
        mail.send(msg)
    except Exception as e:
        print(f"Email error: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['user_id'] = user.id
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email    = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        else:
            user = User(username=username, email=email, password=password, role='viewer')
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    user        = current_user()
    total       = Incident.query.count()
    open_count  = Incident.query.filter_by(status='open').count()
    in_progress = Incident.query.filter_by(status='in_progress').count()
    resolved    = Incident.query.filter_by(status='resolved').count()
    critical    = Incident.query.filter_by(severity='critical', status='open').count()
    recent      = Incident.query.order_by(Incident.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', user=user,
                           total=total, open_count=open_count,
                           in_progress=in_progress, resolved=resolved,
                           critical=critical, recent=recent)

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — INCIDENTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/incidents')
@login_required
def incidents():
    user             = current_user()
    status_filter    = request.args.get('status', '')
    severity_filter  = request.args.get('severity', '')
    query            = Incident.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    incidents_list = query.order_by(Incident.created_at.desc()).all()
    return render_template('incidents.html', incidents=incidents_list, user=user,
                           status_filter=status_filter, severity_filter=severity_filter)

@app.route('/incidents/new', methods=['GET', 'POST'])
@login_required
def new_incident():
    user = current_user()
    if request.method == 'POST':
        incident = Incident(
            title       = request.form['title'],
            description = request.form['description'],
            severity    = request.form['severity'],
            status      = 'open',
            created_by  = user.id
        )
        db.session.add(incident)
        db.session.commit()
        admins = User.query.filter_by(role='admin').all()
        send_notification(
            f'[{incident.severity.upper()}] New Incident: {incident.title}',
            [a.email for a in admins],
            f'Incident #{incident.id} was created by {user.username}.\n\n{incident.description}'
        )
        flash('Incident created successfully.', 'success')
        return redirect(url_for('incident_detail', incident_id=incident.id))
    return render_template('incident_form.html', user=user, incident=None)

@app.route('/incidents/<int:incident_id>')
@login_required
def incident_detail(incident_id):
    user      = current_user()
    incident  = Incident.query.get_or_404(incident_id)
    engineers = User.query.filter(User.role.in_(['admin', 'engineer'])).all()
    return render_template('incident_detail.html', user=user,
                           incident=incident, engineers=engineers)

@app.route('/incidents/<int:incident_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'engineer')
def edit_incident(incident_id):
    user     = current_user()
    incident = Incident.query.get_or_404(incident_id)
    if request.method == 'POST':
        incident.title       = request.form['title']
        incident.description = request.form['description']
        incident.severity    = request.form['severity']
        incident.updated_at  = datetime.utcnow()
        db.session.commit()
        flash('Incident updated.', 'success')
        return redirect(url_for('incident_detail', incident_id=incident.id))
    return render_template('incident_form.html', user=user, incident=incident)

@app.route('/incidents/<int:incident_id>/assign', methods=['POST'])
@login_required
@role_required('admin')
def assign_incident(incident_id):
    incident    = Incident.query.get_or_404(incident_id)
    engineer_id = request.form.get('engineer_id')
    engineer    = User.query.get(engineer_id)
    if engineer:
        incident.assigned_to = engineer.id
        incident.status      = 'in_progress'
        incident.updated_at  = datetime.utcnow()
        db.session.commit()
        send_notification(
            f'Incident Assigned: #{incident.id} - {incident.title}',
            [engineer.email],
            f'You have been assigned incident #{incident.id}.\n\n{incident.description}'
        )
        flash(f'Incident assigned to {engineer.username}.', 'success')
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/incidents/<int:incident_id>/resolve', methods=['POST'])
@login_required
@role_required('admin', 'engineer')
def resolve_incident(incident_id):
    incident            = Incident.query.get_or_404(incident_id)
    incident.status     = 'resolved'
    incident.resolved_at = datetime.utcnow()
    incident.updated_at  = datetime.utcnow()
    db.session.commit()
    creator = User.query.get(incident.created_by)
    send_notification(
        f'Incident Resolved: #{incident.id} - {incident.title}',
        [creator.email],
        f'Incident #{incident.id} has been resolved.'
    )
    flash('Incident resolved.', 'success')
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/incidents/<int:incident_id>/comment', methods=['POST'])
@login_required
def add_comment(incident_id):
    user    = current_user()
    content = request.form.get('content')
    if content:
        comment = Comment(incident_id=incident_id, user_id=user.id, content=content)
        db.session.add(comment)
        db.session.commit()
        flash('Comment added.', 'success')
    return redirect(url_for('incident_detail', incident_id=incident_id))

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — REST API
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/incidents', methods=['GET'])
def api_list_incidents():
    items = Incident.query.all()
    return jsonify([{
        'id': i.id, 'title': i.title, 'severity': i.severity,
        'status': i.status, 'created_at': i.created_at.isoformat()
    } for i in items])

@app.route('/api/incidents/<int:incident_id>', methods=['GET'])
def api_get_incident(incident_id):
    i = Incident.query.get_or_404(incident_id)
    return jsonify({
        'id': i.id, 'title': i.title, 'description': i.description,
        'severity': i.severity, 'status': i.status,
        'created_at': i.created_at.isoformat(),
        'resolved_at': i.resolved_at.isoformat() if i.resolved_at else None
    })

@app.route('/api/incidents', methods=['POST'])
def api_create_incident():
    data     = request.get_json()
    incident = Incident(
        title       = data['title'],
        description = data['description'],
        severity    = data['severity'],
        created_by  = 1
    )
    db.session.add(incident)
    db.session.commit()
    return jsonify({'id': incident.id, 'message': 'Incident created'}), 201

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — ADMIN
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    user  = current_user()
    users = User.query.all()
    return render_template('admin_users.html', user=user, users=users)

@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
@role_required('admin')
def update_user_role(user_id):
    target      = User.query.get_or_404(user_id)
    target.role = request.form['role']
    db.session.commit()
    flash(f'Role updated for {target.username}.', 'success')
    return redirect(url_for('admin_users'))

# ══════════════════════════════════════════════════════════════════════════════
# INIT DB WITH SAMPLE DATA
# ══════════════════════════════════════════════════════════════════════════════

def create_sample_data():
    if User.query.count() == 0:
        admin  = User(username='admin',     email='admin@example.com',   password='admin123', role='admin')
        eng    = User(username='engineer1', email='eng1@example.com',    password='eng123',   role='engineer')
        viewer = User(username='viewer1',   email='viewer1@example.com', password='view123',  role='viewer')
        db.session.add_all([admin, eng, viewer])
        db.session.commit()

        inc1 = Incident(title='Database connection timeout',
                        description='Production DB throwing connection timeout errors every 5 minutes.',
                        severity='critical', status='open', created_by=admin.id)
        inc2 = Incident(title='API response slow',
                        description='REST API endpoints responding in 8s instead of <200ms.',
                        severity='high', status='in_progress',
                        created_by=viewer.id, assigned_to=eng.id)
        inc3 = Incident(title='Disk space warning on server-02',
                        description='Server-02 disk usage hit 85%.',
                        severity='medium', status='resolved',
                        created_by=eng.id, resolved_at=datetime.utcnow())
        db.session.add_all([inc1, inc2, inc3])
        db.session.commit()
        print("✅ Sample data created — Login: admin / admin123")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_data()
    app.run(host='0.0.0.0', port=5000, debug=True)