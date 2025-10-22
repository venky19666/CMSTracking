import hashlib
import os
import secrets
from datetime import datetime
from functools import wraps

from flask import (Flask, flash, jsonify, make_response, redirect,
                   render_template, request, send_file, session, url_for)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cmmc_tracking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB

# File uploads configuration (store inside /static/uploads)
STATIC_UPLOADS_SUBDIR = 'uploads'
app.config['STATIC_UPLOADS_SUBDIR'] = STATIC_UPLOADS_SUBDIR
app.config['UPLOAD_EXTENSIONS'] = {'.pdf', '.png', '.jpg', '.jpeg', '.txt', '.doc', '.docx', '.xlsx', '.csv'}

def _ensure_upload_dir_exists():
    # Use explicit static folder path
    static_folder = os.path.join(os.path.dirname(__file__), 'static')
    uploads_dir = os.path.join(static_folder, STATIC_UPLOADS_SUBDIR)
    os.makedirs(uploads_dir, exist_ok=True)
    print(f"Upload directory: {uploads_dir}")  # Debug print
    return uploads_dir

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    company = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Authorization flag: only authorized users may access the system
    is_authorized = db.Column(db.Boolean, default=False, nullable=False)

class CMMCLevel(db.Model):
    __tablename__ = 'cmmc_level'
    id = db.Column(db.Integer, primary_key=True)
    level_number = db.Column(db.Integer, unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CMMCDomain(db.Model):
    __tablename__ = 'cmmc_domain'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CMMCRequirement(db.Model):
    __tablename__ = 'cmmc_requirement'
    id = db.Column(db.Integer, primary_key=True)
    requirement_id = db.Column(db.String(20), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    level_id = db.Column(db.Integer, db.ForeignKey('cmmc_level.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('cmmc_domain.id'), nullable=False)
    guidance = db.Column(db.Text)
    assessment_objectives = db.Column(db.Text)  # Store specific objectives for this requirement
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    level = db.relationship('CMMCLevel', backref='requirements')
    domain = db.relationship('CMMCDomain', backref='requirements')

class ComplianceRecord(db.Model):
    __tablename__ = 'compliance_record'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requirement_id = db.Column(db.Integer, db.ForeignKey('cmmc_requirement.id'), nullable=False)
    status = db.Column(db.String(20), default='not_started')  # 'compliant', 'non_compliant', 'in_progress', 'not_started'
    artifact_path = db.Column(db.String(500))
    notes = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='compliance_records')
    requirement = db.relationship('CMMCRequirement', backref='compliance_records')

# New Models for objectives (processes and devices)
class ServiceAccount(db.Model):
    __tablename__ = 'service_account'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    owner_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    scopes = db.Column(db.String(255), default='read:summary')
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_user = db.relationship('User', backref='service_accounts')

class AuthorizedDevice(db.Model):
    __tablename__ = 'authorized_device'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    device_name = db.Column(db.String(200))
    device_token = db.Column(db.String(64), unique=True, nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', backref='devices')

def _generate_token() -> str:
    return secrets.token_urlsafe(32)

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def authorized_user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_authorized:
            flash('Your account is awaiting authorization by an administrator.', 'warning')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def service_token_required(required_scopes: list[str] | None = None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing bearer token'}), 401
            token = auth_header.split(' ', 1)[1].strip()
            token_h = _hash_token(token)
            sa = ServiceAccount.query.filter_by(token_hash=token_h, is_active=True).first()
            if not sa:
                return jsonify({'error': 'Invalid token'}), 401
            if required_scopes:
                account_scopes = set((sa.scopes or '').split(','))
                if not set(required_scopes).issubset(account_scopes):
                    return jsonify({'error': 'Insufficient scope'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.before_request
def enforce_device_and_user_authorization():
    # Allow public routes
    open_endpoints = {
        'index', 'login', 'register', 'logout', 'static', 'device_pending'
    }
    if request.endpoint in open_endpoints:
        return None
    if 'user_id' not in session:
        return None
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    # Enforce user authorization
    if not user.is_authorized:
        flash('Your account is awaiting authorization by an administrator.', 'warning')
        return redirect(url_for('index'))
    # Exempt admins from device verification to avoid blocking admin access
    if user.role == 'admin':
        return None
    # Enforce device approval
    device_token = request.cookies.get('device_token')
    if not device_token:
        # Create a pending device and set cookie at response time via special endpoint
        return redirect(url_for('device_pending'))
    # We store hashed token in DB; hash cookie value for lookup
    hashed = hashlib.sha256(device_token.encode('utf-8')).hexdigest()
    device = AuthorizedDevice.query.filter_by(device_token=hashed).first()
    if not device:
        return redirect(url_for('device_pending'))
    # Associate device with user if not already
    if not device.user_id:
        device.user_id = user.id
        db.session.commit()
    if not device.is_approved:
        return redirect(url_for('device_pending'))
    return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if not user.is_authorized:
                flash('Login blocked: your account is not yet authorized by an administrator.', 'warning')
                return render_template('login.html')
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash('Logged in successfully!', 'success')
            # Ensure device token exists and pending record created
            device_token = request.cookies.get('device_token')
            new_cookie_token = None
            if not device_token:
                new_cookie_token = _generate_token()
                device_token = new_cookie_token
            
            # Hash the token for database storage
            hashed_token = hashlib.sha256(device_token.encode('utf-8')).hexdigest()
            device = AuthorizedDevice.query.filter_by(device_token=hashed_token).first()
            
            if not device:
                device = AuthorizedDevice(
                    user_id=user.id,
                    device_name=request.user_agent.string[:180] if request.user_agent else 'Unknown Device',
                    device_token=hashed_token,
                    is_approved=False
                )
                db.session.add(device)
                db.session.commit()
            else:
                device.last_seen_at = datetime.utcnow()
                if not device.user_id:
                    device.user_id = user.id
                db.session.commit()
            resp = redirect(url_for('dashboard'))
            if new_cookie_token:
                resp.set_cookie('device_token', new_cookie_token, httponly=True, samesite='Lax')
            return resp
        flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        company = request.form['company']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            company=company
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
@authorized_user_required
def dashboard():
    user = User.query.get(session['user_id'])
    
    # Get compliance summary
    total_requirements = CMMCRequirement.query.count()
    user_records = ComplianceRecord.query.filter_by(user_id=user.id).all()
    
    compliant_count = sum(1 for record in user_records if record.status == 'compliant')
    in_progress_count = sum(1 for record in user_records if record.status == 'in_progress')
    non_compliant_count = sum(1 for record in user_records if record.status == 'non_compliant')
    not_started_count = total_requirements - len(user_records)
    
    # Progress by level
    levels = CMMCLevel.query.all()
    level_progress = {}
    for level in levels:
        level_requirements = CMMCRequirement.query.filter_by(level_id=level.id).all()
        level_compliant = 0
        for req in level_requirements:
            record = ComplianceRecord.query.filter_by(user_id=user.id, requirement_id=req.id).first()
            if record and record.status == 'compliant':
                level_compliant += 1
        
        level_progress[level.level_number] = {
            'total': len(level_requirements),
            'compliant': level_compliant,
            'percentage': (level_compliant / len(level_requirements)) * 100 if level_requirements else 0
        }
    
    # Progress by domain
    domains = CMMCDomain.query.all()
    domain_progress = {}
    for domain in domains:
        domain_requirements = CMMCRequirement.query.filter_by(domain_id=domain.id).all()
        domain_compliant = 0
        for req in domain_requirements:
            record = ComplianceRecord.query.filter_by(user_id=user.id, requirement_id=req.id).first()
            if record and record.status == 'compliant':
                domain_compliant += 1
        
        domain_progress[domain.code] = {
            'name': domain.name,
            'total': len(domain_requirements),
            'compliant': domain_compliant,
            'percentage': (domain_compliant / len(domain_requirements)) * 100 if domain_requirements else 0
        }
    
    summary = {
        'total': total_requirements,
        'compliant': compliant_count,
        'in_progress': in_progress_count,
        'non_compliant': non_compliant_count,
        'not_started': not_started_count,
        'overall_percentage': (compliant_count / total_requirements) * 100 if total_requirements > 0 else 0
    }
    
    return render_template('dashboard.html', user=user, summary=summary, 
                         level_progress=level_progress, domain_progress=domain_progress)

@app.route('/requirements')
@login_required
@authorized_user_required
def requirements():
    level_filter = request.args.get('level')
    domain_filter = request.args.get('domain')

    levels = CMMCLevel.query.all()
    domains = CMMCDomain.query.all()

    # Default to Level 1 grouped view if no level filter provided
    level1 = CMMCLevel.query.filter_by(level_number=1).first()
    selected_level_id = level_filter or (str(level1.id) if level1 else None)

    query = CMMCRequirement.query
    if selected_level_id:
        query = query.filter_by(level_id=selected_level_id)
    if domain_filter:
        query = query.filter_by(domain_id=domain_filter)

    requirements = query.all()

    # Get user's compliance records
    user_records = {}
    for record in ComplianceRecord.query.filter_by(user_id=session['user_id']).all():
        user_records[record.requirement_id] = record

    # Prepare grouped view for all levels
    is_grouped_mode = False
    grouped_by_domain = []
    level_total = 0
    current_level = None
    
    if selected_level_id and not domain_filter:
        current_level = CMMCLevel.query.get(selected_level_id)
        if current_level:
            is_grouped_mode = True
            # Define domain ordering based on level
            if current_level.level_number == 1:
                # Level 1: Only specific domains
                desired_order = ['AC', 'IA', 'MP', 'PE', 'SC', 'SI']
            else:
                # Level 2 and 3: All domains
                desired_order = ['AC', 'AT', 'AU', 'CM', 'IA', 'IR', 'MA', 'MP', 'PS', 'PE', 'RA', 'CA', 'SC', 'SI']
            
            code_to_domain = {d.code: d for d in domains}
            for code in desired_order:
                d = code_to_domain.get(code)
                if not d:
                    continue
                domain_reqs = CMMCRequirement.query.filter_by(level_id=current_level.id, domain_id=d.id).all()
                if not domain_reqs:
                    continue
                level_total += len(domain_reqs)
                grouped_by_domain.append({
                    'code': d.code,
                    'name': d.name,
                    'requirements': domain_reqs
                })

    return render_template(
        'requirements.html',
        requirements=requirements,
        levels=levels,
        domains=domains,
        user_records=user_records,
        selected_level_id=selected_level_id,
        is_grouped_mode=is_grouped_mode,
        grouped_by_domain=grouped_by_domain,
        level_total=level_total,
        current_level=current_level
    )

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin/index.html')

@app.route('/admin/requirements')
@admin_required
def admin_requirements():
    level_filter = request.args.get('level')
    domain_filter = request.args.get('domain')
    
    query = CMMCRequirement.query
    if level_filter:
        query = query.filter_by(level_id=level_filter)
    if domain_filter:
        query = query.filter_by(domain_id=domain_filter)
    
    requirements = query.all()
    levels = CMMCLevel.query.all()
    domains = CMMCDomain.query.all()
    return render_template('admin/requirements.html', requirements=requirements, 
                         levels=levels, domains=domains)

@app.route('/admin/requirements/add', methods=['GET', 'POST'])
@admin_required
def admin_add_requirement():
    if request.method == 'POST':
        requirement = CMMCRequirement(
            requirement_id=request.form['requirement_id'],
            title=request.form['title'],
            description=request.form['description'],
            level_id=request.form['level_id'],
            domain_id=request.form['domain_id'],
            guidance=request.form['guidance']
        )
        db.session.add(requirement)
        db.session.commit()
        flash('Requirement added successfully!', 'success')
        return redirect(url_for('admin_requirements'))
    
    levels = CMMCLevel.query.all()
    domains = CMMCDomain.query.all()
    return render_template('admin/add_requirement.html', levels=levels, domains=domains)

@app.route('/admin/requirements/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_requirement(id):
    requirement = CMMCRequirement.query.get_or_404(id)
    
    if request.method == 'POST':
        requirement.requirement_id = request.form['requirement_id']
        requirement.title = request.form['title']
        requirement.description = request.form['description']
        requirement.level_id = request.form['level_id']
        requirement.domain_id = request.form['domain_id']
        requirement.guidance = request.form['guidance']
        
        db.session.commit()
        flash('Requirement updated successfully!', 'success')
        return redirect(url_for('admin_requirements'))
    
    levels = CMMCLevel.query.all()
    domains = CMMCDomain.query.all()
    return render_template('admin/edit_requirement.html', requirement=requirement, levels=levels, domains=domains)

@app.route('/admin/levels')
@admin_required
def admin_levels():
    levels = CMMCLevel.query.all()
    return render_template('admin/levels.html', levels=levels)

@app.route('/admin/levels/add', methods=['GET', 'POST'])
@admin_required
def admin_add_level():
    if request.method == 'POST':
        level = CMMCLevel(
            level_number=request.form['level_number'],
            name=request.form['name'],
            description=request.form['description']
        )
        db.session.add(level)
        db.session.commit()
        flash('Level added successfully!', 'success')
        return redirect(url_for('admin_levels'))
    
    return render_template('admin/add_level.html')

@app.route('/admin/levels/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_level(id):
    level = CMMCLevel.query.get_or_404(id)
    
    if request.method == 'POST':
        level.level_number = request.form['level_number']
        level.name = request.form['name']
        level.description = request.form['description']
        
        db.session.commit()
        flash('Level updated successfully!', 'success')
        return redirect(url_for('admin_levels'))
    
    return render_template('admin/edit_level.html', level=level)

@app.route('/admin/domains')
@admin_required
def admin_domains():
    domains = CMMCDomain.query.all()
    return render_template('admin/domains.html', domains=domains)

@app.route('/admin/domains/add', methods=['GET', 'POST'])
@admin_required
def admin_add_domain():
    if request.method == 'POST':
        domain = CMMCDomain(
            code=request.form['code'],
            name=request.form['name'],
            description=request.form['description']
        )
        db.session.add(domain)
        db.session.commit()
        flash('Domain added successfully!', 'success')
        return redirect(url_for('admin_domains'))
    
    return render_template('admin/add_domain.html')

@app.route('/admin/domains/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_domain(id):
    domain = CMMCDomain.query.get_or_404(id)
    
    if request.method == 'POST':
        domain.code = request.form['code']
        domain.name = request.form['name']
        domain.description = request.form['description']
        
        db.session.commit()
        flash('Domain updated successfully!', 'success')
        return redirect(url_for('admin_domains'))
    
    return render_template('admin/edit_domain.html', domain=domain)

@app.route('/admin/reports')
@admin_required
def admin_reports():
    # Overall compliance statistics
    total_users = User.query.filter_by(role='user').count()
    total_requirements = CMMCRequirement.query.count()
    total_records = ComplianceRecord.query.count()
    
    # Compliance by level
    levels = CMMCLevel.query.all()
    level_stats = {}
    for level in levels:
        level_requirements = CMMCRequirement.query.filter_by(level_id=level.id).all()
        compliant_records = 0
        for req in level_requirements:
            compliant_records += ComplianceRecord.query.filter_by(
                requirement_id=req.id, status='compliant'
            ).count()
        
        level_stats[level.level_number] = {
            'name': level.name,
            'total_possible': len(level_requirements) * total_users,
            'compliant': compliant_records,
            'percentage': (compliant_records / (len(level_requirements) * total_users)) * 100 
                         if level_requirements and total_users > 0 else 0
        }
    
    # Recent activity
    recent_records = ComplianceRecord.query.order_by(
        ComplianceRecord.updated_at.desc()
    ).limit(10).all()
    
    return render_template('admin/reports.html', 
                         total_users=total_users,
                         total_requirements=total_requirements,
                         total_records=total_records,
                         level_stats=level_stats,
                         recent_records=recent_records)

# Admin: Users management (authorize/revoke)
@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin' and not user.is_authorized:
        # Ensure admin is authorized by default
        user.is_authorized = True
    else:
        user.is_authorized = not user.is_authorized
    db.session.commit()
    flash('User authorization status updated.', 'success')
    return redirect(url_for('admin_users'))

# Admin: Devices management
@app.route('/admin/devices')
@admin_required
def admin_devices():
    devices = AuthorizedDevice.query.order_by(AuthorizedDevice.last_seen_at.desc()).all()
    return render_template('admin/devices.html', devices=devices)

@app.route('/admin/devices/approve/<int:device_id>', methods=['POST'])
@admin_required
def admin_approve_device(device_id):
    device = AuthorizedDevice.query.get_or_404(device_id)
    device.is_approved = True
    db.session.commit()
    flash('Device approved.', 'success')
    return redirect(url_for('admin_devices'))

@app.route('/admin/devices/revoke/<int:device_id>', methods=['POST'])
@admin_required
def admin_revoke_device(device_id):
    device = AuthorizedDevice.query.get_or_404(device_id)
    device.is_approved = False
    db.session.commit()
    flash('Device revoked.', 'warning')
    return redirect(url_for('admin_devices'))

# Admin: Service accounts
@app.route('/admin/service-accounts', methods=['GET', 'POST'])
@admin_required
def admin_service_accounts():
    if request.method == 'POST':
        name = request.form['name']
        scopes = request.form.get('scopes', 'read:summary')
        raw_token = _generate_token()
        sa = ServiceAccount(
            name=name,
            owner_user_id=session.get('user_id'),
            token_hash=_hash_token(raw_token),
            scopes=scopes,
            is_active=True
        )
        db.session.add(sa)
        db.session.commit()
        flash(f'New service token (copy now): {raw_token}', 'success')
        return redirect(url_for('admin_service_accounts'))
    accounts = ServiceAccount.query.all()
    return render_template('admin/service_accounts.html', accounts=accounts)

@app.route('/admin/service-accounts/toggle/<int:account_id>', methods=['POST'])
@admin_required
def admin_toggle_service_account(account_id):
    sa = ServiceAccount.query.get_or_404(account_id)
    sa.is_active = not sa.is_active
    db.session.commit()
    flash('Service account status updated.', 'success')
    return redirect(url_for('admin_service_accounts'))

@app.route('/compliance/<int:requirement_id>', methods=['GET', 'POST'])
@login_required
def compliance_record(requirement_id):
    requirement = CMMCRequirement.query.get_or_404(requirement_id)
    record = ComplianceRecord.query.filter_by(
        user_id=session['user_id'], 
        requirement_id=requirement_id
    ).first()
    
    if request.method == 'POST':
        status = request.form['status']
        notes = request.form['notes']
        delete_artifact = request.form.get('delete_artifact') == 'true'
        
        # Debug: Check what files are being uploaded
        print(f"Files in request: {list(request.files.keys())}")
        for key in request.files:
            file = request.files[key]
            print(f"File {key}: filename='{file.filename}', content_type='{file.content_type}'")

        # Handle artifact deletion
        if delete_artifact and record and record.artifact_path:
            # Delete the physical file
            try:
                static_folder = os.path.join(os.path.dirname(__file__), 'static')
                file_path = os.path.join(static_folder, record.artifact_path.lstrip('/'))
                print(f"Deleting file: {file_path}")  # Debug print
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print("File deleted successfully")
                else:
                    print("File not found")
            except Exception as e:
                print(f"Error deleting file: {e}")  # Log error but don't fail the request
            artifact_path = None
        else:
            # Handle artifact upload (optional)
            artifact_file = request.files.get('artifact')
            artifact_path = record.artifact_path if record else None  # Keep existing if no new file
            if artifact_file and artifact_file.filename:
                filename = secure_filename(artifact_file.filename)
                ext = os.path.splitext(filename)[1].lower()
                if ext not in app.config['UPLOAD_EXTENSIONS']:
                    flash('Unsupported file type. Allowed: ' + ', '.join(sorted(app.config['UPLOAD_EXTENSIONS'])), 'error')
                    return redirect(request.url)
                uploads_dir = _ensure_upload_dir_exists()
                unique_name = f"{session['user_id']}_{requirement_id}_{int(datetime.utcnow().timestamp())}_{secrets.token_hex(8)}{ext}"
                saved_path = os.path.join(uploads_dir, unique_name)
                print(f"Saving file to: {saved_path}")  # Debug print
                artifact_file.save(saved_path)
                print(f"File saved successfully. File exists: {os.path.exists(saved_path)}")  # Debug print
                # Store relative path under static for serving
                artifact_path = f"/{STATIC_UPLOADS_SUBDIR}/{unique_name}"
                print(f"Artifact path stored as: {artifact_path}")  # Debug print

        if record:
            record.status = status
            record.notes = notes
            if artifact_path is not None:  # Only update if explicitly set (including None for deletion)
                record.artifact_path = artifact_path
            record.updated_at = datetime.utcnow()
        else:
            record = ComplianceRecord(
                user_id=session['user_id'],
                requirement_id=requirement_id,
                status=status,
                notes=notes,
                artifact_path=artifact_path
            )
            db.session.add(record)
        
        db.session.commit()
        flash('Compliance record updated successfully!', 'success')
        return redirect(url_for('requirements'))
    
    return render_template('compliance_record.html', requirement=requirement, record=record)

@app.route('/api/compliance-summary')
@login_required
def api_compliance_summary():
    user_id = session['user_id']
    
    # Get overall stats
    total_requirements = CMMCRequirement.query.count()
    user_records = ComplianceRecord.query.filter_by(user_id=user_id).all()
    
    status_counts = {
        'compliant': 0,
        'non_compliant': 0,
        'in_progress': 0,
        'not_started': total_requirements - len(user_records)
    }
    
    for record in user_records:
        if record.status in status_counts:
            status_counts[record.status] += 1
    
    return jsonify(status_counts)

# Service API for processes acting on behalf of users
@app.route('/api/service/compliance-summary')
@service_token_required(required_scopes=['read:summary'])
def api_service_compliance_summary():
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400
    total_requirements = CMMCRequirement.query.count()
    user_records = ComplianceRecord.query.filter_by(user_id=user_id).all()
    status_counts = {
        'compliant': 0,
        'non_compliant': 0,
        'in_progress': 0,
        'not_started': total_requirements - len(user_records)
    }
    for record in user_records:
        if record.status in status_counts:
            status_counts[record.status] += 1
    return jsonify(status_counts)

@app.route('/uploads/<filename>')
@login_required
@authorized_user_required
def uploaded_file(filename):
    """Serve uploaded files with proper security checks."""
    try:
        static_folder = os.path.join(os.path.dirname(__file__), 'static')
        uploads_dir = os.path.join(static_folder, STATIC_UPLOADS_SUBDIR)
        file_path = os.path.join(uploads_dir, filename)
        
        # Security check: ensure file is within uploads directory
        if not os.path.exists(file_path) or not file_path.startswith(uploads_dir):
            return "File not found", 404
            
        return send_file(file_path)
    except Exception as e:
        print(f"Error serving file {filename}: {e}")
        return "File not found", 404

@app.route('/device-pending')
@login_required
def device_pending():
    # Ensure device cookie exists; if not, set one and create pending device record
    device_token = request.cookies.get('device_token')
    new_cookie_token = None
    if not device_token:
        new_cookie_token = _generate_token()
        device_token = new_cookie_token
    
    # Store hashed token in DB
    hashed = hashlib.sha256(device_token.encode('utf-8')).hexdigest()
    device = AuthorizedDevice.query.filter_by(device_token=hashed).first()
    
    if not device:
        device = AuthorizedDevice(
            user_id=session.get('user_id'),
            device_name=request.user_agent.string[:180] if request.user_agent else 'Unknown Device',
            device_token=hashed,
            is_approved=False
        )
        db.session.add(device)
        db.session.commit()
    
    resp = make_response(render_template('device_pending.html', device=device))
    if new_cookie_token:
        resp.set_cookie('device_token', new_cookie_token, httponly=True, samesite='Lax')
    return resp

def init_database():
    """Initialize the database with CMMC Level 1 data as per the guide."""
    db.create_all()

    # Create admin user if it doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            company='System Administrator',
            is_authorized=True
        )
        db.session.add(admin)

    # Add CMMC Levels if they don't exist
    if not CMMCLevel.query.first():
        levels = [
            CMMCLevel(level_number=1, name="Basic Cyber Hygiene",
                      description="Focuses on the protection of Federal Contract Information (FCI) and encompasses the basic safeguarding requirements specified in FAR Clause 52.204-21."),
            CMMCLevel(level_number=2, name="Intermediate Cyber Hygiene",
                      description="Implementation of NIST SP 800-171 practices"),
            CMMCLevel(level_number=3, name="Good Cyber Hygiene",
                      description="Advanced cybersecurity practices")
        ]
        db.session.add_all(levels)

    # Add CMMC Domains if they don't exist
    if not CMMCDomain.query.first():
        domains = [
            CMMCDomain(code="AC", name="Access Control",
                       description="Limit information system access to authorized users"),
            CMMCDomain(code="AU", name="Audit and Accountability",
                       description="Create, protect, and retain system audit records"),
            CMMCDomain(code="AT", name="Awareness and Training",
                       description="Ensure that personnel are trained in cybersecurity"),
            CMMCDomain(code="CM", name="Configuration Management",
                       description="Establish and maintain baseline configurations"),
            CMMCDomain(code="IA", name="Identification and Authentication",
                       description="Identify and authenticate users and devices"),
            CMMCDomain(code="IR", name="Incident Response",
                       description="Establish operational incident response capability"),
            CMMCDomain(code="MA", name="Maintenance",
                       description="Perform maintenance on systems and components"),
            CMMCDomain(code="MP", name="Media Protection",
                       description="Protect and control information and media"),
            CMMCDomain(code="PS", name="Personnel Security",
                       description="Ensure trustworthiness of personnel"),
            CMMCDomain(code="PE", name="Physical Protection",
                       description="Limit physical access to systems and equipment"),
            CMMCDomain(code="RA", name="Risk Assessment",
                       description="Assess and manage organizational risk"),
            CMMCDomain(code="CA", name="Security Assessment",
                       description="Develop and implement security assessment plans"),
            CMMCDomain(code="SC", name="System and Communications Protection",
                       description="Monitor and control communications"),
            CMMCDomain(code="SI", name="System and Information Integrity",
                       description="Identify, report, and correct system flaws")
        ]
        db.session.add_all(domains)

    # Commit levels and domains so they can be queried for requirements
    db.session.commit()

    # Add CMMC Level 1 Requirements
    if not CMMCRequirement.query.filter_by(level_id=CMMCLevel.query.filter_by(level_number=1).first().id).first():
        level_1_requirements = [
            {
                "requirement_id": "AC.L1-3.1.1", "title": "Authorized Access Control", "domain": "AC",
                "description": "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).",
                "guidance": "Maintain a list of authorized users, processes, and devices. Ensure the system is configured to grant access only to those on the approved list.",
                "assessment_objectives": "[a] authorized users are identified;\n[b] processes acting on behalf of authorized users are identified;\n[c] devices (and other systems) authorized to connect to the system are identified;\n[d] system access is limited to authorized users;\n[e] system access is limited to processes acting on behalf of authorized users; and\n[f] system access is limited to authorized devices (including other systems)."
            },
            {
                "requirement_id": "AC.L1-3.1.2", "title": "Transaction & Function Control", "domain": "AC",
                "description": "Limit information system access to the types of transactions and functions that authorized users are permitted to execute.",
                "guidance": "Use role-based access control (RBAC) to ensure users can only perform functions necessary for their job roles (e.g., create, read, update, delete).",
                "assessment_objectives": "[a] the types of transactions and functions that authorized users are permitted to execute are defined; and\n[b] system access is limited to the types of transactions and functions that authorized users are permitted to execute."
            },
            {
                "requirement_id": "AC.L1-3.1.20", "title": "External Connections", "domain": "AC",
                "description": "Verify and control/limit connections to and use of external information systems.",
                "guidance": "Use firewalls and connection policies to manage connections between your network and external ones. Control access from personally owned devices.",
                "assessment_objectives": "[a] connections to external systems are identified;\n[b] the use of external systems is identified;\n[c] connections to external systems are verified;\n[d] the use of external systems is verified; and\n[e] connections to external systems are controlled/limited."
            },
            {
                "requirement_id": "AC.L1-3.1.22", "title": "Control Public Information", "domain": "AC",
                "description": "Control information posted or processed on publicly accessible information systems.",
                "guidance": "Establish a review process to prevent Federal Contract Information (FCI) from being posted on public systems like company websites or forums.",
                "assessment_objectives": "[a] individuals authorized to post or process information on publicly accessible systems are identified;\n[b] procedures to ensure FCI is not posted or processed on publicly accessible systems are identified;\n[c] a review process is in place prior to posting of any content to publicly accessible systems;\n[d] content on publicly accessible systems is reviewed to ensure that it does not include FCI; and\n[e] mechanisms are in place to remove and address improper posting of FCI."
            },
            {
                "requirement_id": "IA.L1-3.5.1", "title": "Identification", "domain": "IA",
                "description": "Identify information system users, processes acting on behalf of users, or devices.",
                "guidance": "Assign unique identifiers (e.g., usernames) to all users, processes, and devices that require access to company systems.",
                "assessment_objectives": "[a] system users are identified;\n[b] processes acting on behalf of users are identified; and\n[c] devices are identified."
            },
            {
                "requirement_id": "IA.L1-3.5.2", "title": "Authentication", "domain": "IA",
                "description": "Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems.",
                "guidance": "Verify identity before granting access, typically with a username and strong password. Always change default passwords on new devices and systems.",
                "assessment_objectives": "[a] the identity of each user is authenticated or verified as a prerequisite to system access;\n[b] the identity of each process acting on behalf of a user is authenticated or verified as a prerequisite to system access; and\n[c] the identity of each device accessing or connecting to the system is authenticated or verified as a prerequisite to system access."
            },
            {
                "requirement_id": "MP.L1-3.8.3", "title": "Media Disposal", "domain": "MP",
                "description": "Sanitize or destroy information system media containing Federal Contract Information before disposal or release for reuse.",
                "guidance": "For any media containing FCI (e.g., paper, USB drives, hard drives), either physically destroy it or use a secure sanitization process to erase the data before disposal or reuse.",
                "assessment_objectives": "[a] system media containing FCI is sanitized or destroyed before disposal; and\n[b] system media containing FCI is sanitized or destroyed before release for reuse."
            },
            {
                "requirement_id": "PE.L1-3.10.1", "title": "Limit Physical Access", "domain": "PE",
                "description": "Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals.",
                "guidance": "Use locks, card readers, or other physical controls to restrict access to offices, server rooms, and equipment. Maintain a list of personnel with authorized physical access.",
                "assessment_objectives": "[a] authorized individuals allowed physical access are identified;\n[b] physical access to organizational systems is limited to authorized individuals;\n[c] physical access to equipment is limited to authorized individuals; and\n[d] physical access to operating environments is limited to authorized individuals."
            },
            {
                "requirement_id": "PE.L1-3.10.3", "title": "Escort Visitors", "domain": "PE",
                "description": "Escort visitors and monitor visitor activity.",
                "guidance": "Ensure all visitors are escorted by an employee at all times within the facility and wear visitor identification.",
                "assessment_objectives": "[a] visitors are escorted; and\n[b] visitor activity is monitored."
            },
            {
                "requirement_id": "PE.L1-3.10.4", "title": "Physical Access Logs", "domain": "PE",
                "description": "Maintain audit logs of physical access.",
                "guidance": "Use a sign-in sheet or electronic system to log all individuals entering and leaving the facility. Retain these logs for a defined period.",
                "assessment_objectives": "[a] audit logs of physical access are maintained."
            },
            {
                "requirement_id": "PE.L1-3.10.5", "title": "Manage Physical Access", "domain": "PE",
                "description": "Control and manage physical access devices.",
                "guidance": "Keep an inventory of all physical access devices like keys and key cards. Know who has them, and revoke access when personnel leave or change roles.",
                "assessment_objectives": "[a] physical access devices are identified;\n[b] physical access devices are controlled; and\n[c] physical access devices are managed."
            },
            {
                "requirement_id": "SC.L1-3.13.1", "title": "Boundary Protection", "domain": "SC",
                "description": "Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems) at the external boundaries and key internal boundaries of the information systems.",
                "guidance": "Use firewalls to protect the boundary between your internal network and the internet, blocking unwanted traffic and malicious websites.",
                "assessment_objectives": "[a] the external system boundary is defined;\n[b] key internal system boundaries are defined;\n[c] communications are monitored at the external system boundary;\n[d] communications are monitored at key internal boundaries;\n[e] communications are controlled at the external system boundary;\n[f] communications are controlled at key internal boundaries;\n[g] communications are protected at the external system boundary; and\n[h] communications are protected at key internal boundaries."
            },
            {
                "requirement_id": "SC.L1-3.13.5", "title": "Public-Access System Separation", "domain": "SC",
                "description": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
                "guidance": "Isolate publicly accessible systems (like a public website) from your internal network using a demilitarized zone (DMZ) or separate VLAN.",
                "assessment_objectives": "[a] publicly accessible system components are identified; and\n[b] subnetworks for publicly accessible system components are physically or logically separated from internal networks."
            },
            {
                "requirement_id": "SI.L1-3.14.1", "title": "Flaw Remediation", "domain": "SI",
                "description": "Identify, report, and correct information and information system flaws in a timely manner.",
                "guidance": "Implement a patch management process to fix software and firmware flaws within a defined timeframe based on vendor notifications.",
                "assessment_objectives": "[a] the time within which to identify system flaws is specified;\n[b] system flaws are identified within the specified time frame;\n[c] the time within which to report system flaws is specified;\n[d] system flaws are reported within the specified time frame;\n[e] the time within which to correct system flaws is specified; and\n[f] system flaws are corrected within the specified time frame."
            },
            {
                "requirement_id": "SI.L1-3.14.2", "title": "Malicious Code Protection", "domain": "SI",
                "description": "Provide protection from malicious code at appropriate locations within organizational information systems.",
                "guidance": "Use anti-virus and anti-malware software on workstations, servers, and firewalls to protect against malicious code like viruses and ransomware.",
                "assessment_objectives": "[a] designated locations for malicious code protection are identified; and\n[b] protection from malicious code at designated locations is provided."
            },
            {
                "requirement_id": "SI.L1-3.14.4", "title": "Update Malicious Code Protection", "domain": "SI",
                "description": "Update malicious code protection mechanisms when new releases are available.",
                "guidance": "Configure anti-malware software to update its definition files automatically and frequently (e.g., daily) to protect against the latest threats.",
                "assessment_objectives": "[a] malicious code protection mechanisms are updated when new releases are available."
            },
            {
                "requirement_id": "SI.L1-3.14.5", "title": "System & File Scanning", "domain": "SI",
                "description": "Perform periodic scans of the information system and real-time scans of files from external sources as files are downloaded, opened, or executed.",
                "guidance": "Configure anti-malware software to perform periodic full-system scans and real-time scans of files from external sources like email attachments and USB drives.",
                "assessment_objectives": "[a] the frequency for malicious code scans is defined;\n[b] malicious code scans are performed with the defined frequency; and\n[c] real-time malicious code scans of files from external sources as files are downloaded, opened, or executed are performed."
            }
        ]

        level1 = CMMCLevel.query.filter_by(level_number=1).first()

        for req_data in level_1_requirements:
            domain = CMMCDomain.query.filter_by(code=req_data['domain']).first()
            
            if domain:
                requirement = CMMCRequirement(
                    requirement_id=req_data['requirement_id'],
                    title=req_data['title'],
                    description=req_data['description'],
                    level_id=level1.id,
                    domain_id=domain.id,
                    guidance=req_data['guidance'],
                    assessment_objectives=req_data['assessment_objectives']
                )
                db.session.add(requirement)

    # Add CMMC Level 2 Requirements
    if not CMMCRequirement.query.filter_by(level_id=CMMCLevel.query.filter_by(level_number=2).first().id).first():
        level_2_requirements = [
            # Access Control (AC) Requirements
            {
                "requirement_id": "AC.L2-3.1.1", "title": "Authorized Access Control [CUI Data]", "domain": "AC",
                "description": "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).",
                "guidance": "Maintain a list of authorized users, processes, and devices. Ensure the system is configured to grant access only to those on the approved list.",
                "assessment_objectives": "[a] authorized users are identified;\n[b] processes acting on behalf of authorized users are identified;\n[c] devices (and other systems) authorized to connect to the system are identified;\n[d] system access is limited to authorized users;\n[e] system access is limited to processes acting on behalf of authorized users; and\n[f] system access is limited to authorized devices (including other systems)."
            },
            {
                "requirement_id": "AC.L2-3.1.2", "title": "Transaction & Function Control", "domain": "AC",
                "description": "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
                "guidance": "Use role-based access control (RBAC) to ensure users can only perform functions necessary for their job roles (e.g., create, read, update, delete).",
                "assessment_objectives": "[a] the types of transactions and functions that authorized users are permitted to execute are defined; and\n[b] system access is limited to the types of transactions and functions that authorized users are permitted to execute."
            },
            {
                "requirement_id": "AC.L2-3.1.3", "title": "Control CUI Flow", "domain": "AC",
                "description": "Control the flow of CUI in accordance with approved authorizations.",
                "guidance": "Implement network segmentation and data flow controls to ensure CUI moves only between authorized systems according to security policies.",
                "assessment_objectives": "[a] security policies for CUI flow are defined;\n[b] CUI flow between connected systems is controlled according to security policies; and\n[c] CUI flow controls are implemented and enforced."
            },
            {
                "requirement_id": "AC.L2-3.1.4", "title": "Separation of Duties", "domain": "AC",
                "description": "Separate the duties of individuals to reduce the risk of malevolent activity without collusion.",
                "guidance": "Ensure that no single individual has complete control over critical functions. Separate authorization, execution, and verification duties.",
                "assessment_objectives": "[a] duties are identified and documented;\n[b] duties are separated to reduce risk of malevolent activity; and\n[c] separation of duties is enforced through system controls."
            },
            {
                "requirement_id": "AC.L2-3.1.5", "title": "Least Privilege", "domain": "AC",
                "description": "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
                "guidance": "Grant users only the minimum access necessary to perform their job functions. Regularly review and revoke unnecessary privileges.",
                "assessment_objectives": "[a] least privilege principle is defined;\n[b] user access is limited to minimum necessary privileges;\n[c] privileged account access is limited to minimum necessary; and\n[d] least privilege is enforced through system controls."
            },
            {
                "requirement_id": "AC.L2-3.1.6", "title": "Non-Privileged Account Use", "domain": "AC",
                "description": "Use non-privileged accounts or roles when accessing nonsecurity functions.",
                "guidance": "Use standard user accounts for daily operations. Only use administrative accounts when performing administrative tasks.",
                "assessment_objectives": "[a] non-privileged accounts are used for non-security functions;\n[b] privileged accounts are used only when necessary; and\n[c] account usage is monitored and enforced."
            },
            {
                "requirement_id": "AC.L2-3.1.7", "title": "Privileged Functions", "domain": "AC",
                "description": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.",
                "guidance": "Implement controls to prevent standard users from executing administrative functions. Log all attempts to execute privileged functions.",
                "assessment_objectives": "[a] privileged functions are identified;\n[b] non-privileged users are prevented from executing privileged functions;\n[c] execution of privileged functions is captured in audit logs; and\n[d] privileged function execution is monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.8", "title": "Unsuccessful Logon Attempts", "domain": "AC",
                "description": "Limit unsuccessful logon attempts.",
                "guidance": "Implement account lockout policies after a specified number of failed login attempts to prevent brute force attacks.",
                "assessment_objectives": "[a] maximum number of unsuccessful logon attempts is defined;\n[b] unsuccessful logon attempts are limited to the defined maximum; and\n[c] account lockout mechanisms are implemented and enforced."
            },
            {
                "requirement_id": "AC.L2-3.1.9", "title": "Privacy & Security Notices", "domain": "AC",
                "description": "Provide privacy and security notices consistent with applicable CUI rules.",
                "guidance": "Display appropriate privacy and security notices to users accessing systems containing CUI, consistent with applicable regulations.",
                "assessment_objectives": "[a] privacy and security notice requirements are defined;\n[b] privacy and security notices are provided to users;\n[c] notices are consistent with applicable CUI rules; and\n[d] notice compliance is monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.10", "title": "Session Lock", "domain": "AC",
                "description": "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.",
                "guidance": "Configure workstations to automatically lock after a period of inactivity. Use screensavers that hide the display content.",
                "assessment_objectives": "[a] session lock timeout is defined;\n[b] session locks are implemented with pattern-hiding displays;\n[c] session locks activate after period of inactivity; and\n[d] session lock controls are enforced."
            },
            {
                "requirement_id": "AC.L2-3.1.11", "title": "Session Termination", "domain": "AC",
                "description": "Terminate (automatically) a user session after a defined condition.",
                "guidance": "Implement automatic session termination for conditions like end of workday, maximum session time, or security events.",
                "assessment_objectives": "[a] session termination conditions are defined;\n[b] user sessions are terminated upon meeting defined conditions;\n[c] session termination is automated where possible; and\n[d] session termination is logged and monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.12", "title": "Control Remote Access", "domain": "AC",
                "description": "Monitor and control remote access sessions.",
                "guidance": "Use VPNs and remote access controls. Monitor all remote connections and log remote access activities.",
                "assessment_objectives": "[a] remote access sessions are monitored;\n[b] remote access sessions are controlled;\n[c] remote access activities are logged; and\n[d] remote access is limited to authorized users and systems."
            },
            {
                "requirement_id": "AC.L2-3.1.13", "title": "Remote Access Confidentiality", "domain": "AC",
                "description": "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.",
                "guidance": "Use strong encryption for all remote access sessions, including VPN connections and remote desktop sessions.",
                "assessment_objectives": "[a] cryptographic mechanisms are implemented;\n[b] remote access sessions are encrypted;\n[c] encryption strength is appropriate; and\n[d] cryptographic protection is monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.14", "title": "Remote Access Routing", "domain": "AC",
                "description": "Route remote access via managed access control points.",
                "guidance": "Ensure all remote access connections are routed through approved and monitored access control points.",
                "assessment_objectives": "[a] access control points are identified and managed;\n[b] remote access is routed through managed control points;\n[c] routing is enforced through network configuration; and\n[d] routing compliance is monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.15", "title": "Privileged Remote Access", "domain": "AC",
                "description": "Authorize remote execution of privileged commands and remote access to security-relevant information.",
                "guidance": "Implement additional authorization requirements for remote execution of privileged commands and access to sensitive information.",
                "assessment_objectives": "[a] remote execution authorization requirements are defined;\n[b] remote execution of privileged commands is authorized;\n[c] remote access to security-relevant information is authorized; and\n[d] authorization is logged and monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.16", "title": "Wireless Access Authorization", "domain": "AC",
                "description": "Authorize wireless access prior to allowing such connections.",
                "guidance": "Implement wireless access authorization processes to approve devices before they can connect to wireless networks.",
                "assessment_objectives": "[a] wireless access authorization procedures are defined;\n[b] wireless access is authorized prior to connection;\n[c] unauthorized wireless access is prevented; and\n[d] wireless access authorization is monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.17", "title": "Wireless Access Protection", "domain": "AC",
                "description": "Protect wireless access using authentication and encryption.",
                "guidance": "Use WPA3 or WPA2 encryption for wireless networks. Implement strong authentication for wireless access.",
                "assessment_objectives": "[a] wireless access authentication is implemented;\n[b] wireless access encryption is implemented;\n[c] wireless access is protected from unauthorized use; and\n[d] wireless access security is monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.18", "title": "Mobile Device Connection", "domain": "AC",
                "description": "Control connection of mobile devices.",
                "guidance": "Implement mobile device management (MDM) solutions to control and monitor access to mobile devices that handle FCI or CUI.",
                "assessment_objectives": "[a] mobile device connection controls are implemented;\n[b] mobile device access is monitored;\n[c] mobile device security policies are enforced; and\n[d] mobile device compliance is assessed."
            },
            {
                "requirement_id": "AC.L2-3.1.19", "title": "Encrypt CUI on Mobile", "domain": "AC",
                "description": "Encrypt CUI on mobile devices and mobile computing platforms.",
                "guidance": "Use device encryption and secure containers to protect CUI on mobile devices. Implement remote wipe capabilities.",
                "assessment_objectives": "[a] CUI encryption on mobile devices is implemented;\n[b] mobile device encryption is enforced;\n[c] secure containers are used for CUI; and\n[d] mobile device security is monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.20", "title": "External Connections [CUI Data]", "domain": "AC",
                "description": "Verify and control/limit connections to and use of external systems.",
                "guidance": "Use firewalls and connection policies to manage connections between your network and external ones. Control access from personally owned devices.",
                "assessment_objectives": "[a] connections to external systems are identified;\n[b] the use of external systems is identified;\n[c] connections to external systems are verified;\n[d] the use of external systems is verified; and\n[e] connections to external systems are controlled/limited."
            },
            {
                "requirement_id": "AC.L2-3.1.21", "title": "Portable Storage Use", "domain": "AC",
                "description": "Limit use of portable storage devices on external systems.",
                "guidance": "Implement controls to limit or prevent the use of portable storage devices like USB drives on external systems.",
                "assessment_objectives": "[a] portable storage device policies are defined;\n[b] use of portable storage devices on external systems is limited;\n[c] portable storage device controls are enforced; and\n[d] portable storage device usage is monitored."
            },
            {
                "requirement_id": "AC.L2-3.1.22", "title": "Control Public Information [CUI Data]", "domain": "AC",
                "description": "Control CUI posted or processed on publicly accessible systems.",
                "guidance": "Establish a review process to prevent CUI from being posted on public systems like company websites or forums.",
                "assessment_objectives": "[a] individuals authorized to post or process information on publicly accessible systems are identified;\n[b] procedures to ensure CUI is not posted or processed on publicly accessible systems are identified;\n[c] a review process is in place prior to posting of any content to publicly accessible systems;\n[d] content on publicly accessible systems is reviewed to ensure that it does not include CUI; and\n[e] mechanisms are in place to remove and address improper posting of CUI."
            },
            # Awareness and Training (AT) Requirements
            {
                "requirement_id": "AT.L2-3.2.1", "title": "Role-Based Risk Awareness", "domain": "AT",
                "description": "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.",
                "guidance": "Provide role-specific security awareness training that covers risks associated with each role and relevant security policies and procedures.",
                "assessment_objectives": "[a] role-based risk awareness requirements are defined;\n[b] managers are made aware of security risks;\n[c] systems administrators are made aware of security risks;\n[d] users are made aware of security risks; and\n[e] applicable policies, standards, and procedures are communicated."
            },
            {
                "requirement_id": "AT.L2-3.2.2", "title": "Role-Based Training", "domain": "AT",
                "description": "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.",
                "guidance": "Provide specialized security training for personnel with specific security responsibilities, such as system administrators and security officers.",
                "assessment_objectives": "[a] role-based training requirements are defined;\n[b] personnel are trained for their assigned security duties;\n[c] training is tailored to specific roles; and\n[d] role-based training effectiveness is assessed."
            },
            {
                "requirement_id": "AT.L2-3.2.3", "title": "Insider Threat Awareness", "domain": "AT",
                "description": "Provide security awareness training on recognizing and reporting potential indicators of insider threat.",
                "guidance": "Conduct regular security awareness training that includes recognizing insider threat indicators and proper reporting procedures.",
                "assessment_objectives": "[a] insider threat awareness training requirements are defined;\n[b] security awareness training is provided;\n[c] insider threat indicators are covered in training; and\n[d] training effectiveness is assessed."
            },
            # Audit and Accountability (AU) Requirements
            {
                "requirement_id": "AU.L2-3.3.1", "title": "System Auditing", "domain": "AU",
                "description": "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
                "guidance": "Implement comprehensive audit logging for all system activities. Retain audit logs according to organizational policy and legal requirements.",
                "assessment_objectives": "[a] audit record requirements are defined;\n[b] system audit records are created;\n[c] audit records are retained according to policy; and\n[d] audit record integrity is protected."
            },
            {
                "requirement_id": "AU.L2-3.3.2", "title": "User Accountability", "domain": "AU",
                "description": "Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.",
                "guidance": "Configure audit logs to capture user identification, timestamps, and actions performed. Ensure logs cannot be modified by users.",
                "assessment_objectives": "[a] user actions are uniquely traceable;\n[b] audit records contain sufficient information for accountability;\n[c] audit record integrity is protected; and\n[d] user accountability is enforced."
            },
            {
                "requirement_id": "AU.L2-3.3.3", "title": "Event Review", "domain": "AU",
                "description": "Review and update logged events.",
                "guidance": "Regularly review audit logs for suspicious activities. Update logging configurations based on security requirements and threat landscape.",
                "assessment_objectives": "[a] audit record review procedures are defined;\n[b] audit records are regularly reviewed;\n[c] logged events are updated as needed; and\n[d] audit review findings are addressed."
            },
            {
                "requirement_id": "AU.L2-3.3.4", "title": "Audit Failure Alerting", "domain": "AU",
                "description": "Alert in the event of an audit logging process failure.",
                "guidance": "Implement monitoring and alerting for audit system failures. Ensure backup audit mechanisms are in place.",
                "assessment_objectives": "[a] audit processing failure conditions are defined;\n[b] audit processing failures are detected;\n[c] alerts are generated for audit failures; and\n[d] audit system failures are addressed promptly."
            },
            {
                "requirement_id": "AU.L2-3.3.5", "title": "Audit Correlation", "domain": "AU",
                "description": "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.",
                "guidance": "Use security information and event management (SIEM) systems to correlate audit records across different systems and components.",
                "assessment_objectives": "[a] audit record correlation procedures are defined;\n[b] audit records are correlated across system components;\n[c] correlation analysis is performed; and\n[d] correlation findings are reported."
            },
            {
                "requirement_id": "AU.L2-3.3.6", "title": "Reduction & Reporting", "domain": "AU",
                "description": "Provide audit record reduction and report generation to support on-demand analysis and reporting.",
                "guidance": "Implement tools and processes for audit record reduction and automated report generation to support security analysis.",
                "assessment_objectives": "[a] audit record reduction procedures are defined;\n[b] audit record reduction is implemented;\n[c] report generation capabilities are provided; and\n[d] on-demand analysis and reporting is supported."
            },
            {
                "requirement_id": "AU.L2-3.3.7", "title": "Authoritative Time Source", "domain": "AU",
                "description": "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.",
                "guidance": "Configure all systems to synchronize their clocks with authoritative time sources to ensure accurate timestamps in audit records.",
                "assessment_objectives": "[a] time synchronization requirements are defined;\n[b] system clocks are synchronized with authoritative time sources;\n[c] time synchronization is monitored; and\n[d] time synchronization accuracy is verified."
            },
            {
                "requirement_id": "AU.L2-3.3.8", "title": "Audit Protection", "domain": "AU",
                "description": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
                "guidance": "Implement strong access controls for audit logs and logging tools. Use encryption and integrity protection for audit data.",
                "assessment_objectives": "[a] audit information protection requirements are defined;\n[b] audit information is protected from unauthorized access;\n[c] audit logging tools are protected; and\n[d] audit information integrity is maintained."
            },
            {
                "requirement_id": "AU.L2-3.3.9", "title": "Audit Management", "domain": "AU",
                "description": "Limit management of audit logging functionality to a subset of privileged users.",
                "guidance": "Restrict access to audit logging configuration and management to authorized administrators only.",
                "assessment_objectives": "[a] privileged users for audit management are identified;\n[b] audit logging functionality access is limited to privileged users;\n[c] audit management access is monitored; and\n[d] audit management activities are logged."
            },
            # Configuration Management (CM) Requirements
            {
                "requirement_id": "CM.L2-3.4.1", "title": "System Baselining", "domain": "CM",
                "description": "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.",
                "guidance": "Create and maintain secure baseline configurations for all systems. Keep inventories of all organizational information systems.",
                "assessment_objectives": "[a] baseline configuration requirements are defined;\n[b] baseline configurations are established;\n[c] system inventories are maintained; and\n[d] baseline configurations are updated as needed."
            },
            {
                "requirement_id": "CM.L2-3.4.2", "title": "Security Configuration Enforcement", "domain": "CM",
                "description": "Establish and enforce security configuration settings for information technology products employed in organizational systems.",
                "guidance": "Implement security configuration standards and enforce them across all IT products and systems.",
                "assessment_objectives": "[a] security configuration settings are established;\n[b] security configuration settings are enforced;\n[c] IT products are configured according to standards; and\n[d] configuration compliance is monitored."
            },
            {
                "requirement_id": "CM.L2-3.4.3", "title": "System Change Management", "domain": "CM",
                "description": "Track, review, approve or disapprove, and log changes to organizational systems.",
                "guidance": "Implement formal change control processes that require approval for all system changes, including testing and rollback procedures.",
                "assessment_objectives": "[a] change control processes are defined;\n[b] system changes are tracked;\n[c] system changes are reviewed and approved; and\n[d] system changes are logged."
            },
            {
                "requirement_id": "CM.L2-3.4.4", "title": "Security Impact Analysis", "domain": "CM",
                "description": "Analyze the security impact of changes prior to implementation.",
                "guidance": "Conduct security impact assessments for all proposed system changes to identify potential security risks.",
                "assessment_objectives": "[a] security impact analysis procedures are defined;\n[b] security impact analysis is performed;\n[c] security impacts are documented; and\n[d] security impact findings are addressed."
            },
            {
                "requirement_id": "CM.L2-3.4.5", "title": "Access Restrictions for Change", "domain": "CM",
                "description": "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.",
                "guidance": "Implement access controls for system changes, including physical security for change management systems and logical access controls.",
                "assessment_objectives": "[a] access restrictions for changes are defined;\n[b] access restrictions are documented;\n[c] access restrictions are approved; and\n[d] access restrictions are enforced."
            },
            {
                "requirement_id": "CM.L2-3.4.6", "title": "Least Functionality", "domain": "CM",
                "description": "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.",
                "guidance": "Configure systems to provide only necessary functionality. Disable unnecessary services, ports, and protocols.",
                "assessment_objectives": "[a] least functionality principle is applied;\n[b] system configurations provide only essential capabilities;\n[c] unnecessary functionality is disabled; and\n[d] configuration effectiveness is monitored."
            },
            {
                "requirement_id": "CM.L2-3.4.7", "title": "Nonessential Functionality", "domain": "CM",
                "description": "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.",
                "guidance": "Implement controls to prevent users from installing unauthorized software and using nonessential network services.",
                "assessment_objectives": "[a] nonessential programs are restricted;\n[b] nonessential functions are disabled;\n[c] nonessential ports and protocols are blocked; and\n[d] software installation is controlled."
            },
            {
                "requirement_id": "CM.L2-3.4.8", "title": "Application Execution Policy", "domain": "CM",
                "description": "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.",
                "guidance": "Implement application whitelisting or blacklisting to control software execution on organizational systems.",
                "assessment_objectives": "[a] application execution policy is defined;\n[b] unauthorized software execution is prevented;\n[c] authorized software execution is allowed; and\n[d] application execution policy is enforced."
            },
            {
                "requirement_id": "CM.L2-3.4.9", "title": "User-Installed Software", "domain": "CM",
                "description": "Control and monitor user-installed software.",
                "guidance": "Implement controls to prevent users from installing software without authorization. Use administrative privileges and software deployment tools.",
                "assessment_objectives": "[a] user-installed software controls are implemented;\n[b] user software installation is controlled;\n[c] user software installation is monitored; and\n[d] unauthorized software installation is prevented."
            },
            # Identification and Authentication (IA) Requirements
            {
                "requirement_id": "IA.L2-3.5.1", "title": "Identification [CUI Data]", "domain": "IA",
                "description": "Identify system users, processes acting on behalf of users, and devices.",
                "guidance": "Assign unique identifiers (e.g., usernames) to all users, processes, and devices that require access to company systems.",
                "assessment_objectives": "[a] system users are identified;\n[b] processes acting on behalf of users are identified; and\n[c] devices are identified."
            },
            {
                "requirement_id": "IA.L2-3.5.2", "title": "Authentication [CUI Data]", "domain": "IA",
                "description": "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.",
                "guidance": "Verify identity before granting access, typically with a username and strong password. Always change default passwords on new devices and systems.",
                "assessment_objectives": "[a] the identity of each user is authenticated or verified as a prerequisite to system access;\n[b] the identity of each process acting on behalf of a user is authenticated or verified as a prerequisite to system access; and\n[c] the identity of each device accessing or connecting to the system is authenticated or verified as a prerequisite to system access."
            },
            {
                "requirement_id": "IA.L2-3.5.3", "title": "Multifactor Authentication", "domain": "IA",
                "description": "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.",
                "guidance": "Implement multifactor authentication (MFA) for all privileged accounts and network access to non-privileged accounts.",
                "assessment_objectives": "[a] multifactor authentication is implemented for privileged accounts;\n[b] multifactor authentication is implemented for network access;\n[c] MFA is enforced for all applicable accounts; and\n[d] MFA effectiveness is monitored."
            },
            {
                "requirement_id": "IA.L2-3.5.4", "title": "Replay-Resistant Authentication", "domain": "IA",
                "description": "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.",
                "guidance": "Use authentication mechanisms that prevent replay attacks for all account access, such as challenge-response protocols.",
                "assessment_objectives": "[a] replay-resistant authentication is implemented;\n[b] privileged account access uses replay-resistant mechanisms;\n[c] non-privileged account access uses replay-resistant mechanisms; and\n[d] replay attack prevention is effective."
            },
            {
                "requirement_id": "IA.L2-3.5.5", "title": "Identifier Reuse", "domain": "IA",
                "description": "Prevent reuse of identifiers for a defined period.",
                "guidance": "Implement controls to prevent reuse of user identifiers, usernames, and other identifiers for a specified period.",
                "assessment_objectives": "[a] identifier reuse prevention period is defined;\n[b] identifier reuse is prevented;\n[c] identifier reuse controls are enforced; and\n[d] identifier reuse prevention is monitored."
            },
            {
                "requirement_id": "IA.L2-3.5.6", "title": "Identifier Handling", "domain": "IA",
                "description": "Disable identifiers after a defined period of inactivity.",
                "guidance": "Implement automatic disabling of user accounts and identifiers after a period of inactivity to prevent unauthorized access.",
                "assessment_objectives": "[a] inactivity period is defined;\n[b] inactive identifiers are disabled;\n[c] identifier disabling is automated; and\n[d] identifier management is monitored."
            },
            {
                "requirement_id": "IA.L2-3.5.7", "title": "Password Complexity", "domain": "IA",
                "description": "Enforce a minimum password complexity and change of characters when new passwords are created.",
                "guidance": "Implement strong password policies requiring minimum length, complexity, and character requirements.",
                "assessment_objectives": "[a] password complexity requirements are defined;\n[b] minimum password complexity is enforced;\n[c] password character requirements are enforced; and\n[d] password policy compliance is monitored."
            },
            {
                "requirement_id": "IA.L2-3.5.8", "title": "Password Reuse", "domain": "IA",
                "description": "Prohibit password reuse for a specified number of generations.",
                "guidance": "Implement password history controls to prevent reuse of recent passwords for a specified number of password changes.",
                "assessment_objectives": "[a] password reuse prevention period is defined;\n[b] password reuse is prohibited;\n[c] password history is maintained; and\n[d] password reuse prevention is enforced."
            },
            {
                "requirement_id": "IA.L2-3.5.9", "title": "Temporary Passwords", "domain": "IA",
                "description": "Allow temporary password use for system logons with an immediate change to a permanent password.",
                "guidance": "Implement temporary password mechanisms that require immediate change to permanent passwords upon first login.",
                "assessment_objectives": "[a] temporary password procedures are defined;\n[b] temporary passwords are allowed for system logons;\n[c] immediate change to permanent password is required; and\n[d] temporary password usage is monitored."
            },
            {
                "requirement_id": "IA.L2-3.5.10", "title": "Cryptographically-Protected Passwords", "domain": "IA",
                "description": "Store and transmit only cryptographically-protected passwords.",
                "guidance": "Use strong cryptographic hashing for password storage and encryption for password transmission.",
                "assessment_objectives": "[a] password storage uses cryptographic protection;\n[b] password transmission uses cryptographic protection;\n[c] cryptographic mechanisms are appropriate; and\n[d] password protection is monitored."
            },
            {
                "requirement_id": "IA.L2-3.5.11", "title": "Obscure Feedback", "domain": "IA",
                "description": "Obscure feedback of authentication information.",
                "guidance": "Implement authentication feedback mechanisms that do not reveal sensitive authentication information to unauthorized parties.",
                "assessment_objectives": "[a] authentication feedback requirements are defined;\n[b] authentication information feedback is obscured;\n[c] sensitive information is protected; and\n[d] authentication feedback is monitored."
            },
            # Incident Response (IR) Requirements
            {
                "requirement_id": "IR.L2-3.6.1", "title": "Incident Handling", "domain": "IR",
                "description": "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
                "guidance": "Develop and implement comprehensive incident response procedures covering all phases of incident handling.",
                "assessment_objectives": "[a] incident handling capability is established;\n[b] preparation activities are defined;\n[c] detection capabilities are implemented;\n[d] analysis procedures are established;\n[e] containment procedures are defined;\n[f] recovery procedures are established; and\n[g] user response activities are defined."
            },
            {
                "requirement_id": "IR.L2-3.6.2", "title": "Incident Reporting", "domain": "IR",
                "description": "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.",
                "guidance": "Implement incident tracking and reporting systems to ensure proper documentation and escalation of security incidents.",
                "assessment_objectives": "[a] incident tracking procedures are defined;\n[b] incidents are documented;\n[c] incidents are reported to designated officials;\n[d] external reporting requirements are met; and\n[e] incident reporting is monitored."
            },
            {
                "requirement_id": "IR.L2-3.6.3", "title": "Incident Response Testing", "domain": "IR",
                "description": "Test the organizational incident response capability.",
                "guidance": "Conduct regular testing of incident response procedures through tabletop exercises and simulations.",
                "assessment_objectives": "[a] incident response testing procedures are defined;\n[b] incident response capability is tested;\n[c] test results are documented; and\n[d] improvements are implemented based on test results."
            },
            # Maintenance (MA) Requirements
            {
                "requirement_id": "MA.L2-3.7.1", "title": "Perform Maintenance", "domain": "MA",
                "description": "Perform maintenance on organizational systems.",
                "guidance": "Establish and follow regular maintenance schedules for all organizational systems to ensure proper operation and security.",
                "assessment_objectives": "[a] maintenance procedures are defined;\n[b] maintenance schedules are established;\n[c] maintenance is performed according to schedule; and\n[d] maintenance activities are documented."
            },
            {
                "requirement_id": "MA.L2-3.7.2", "title": "System Maintenance Control", "domain": "MA",
                "description": "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.",
                "guidance": "Implement controls to ensure only authorized personnel use approved tools and techniques for system maintenance.",
                "assessment_objectives": "[a] maintenance control procedures are defined;\n[b] maintenance tools are controlled;\n[c] maintenance techniques are controlled;\n[d] maintenance personnel are authorized; and\n[e] maintenance activities are monitored."
            },
            {
                "requirement_id": "MA.L2-3.7.3", "title": "Equipment Sanitization", "domain": "MA",
                "description": "Ensure equipment removed for off-site maintenance is sanitized of any CUI.",
                "guidance": "Implement procedures to sanitize equipment containing CUI before sending it off-site for maintenance.",
                "assessment_objectives": "[a] equipment sanitization procedures are defined;\n[b] equipment is sanitized before off-site maintenance;\n[c] sanitization effectiveness is verified; and\n[d] sanitization activities are documented."
            },
            {
                "requirement_id": "MA.L2-3.7.4", "title": "Media Inspection", "domain": "MA",
                "description": "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.",
                "guidance": "Scan all diagnostic and test media for malware before using them on organizational systems.",
                "assessment_objectives": "[a] media inspection procedures are defined;\n[b] diagnostic and test media are inspected;\n[c] malicious code detection is performed; and\n[d] clean media is used in organizational systems."
            },
            {
                "requirement_id": "MA.L2-3.7.5", "title": "Nonlocal Maintenance", "domain": "MA",
                "description": "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.",
                "guidance": "Implement MFA for remote maintenance sessions and ensure proper session termination.",
                "assessment_objectives": "[a] nonlocal maintenance procedures are defined;\n[b] multifactor authentication is required for nonlocal maintenance;\n[c] maintenance sessions are terminated when complete; and\n[d] nonlocal maintenance is monitored."
            },
            {
                "requirement_id": "MA.L2-3.7.6", "title": "Maintenance Personnel", "domain": "MA",
                "description": "Supervise the maintenance activities of maintenance personnel without required access authorization.",
                "guidance": "Ensure all maintenance personnel have proper authorization and supervise their activities.",
                "assessment_objectives": "[a] maintenance personnel authorization procedures are defined;\n[b] maintenance personnel are authorized;\n[c] maintenance activities are supervised; and\n[d] unauthorized maintenance is prevented."
            },
            # Media Protection (MP) Requirements
            {
                "requirement_id": "MP.L2-3.8.1", "title": "Media Protection", "domain": "MP",
                "description": "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.",
                "guidance": "Implement physical and logical controls to protect media containing CUI from unauthorized access or theft.",
                "assessment_objectives": "[a] media protection procedures are defined;\n[b] physical controls are implemented;\n[c] secure storage is provided;\n[d] both paper and digital media are protected; and\n[e] media protection is monitored."
            },
            {
                "requirement_id": "MP.L2-3.8.2", "title": "Media Access", "domain": "MP",
                "description": "Limit access to CUI on system media to authorized users.",
                "guidance": "Implement access controls to ensure only authorized users can access media containing CUI.",
                "assessment_objectives": "[a] media access procedures are defined;\n[b] access to CUI on media is limited to authorized users;\n[c] unauthorized access is prevented; and\n[d] media access is monitored."
            },
            {
                "requirement_id": "MP.L2-3.8.3", "title": "Media Disposal [CUI Data]", "domain": "MP",
                "description": "Sanitize or destroy system media containing CUI before disposal or release for reuse.",
                "guidance": "For any media containing CUI (e.g., paper, USB drives, hard drives), either physically destroy it or use a secure sanitization process to erase the data before disposal or reuse.",
                "assessment_objectives": "[a] media disposal procedures are defined;\n[b] system media containing CUI is sanitized or destroyed before disposal; and\n[c] system media containing CUI is sanitized or destroyed before release for reuse."
            },
            {
                "requirement_id": "MP.L2-3.8.4", "title": "Media Markings", "domain": "MP",
                "description": "Mark media with necessary CUI markings and distribution limitations.",
                "guidance": "Ensure all media containing CUI is properly marked with appropriate classification and distribution limitations.",
                "assessment_objectives": "[a] media marking procedures are defined;\n[b] media is marked with necessary CUI markings;\n[c] distribution limitations are marked; and\n[d] marking compliance is verified."
            },
            {
                "requirement_id": "MP.L2-3.8.5", "title": "Media Accountability", "domain": "MP",
                "description": "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.",
                "guidance": "Implement tracking and accountability measures for media containing CUI during transport and storage.",
                "assessment_objectives": "[a] media accountability procedures are defined;\n[b] access to media containing CUI is controlled;\n[c] accountability is maintained during transport; and\n[d] media tracking is implemented."
            },
            {
                "requirement_id": "MP.L2-3.8.6", "title": "Portable Storage Encryption", "domain": "MP",
                "description": "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.",
                "guidance": "Use encryption to protect CUI on portable storage devices during transport, or implement alternative physical safeguards.",
                "assessment_objectives": "[a] portable storage encryption procedures are defined;\n[b] cryptographic mechanisms are implemented;\n[c] CUI on digital media is protected during transport; and\n[d] alternative physical safeguards are used when appropriate."
            },
            {
                "requirement_id": "MP.L2-3.8.7", "title": "Removeable Media", "domain": "MP",
                "description": "Control the use of removable media on system components.",
                "guidance": "Implement controls to limit and monitor the use of removable media on organizational systems.",
                "assessment_objectives": "[a] removable media control procedures are defined;\n[b] use of removable media is controlled;\n[c] removable media usage is monitored; and\n[d] unauthorized removable media use is prevented."
            },
            {
                "requirement_id": "MP.L2-3.8.8", "title": "Shared Media", "domain": "MP",
                "description": "Prohibit the use of portable storage devices when such devices have no identifiable owner.",
                "guidance": "Implement policies to prevent the use of unowned or unidentified portable storage devices.",
                "assessment_objectives": "[a] shared media procedures are defined;\n[b] use of unowned portable storage devices is prohibited;\n[c] device ownership is verified; and\n[d] policy compliance is monitored."
            },
            {
                "requirement_id": "MP.L2-3.8.9", "title": "Protect Backups", "domain": "MP",
                "description": "Protect the confidentiality of backup CUI at storage locations.",
                "guidance": "Implement appropriate security controls to protect backup media containing CUI at storage locations.",
                "assessment_objectives": "[a] backup protection procedures are defined;\n[b] backup CUI confidentiality is protected;\n[c] storage locations are secured; and\n[d] backup security is monitored."
            },
            # Personnel Security (PS) Requirements
            {
                "requirement_id": "PS.L2-3.9.1", "title": "Screen Individuals", "domain": "PS",
                "description": "Screen individuals prior to authorizing access to organizational systems containing CUI.",
                "guidance": "Conduct background checks and security screenings for personnel who will have access to systems containing CUI.",
                "assessment_objectives": "[a] individual screening procedures are defined;\n[b] individuals are screened prior to access authorization;\n[c] screening results are documented; and\n[d] access is granted based on screening results."
            },
            {
                "requirement_id": "PS.L2-3.9.2", "title": "Personnel Actions", "domain": "PS",
                "description": "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers.",
                "guidance": "Implement procedures to revoke access and protect systems when personnel leave or change roles.",
                "assessment_objectives": "[a] personnel action procedures are defined;\n[b] systems are protected during personnel actions;\n[c] access is revoked when appropriate;\n[d] systems remain protected after personnel actions; and\n[e] personnel action procedures are monitored."
            },
            # Physical Protection (PE) Requirements
            {
                "requirement_id": "PE.L2-3.10.1", "title": "Limit Physical Access [CUI Data]", "domain": "PE",
                "description": "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.",
                "guidance": "Use locks, card readers, or other physical controls to restrict access to offices, server rooms, and equipment. Maintain a list of personnel with authorized physical access.",
                "assessment_objectives": "[a] authorized individuals allowed physical access are identified;\n[b] physical access to organizational systems is limited to authorized individuals;\n[c] physical access to equipment is limited to authorized individuals; and\n[d] physical access to operating environments is limited to authorized individuals."
            },
            {
                "requirement_id": "PE.L2-3.10.2", "title": "Monitor Facility", "domain": "PE",
                "description": "Protect and monitor the physical facility and support infrastructure for organizational systems.",
                "guidance": "Implement physical security measures including surveillance, alarms, and environmental controls to protect facilities and infrastructure.",
                "assessment_objectives": "[a] facility protection procedures are defined;\n[b] physical facility is protected;\n[c] support infrastructure is protected;\n[d] monitoring systems are implemented; and\n[e] facility security is monitored."
            },
            {
                "requirement_id": "PE.L2-3.10.3", "title": "Escort Visitors [CUI Data]", "domain": "PE",
                "description": "Escort visitors and monitor visitor activity.",
                "guidance": "Ensure all visitors are escorted by an employee at all times within the facility and wear visitor identification.",
                "assessment_objectives": "[a] visitor escort procedures are defined;\n[b] visitors are escorted; and\n[c] visitor activity is monitored."
            },
            {
                "requirement_id": "PE.L2-3.10.4", "title": "Physical Access Logs [CUI Data]", "domain": "PE",
                "description": "Maintain audit logs of physical access.",
                "guidance": "Use a sign-in sheet or electronic system to log all individuals entering and leaving the facility. Retain these logs for a defined period.",
                "assessment_objectives": "[a] physical access logging procedures are defined;\n[b] audit logs of physical access are maintained; and\n[c] access logs are retained according to policy."
            },
            {
                "requirement_id": "PE.L2-3.10.5", "title": "Manage Physical Access [CUI Data]", "domain": "PE",
                "description": "Control and manage physical access devices.",
                "guidance": "Keep an inventory of all physical access devices like keys and key cards. Know who has them, and revoke access when personnel leave or change roles.",
                "assessment_objectives": "[a] physical access device management procedures are defined;\n[b] physical access devices are identified;\n[c] physical access devices are controlled; and\n[d] physical access devices are managed."
            },
            {
                "requirement_id": "PE.L2-3.10.6", "title": "Alternative Work Sites", "domain": "PE",
                "description": "Enforce safeguarding measures for CUI at alternate work sites.",
                "guidance": "Implement security measures to protect CUI at remote work locations and alternative work sites.",
                "assessment_objectives": "[a] alternative work site procedures are defined;\n[b] safeguarding measures are enforced at alternate work sites;\n[c] CUI is protected at alternate work sites; and\n[d] alternative work site security is monitored."
            },
            # Risk Assessment (RA) Requirements
            {
                "requirement_id": "RA.L2-3.11.1", "title": "Risk Assessments", "domain": "RA",
                "description": "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI.",
                "guidance": "Conduct regular risk assessments to identify and evaluate risks to organizational operations, assets, and individuals from system operations and CUI handling.",
                "assessment_objectives": "[a] risk assessment procedures are defined;\n[b] risk assessments are conducted periodically;\n[c] risks to organizational operations are assessed;\n[d] risks to organizational assets are assessed;\n[e] risks to individuals are assessed; and\n[f] risk assessment results are documented."
            },
            {
                "requirement_id": "RA.L2-3.11.2", "title": "Vulnerability Scan", "domain": "RA",
                "description": "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.",
                "guidance": "Implement regular vulnerability scanning of systems and applications, and conduct additional scans when new vulnerabilities are discovered.",
                "assessment_objectives": "[a] vulnerability scanning procedures are defined;\n[b] systems are scanned for vulnerabilities periodically;\n[c] applications are scanned for vulnerabilities periodically;\n[d] additional scans are conducted when new vulnerabilities are identified; and\n[e] vulnerability scan results are documented."
            },
            {
                "requirement_id": "RA.L2-3.11.3", "title": "Vulnerability Remediation", "domain": "RA",
                "description": "Remediate vulnerabilities in accordance with risk assessments.",
                "guidance": "Implement a process to prioritize and remediate vulnerabilities based on risk assessment results and organizational priorities.",
                "assessment_objectives": "[a] vulnerability remediation procedures are defined;\n[b] vulnerabilities are prioritized based on risk assessments;\n[c] vulnerabilities are remediated according to risk; and\n[d] remediation activities are tracked and documented."
            },
            # Security Assessment (CA) Requirements
            {
                "requirement_id": "CA.L2-3.12.1", "title": "Security Control Assessment", "domain": "CA",
                "description": "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.",
                "guidance": "Conduct regular assessments of security controls to ensure they are functioning effectively and meeting security requirements.",
                "assessment_objectives": "[a] security control assessment procedures are defined;\n[b] security controls are assessed periodically;\n[c] control effectiveness is evaluated;\n[d] assessment results are documented; and\n[e] control improvements are implemented as needed."
            },
            {
                "requirement_id": "CA.L2-3.12.2", "title": "Operational Plan of Action", "domain": "CA",
                "description": "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.",
                "guidance": "Create and execute remediation plans to address security deficiencies and vulnerabilities identified during assessments.",
                "assessment_objectives": "[a] plan of action procedures are defined;\n[b] plans of action are developed for deficiencies;\n[c] plans of action are developed for vulnerabilities;\n[d] plans of action are implemented; and\n[e] plan effectiveness is monitored."
            },
            {
                "requirement_id": "CA.L2-3.12.3", "title": "Security Control Monitoring", "domain": "CA",
                "description": "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.",
                "guidance": "Implement continuous monitoring of security controls to ensure they remain effective over time.",
                "assessment_objectives": "[a] security control monitoring procedures are defined;\n[b] security controls are monitored on an ongoing basis;\n[c] control effectiveness is continuously evaluated;\n[d] monitoring results are documented; and\n[e] control adjustments are made as needed."
            },
            {
                "requirement_id": "CA.L2-3.12.4", "title": "System Security Plan", "domain": "CA",
                "description": "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.",
                "guidance": "Create comprehensive system security plans that document all aspects of system security implementation and operation.",
                "assessment_objectives": "[a] system security plan procedures are defined;\n[b] system security plans are developed;\n[c] system boundaries are documented;\n[d] system environments of operation are documented;\n[e] security requirement implementation is documented;\n[f] system relationships and connections are documented; and\n[g] plans are updated periodically."
            },
            # System and Communications Protection (SC) Requirements
            {
                "requirement_id": "SC.L2-3.13.1", "title": "Boundary Protection [CUI Data]", "domain": "SC",
                "description": "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.",
                "guidance": "Use firewalls to protect the boundary between your internal network and the internet, blocking unwanted traffic and malicious websites.",
                "assessment_objectives": "[a] the external system boundary is defined;\n[b] key internal system boundaries are defined;\n[c] communications are monitored at the external system boundary;\n[d] communications are monitored at key internal boundaries;\n[e] communications are controlled at the external system boundary;\n[f] communications are controlled at key internal boundaries;\n[g] communications are protected at the external system boundary; and\n[h] communications are protected at key internal boundaries."
            },
            {
                "requirement_id": "SC.L2-3.13.2", "title": "Security Engineering", "domain": "SC",
                "description": "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.",
                "guidance": "Implement security-by-design principles throughout the system development lifecycle to build security into systems from the ground up.",
                "assessment_objectives": "[a] security engineering procedures are defined;\n[b] architectural designs promote security;\n[c] software development techniques promote security;\n[d] systems engineering principles promote security; and\n[e] security engineering effectiveness is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.3", "title": "Role Separation", "domain": "SC",
                "description": "Separate user functionality from system management functionality.",
                "guidance": "Implement role separation to prevent users from accessing system management functions and vice versa.",
                "assessment_objectives": "[a] role separation procedures are defined;\n[b] user functionality is separated from system management functionality;\n[c] role separation is enforced; and\n[d] role separation effectiveness is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.4", "title": "Shared Resource Control", "domain": "SC",
                "description": "Prevent unauthorized and unintended information transfer via shared system resources.",
                "guidance": "Implement controls to prevent information leakage through shared system resources like memory, storage, and network interfaces.",
                "assessment_objectives": "[a] shared resource control procedures are defined;\n[b] unauthorized information transfer is prevented;\n[c] unintended information transfer is prevented;\n[d] shared resource access is controlled; and\n[e] shared resource security is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.5", "title": "Public-Access System Separation [CUI Data]", "domain": "SC",
                "description": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
                "guidance": "Isolate publicly accessible systems (like a public website) from your internal network using a demilitarized zone (DMZ) or separate VLAN.",
                "assessment_objectives": "[a] public-access system separation procedures are defined;\n[b] publicly accessible system components are identified; and\n[c] subnetworks for publicly accessible system components are physically or logically separated from internal networks."
            },
            {
                "requirement_id": "SC.L2-3.13.6", "title": "Network Communication by Exception", "domain": "SC",
                "description": "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).",
                "guidance": "Implement default-deny network policies that only allow explicitly authorized network communications.",
                "assessment_objectives": "[a] network communication procedures are defined;\n[b] network communications traffic is denied by default;\n[c] network communications traffic is allowed by exception; and\n[d] network communication policies are enforced."
            },
            {
                "requirement_id": "SC.L2-3.13.7", "title": "Split Tunneling", "domain": "SC",
                "description": "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).",
                "guidance": "Configure VPN and remote access systems to prevent split tunneling that could bypass security controls.",
                "assessment_objectives": "[a] split tunneling prevention procedures are defined;\n[b] split tunneling is prevented;\n[c] remote device connections are controlled; and\n[d] split tunneling prevention is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.8", "title": "Data in Transit", "domain": "SC",
                "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.",
                "guidance": "Use encryption to protect CUI during transmission over networks, or implement alternative physical safeguards.",
                "assessment_objectives": "[a] data in transit protection procedures are defined;\n[b] cryptographic mechanisms are implemented;\n[c] CUI is protected during transmission;\n[d] alternative physical safeguards are used when appropriate; and\n[e] data in transit protection is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.9", "title": "Connections Termination", "domain": "SC",
                "description": "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.",
                "guidance": "Implement automatic termination of network connections when sessions end or after periods of inactivity.",
                "assessment_objectives": "[a] connection termination procedures are defined;\n[b] network connections are terminated at the end of sessions;\n[c] network connections are terminated after periods of inactivity; and\n[d] connection termination is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.10", "title": "Key Management", "domain": "SC",
                "description": "Establish and manage cryptographic keys for cryptography employed in organizational systems.",
                "guidance": "Implement proper key management practices including key generation, distribution, storage, rotation, and destruction.",
                "assessment_objectives": "[a] key management procedures are defined;\n[b] cryptographic keys are established;\n[c] cryptographic keys are managed;\n[d] key lifecycle is properly handled; and\n[e] key management security is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.11", "title": "CUI Encryption", "domain": "SC",
                "description": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
                "guidance": "Use only FIPS-validated cryptographic algorithms and implementations when protecting CUI.",
                "assessment_objectives": "[a] CUI encryption procedures are defined;\n[b] FIPS-validated cryptography is employed;\n[c] CUI confidentiality is protected; and\n[d] cryptographic compliance is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.12", "title": "Collaborative Device Control", "domain": "SC",
                "description": "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.",
                "guidance": "Implement controls to prevent unauthorized remote activation of collaborative devices and provide clear indicators when devices are in use.",
                "assessment_objectives": "[a] collaborative device control procedures are defined;\n[b] remote activation of collaborative devices is prohibited;\n[c] device usage indicators are provided; and\n[d] collaborative device security is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.13", "title": "Mobile Code", "domain": "SC",
                "description": "Control and monitor the use of mobile code.",
                "guidance": "Implement controls to restrict and monitor the execution of mobile code like JavaScript, Java applets, and ActiveX controls.",
                "assessment_objectives": "[a] mobile code control procedures are defined;\n[b] mobile code use is controlled;\n[c] mobile code use is monitored; and\n[d] mobile code security is enforced."
            },
            {
                "requirement_id": "SC.L2-3.13.14", "title": "Voice over Internet Protocol", "domain": "SC",
                "description": "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.",
                "guidance": "Implement security controls for VoIP systems to prevent unauthorized access and monitor usage.",
                "assessment_objectives": "[a] VoIP control procedures are defined;\n[b] VoIP use is controlled;\n[c] VoIP use is monitored; and\n[d] VoIP security is enforced."
            },
            {
                "requirement_id": "SC.L2-3.13.15", "title": "Communications Authenticity", "domain": "SC",
                "description": "Protect the authenticity of communications sessions.",
                "guidance": "Implement mechanisms to verify the authenticity of communications sessions and prevent session hijacking.",
                "assessment_objectives": "[a] communications authenticity procedures are defined;\n[b] communications session authenticity is protected;\n[c] session hijacking is prevented; and\n[d] communications authenticity is monitored."
            },
            {
                "requirement_id": "SC.L2-3.13.16", "title": "Data at Rest", "domain": "SC",
                "description": "Protect the confidentiality of CUI at rest.",
                "guidance": "Use encryption to protect CUI stored on systems and storage devices.",
                "assessment_objectives": "[a] data at rest protection procedures are defined;\n[b] CUI confidentiality is protected at rest;\n[c] encryption is used for data at rest; and\n[d] data at rest protection is monitored."
            },
            # System and Information Integrity (SI) Requirements
            {
                "requirement_id": "SI.L2-3.14.1", "title": "Flaw Remediation [CUI Data]", "domain": "SI",
                "description": "Identify, report, and correct system flaws in a timely manner.",
                "guidance": "Implement a patch management process to fix software and firmware flaws within a defined timeframe based on vendor notifications.",
                "assessment_objectives": "[a] flaw remediation procedures are defined;\n[b] system flaws are identified;\n[c] system flaws are reported;\n[d] system flaws are corrected in a timely manner; and\n[e] flaw remediation is monitored."
            },
            {
                "requirement_id": "SI.L2-3.14.2", "title": "Malicious Code Protection [CUI Data]", "domain": "SI",
                "description": "Provide protection from malicious code at designated locations within organizational systems.",
                "guidance": "Use anti-virus and anti-malware software on workstations, servers, and firewalls to protect against malicious code like viruses and ransomware.",
                "assessment_objectives": "[a] malicious code protection procedures are defined;\n[b] designated locations for malicious code protection are identified; and\n[c] protection from malicious code at designated locations is provided."
            },
            {
                "requirement_id": "SI.L2-3.14.3", "title": "Security Alerts & Advisories", "domain": "SI",
                "description": "Monitor system security alerts and advisories and take action in response.",
                "guidance": "Subscribe to security alert services and implement processes to respond to security advisories and alerts.",
                "assessment_objectives": "[a] security alert monitoring procedures are defined;\n[b] system security alerts are monitored;\n[c] security advisories are monitored;\n[d] action is taken in response to alerts and advisories; and\n[e] response effectiveness is monitored."
            },
            {
                "requirement_id": "SI.L2-3.14.4", "title": "Update Malicious Code Protection [CUI Data]", "domain": "SI",
                "description": "Update malicious code protection mechanisms when new releases are available.",
                "guidance": "Configure anti-malware software to update its definition files automatically and frequently (e.g., daily) to protect against the latest threats.",
                "assessment_objectives": "[a] malicious code protection update procedures are defined;\n[b] malicious code protection mechanisms are updated when new releases are available; and\n[c] update effectiveness is monitored."
            },
            {
                "requirement_id": "SI.L2-3.14.5", "title": "System & File Scanning [CUI Data]", "domain": "SI",
                "description": "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.",
                "guidance": "Configure anti-malware software to perform periodic full-system scans and real-time scans of files from external sources like email attachments and USB drives.",
                "assessment_objectives": "[a] scanning procedures are defined;\n[b] periodic scans of organizational systems are performed;\n[c] real-time scans of files from external sources are performed; and\n[d] scanning effectiveness is monitored."
            },
            {
                "requirement_id": "SI.L2-3.14.6", "title": "Monitor Communications for Attacks", "domain": "SI",
                "description": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
                "guidance": "Implement network monitoring and intrusion detection systems to identify malicious activity and potential security threats.",
                "assessment_objectives": "[a] communications monitoring procedures are defined;\n[b] organizational systems are monitored;\n[c] inbound communications traffic is monitored;\n[d] outbound communications traffic is monitored;\n[e] attacks are detected; and\n[f] indicators of potential attacks are detected."
            },
            {
                "requirement_id": "SI.L2-3.14.7", "title": "Identify Unauthorized Use", "domain": "SI",
                "description": "Identify unauthorized use of organizational systems.",
                "guidance": "Implement monitoring and detection systems to identify unauthorized access and use of organizational systems.",
                "assessment_objectives": "[a] unauthorized use identification procedures are defined;\n[b] unauthorized use of organizational systems is identified;\n[c] unauthorized access is detected; and\n[d] unauthorized use monitoring is effective."
            }
        ]

        level2 = CMMCLevel.query.filter_by(level_number=2).first()

        for req_data in level_2_requirements:
            domain = CMMCDomain.query.filter_by(code=req_data['domain']).first()
            
            if domain:
                requirement = CMMCRequirement(
                    requirement_id=req_data['requirement_id'],
                    title=req_data['title'],
                    description=req_data['description'],
                    level_id=level2.id,
                    domain_id=domain.id,
                    guidance=req_data['guidance'],
                    assessment_objectives=req_data['assessment_objectives']
                )
                db.session.add(requirement)

    # Add CMMC Level 3 Requirements (Basic set for demonstration)
    if not CMMCRequirement.query.filter_by(level_id=CMMCLevel.query.filter_by(level_number=3).first().id).first():
        level_3_requirements = [
            # Access Control (AC) Requirements
            {
                "requirement_id": "AC.L3-3.1.1", "title": "Advanced Access Control [CUI Data]", "domain": "AC",
                "description": "Implement advanced access control mechanisms for CUI data with enhanced security controls.",
                "guidance": "Deploy advanced identity and access management solutions with role-based access control, privileged access management, and continuous monitoring.",
                "assessment_objectives": "[a] advanced access control mechanisms are implemented;\n[b] CUI data access is controlled with enhanced security;\n[c] access control effectiveness is continuously monitored; and\n[d] access control policies are enforced."
            },
            {
                "requirement_id": "AC.L3-3.1.2", "title": "Advanced Session Management", "domain": "AC",
                "description": "Implement advanced session management with enhanced security controls and monitoring.",
                "guidance": "Deploy advanced session management solutions with real-time monitoring, anomaly detection, and automated response capabilities.",
                "assessment_objectives": "[a] advanced session management is implemented;\n[b] session security controls are enhanced;\n[c] session monitoring is continuous; and\n[d] session management effectiveness is verified."
            },
            # Audit and Accountability (AU) Requirements
            {
                "requirement_id": "AU.L3-3.3.1", "title": "Advanced Audit Logging", "domain": "AU",
                "description": "Implement advanced audit logging with comprehensive coverage and real-time analysis.",
                "guidance": "Deploy advanced SIEM solutions with real-time log analysis, correlation, and automated response capabilities.",
                "assessment_objectives": "[a] advanced audit logging is implemented;\n[b] comprehensive audit coverage is provided;\n[c] real-time log analysis is performed; and\n[d] audit logging effectiveness is monitored."
            },
            # Configuration Management (CM) Requirements
            {
                "requirement_id": "CM.L3-3.4.1", "title": "Advanced Configuration Management", "domain": "CM",
                "description": "Implement advanced configuration management with automated compliance monitoring.",
                "guidance": "Deploy advanced configuration management tools with automated compliance checking, drift detection, and remediation capabilities.",
                "assessment_objectives": "[a] advanced configuration management is implemented;\n[b] automated compliance monitoring is provided;\n[c] configuration drift is detected; and\n[d] configuration management effectiveness is verified."
            },
            # Identification and Authentication (IA) Requirements
            {
                "requirement_id": "IA.L3-3.5.1", "title": "Advanced Authentication", "domain": "IA",
                "description": "Implement advanced authentication mechanisms with enhanced security controls.",
                "guidance": "Deploy advanced authentication solutions including biometric authentication, hardware tokens, and adaptive authentication.",
                "assessment_objectives": "[a] advanced authentication mechanisms are implemented;\n[b] enhanced security controls are deployed;\n[c] authentication effectiveness is monitored; and\n[d] authentication security is continuously improved."
            },
            # System and Communications Protection (SC) Requirements
            {
                "requirement_id": "SC.L3-3.13.1", "title": "Advanced Network Protection", "domain": "SC",
                "description": "Implement advanced network protection with comprehensive security controls.",
                "guidance": "Deploy advanced network security solutions including next-generation firewalls, intrusion prevention systems, and network segmentation.",
                "assessment_objectives": "[a] advanced network protection is implemented;\n[b] comprehensive security controls are deployed;\n[c] network security is continuously monitored; and\n[d] network protection effectiveness is verified."
            },
            # System and Information Integrity (SI) Requirements
            {
                "requirement_id": "SI.L3-3.14.1", "title": "Advanced Threat Protection", "domain": "SI",
                "description": "Implement advanced threat protection with comprehensive security monitoring.",
                "guidance": "Deploy advanced threat protection solutions including endpoint detection and response, security orchestration, and automated response capabilities.",
                "assessment_objectives": "[a] advanced threat protection is implemented;\n[b] comprehensive security monitoring is provided;\n[c] threat detection is automated; and\n[d] threat protection effectiveness is continuously improved."
            }
        ]

        level3 = CMMCLevel.query.filter_by(level_number=3).first()

        for req_data in level_3_requirements:
            domain = CMMCDomain.query.filter_by(code=req_data['domain']).first()
            
            if domain:
                requirement = CMMCRequirement(
                    requirement_id=req_data['requirement_id'],
                    title=req_data['title'],
                    description=req_data['description'],
                    level_id=level3.id,
                    domain_id=domain.id,
                    guidance=req_data['guidance'],
                    assessment_objectives=req_data['assessment_objectives']
                )
                db.session.add(requirement)

    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_database()
    app.run(debug=True)
