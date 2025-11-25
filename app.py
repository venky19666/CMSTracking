import hashlib
import json
import os
import re
import secrets
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, flash, jsonify, make_response, redirect,
                   render_template, request, send_file, session, url_for)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
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

SECURITY_QUESTIONS = [
    {'id': 'first_pet', 'text': 'What is the name of your first pet?'},
    {'id': 'birth_city', 'text': 'In what city were you born?'},
    {'id': 'favorite_teacher', 'text': 'What is the name of your favorite teacher?'},
    {'id': 'childhood_nickname', 'text': 'What was your childhood nickname?'},
    {'id': 'favorite_book', 'text': 'What is your favorite book?'},
    {'id': 'favorite_food', 'text': 'What is your favorite food?'},
    {'id': 'dream_job', 'text': 'What was your dream job as a child?'},
    {'id': 'first_school', 'text': 'What is the name of your first school?'}
]

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
    security_profile = db.relationship('UserSecurity', backref='user', uselist=False)

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
    examples = db.Column(db.Text)  # Store examples for this requirement
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
    completed_objectives = db.Column(db.Text)  # JSON array of completed objective letters (e.g., '["a", "b", "c"]')
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='compliance_records')
    requirement = db.relationship('CMMCRequirement', backref='compliance_records')
    
    def get_completed_objectives(self):
        """Return list of completed objective letters."""
        if self.completed_objectives:
            try:
                return json.loads(self.completed_objectives)
            except:
                return []
        return []
    
    def set_completed_objectives(self, objectives_list):
        """Set completed objectives as JSON string."""
        self.completed_objectives = json.dumps(objectives_list) if objectives_list else None

# New Models for objectives (processes and devices)
class UserSecurity(db.Model):
    __tablename__ = 'user_security'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    question_key = db.Column(db.String(50), nullable=False)
    answer_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def verify_answer(self, candidate: str) -> bool:
        candidate_normalized = (candidate or '').strip().lower()
        return check_password_hash(self.answer_hash, candidate_normalized)


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


EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')


def validate_password_strength(password: str) -> bool:
    """
    Password must be at least 8 chars, include letters, numbers, and special characters.
    """
    if not password or len(password) < 8:
        return False
    has_letter = re.search(r'[A-Za-z]', password)
    has_number = re.search(r'\d', password)
    has_special = re.search(r'[^A-Za-z0-9]', password)
    return all([has_letter, has_number, has_special])


def normalize_security_answer(answer: str) -> str:
    return (answer or '').strip().lower()


def is_valid_email(address: str) -> bool:
    return bool(address and EMAIL_PATTERN.match(address))

def parse_assessment_objectives(objectives_text):
    """Parse assessment objectives text and extract individual objectives.
    
    Returns a list of dictionaries with 'label' (a, b, c, etc.) and 'description' (text).
    """
    if not objectives_text:
        return []
    
    objectives = []
    # Pattern to match [a], [b], [c], etc. followed by text
    # Looks for [letter] followed by text until next [letter] or end of string
    # Split by lines and process each line that starts with [letter]
    lines = objectives_text.split('\n')
    current_obj = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Check if line starts with [letter]
        match = re.match(r'\[([a-z])\]\s*(.+)', line, re.IGNORECASE)
        if match:
            # Save previous objective if exists
            if current_obj:
                objectives.append(current_obj)
            # Start new objective
            label = match.group(1).lower()
            description = match.group(2).strip().rstrip(';').strip()
            # Remove "and" at the end if it's the last objective
            if description.endswith(' and'):
                description = description[:-4].strip()
            current_obj = {
                'label': label,
                'description': description
            }
        elif current_obj and line:
            # Continue current objective description (multi-line)
            line_clean = line.strip().rstrip(';').strip()
            if line_clean and not line_clean.startswith('['):
                if line_clean.endswith(' and'):
                    line_clean = line_clean[:-4].strip()
                current_obj['description'] += ' ' + line_clean
    
    # Add last objective
    if current_obj:
        objectives.append(current_obj)
    
    return objectives

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
        'index', 'login', 'register', 'logout', 'static', 'device_pending', 'forgot_password'
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
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        company = request.form['company'].strip()
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer', '')

        if len(username) < 4:
            flash('Username must be at least 4 characters long.', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        if not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        if User.query.filter_by(email=email).first():
            flash('Email address already exists.', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        if not validate_password_strength(password):
            flash('Password must be at least 8 characters and include letters, numbers, and special characters.', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        allowed_questions = {q['id'] for q in SECURITY_QUESTIONS}
        if security_question not in allowed_questions:
            flash('Please select a security question.', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        normalized_answer = normalize_security_answer(security_answer)
        if not normalized_answer:
            flash('Please provide an answer to the security question.', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            company=company
        )
        db.session.add(user)
        db.session.flush()
        security_profile = UserSecurity(
            user_id=user.id,
            question_key=security_question,
            answer_hash=generate_password_hash(normalized_answer)
        )
        db.session.add(security_profile)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', security_questions=SECURITY_QUESTIONS)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not identifier:
            flash('Please enter your username or email.', 'error')
            return render_template('forgot_password.html', security_questions=SECURITY_QUESTIONS)

        user = User.query.filter(or_(User.username == identifier, User.email == identifier)).first()
        if not user:
            flash('No account found with the provided username or email.', 'error')
            return render_template('forgot_password.html', security_questions=SECURITY_QUESTIONS)

        if not user.security_profile:
            flash('Security question is not configured for this account. Please contact an administrator.', 'error')
            return render_template('forgot_password.html', security_questions=SECURITY_QUESTIONS)

        if user.security_profile.question_key != security_question:
            flash('Security question does not match our records.', 'error')
            return render_template('forgot_password.html', security_questions=SECURITY_QUESTIONS)

        if not user.security_profile.verify_answer(security_answer):
            flash('Security answer is incorrect.', 'error')
            return render_template('forgot_password.html', security_questions=SECURITY_QUESTIONS)

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('forgot_password.html', security_questions=SECURITY_QUESTIONS)

        if not validate_password_strength(new_password):
            flash('Password must be at least 8 characters and include letters, numbers, and special characters.', 'error')
            return render_template('forgot_password.html', security_questions=SECURITY_QUESTIONS)

        user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        flash('Password reset successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html', security_questions=SECURITY_QUESTIONS)

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

    # Domains available for the selected level (for filter dropdown)
    domains_for_filter = domains
    if selected_level_id:
        domain_ids = {r.domain_id for r in CMMCRequirement.query.filter_by(level_id=selected_level_id).all()}
        domains_for_filter = [d for d in domains if d.id in domain_ids]

    # Get user's compliance records - only for filtered requirements
    user_records = {}
    filtered_requirement_ids = [r.id for r in requirements] if requirements else []
    if filtered_requirement_ids:
        for record in ComplianceRecord.query.filter_by(user_id=session['user_id']).filter(ComplianceRecord.requirement_id.in_(filtered_requirement_ids)).all():
            user_records[record.requirement_id] = record

    # Calculate progress summary for filtered requirements only
    progress_summary = {
        'total': len(requirements),
        'compliant': sum(1 for r in user_records.values() if r.status == 'compliant'),
        'in_progress': sum(1 for r in user_records.values() if r.status == 'in_progress'),
        'non_compliant': sum(1 for r in user_records.values() if r.status == 'non_compliant'),
        'not_started': len(requirements) - len(user_records)
    }

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
        domains=domains_for_filter,
        user_records=user_records,
        selected_level_id=selected_level_id,
        is_grouped_mode=is_grouped_mode,
        grouped_by_domain=grouped_by_domain,
        level_total=level_total,
        current_level=current_level,
        progress_summary=progress_summary
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
    # Compute a safe next URL for returning after POST
    default_next = url_for('requirements', level=requirement.level_id)
    ref = request.referrer or ''
    next_url = default_next
    try:
        # Prefer referrer if it points to requirements view
        # Parse the referrer to check if it's a requirements page
        if ref and '/requirements' in ref:
            # Use the full referrer URL to preserve query parameters (level, domain filters, etc.)
            parsed = urlparse(ref)
            # Only use referrer if it's from the same host (security check)
            if parsed.netloc == '' or parsed.netloc == request.host:
                next_url = ref
    except Exception:
        next_url = default_next
    
    if request.method == 'POST':
        status = request.form['status']
        notes = request.form['notes']
        delete_artifact = request.form.get('delete_artifact') == 'true'
        next_override = request.form.get('next')
        if next_override:
            next_url = next_override
        
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
            # Ensure database reference is also cleared
            artifact_path = None
            record.artifact_path = None
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

        # Handle objective completion
        completed_objectives = []
        if status == 'compliant':
            # If compliant, mark all objectives as completed
            objectives = parse_assessment_objectives(requirement.assessment_objectives)
            completed_objectives = [obj['label'] for obj in objectives]
        elif status == 'in_progress':
            # Get completed objectives from form checkboxes
            objective_keys = [key for key in request.form.keys() if key.startswith('objective_')]
            completed_objectives = [key.replace('objective_', '') for key in objective_keys if request.form.get(key) == 'on']

        if record:
            record.status = status
            record.notes = notes
            record.set_completed_objectives(completed_objectives)
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
            record.set_completed_objectives(completed_objectives)
            db.session.add(record)
        
        db.session.commit()
        flash('Compliance record updated successfully!', 'success')
        return redirect(next_url)
    
    # Parse objectives for display
    objectives = parse_assessment_objectives(requirement.assessment_objectives) if requirement.assessment_objectives else []
    completed_obj_labels = record.get_completed_objectives() if record else []
    
    return render_template('compliance_record.html', 
                         requirement=requirement, 
                         record=record, 
                         next_url=next_url,
                         objectives=objectives,
                         completed_objectives=completed_obj_labels)

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
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] authorized users are identified;\n[b] processes acting on behalf of authorized users are identified;\n[c] devices (and other systems) authorized to connect to the system are identified;\n[d] system access is limited to authorized users;\n[e] system access is limited to processes acting on behalf of authorized users; and\n[f] system access is limited to authorized devices (including other systems).",
                "examples": "Example 1\n\nYour company maintains a list of all personnel authorized to use company information systems [a]. This list is used to support identification and authentication activities conducted by IT when authorizing access to systems [a,d].\n\nExample 2\n\nA coworker wants to buy a new multi-function printer/scanner/fax device and make it available on the company network. You explain that the company controls system and device access to the network, and will prevent network access by unauthorized systems and devices [c]. You help the coworker submit a ticket that asks for the printer to be granted access to the network, and appropriate leadership approves the device [f]."
            },
            {
                "requirement_id": "AC.L1-3.1.2", "title": "Transaction & Function Control", "domain": "AC",
                "description": "Limit information system access to the types of transactions and functions that authorized users are permitted to execute.",
                "guidance": "Use role-based access control (RBAC) to ensure users can only perform functions necessary for their job roles (e.g., create, read, update, delete).",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] the types of transactions and functions that authorized users are permitted to execute are defined; and\n[b] system access is limited to the defined types of transactions and functions for authorized users.",
                "examples": "Example\n\nYou supervise the team that manages DoD contracts for your company. Members of your team need to access the contract information to perform their work properly. Because some of that data contains FCI, you work with IT to set up your group's systems so that users can be assigned access based on their specific roles [a]. Each role limits whether an employee has read-access or create/read/delete/update -access [b]. Implementing this access control restricts access to FCI information unless specifically authorized."
            },
            {
                "requirement_id": "AC.L1-3.1.20", "title": "External Connections", "domain": "AC",
                "description": "Verify and control/limit connections to and use of external information systems.",
                "guidance": "Use firewalls and connection policies to manage connections between your network and external ones. Control access from personally owned devices.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] connections to external systems are identified;\n[b] the use of external systems is identified;\n[c] connections to external systems are verified;\n[d] the use of external systems is verified;\n[e] connections to external systems are controlled/limited; and\n[f] the use of external systems is controlled/limited.",
                "examples": "Example\n\nYou and your coworkers are working on a big proposal and will put in extra hours over the weekend to get it done. Part of the proposal includes FCI. Because FCI should not be shared publicly, you remind your coworkers of the policy requirement to use their company laptops, not personal laptops or tablets, when working on the proposal over the weekend [b,f]. You also remind everyone to work from the cloud environment that is approved for processing and storing FCI rather than the other collaborative tools that may be used for other projects [b,f]."
            },
            {
                "requirement_id": "AC.L1-3.1.22", "title": "Control Public Information", "domain": "AC",
                "description": "Control information posted or processed on publicly accessible information systems.",
                "guidance": "Establish a review process to prevent Federal Contract Information (FCI) from being posted on public systems like company websites or forums.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] individuals authorized to post or process information on publicly accessible systems are identified;\n[b] procedures to ensure FCI is not posted or processed on publicly accessible systems are identified;\n[c] a review process is in place prior to posting of any content to publicly accessible systems;\n[d] content on publicly accessible systems is reviewed to ensure that it does not include FCI; and\n[e] mechanisms are in place to remove and address improper posting of FCI.",
                "examples": "Example\n\nYour company decides to start issuing press releases about its projects in an effort to reach more potential customers. Your company receives FCI from the government as part of its DoD contract. Because you recognize the need to manage controlled information, including FCI, you meet with the employees who write the releases and post information to establish a review process [c]. It is decided that you will review press releases for FCI before posting it on the company website [a,d]. Only certain employees will be authorized to post to the website [a]."
            },
            {
                "requirement_id": "IA.L1-3.5.1", "title": "Identification", "domain": "IA",
                "description": "Identify information system users, processes acting on behalf of users, or devices.",
                "guidance": "Assign unique identifiers (e.g., usernames) to all users, processes, and devices that require access to company systems.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] system users are identified;\n[b] processes acting on behalf of users are identified; and\n[c] devices accessing the system are identified.",
                "examples": "Example\n\nYou want to make sure that all employees working on a project can access important information about it. Because this is work for the DoD and may contain FCI, you also need to prevent employees who are not working on that project from being able to access the information. You assign each employee is assigned a unique user ID, which they use to log into the system [a]."
            },
            {
                "requirement_id": "IA.L1-3.5.2", "title": "Authentication", "domain": "IA",
                "description": "Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems.",
                "guidance": "Verify identity before granting access, typically with a username and strong password. Always change default passwords on new devices and systems.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] the identity of each user is authenticated or verified as a prerequisite to system access;\n[b] the identity of each process acting on behalf of a user is authenticated or verified as a prerequisite to system access; and\n[c] the identity of each device accessing or connecting to the system is authenticated or verified as a prerequisite to system access.",
                "examples": "Example 1\n\nYou are in charge of purchasing. You know that some laptops come with a default username and password. You notify IT that all default passwords should be reset prior to laptop use [a]. You ask IT to explain the importance of resetting default passwords and convey how easily they are discovered using internet searches during next week's cybersecurity awareness training.\n\nExample 2\n\nYour company decides to use cloud services for email and other capabilities. Upon reviewing this practice, you realize every user or device that connects to the cloud service must be authenticated. As a result, you work with your cloud service provider to ensure that only properly authenticated users and devices are allowed to connect to the system [a,c]."
            },
            {
                "requirement_id": "MP.L1-3.8.3", "title": "Media Disposal", "domain": "MP",
                "description": "Sanitize or destroy information system media containing Federal Contract Information before disposal or release for reuse.",
                "guidance": "For any media containing FCI (e.g., paper, USB drives, hard drives), either physically destroy it or use a secure sanitization process to erase the data before disposal or reuse.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a]system media containing FCI is sanitized or destroyed before disposal; and\n[b]system media containing FCI is sanitized before it is released for reuse.",
                "examples": "Example\n\nAs you pack for an office move, you find some old CDs in a file cabinet. You determine that one has information about an old project your company did for the DoD. You shred the CD rather than simply throwing it in the trash [a]."
            },
            {
                "requirement_id": "PE.L1-3.10.1", "title": "Limit Physical Access", "domain": "PE",
                "description": "Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals.",
                "guidance": "Use locks, card readers, or other physical controls to restrict access to offices, server rooms, and equipment. Maintain a list of personnel with authorized physical access.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] authorized individuals allowed physical access are identified;\n[b] physical access to organizational systems is limited to authorized individuals;\n[c] physical access to equipment is limited to authorized individuals; and\n[d] physical access to operating environments is limited to authorized individuals.",
                "examples": "Example\n\nYou manage a DoD project that requires special equipment used only by project team members [b,c]. You work with the facilities manager to put locks on the doors to the areas where the equipment is stored and used [b,c,d]. Project team members are the only individuals issued with keys to the space. This restricts access to only those employees who work on the DoD project and require access to that equipment."
            },
            {
                "requirement_id": "PE.L1-3.10.3", "title": "Escort Visitors", "domain": "PE",
                "description": "Escort visitors and monitor visitor activity.",
                "guidance": "Ensure all visitors are escorted by an employee at all times within the facility and wear visitor identification.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] visitors are escorted; and\n[b] visitor activity is monitored.",
                "examples": "Example\n\nComing back from a meeting, you see the friend of a coworker walking down the hallway near your office. You know this person well and trust them, but are not sure why they are in the building. You stop to talk, and the person explains that they are meeting a coworker for lunch, but cannot remember where the lunchroom is. You walk the person back to the reception area to get a visitor badge and wait until someone can escort them to the lunch room [a]. You report this incident, and the company decides to install a badge reader at the main door so visitors cannot enter without an escort [a]."
            },
            {
                "requirement_id": "PE.L1-3.10.4", "title": "Physical Access Logs", "domain": "PE",
                "description": "Maintain audit logs of physical access.",
                "guidance": "Use a sign-in sheet or electronic system to log all individuals entering and leaving the facility. Retain these logs for a defined period.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] audit logs of physical access are maintained.",
                "examples": "Example\n\nYou and your coworkers like to have friends and family join you for lunch at the office on Fridays. Your small company has just signed a contract with the DoD, however, and you now need to document who enters and leaves your facility. You work with the reception staff to ensure that all non-employees sign in at the reception area and sign out when they leave [a]. You retain those paper sign-in sheets in a locked filing cabinet for one year. Employees receive badges or key cards that enable tracking and logging access to company facilities."
            },
            {
                "requirement_id": "PE.L1-3.10.5", "title": "Manage Physical Access", "domain": "PE",
                "description": "Control and manage physical access devices.",
                "guidance": "Keep an inventory of all physical access devices like keys and key cards. Know who has them, and revoke access when personnel leave or change roles.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] physical access devices are identified;\n[b] physical access devices are controlled; and\n[c] physical access devices are managed.",
                "examples": "Example\n\nYou are a facility manager. A team member retired today and returns their company keys to you. The project on which they were working requires access to areas that contain equipment with FCI. You receive the keys, check your electronic records against the serial numbers on the keys to ensure all have been returned, and mark each key returned [c]."
            },
            {
                "requirement_id": "SC.L1-3.13.1", "title": "Boundary Protection", "domain": "SC",
                "description": "Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems) at the external boundaries and key internal boundaries of the information systems.",
                "guidance": "Use firewalls to protect the boundary between your internal network and the internet, blocking unwanted traffic and malicious websites.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] the external system boundary is defined;\n[b] key internal system boundaries are defined;\n[c] communications are monitored at the external system boundary;\n[d] communications are monitored at key internal boundaries;\n[e] communications are controlled at the external system boundary;\n[f] communications are controlled at key internal boundaries;\n[g] communications are protected at the external system boundary; and\n[h] communications are protected at key internal boundaries.",
                "examples": "Example\n\nYou are setting up the new network and want to keep your company's information and resources safe. You start by sketching out a simple diagram that identifies the external boundary of your network and any internal boundaries that are needed [a,b]. The first piece of equipment you install is the firewall, a device to separate your internal network from the internet. The firewall also has a feature that allows you to block access to potentially malicious websites, and you configure that service as well [a,c,e,g]. Some of your coworkers complain that they cannot get onto certain websites [c,e,g]. You explain that the new network blocks websites that are known for spreading malware. The firewall sends you a daily digest of blocked activity so that you can monitor the system for attack trends [c,d]."
            },
            {
                "requirement_id": "SC.L1-3.13.5", "title": "Public-Access System Separation", "domain": "SC",
                "description": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
                "guidance": "Isolate publicly accessible systems (like a public website) from your internal network using a demilitarized zone (DMZ) or separate VLAN.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] publicly accessible system components are identified; and\n[b] subnetworks for publicly accessible system components are physically or logically separated from internal networks.",
                "examples": "Example\n\nThe head of recruiting at your firm wants to launch a website to post job openings and allow the public to download an application form [a]. After some discussion, your team realizes it needs to use a firewall to create a perimeter network to do this [b]. You host the server separately from the company's internal network and make sure the network on which it resides is isolated with the proper firewall rules [b]."
            },
            {
                "requirement_id": "SI.L1-3.14.1", "title": "Flaw Remediation", "domain": "SI",
                "description": "Identify, report, and correct information and information system flaws in a timely manner.",
                "guidance": "Implement a patch management process to fix software and firmware flaws within a defined timeframe based on vendor notifications.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] the time within which to identify system flaws is specified;\n[b] system flaws are identified within the specified time frame;\n[c] the time within which to report system flaws is specified;\n[d] system flaws are reported within the specified time frame;\n[e] the time within which to correct system flaws is specified; and\n[f] system flaws are corrected within the specified time frame.",
                "examples": "Example\n\nYou know that software vendors typically release patches, service packs, hot fixes, etc. and want to make sure your software is up to date. You develop a policy that requires checking vendor websites for flaw notifications every week [a]. The policy further requires that those flaws be assessed for severity and patched on end-user computers once each week and servers once each month [c,e]. Consistent with that policy, you configure the system to check for updates weekly or daily depending on the criticality of the software [b,e]. Your team reviews available updates and implements the applicable ones according to the defined schedule [f]."
            },
            {
                "requirement_id": "SI.L1-3.14.2", "title": "Malicious Code Protection", "domain": "SI",
                "description": "Provide protection from malicious code at appropriate locations within organizational information systems.",
                "guidance": "Use anti-virus and anti-malware software on workstations, servers, and firewalls to protect against malicious code like viruses and ransomware.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] designated locations for malicious code protection are identified; and\n[b] protection from malicious code at designated locations is provided.",
                "examples": "Example\n\nYou are buying a new computer and want to protect your company's information from viruses and spyware. You buy and install anti-malware software [a,b]."
            },
            {
                "requirement_id": "SI.L1-3.14.4", "title": "Update Malicious Code Protection", "domain": "SI",
                "description": "Update malicious code protection mechanisms when new releases are available.",
                "guidance": "Configure anti-malware software to update its definition files automatically and frequently (e.g., daily) to protect against the latest threats.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] malicious code protection mechanisms are updated when new releases are available.",
                "examples": "Example\n\nYou have installed anti-malware software to protect a computer from malicious code. Knowing that malware evolves rapidly, you configure the software to automatically check for malware definition updates every day and update as needed [a]."
            },
            {
                "requirement_id": "SI.L1-3.14.5", "title": "System & File Scanning", "domain": "SI",
                "description": "Perform periodic scans of the information system and real-time scans of files from external sources as files are downloaded, opened, or executed.",
                "guidance": "Configure anti-malware software to perform periodic full-system scans and real-time scans of files from external sources like email attachments and USB drives.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-171A]\n\nDetermine if:\n\n[a] the frequency for malicious code scans is defined;\n[b] malicious code scans are performed with the defined frequency; and\n[c] real-time malicious code scans of files from external sources as files are downloaded, opened, or executed are performed.",
                "examples": "Example\n\nYou work with your company's email provider to enable enhanced protections that will scan all attachments to identify and quarantine those that may be harmful prior to a user opening them [c]. In addition, you configure antivirus software on each computer and to scan for malicious code every day [a,b]. The software also scans files that are downloaded or copied from removable media such as USB drives. It quarantines any suspicious files and notifies the security team [c]."
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
                    assessment_objectives=req_data['assessment_objectives'],
                    examples=req_data.get('examples', '')
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
                "assessment_objectives": "[a] authorized users are identified;\n[b] processes acting on behalf of authorized users are identified;\n[c] devices (and other systems) authorized to connect to the system are identified;\n[d] system access is limited to authorized users;\n[e] system access is limited to processes acting on behalf of authorized users; and\n[f] system access is limited to authorized devices (including other systems).",
                "examples": "Example 1\nYour company maintains a list of all personnel authorized to use company information systems, including those that store, process, and transmit CUI [a]. This list is used to support identification and authentication activities conducted by IT when authorizing access to systems [a,d].\n\nExample 2\nA coworker wants to buy a new multi-function printer/scanner/fax device and make it available on the company network within the CUI enclave. You explain that the company controls system and device access to the network and will prevent network access by unauthorized systems and devices [c]. You help the coworker submit a ticket that asks for the printer to be granted access to the network, and appropriate leadership approves the device [f]."
            },
            {
                "requirement_id": "AC.L2-3.1.2", "title": "Transaction & Function Control", "domain": "AC",
                "description": "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
                "guidance": "Use role-based access control (RBAC) to ensure users can only perform functions necessary for their job roles (e.g., create, read, update, delete).",
                "assessment_objectives": "[a] the types of transactions and functions that authorized users are permitted to execute are defined; and\n[b] system access is limited to the types of transactions and functions that authorized users are permitted to execute.",
                "examples": "Example\nYour team manages DoD contracts for your company. Members of your team need to access the contract information to perform their work properly. Because some of that data contains CUI, you work with IT to set up your group's systems so that users can be assigned access based on their specific roles [a]. Each role limits whether an employee has read-access or create/read/delete/update-access [b]. Implementing this access control restricts access to CUI information unless specifically authorized."
            },
            {
                "requirement_id": "AC.L2-3.1.3", "title": "Control CUI Flow", "domain": "AC",
                "description": "Control the flow of CUI in accordance with approved authorizations.",
                "guidance": "Implement network segmentation and data flow controls to ensure CUI moves only between authorized systems according to security policies.",
                "assessment_objectives": "[a] security policies for CUI flow are defined;\n[b] CUI flow between connected systems is controlled according to security policies; and\n[c] CUI flow controls are implemented and enforced.",
                "examples": "Example 1\nYou configure a proxy device on your company's network. CUI is stored within this environment. Your goal is to better mask and protect the devices inside the network while enforcing information flow policies. After the device is configured, information does not flow directly from the internal network to the internet. The proxy device intercepts the traffic and analyzes it to determine if the traffic conforms to organization information flow control policies. If it does, the device allows the information to pass to its destination [b]. The proxy blocks traffic that does not meet policy requirements [e].\n\nExample 2\nAs a subcontractor on a DoD contract, your organization sometimes needs to transmit CUI to the prime contractor. You create a policy document that specifies who is allowed to transmit CUI and that such transmission requires manager approval [a,c,d]. The policy instructs users to encrypt any CUI transmitted via email or to use a designated secure file sharing utility [b,d]. The policy states"
            },
            {
                "requirement_id": "AC.L2-3.1.4", "title": "Separation of Duties", "domain": "AC",
                "description": "Separate the duties of individuals to reduce the risk of malevolent activity without collusion.",
                "guidance": "Ensure that no single individual has complete control over critical functions. Separate authorization, execution, and verification duties.",
                "assessment_objectives": "[a] duties are identified and documented;\n[b] duties are separated to reduce risk of malevolent activity; and\n[c] separation of duties is enforced through system controls.",
                "examples": "Example 1\nYou are responsible for the management of several key systems within your organization including some that process CUI. You assign the task of reviewing the system logs to two different people. This way, no one person is solely responsible for the execution of this critical security function [c].\n\nExample 2\nYou are a system administrator. Human Resources notifies you of a new hire, and you create an account with general privileges, but you are not allowed to grant access to systems that contain CUI [a,b]. The program manager contacts the team in your organization that has system administration authority over the CUI systems and informs them which CUI the new hire will need to access. Subsequently, a second system administrator grants access privileges to the new hire [c]."
            },
            {
                "requirement_id": "AC.L2-3.1.5", "title": "Least Privilege", "domain": "AC",
                "description": "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
                "guidance": "Grant users only the minimum access necessary to perform their job functions. Regularly review and revoke unnecessary privileges.",
                "assessment_objectives": "[a] least privilege principle is defined;\n[b] user access is limited to minimum necessary privileges;\n[c] privileged account access is limited to minimum necessary; and\n[d] least privilege is enforced through system controls.",
                "examples": "Example\nYou create accounts for an organization that processes CUI. By default, everyone is assigned a basic user role, which prevents a user from modifying system configurations. Privileged access is only assigned to users and processes that require it to carry out job functions, such as IT staff, and is very selectively granted [b,d]."
            },
            {
                "requirement_id": "AC.L2-3.1.6", "title": "Non-Privileged Account Use", "domain": "AC",
                "description": "Use non-privileged accounts or roles when accessing nonsecurity functions.",
                "guidance": "Use standard user accounts for daily operations. Only use administrative accounts when performing administrative tasks.",
                "assessment_objectives": "[a] non-privileged accounts are used for non-security functions;\n[b] privileged accounts are used only when necessary; and\n[c] account usage is monitored and enforced.",
                "examples": "Example\nYour organization handles CUI and has put security controls in place that prevent non-privileged users from performing privileged activities [a,b,c]. However, a standard user was accidentally given elevated system administrator privileges. The organization has implemented an endpoint detection and response solution that provides visibility into the use of privileged activities. The monitoring system logs a security misconfiguration because the use of administrative privileges was performed by a user who was not known to have that ability. This allows you to correct the error [d]."
            },
            {
                "requirement_id": "AC.L2-3.1.7", "title": "Privileged Functions", "domain": "AC",
                "description": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.",
                "guidance": "Implement controls to prevent standard users from executing administrative functions. Log all attempts to execute privileged functions.",
                "assessment_objectives": "[a] privileged functions are identified;\n[b] non-privileged users are prevented from executing privileged functions;\n[c] execution of privileged functions is captured in audit logs; and\n[d] privileged function execution is monitored.",
                "examples": "Example\nYour organization handles CUI and has put security controls in place that prevent non-privileged users from performing privileged activities [a,b,c]. However, a standard user was accidentally given elevated system administrator privileges. The organization has implemented an endpoint detection and response solution that provides visibility into the use of privileged activities. The monitoring system logs a security misconfiguration because the use of administrative privileges was performed by a user who was not known to have that ability. This allows you to correct the error [d]."
            },
            {
                "requirement_id": "AC.L2-3.1.8", "title": "Unsuccessful Logon Attempts", "domain": "AC",
                "description": "Limit unsuccessful logon attempts.",
                "guidance": "Implement account lockout policies after a specified number of failed login attempts to prevent brute force attacks.",
                "assessment_objectives": "[a] maximum number of unsuccessful logon attempts is defined;\n[b] unsuccessful logon attempts are limited to the defined maximum; and\n[c] account lockout mechanisms are implemented and enforced.",
                "examples": "Example\nYou attempt to log on to your work computer, which stores CUI. You mistype your password three times in a row, and an error message is generated telling you the account is locked [b]. You call your IT help desk or system administrator to request assistance. The system administrator explains that the account is locked as a result of three unsuccessful logon attempts [a]. The administrator offers to unlock the account and notes that you can wait 30 minutes for the account to unlock automatically."
            },
            {
                "requirement_id": "AC.L2-3.1.9", "title": "Privacy & Security Notices", "domain": "AC",
                "description": "Provide privacy and security notices consistent with applicable CUI rules.",
                "guidance": "Display appropriate privacy and security notices to users accessing systems containing CUI, consistent with applicable regulations.",
                "assessment_objectives": "[a] privacy and security notice requirements are defined;\n[b] privacy and security notices are provided to users;\n[c] notices are consistent with applicable CUI rules; and\n[d] notice compliance is monitored.",
                "examples": "Example\nYou are setting up IT equipment including a database server that will contain CUI. You have worked with legal counsel to draft a notification. It contains both general and specific CUI security and privacy requirements [a]. The system displays the required security and privacy information before anyone logs on to your organization's computers that contain or provide access to CUI [b]."
            },
            {
                "requirement_id": "AC.L2-3.1.10", "title": "Session Lock", "domain": "AC",
                "description": "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.",
                "guidance": "Configure workstations to automatically lock after a period of inactivity. Use screensavers that hide the display content.",
                "assessment_objectives": "[a] session lock timeout is defined;\n[b] session locks are implemented with pattern-hiding displays;\n[c] session locks activate after period of inactivity; and\n[d] session lock controls are enforced.",
                "examples": "Example\nYou manage systems for an organization that stores, processes, and transmits CUI. You notice that employees leave their offices without locking their computers. Sometimes their screens display sensitive company information. You configure all machines to lock after five minutes of inactivity [a,b]. You also remind your coworkers to lock their systems when they walk away [a]."
            },
            {
                "requirement_id": "AC.L2-3.1.11", "title": "Session Termination", "domain": "AC",
                "description": "Terminate (automatically) a user session after a defined condition.",
                "guidance": "Implement automatic session termination for conditions like end of workday, maximum session time, or security events.",
                "assessment_objectives": "[a] session termination conditions are defined;\n[b] user sessions are terminated upon meeting defined conditions;\n[c] session termination is automated where possible; and\n[d] session termination is logged and monitored.",
                "examples": "Example 1\nYou manage systems containing CUI for your organization and configure the system to terminate all user sessions after 1 hour of inactivity [a]. As the session timeout approaches, the system prompts users with a warning banner asking if they want to continue the session. When the session timeout does occur, the login page pops up, and the users must log in to start a new session [b].\n\nExample 2\nA user is logged into a corporate database containing CUI but is not authorized to view CUI. The user has submitted a series of queries that unintentionally violate policy, as they attempt to extract CUI that the user is not authorized to view [a]. The session terminates with a warning as a result of a violation of corporate policy [b]. The user must reestablish the session before being able to submit additional legitimate queries."
            },
            {
                "requirement_id": "AC.L2-3.1.12", "title": "Control Remote Access", "domain": "AC",
                "description": "Monitor and control remote access sessions.",
                "guidance": "Use VPNs and remote access controls. Monitor all remote connections and log remote access activities.",
                "assessment_objectives": "[a] remote access sessions are permitted;\n[b] the types of permitted remote access are identified;\n[c] remote access sessions are controlled; and\n[d] remote access sessions are monitored.",
                "examples": "Example\nYou often need to work from remote locations, such as your home or client sites, and you are permitted to access your organization's internal networks (including a network containing CUI) from those remote locations [a]. A system administrator issues you a company laptop with VPN software installed, which is required to connect to the networks remotely [b]. After the laptop connects to the VPN server, you must accept a privacy notice that states that the company's security department may monitor the connection. This monitoring is achieved through the analysis of data from sensors on the network notifying IT if issues arise. The security department may also review audit logs to see who is connecting remotely, when, and what information they are accessing [d]. During session establishment, the message \"Verifying Compliance\" means software like a Device Health Check (DHC) application is checking the remote device to ensure it meets the established requirements to connect [c]."
            },
            {
                "requirement_id": "AC.L2-3.1.13", "title": "Remote Access Confidentiality", "domain": "AC",
                "description": "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.",
                "guidance": "Use strong encryption for all remote access sessions, including VPN connections and remote desktop sessions.",
                "assessment_objectives": "[a] cryptographic mechanisms to protect the confidentiality of remote access sessions are identified; and\n[b] cryptographic mechanisms to protect the confidentiality of remote access sessions are implemented.",
                "examples": "Example\nYou are responsible for implementing a remote network access capability for users who access CUI remotely. In order to provide session confidentiality, you decide to implement a VPN mechanism and select a product that has completed FIPS 140 validation [a,b]."
            },
            {
                "requirement_id": "AC.L2-3.1.14", "title": "Remote Access Routing", "domain": "AC",
                "description": "Route remote access via managed access control points.",
                "guidance": "Ensure all remote access connections are routed through approved and monitored access control points.",
                "assessment_objectives": "[a] managed access control points are identified and implemented; and\n[b] remote access is routed through managed network access control points.",
                "examples": "Example\nYou manage systems for a company that processes CUI at multiple locations, and several employees at different locations need to connect to the organization's networks while working remotely. Because each company location has a direct connection to headquarters, you decide to route all remote access through the headquarters location [a]. All remote traffic is routed through a single location to simplify monitoring [b]."
            },
            {
                "requirement_id": "AC.L2-3.1.15", "title": "Privileged Remote Access", "domain": "AC",
                "description": "Authorize remote execution of privileged commands and remote access to security-relevant information.",
                "guidance": "Implement additional authorization requirements for remote execution of privileged commands and access to sensitive information.",
                "assessment_objectives": "[a] privileged commands authorized for remote execution are identified;\n[b] security-relevant information authorized to be accessed remotely is identified;\n[c] the execution of the identified privileged commands via remote access is authorized; and\n[d] access to the identified security-relevant information via remote access is authorized.",
                "examples": "Example\nYour company's Access Control Policy permits certain work roles to remotely perform a limited set of privileged commands from company-owned computers [a]. You implement controls to enforce who can remotely execute a privileged command, which privileged commands they can execute, and who is allowed access to security relevant information such as audit log configuration settings [a,c,d]."
            },
            {
                "requirement_id": "AC.L2-3.1.16", "title": "Wireless Access Authorization", "domain": "AC",
                "description": "Authorize wireless access prior to allowing such connections.",
                "guidance": "Implement wireless access authorization processes to approve devices before they can connect to wireless networks.",
                "assessment_objectives": "[a] wireless access points are identified; and\n[b] wireless access is authorized prior to allowing such connections.",
                "examples": "Example\nYour company is implementing a wireless network at its headquarters. CUI may be transmitted on this network. You work with management to draft a policy about the use of the wireless network. The policy states that only company-approved devices that contain verified security configuration settings are allowed to connect. The policy also includes usage restrictions that must be followed for anyone who wants to use the wireless network. Authorization is required before devices are allowed to connect to the wireless network [b]."
            },
            {
                "requirement_id": "AC.L2-3.1.17", "title": "Wireless Access Protection", "domain": "AC",
                "description": "Protect wireless access using authentication and encryption.",
                "guidance": "Use WPA3 or WPA2 encryption for wireless networks. Implement strong authentication for wireless access.",
                "assessment_objectives": "[a] wireless access to the system is protected using authentication; and\n[b] wireless access to the system is protected using encryption.",
                "examples": "Example 1\nYou manage the wireless network at a small company and are installing a new wireless solution that may transmit CUI. You start by selecting a product that employs encryption validated against the FIPS 140 standard. You configure the wireless solution to use WPA2, requiring users to enter a pre-shared key to connect to the wireless network [a,b].\n\nExample 2\nYou manage the wireless network at a large company and are installing a new wireless solution that may transmit CUI. You start by selecting a product that employs encryption that is validated against the FIPS 140 standard. Because of the size of your workforce, you configure the wireless system to authenticate users with a RADIUS server. Users must provide the wireless system with their domain usernames and passwords to be able to connect, and the RADIUS server verifies those credentials. Users unable to authenticate are denied access [a,b]."
            },
            {
                "requirement_id": "AC.L2-3.1.18", "title": "Mobile Device Connection", "domain": "AC",
                "description": "Control connection of mobile devices.",
                "guidance": "Implement mobile device management (MDM) solutions to control and monitor access to mobile devices that handle FCI or CUI.",
                "assessment_objectives": "[a] mobile devices that process, store, or transmit CUI are identified;\n[b] mobile device connections are authorized; and\n[c] mobile device connections are monitored and logged.",
                "examples": "Example\nYour organization has a policy stating that all mobile devices, including iPads, tablets, mobile phones, and Personal Digital Assistants (PDAs), must be approved and registered with the IT department before connecting to the network that contains CUI. The IT department uses a Mobile Device Management solution to monitor mobile devices and enforce policies across the enterprise [b,c]."
            },
            {
                "requirement_id": "AC.L2-3.1.19", "title": "Encrypt CUI on Mobile", "domain": "AC",
                "description": "Encrypt CUI on mobile devices and mobile computing platforms.",
                "guidance": "Use device encryption and secure containers to protect CUI on mobile devices. Implement remote wipe capabilities.",
                "assessment_objectives": "[a] mobile devices and mobile computing platforms that process, store, or transmit CUI are identified; and\n[b] encryption is employed to protect CUI on identified mobile devices and mobile computing platforms.",
                "examples": "Example\nYou are in charge of mobile device security for a company that processes CUI. You configure all laptops to use the full-disk encryption technology built into the operating system. This approach is FIPS-validated and encrypts all files, folders, and volumes.\n\nPhones and tablets pose a greater technical challenge with their wide range of manufacturers and operating systems. You select a proprietary mobile device management (MDM) solution to enforce FIPS-validated encryption on those devices [a,b]."
            },
            {
                "requirement_id": "AC.L2-3.1.20", "title": "External Connections [CUI Data]", "domain": "AC",
                "description": "Verify and control/limit connections to and use of external systems.",
                "guidance": "Use firewalls and connection policies to manage connections between your network and external ones. Control access from personally owned devices.",
                "assessment_objectives": "[a] connections to external systems are identified;\n[b] the use of external systems is identified;\n[c] connections to external systems are verified;\n[d] the use of external systems is verified; and\n[e] connections to external systems are controlled/limited.",
                "examples": "Example\nYour company has a project that contains CUI. You remind your coworkers of the policy requirement to use their company laptops, not personal laptops or tablets, when working remotely on the project [b,f]. You also remind everyone to work from the cloud environment that is approved for processing and storing CUI rather than the other collaborative tools that may be used for other projects [b,f]."
            },
            {
                "requirement_id": "AC.L2-3.1.21", "title": "Portable Storage Use", "domain": "AC",
                "description": "Limit use of portable storage devices on external systems.",
                "guidance": "Implement controls to limit or prevent the use of portable storage devices like USB drives on external systems.",
                "assessment_objectives": "[a] the use of portable storage devices containing CUI on external systems is identified and documented;\n[b] limits on the use of portable storage devices containing CUI on external systems are defined; and\n[c] the use of portable storage devices containing CUI on external systems is limited as defined.",
                "examples": "Example\nYour organization, which stores and processes CUI, has a written portable device usage restriction policy. It states that users can only use external storage devices such as thumb dives or external hard disks that belong to the company. When needed for a specific business function, a user checks the device out from IT and returns it to IT when no longer needed [a,b]."
            },
            {
                "requirement_id": "AC.L2-3.1.22", "title": "Control Public Information [CUI Data]", "domain": "AC",
                "description": "Control CUI posted or processed on publicly accessible systems.",
                "guidance": "Establish a review process to prevent CUI from being posted on public systems like company websites or forums.",
                "assessment_objectives": "[a] individuals authorized to post or process information on publicly accessible systems are identified;\n[b] procedures to ensure CUI is not posted or processed on publicly accessible systems are identified;\n[c] a review process is in place prior to posting of any content to publicly accessible systems;\n[d] content on publicly accessible systems is reviewed to ensure that it does not include CUI; and\n[e] mechanisms are in place to remove and address improper posting of CUI.",
                "examples": "Example\nYour company decides to start issuing press releases about its projects in an effort to reach more potential customers. Your company receives CUI from the government as part of its DoD contract. Because you recognize the need to manage controlled information, including CUI, you meet with the employees who write the releases and post information to establish a review process [c]. It is decided that you will review press releases for CUI before posting it on the company website [a,d]. Only certain employees will be authorized to post to the website [a]."
            },
            # Awareness and Training (AT) Requirements
            {
                "requirement_id": "AT.L2-3.2.1", "title": "Role-Based Risk Awareness", "domain": "AT",
                "description": "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.",
                "guidance": "Provide role-specific security awareness training that covers risks associated with each role and relevant security policies and procedures.",
                "assessment_objectives": "[a] security risks associated with organizational activities involving CUI are identified;\n[b] policies, standards, and procedures related to the security of the system are identified;\n[c] managers, systems administrators, and users of the system are made aware of the security risks associated with their activities; and\n[d] managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system.",
                "examples": "Example\nYour organization holds a DoD contract which requires the use of CUI. You want to provide information to employees so they can identify phishing emails. To do this, you prepare a presentation that highlights basic traits, including:\n\n• suspicious-looking email address or domain name;\n• a message that contains an attachment or URL; and\n• a message that is poorly written and often contains obvious misspelled words.\n\nYou encourage everyone to not click on attachments or links in a suspicious email [c]. You tell employees to forward such a message immediately to IT security [d]. You download free security awareness posters to hang in the office [c,d]. You send regular emails and tips to all employees to ensure your message is not forgotten over time [c,d]."
            },
            {
                "requirement_id": "AT.L2-3.2.2", "title": "Role-Based Training", "domain": "AT",
                "description": "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.",
                "guidance": "Provide specialized security training for personnel with specific security responsibilities, such as system administrators and security officers.",
                "assessment_objectives": "[a] information security-related duties, roles, and responsibilities are defined;\n[b] information security-related duties, roles, and responsibilities are assigned to designated personnel; and\n[c] personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibilities.",
                "examples": "Example\nYour company upgraded the firewall to a newer, more advanced system to protect the CUI it stores. You have been identified as an employee who needs training on the new device [a,b,c]. This will enable you to use the firewall effectively and efficiently. Your company considered training resources when it planned for the upgrade and ensured that training funds were available as part of the upgrade project [c]."
            },
            {
                "requirement_id": "AT.L2-3.2.3", "title": "Insider Threat Awareness", "domain": "AT",
                "description": "Provide security awareness training on recognizing and reporting potential indicators of insider threat.",
                "guidance": "Conduct regular security awareness training that includes recognizing insider threat indicators and proper reporting procedures.",
                "assessment_objectives": "[a] potential indicators associated with insider threats are identified; and\n[b] security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers and employees.",
                "examples": "Example\nYou are responsible for training all employees on the awareness of high-risk behaviors that can indicate a potential insider threat [b]. You educate yourself on the latest research on insider threat indicators by reviewing a number of law enforcement bulletins [a]. You then add the following example to the training package: A baseline of normal behavior for work schedules has been created. One employee's normal work schedule is 8:00 AM–5:00 PM, but another employee noticed that the employee has been working until 9:00 PM every day even though no projects requiring additional hours have been assigned [b]. The observing employee reports the abnormal work schedule using the established reporting guidelines."
            },
            # Audit and Accountability (AU) Requirements
            {
                "requirement_id": "AU.L2-3.3.1", "title": "System Auditing", "domain": "AU",
                "description": "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
                "guidance": "Implement comprehensive audit logging for all system activities. Retain audit logs according to organizational policy and legal requirements.",
                "assessment_objectives": "[a] audit logs needed (i.e., event types to be logged) to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity are specified;\n[b] the content of audit records needed to support monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity is defined;\n[c] audit records are created (generated);\n[d] audit records, once created, contain the defined content;\n[e] retention requirements for audit records are defined; and\n[f] audit records are retained as defined.",
                "examples": "Example\nYou set up audit logging capability for your company. You determine that all systems that contain CUI must have extra detail in the audit logs. Because of this, you configure these systems to log the following information for all user actions [b,c]:\n\n• time stamps;\n• source and destination addresses;\n• user or process identifiers;\n• event descriptions;\n• success or fail indications; and\n• filenames."
            },
            {
                "requirement_id": "AU.L2-3.3.2", "title": "User Accountability", "domain": "AU",
                "description": "Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.",
                "guidance": "Configure audit logs to capture user identification, timestamps, and actions performed. Ensure logs cannot be modified by users.",
                "assessment_objectives": "[a] the content of the audit records needed to support the ability to uniquely trace users to their actions is defined; and\n[b] audit records, once created, contain the defined content.",
                "examples": "Example\nYou manage systems for a company that stores, processes, and transmits CUI. You want to ensure that you can trace all remote access sessions to a specific user. You configure the VPN device to capture the following information for all remote access connections: source and destination IP address, user ID, machine name, time stamp, and user actions during the remote session [b]."
            },
            {
                "requirement_id": "AU.L2-3.3.3", "title": "Event Review", "domain": "AU",
                "description": "Review and update logged events.",
                "guidance": "Regularly review audit logs for suspicious activities. Update logging configurations based on security requirements and threat landscape.",
                "assessment_objectives": "[a] a process for determining when to review logged events is defined;\n[b] event types being logged are reviewed in accordance with the defined review process; and\n[c] event types being logged are updated based on the review.",
                "examples": "Example\nYou are in charge of IT operations for a company that processes CUI and are responsible for identifying and documenting which events are relevant to the security of your company's systems. Your company has decided that this list of events should be updated annually or when new security threats or events have been identified, which may require additional events to be logged and reviewed [a]. The list of events you are capturing in your logs started as the list of recommended events given by the manufacturers of your operating systems and devices, but it has grown from experience.\n\nYour company experiences a security incident, and a forensics review shows the logs appear to have been deleted by a remote user. You notice that remote sessions are not currently being logged [b]. You update the list of events to include logging all VPN sessions [c]."
            },
            {
                "requirement_id": "AU.L2-3.3.4", "title": "Audit Failure Alerting", "domain": "AU",
                "description": "Alert in the event of an audit logging process failure.",
                "guidance": "Implement monitoring and alerting for audit system failures. Ensure backup audit mechanisms are in place.",
                "assessment_objectives": "[a] personnel or roles to be alerted in the event of an audit logging process failure are identified;\n[b] types of audit logging process failures for which alert will be generated are defined; and\n[c] identified personnel or roles are alerted in the event of an audit logging process failure.",
                "examples": "Example\nYou are in charge of IT operations for a company that processes CUI, and your responsibilities include managing the audit logging process. You configure your systems to send you an email in the event of an audit log failure. One day, you receive one of these alerts. You connect to the system, restart logging, and determine why the logging stopped [a,b,c]."
            },
            {
                "requirement_id": "AU.L2-3.3.5", "title": "Audit Correlation", "domain": "AU",
                "description": "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.",
                "guidance": "Use security information and event management (SIEM) systems to correlate audit records across different systems and components.",
                "assessment_objectives": "[a] audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity are defined; and\n[b] defined audit record review, analysis, and reporting processes are correlated.",
                "examples": "Example\nYou are a member of a cyber defense team responsible for audit log analysis. You run an automated tool that analyzes all the audit logs across a Local Area Network (LAN) segment simultaneously looking for similar anomalies on separate systems at separate locations. Some of these systems store CUI. After extracting anomalous information and performing a correlation analysis [b], you determine that four different systems have had their event log information cleared between 2:00 AM to 3:00 AM, although the associated dates are different. The team monitors all systems on the same LAN segment between 2:00 AM to 3:00 AM for the next 30 days."
            },
            {
                "requirement_id": "AU.L2-3.3.6", "title": "Reduction & Reporting", "domain": "AU",
                "description": "Provide audit record reduction and report generation to support on-demand analysis and reporting.",
                "guidance": "Implement tools and processes for audit record reduction and automated report generation to support security analysis.",
                "assessment_objectives": "[a] an audit record reduction capability that supports on-demand analysis is provided; and\n[b] a report generation capability that supports on-demand reporting is provided.",
                "examples": "Example\nYou are in charge of IT operations in a company that processes CUI. You are responsible for providing audit record reduction and report generation capability. To support this function, you deploy an open-source solution that will collect and analyze data for signs of anomalies. The solution queries your central log repository to extract relevant data and provide you with a concise and comprehensive view for further analysis to identify potentially malicious activity [a]. In addition to creating on-demand datasets for analysis, you create customized reports explaining the contents of the data set [b]."
            },
            {
                "requirement_id": "AU.L2-3.3.7", "title": "Authoritative Time Source", "domain": "AU",
                "description": "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.",
                "guidance": "Configure all systems to synchronize their clocks with authoritative time sources to ensure accurate timestamps in audit records.",
                "assessment_objectives": "[a] internal system clocks are used to generate time stamps for audit records;\n[b] an authoritative source with which to compare and synchronize internal system clocks is specified; and\n[c] internal system clocks used to generate time stamps for audit records are compared to and synchronized with the specified authoritative time source.",
                "examples": "Example\nYou are setting up several new computers on your company's network, which contains CUI. You update the time settings on each machine to use the same authoritative time server on the internet [b,c]. When you review audit logs, all your machines will have synchronized time, which aids in any potential security investigations."
            },
            {
                "requirement_id": "AU.L2-3.3.8", "title": "Audit Protection", "domain": "AU",
                "description": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
                "guidance": "Implement strong access controls for audit logs and logging tools. Use encryption and integrity protection for audit data.",
                "assessment_objectives": "[a] audit information is protected from unauthorized access;\n[b] audit information is protected from unauthorized modification;\n[c] audit information is protected from unauthorized deletion;\n[d] audit logging tools are protected from unauthorized access;\n[e] audit logging tools are protected from unauthorized modification; and\n[f] audit logging tools are protected from unauthorized deletion.",
                "examples": "Example\nYou are in charge of IT operations in a company that handles CUI. Your responsibilities include protecting audit information and audit logging tools. You protect the information from modification or deletion by having audit log events forwarded to a central server and by restricting the local audit logs to only be viewable by the system administrators [a,b,c]. Only a small group of security professionals can view the data on the central audit server [b,c,d]. For an additional layer of protection, you back up the server daily and encrypt the backups before sending them to a cloud data repository [a,b,c]."
            },
            {
                "requirement_id": "AU.L2-3.3.9", "title": "Audit Management", "domain": "AU",
                "description": "Limit management of audit logging functionality to a subset of privileged users.",
                "guidance": "Restrict access to audit logging configuration and management to authorized administrators only.",
                "assessment_objectives": "[a] a subset of privileged users granted access to manage audit logging functionality is defined; and\n[b] management of audit logging functionality is limited to the defined subset of privileged users.",
                "examples": "Example\nYou are responsible for the administration of select company infrastructure that contains CUI, but you are not responsible for managing audit information. You are not permitted to review audit logs, delete audit logs, or modify audit log settings [b]. Full control of audit logging functions has been given to senior system administrators [a,b]. This separation of system administration duties from audit logging management is necessary to prevent possible log file tampering."
            },
            # Configuration Management (CM) Requirements
            {
                "requirement_id": "CM.L2-3.4.1", "title": "System Baselining", "domain": "CM",
                "description": "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.",
                "guidance": "Create and maintain secure baseline configurations for all systems. Keep inventories of all organizational information systems.",
                "assessment_objectives": "[a] a baseline configuration is established;\n[b] the baseline configuration includes hardware, software, firmware, and documentation;\n[c] the baseline configuration is maintained (reviewed and updated) throughout the system development life cycle;\n[d] a system inventory is established;\n[e] the system inventory includes hardware, software, firmware, and documentation; and\n[f] the inventory is maintained (reviewed and updated) throughout the system development life cycle.",
                "examples": "Example\nYou are in charge of upgrading the computer operating systems of your office's computers. Some of these computers process, store, or transmit CUI. You research how to set up and configure a workstation with the least functionality and highest security and use that as the framework for creating a configuration that minimizes functionality while still allowing users to do their tasks. After testing the new baseline on a single workstation, you document this configuration and apply it to the other computers [a]. You then check to make sure that the software changes are accurately reflected in your master system inventory [e]. Finally, you set a calendar reminder to review the baseline in three months [f]."
            },
            {
                "requirement_id": "CM.L2-3.4.2", "title": "Security Configuration Enforcement", "domain": "CM",
                "description": "Establish and enforce security configuration settings for information technology products employed in organizational systems.",
                "guidance": "Implement security configuration standards and enforce them across all IT products and systems.",
                "assessment_objectives": "[a] security configuration settings for information technology products employed in the system are established and included in the baseline configuration; and\n[b] security configuration settings for information technology products employed in the system are enforced.",
                "examples": "Example\nYou manage baseline configurations for your company's systems, including those that process, store, and transmit CUI. As part of this, you download a secure configuration guide for each of your asset types (servers, workstations, network components, operating systems, middleware, and applications) from a well-known and trusted IT security organization. You then apply all of the settings that you can while still ensuring the assets can perform the role for which they are needed. Once you have the configuration settings identified and tested, you document them to ensure all applicable machines can be configured the same way [a,b]."
            },
            {
                "requirement_id": "CM.L2-3.4.3", "title": "System Change Management", "domain": "CM",
                "description": "Track, review, approve or disapprove, and log changes to organizational systems.",
                "guidance": "Implement formal change control processes that require approval for all system changes, including testing and rollback procedures.",
                "assessment_objectives": "[a] changes to the system are tracked;\n[b] changes to the system are reviewed;\n[c] changes to the system are approved or disapproved; and\n[d] changes to the system are logged.",
                "examples": "Example\nOnce a month, the management and technical team leads join a change control board meeting. During this meeting, everyone reviews all proposed changes to the environment [b,c]. This includes changes to the physical and computing environments. The meeting ensures that relevant subject-matter experts review changes and propose alternatives where needed."
            },
            {
                "requirement_id": "CM.L2-3.4.4", "title": "Security Impact Analysis", "domain": "CM",
                "description": "Analyze the security impact of changes prior to implementation.",
                "guidance": "Conduct security impact assessments for all proposed system changes to identify potential security risks.",
                "assessment_objectives": "[a] the security impact of changes to the system is analyzed prior to implementation.",
                "examples": "Example\nYou have been asked to deploy a new web browser plug-in. Your standard change management process requires that you produce a detailed plan for the change, including a review of its potential security impact. A subject-matter expert who did not submit the change reviews the plan and tests the new plug-in for functionality and security. You update the change plan based on the expert's findings and submit it to the change control board for final approval [a]."
            },
            {
                "requirement_id": "CM.L2-3.4.5", "title": "Access Restrictions for Change", "domain": "CM",
                "description": "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.",
                "guidance": "Implement access controls for system changes, including physical security for change management systems and logical access controls.",
                "assessment_objectives": "[a] physical access restrictions associated with changes to the system are defined;\n[b] physical access restrictions associated with changes to the system are documented;\n[c] physical access restrictions associated with changes to the system are approved;\n[d] physical access restrictions associated with changes to the system are enforced;\n[e] logical access restrictions associated with changes to the system are defined;\n[f] logical access restrictions associated with changes to the system are documented;\n[g] logical access restrictions associated with changes to the system are approved; and\n[h] logical access restrictions associated with changes to the system are enforced.",
                "examples": "Example\nYour datacenter requires expanded storage capacity in a server. The change has been approved, and security is planning to allow an external technician to access the building at a specific date and time under the supervision of a manager [a,b,c,d]. A system administrator creates a temporary privileged account that can be used to log into the server's operating system and update storage settings [e,f,g]. On the appointed day, the technician is escorted into the datacenter, upgrades the hardware, expands the storage in the operating system (OS), and departs. The manager verifies the upgrade and disables the privileged account [h]."
            },
            {
                "requirement_id": "CM.L2-3.4.6", "title": "Least Functionality", "domain": "CM",
                "description": "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.",
                "guidance": "Configure systems to provide only necessary functionality. Disable unnecessary services, ports, and protocols.",
                "assessment_objectives": "[a] essential system capabilities are defined based on the principle of least functionality; and\n[b] the system is configured to provide only the defined essential capabilities.",
                "examples": "Example\nYou have ordered a new server, which has arrived with a number of free utilities installed in addition to the operating system. Before you deploy the server, you research the utilities to determine which ones can be eliminated without impacting functionality. You remove the unneeded software, then move on to disable unused ports and services. The server that enters production therefore has only the essential capabilities enabled for the system to function in its role [a,b]."
            },
            {
                "requirement_id": "CM.L2-3.4.7", "title": "Nonessential Functionality", "domain": "CM",
                "description": "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.",
                "guidance": "Implement controls to prevent users from installing unauthorized software and using nonessential network services.",
                "assessment_objectives": "[a] essential programs are defined;\n[b] the use of nonessential programs is defined;\n[c] the use of nonessential programs is restricted, disabled, or prevented as defined;\n[d] essential functions are defined;\n[e] the use of nonessential functions is defined;\n[f] the use of nonessential functions is restricted, disabled, or prevented as defined;\n[g] essential ports are defined;\n[h] the use of nonessential ports is defined;\n[i] the use of nonessential ports is restricted, disabled, or prevented as defined;\n[j] essential protocols are defined;\n[k] the use of nonessential protocols is defined;\n[l] the use of nonessential protocols is restricted, disabled, or prevented as defined;\n[m] essential services are defined;\n[n] the use of nonessential services is defined; and\n[o] the use of nonessential services is restricted, disabled, or prevented as defined.",
                "examples": "Example\nYou are responsible for purchasing new endpoint hardware, installing organizationally required software to the hardware, and configuring the endpoint in accordance with the organization's policy. The organization has a system imaging capability that loads all necessary software, but it does not remove unnecessary services, eliminate the use of certain protocols, or close unused ports. After imaging the systems, you close all ports and block the use of all protocols except the following:\n\n• TCP for SSH on port 22;\n• SMTP on port 25;\n• TCP and UDP on port 53; and\n• HTTP and HTTPS on port 443.\n\nThe use of any other ports or protocols are allowed by exception only [i,l,o]."
            },
            {
                "requirement_id": "CM.L2-3.4.8", "title": "Application Execution Policy", "domain": "CM",
                "description": "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.",
                "guidance": "Implement application whitelisting or blacklisting to control software execution on organizational systems.",
                "assessment_objectives": "[a] a policy specifying whether whitelisting or blacklisting is to be implemented is specified;\n[b] the software allowed to execute under whitelisting or denied use under blacklisting is specified; and\n[c] whitelisting to allow the execution of authorized software or blacklisting to prevent the use of unauthorized software is implemented as specified.",
                "examples": "Example\nTo improve your company's protection from malware, you have decided to allow only designated programs to run. With additional research you identify a capability within the latest operating system that can control executables, scripts, libraries, or application installers run in your environment [c]. To ensure success you begin by authorizing digitally signed executables. Once they are deployed, you then plan to evaluate and deploy whitelisting for software libraries and scripts [c]."
            },
            {
                "requirement_id": "CM.L2-3.4.9", "title": "User-Installed Software", "domain": "CM",
                "description": "Control and monitor user-installed software.",
                "guidance": "Implement controls to prevent users from installing software without authorization. Use administrative privileges and software deployment tools.",
                "assessment_objectives": "[a] a policy for controlling the installation of software by users is established;\n[b] installation of software by users is controlled based on the established policy; and\n[c] installation of software by users is monitored.",
                "examples": "Example\nYou are a system administrator. A user calls you for help installing a software package. They are receiving a message asking for a password because they do not have permission to install the software. You explain that the policy prohibits users from installing software without approval [a]. When you set up workstations for users, you do not provide administrative privileges. After the call, you redistribute the policy to all users ensuring everyone in the company is aware of the restrictions."
            },
            # Identification and Authentication (IA) Requirements
            {
                "requirement_id": "IA.L2-3.5.1", "title": "Identification [CUI Data]", "domain": "IA",
                "description": "Identify system users, processes acting on behalf of users, and devices.",
                "guidance": "Assign unique identifiers (e.g., usernames) to all users, processes, and devices that require access to company systems.",
                "assessment_objectives": "[a] system users are identified;\n[b] processes acting on behalf of users are identified; and\n[c] devices accessing the system are identified.",
                "examples": "Example\nYou want to make sure that all employees working on a project can access important information about it. Because this is work for the DoD and may contain CUI, you also need to prevent employees who are not working on that project from being able to access the information. You assign each employee is assigned a unique user ID, which they use to log into the system [a]."
            },
            {
                "requirement_id": "IA.L2-3.5.2", "title": "Authentication [CUI Data]", "domain": "IA",
                "description": "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.",
                "guidance": "Verify identity before granting access, typically with a username and strong password. Always change default passwords on new devices and systems.",
                "assessment_objectives": "[a] the identity of each user is authenticated or verified as a prerequisite to system access;\n[b] the identity of each process acting on behalf of a user is authenticated or verified as a prerequisite to system access; and\n[c] the identity of each device accessing or connecting to the system is authenticated or verified as a prerequisite to system access.",
                "examples": "Example 1\nYou are in charge of purchasing. You know that some laptops come with a default username and password. You notify IT that all default passwords should be reset prior to laptop use [a]. You ask IT to explain the importance of resetting default passwords and convey how easily they are discovered using internet searches during next week's cybersecurity awareness training.\n\nExample 2\nYour company decides to use cloud services for email and other capabilities. Upon reviewing this requirement, you realize every user or device that connects to the cloud service must be authenticated. As a result, you work with your cloud service provider to ensure that only properly authenticated users and devices are allowed to connect to the system [a,c]."
            },
            {
                "requirement_id": "IA.L2-3.5.3", "title": "Multifactor Authentication", "domain": "IA",
                "description": "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.",
                "guidance": "Implement multifactor authentication (MFA) for all privileged accounts and network access to non-privileged accounts.",
                "assessment_objectives": "[a] privileged accounts are identified;\n[b] multifactor authentication is implemented for local access to privileged accounts;\n[c] multifactor authentication is implemented for network access to privileged accounts; and\n[d] multifactor authentication is implemented for network access to non-privileged accounts.",
                "examples": "Example\nYou decide to implement multifactor authentication (MFA) to improve the security of your network. Your first step is enabling MFA on VPN access to your internal network [c,d]. When users initiate remote access, they will be prompted for the additional authentication factor. Because you also use a cloud-based email solution, you require MFA for access to that resource as well [c,d]. Finally, you enable MFA for both local and network logins for the system administrator accounts used to patch and manage servers [a,b,c]."
            },
            {
                "requirement_id": "IA.L2-3.5.4", "title": "Replay-Resistant Authentication", "domain": "IA",
                "description": "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.",
                "guidance": "Use authentication mechanisms that prevent replay attacks for all account access, such as challenge-response protocols.",
                "assessment_objectives": "[a] replay-resistant authentication mechanisms are implemented for network account access to privileged and non-privileged accounts.",
                "examples": "Example\nTo protect your IT infrastructure, you understand that the methods for authentication must not be easily copied and re-sent to your systems by an adversary. You select Kerberos for authentication because of its built-in resistance to replay attacks. As a next step you upgrade all of your web applications to require Transport Layer Security (TLS), which also is replay-resistant. Your use of MFA to protect remote access also confers some replay resistance."
            },
            {
                "requirement_id": "IA.L2-3.5.5", "title": "Identifier Reuse", "domain": "IA",
                "description": "Prevent reuse of identifiers for a defined period.",
                "guidance": "Implement controls to prevent reuse of user identifiers, usernames, and other identifiers for a specified period.",
                "assessment_objectives": "[a] a period within which identifiers cannot be reused is defined; and\n[b] reuse of identifiers is prevented within the defined period.",
                "examples": "Example\nAs a system administrator, you maintain a central directory/domain that holds the accounts for users, computers, and network devices. As part of your job, you issue unique usernames (e.g., riley@acme.com) for the staff to access resources. When you issue staff computers you also rename the computer to reflect to whom it is assigned (e.g., riley-laptop01). Riley has recently left the organization, so you must manage the former staff member's account. Incidentally, their replacement is also named Riley. In the directory, you do not assign the previous account to the new user, as policy has defined an identifier reuse period of 24 months [a]. In accordance with policy, you create an account called riley02 [b]. This account is assigned the appropriate permissions for the new user. A new laptop is also provided with the identifier of riley02-laptop01."
            },
            {
                "requirement_id": "IA.L2-3.5.6", "title": "Identifier Handling", "domain": "IA",
                "description": "Disable identifiers after a defined period of inactivity.",
                "guidance": "Implement automatic disabling of user accounts and identifiers after a period of inactivity to prevent unauthorized access.",
                "assessment_objectives": "[a] a period of inactivity after which an identifier is disabled is defined; and\n[b] identifiers are disabled after the defined period of inactivity.",
                "examples": "Example\nOne of your responsibilities is to enforce your company's inactive account policy: any account that has not been used in the last 45 days must be disabled [a]. You enforce this by writing a script that runs once a day to check the last login date for each account and generates a report of the accounts with no login records for the last 45 days. After reviewing the report, you notify each inactive employee's supervisor and disable the account [b]."
            },
            {
                "requirement_id": "IA.L2-3.5.7", "title": "Password Complexity", "domain": "IA",
                "description": "Enforce a minimum password complexity and change of characters when new passwords are created.",
                "guidance": "Implement strong password policies requiring minimum length, complexity, and character requirements.",
                "assessment_objectives": "[a] password complexity requirements are defined;\n[b] password change of character requirements are defined;\n[c] minimum password complexity requirements as defined are enforced when new passwords are created; and\n[d] minimum password change of character requirements as defined are enforced when new passwords are created.",
                "examples": "Example\nYou work with management to define password complexity rules and ensure they are listed in the company's security policy. You define and enforce a minimum number of characters for each password and ensure that a certain number of characters must be changed when updating passwords [a,b]. Characters include numbers, lowercase and uppercase letters, and symbols [a]. These rules help create hard-to-guess passwords, which help to secure your network."
            },
            {
                "requirement_id": "IA.L2-3.5.8", "title": "Password Reuse", "domain": "IA",
                "description": "Prohibit password reuse for a specified number of generations.",
                "guidance": "Implement password history controls to prevent reuse of recent passwords for a specified number of password changes.",
                "assessment_objectives": "[a] the number of generations during which a password cannot be reused is specified and\n[b] reuse of passwords is prohibited during the specified number of generations.",
                "examples": "Example\nYou explain in your company's security policy that changing passwords regularly provides increased security by reducing the ability of adversaries to exploit stolen or purchased passwords over an extended period. You define how often individuals can reuse their passwords and the minimum number of password generations before reuse [a]. If a user tries to reuse a password before the number of password generations has been exceeded, an error message is generated, and the user is required to enter a new password [b]."
            },
            {
                "requirement_id": "IA.L2-3.5.9", "title": "Temporary Passwords", "domain": "IA",
                "description": "Allow temporary password use for system logons with an immediate change to a permanent password.",
                "guidance": "Implement temporary password mechanisms that require immediate change to permanent passwords upon first login.",
                "assessment_objectives": "[a] an immediate change to a permanent password is required when a temporary password is used for system logon.",
                "examples": "Example\nOne of your duties as a systems administrator is to create accounts for new users. You configure all systems with user accounts to require users to change a temporary password upon initial login to a permanent password [a]. When a user logs on for the first time, they are prompted to create a unique password that meets all of the defined complexity rules."
            },
            {
                "requirement_id": "IA.L2-3.5.10", "title": "Cryptographically-Protected Passwords", "domain": "IA",
                "description": "Store and transmit only cryptographically-protected passwords.",
                "guidance": "Use strong cryptographic hashing for password storage and encryption for password transmission.",
                "assessment_objectives": "[a] passwords are cryptographically protected in storage; and\n[b] passwords are cryptographically protected in transit..",
                "examples": "Example\nYou are responsible for managing passwords for your organization. You protect all passwords with a one-way transformation, or hashing, before storing them. Passwords are never transmitted across a network unencrypted [a,b]."
            },
            {
                "requirement_id": "IA.L2-3.5.11", "title": "Obscure Feedback", "domain": "IA",
                "description": "Obscure feedback of authentication information.",
                "guidance": "Implement authentication feedback mechanisms that do not reveal sensitive authentication information to unauthorized parties.",
                "assessment_objectives": "[a] authentication information is obscured during the authentication process.",
                "examples": "Example\nAs a system administrator, you configure your systems to display an asterisk when users enter their passwords into a computer system [a]. For mobile devices, the password characters are briefly displayed to the user before being obscured. This prevents people from figuring out passwords by looking over someone's shoulder."
            },
            # Incident Response (IR) Requirements
            {
                "requirement_id": "IR.L2-3.6.1", "title": "Incident Handling", "domain": "IR",
                "description": "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
                "guidance": "Develop and implement comprehensive incident response procedures covering all phases of incident handling.",
                "assessment_objectives": "[a] an operational incident-handling capability is established;\n[b] the operational incident-handling capability includes preparation;\n[c] the operational incident-handling capability includes detection;\n[d] the operational incident-handling capability includes analysis;\n[e] the operational incident-handling capability includes containment;\n[f] the operational incident-handling capability includes recovery; and\n[g] the operational incident-handling capability includes user response activities.",
                "examples": "Example\nYour manager asks you to set up your company's incident-response capability [a]. First, you create an email address to collect information on possible incidents. Next, you draft a contact list of all the people who need to know when an incident occurs. You document a procedure for how to submit incidents that includes roles and responsibilities when a potential incident is detected or reported. The procedure also explains how to track incidents, from initial creation to closure [b]."
            },
            {
                "requirement_id": "IR.L2-3.6.2", "title": "Incident Reporting", "domain": "IR",
                "description": "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.",
                "guidance": "Implement incident tracking and reporting systems to ensure proper documentation and escalation of security incidents.",
                "assessment_objectives": "[a] incidents are tracked;\n[b] incidents are documented;\n[c] authorities to whom incidents are to be reported are identified;\n[d] organizational officials to whom incidents are to be reported are identified;\n[e] identified authorities are notified of incidents; and\n[f] identified organizational officials are notified of incidents.",
                "examples": "Example\nYou notice unusual activity on a server and determine a potential security incident has occurred. You open a tracking ticket with the Security Operations Center (SOC), which assigns an incident handler to work the ticket [a]. The handler investigates and documents initial findings, which lead to a determination that unauthorized access occurred on the server [b]. The SOC establishes an incident management team consisting of security, database, network, and system administrators. The team meets daily to update progress and plan courses of action to contain the incident [a]. At the end of the day, the team provides a status report to IT executives [d,f]. Two days later, the team declares the incident contained. The team produces a final report as the database system is rebuilt and placed back into operation."
            },
            {
                "requirement_id": "IR.L2-3.6.3", "title": "Incident Response Testing", "domain": "IR",
                "description": "Test the organizational incident response capability.",
                "guidance": "Conduct regular testing of incident response procedures through tabletop exercises and simulations.",
                "assessment_objectives": "[a] the incident response capability is tested.",
                "examples": "Example\nYou decide to conduct an incident response table top exercise that simulates an attacker gaining access to the network through a compromised server. You include relevant IT staff such as security, database, network, and system administrators as participants. You also request representatives from legal, human resources, and communications. You provide a scenario to the group and have prepared key questions aligned with the response plans to guide the exercise. During the exercise, you focus on how the team executes the incident response plan. Afterward, you conduct a debrief with everyone that was involved to provide feedback and develop improvements to the incident response plan [a]."
            },
            # Maintenance (MA) Requirements
            {
                "requirement_id": "MA.L2-3.7.1", "title": "Perform Maintenance", "domain": "MA",
                "description": "Perform maintenance on organizational systems.",
                "guidance": "Establish and follow regular maintenance schedules for all organizational systems to ensure proper operation and security.",
                "assessment_objectives": "[a] system maintenance is performed.",
                "examples": "Example\nYou are responsible for maintenance activities on your company's machines. This includes regular planned maintenance, unscheduled maintenance, reconfigurations when required, and damage repairs [a]. You know that failing to conduct maintenance activities can impact system security and availability, so you ensure that maintenance is regularly performed. You track all maintenance performed to assist with troubleshooting later if needed."
            },
            {
                "requirement_id": "MA.L2-3.7.2", "title": "System Maintenance Control", "domain": "MA",
                "description": "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.",
                "guidance": "Implement controls to ensure only authorized personnel use approved tools and techniques for system maintenance.",
                "assessment_objectives": "[a] tools used to conduct system maintenance are controlled;\n[b] techniques used to conduct system maintenance are controlled;\n[c] mechanisms used to conduct system maintenance are controlled; and\n[d] personnel used to conduct system maintenance are controlled.",
                "examples": "Example\nYou are responsible for maintenance activities on your company's machines. To avoid introducing additional vulnerability into the systems you are maintaining, you make sure that all maintenance tools are approved and their usage is monitored and controlled [a,b]. You ensure the tools are kept current and up-to-date [a]. You and your backup are the only people authorized to use these tools and perform system maintenance [d]."
            },
            {
                "requirement_id": "MA.L2-3.7.3", "title": "Equipment Sanitization", "domain": "MA",
                "description": "Ensure equipment removed for off-site maintenance is sanitized of any CUI.",
                "guidance": "Implement procedures to sanitize equipment containing CUI before sending it off-site for maintenance.",
                "assessment_objectives": "[a] equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI.",
                "examples": "Example\nYou manage your organization's IT equipment. A recent DoD project has been using a storage array to house CUI. Recently, the array has experienced disk issues. After troubleshooting with the vendor, they recommend several drives be replaced in the array. Knowing the drives may contain CUI, you reference NIST 800-88 Rev. 1 and determine a strategy you can implement on the defective equipment – processing the drives with a degaussing unit [a]. Once all the drives have been wiped, you document the action and ship the faulty drives to the vendor."
            },
            {
                "requirement_id": "MA.L2-3.7.4", "title": "Media Inspection", "domain": "MA",
                "description": "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.",
                "guidance": "Scan all diagnostic and test media for malware before using them on organizational systems.",
                "assessment_objectives": "[a] media containing diagnostic and test programs are checked for malicious code before being used in organizational systems that process, store, or transmit CUI.",
                "examples": "Example\nYou have recently been experiencing performance issues on one of your servers. After troubleshooting for much of the morning, the vendor has asked to install a utility that will collect more data from the server. The file is stored on the vendor's FTP server. The support technician gives you the FTP site so you can anonymously download the utility file. You also ask him for a hash of the utility file. As you download the file to your local computer, you realize it is compressed. You unzip the file and perform a manual antivirus scan, which reports no issues [a]. To verify the utility file has not been altered, you run an application to see that the hash from the vendor matches."
            },
            {
                "requirement_id": "MA.L2-3.7.5", "title": "Nonlocal Maintenance", "domain": "MA",
                "description": "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.",
                "guidance": "Implement MFA for remote maintenance sessions and ensure proper session termination.",
                "assessment_objectives": "[a] multifactor authentication is used to establish nonlocal maintenance sessions via external network connections; and\n[b] nonlocal maintenance sessions established via external network connections are terminated when nonlocal maintenance is complete.",
                "examples": "Example\nYou are responsible for maintaining your company's firewall. In order to conduct maintenance while working remotely, you connect to the firewall's management interface and log in using administrator credentials. The firewall then sends a verification request to the multifactor authentication app on your smartphone [a]. You need both of these things to prove your identity [a]. After you respond to the multifactor challenge, you have access to the maintenance interface. When you finish your activities, you shut down the remote connection by logging out and quitting your web browser [b]."
            },
            {
                "requirement_id": "MA.L2-3.7.6", "title": "Maintenance Personnel", "domain": "MA",
                "description": "Supervise the maintenance activities of maintenance personnel without required access authorization.",
                "guidance": "Ensure all maintenance personnel have proper authorization and supervise their activities.",
                "assessment_objectives": "[a] maintenance personnel without required access authorization are supervised during maintenance activities.",
                "examples": "Example\nOne of your software providers has to come on-site to update the software on your company's computers. You give the individual a temporary logon and password that expires in 12 hours and is limited to accessing only the computers necessary to complete the work [a]. This gives the technician access long enough to perform the update. You monitor the individual's physical and network activity while the maintenance is taking place [a] and revoke access when the job is done."
            },
            # Media Protection (MP) Requirements
            {
                "requirement_id": "MP.L2-3.8.1", "title": "Media Protection", "domain": "MP",
                "description": "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.",
                "guidance": "Implement physical and logical controls to protect media containing CUI from unauthorized access or theft.",
                "assessment_objectives": "[a] paper media containing CUI is physically controlled;\n[b] digital media containing CUI is physically controlled;\n[c] paper media containing CUI is securely stored; and\n[d] digital media containing CUI is securely stored.",
                "examples": "Example\nYour company has CUI for a specific Army contract contained on a USB drive. You store the drive in a locked drawer, and you log it on an inventory [d]. You establish a procedure to check out the USB drive so you have a history of who is accessing it. These procedures help to maintain the confidentiality, integrity, and availability of the data."
            },
            {
                "requirement_id": "MP.L2-3.8.2", "title": "Media Access", "domain": "MP",
                "description": "Limit access to CUI on system media to authorized users.",
                "guidance": "Implement access controls to ensure only authorized users can access media containing CUI.",
                "assessment_objectives": "[a] access to CUI on system media is limited to authorized users.",
                "examples": "Example\nYour company has CUI for a specific Army contract contained on a USB drive. In order to control the data, you establish specific procedures for handling the drive. You designate the project manager as the owner of the data and require anyone who needs access to the data to get permission from the data owner [a]. The data owner maintains a list of users that are authorized to access the information. Before an authorized individual can get access to the USB drive that contains the CUI they have to fill out a log and check out the drive. When they are done with the data, they check in the drive and return it to its secure storage location."
            },
            {
                "requirement_id": "MP.L2-3.8.3", "title": "Media Disposal [CUI Data]", "domain": "MP",
                "description": "Sanitize or destroy system media containing CUI before disposal or release for reuse.",
                "guidance": "For any media containing CUI (e.g., paper, USB drives, hard drives), either physically destroy it or use a secure sanitization process to erase the data before disposal or reuse.",
                "assessment_objectives": "[a] system media containing CUI is sanitized or destroyed before disposal; and\n[b] system media containing CUI is sanitized before it is released for reuse.",
                "examples": "Example\nAs you pack for an office move, you find some old CDs in a file cabinet. You determine that one has information about an old project your company did for the DoD. You shred the CD rather than simply throwing it in the trash [a]."
            },
            {
                "requirement_id": "MP.L2-3.8.4", "title": "Media Markings", "domain": "MP",
                "description": "Mark media with necessary CUI markings and distribution limitations.",
                "guidance": "Ensure all media containing CUI is properly marked with appropriate classification and distribution limitations.",
                "assessment_objectives": "[a] media containing CUI is marked with applicable CUI markings; and\n[b] media containing CUI is marked with distribution limitations.",
                "examples": "Example\nYou were recently contacted by the project team for a new DoD program. The team said they wanted the CUI in use for the program to be properly protected. When speaking with them, you realize that most of the protections will be provided as part of existing enterprise cybersecurity capabilities. They also mentioned that the project team will use several USB drives to share specific data. You explain that the team must ensure the USB drives are externally marked to indicate the presence of CUI [a]. The project team labels the outside of each USB drive with an appropriate CUI label following NARA guidance [a]. Further, the labels indicate that distribution is limited to those employees supporting the DoD program [a]."
            },
            {
                "requirement_id": "MP.L2-3.8.5", "title": "Media Accountability", "domain": "MP",
                "description": "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.",
                "guidance": "Implement tracking and accountability measures for media containing CUI during transport and storage.",
                "assessment_objectives": "[a] access to media containing CUI is controlled; and\n[b] accountability for media containing CUI is maintained during transport outside of controlled areas.",
                "examples": "Example\nYour team has recently completed configuring a server for a DoD customer. The customer has asked that it be ready to plug in and use. An application installed on the server contains data that is considered CUI. You box the server for shipment using tamper-evident packaging and label it with the specific recipient for the shipment [b]. You select a reputable shipping service so you will get a tracking number to monitor the progress. Once the item is shipped, you send the recipients the tracking number so they can monitor and ensure prompt delivery at their facility."
            },
            {
                "requirement_id": "MP.L2-3.8.6", "title": "Portable Storage Encryption", "domain": "MP",
                "description": "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.",
                "guidance": "Use encryption to protect CUI on portable storage devices during transport, or implement alternative physical safeguards.",
                "assessment_objectives": "[a] the confidentiality of CUI stored on digital media is protected during transport using cryptographic mechanisms or alternative physical safeguards.",
                "examples": "Example\nYou manage the backups for file servers in your datacenter. You know that in addition to the company's sensitive information, CUI is stored on the file servers. As part of a broader plan to protect data, you send the backup tapes off site to a vendor. You are aware that your backup software provides the option to encrypt data onto tape. You develop a plan to test and enable backup encryption for the data sent off site. This encryption provides additional protections for the data on the backup tapes during transport and offsite storage [a]."
            },
            {
                "requirement_id": "MP.L2-3.8.7", "title": "Removeable Media", "domain": "MP",
                "description": "Control the use of removable media on system components.",
                "guidance": "Implement controls to limit and monitor the use of removable media on organizational systems.",
                "assessment_objectives": "[a] the use of removable media on system components is controlled.",
                "examples": "Example\nYou are in charge of IT operations. You establish a policy for removable media that includes USB drives [a]. The policy information such as:\n\n• only USB drives issued by the organization may be used; and\n• USB drives are to be used for work purposes only [a].\n\nYou set up a separate computer to scan these drives before anyone uses them on the network. This computer has anti-virus software installed that is kept up to date."
            },
            {
                "requirement_id": "MP.L2-3.8.8", "title": "Shared Media", "domain": "MP",
                "description": "Prohibit the use of portable storage devices when such devices have no identifiable owner.",
                "guidance": "Implement policies to prevent the use of unowned or unidentified portable storage devices.",
                "assessment_objectives": "[a] the use of portable storage devices is prohibited when such devices have no identifiable owner.",
                "examples": "Example\nYou are the IT manager. One day, a staff member reports finding a USB drive in the parking lot. You investigate and learn that there are no labels on the outside of the drive to indicate who might be responsible for it. You send an email to all employees to remind them that IT policies expressly prohibit plugging unknown devices into company computers. You also direct staff members to turn in to the IT help desk any devices that have no identifiable owner [a]."
            },
            {
                "requirement_id": "MP.L2-3.8.9", "title": "Protect Backups", "domain": "MP",
                "description": "Protect the confidentiality of backup CUI at storage locations.",
                "guidance": "Implement appropriate security controls to protect backup media containing CUI at storage locations.",
                "assessment_objectives": "[a] the confidentiality of backup CUI is protected at storage locations.",
                "examples": "Example\nYou are in charge of protecting CUI for your company. Because the company's backups contain CUI, you work with IT to protect the confidentiality of backup data. You agree to encrypt all CUI data as it is saved to an external hard drive [a]."
            },
            # Personnel Security (PS) Requirements
            {
                "requirement_id": "PS.L2-3.9.1", "title": "Screen Individuals", "domain": "PS",
                "description": "Screen individuals prior to authorizing access to organizational systems containing CUI.",
                "guidance": "Conduct background checks and security screenings for personnel who will have access to systems containing CUI.",
                "assessment_objectives": "[a] individuals are screened prior to authorizing access to organizational systems containing CUI.",
                "examples": "Example\nYou are in charge of security at your organization. You complete standard criminal background and credit checks of all individuals you hire before they can access CUI [a]. Your screening program follows appropriate laws, policies, regulations, and criteria for the level of access required for each position."
            },
            {
                "requirement_id": "PS.L2-3.9.2", "title": "Personnel Actions", "domain": "PS",
                "description": "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers.",
                "guidance": "Implement procedures to revoke access and protect systems when personnel leave or change roles.",
                "assessment_objectives": "[a] a policy and/or process for terminating system access and any credentials coincident with personnel actions is established;\n[b] system access and credentials are terminated consistent with personnel actions such as termination or transfer; and\n[c] the system is protected during and after personnel transfer actions.",
                "examples": "Example 1\nYou are in charge of IT operations. Per organizational policies, when workers leave the company, you remove them from any physical CUI access lists. If you are not their supervisor, you contact their supervisor or human resources immediately and ask them to:\n\n• turn in the former employees' computers for proper handling;\n• inform help desk or system administrators to have the former employees' system access revoked;\n• retrieve the former employees' identification and access cards; and\n• have the former employees attend an exit interview where you or human resources remind them of their obligations to not discuss CUI [b].\n\nExample 2\nAn employee transfers from one working group in your company to another. Human resources team notifies IT of the transfer date, and the employee's new manager follows procedure by submitting a ticket to the IT help desk to provide information on the access rights the employee will require in their new role. IT implements the rights for the new position and revokes the access for the prior position on the official date of the transfer [c]."
            },
            # Physical Protection (PE) Requirements
            {
                "requirement_id": "PE.L2-3.10.1", "title": "Limit Physical Access [CUI Data]", "domain": "PE",
                "description": "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.",
                "guidance": "Use locks, card readers, or other physical controls to restrict access to offices, server rooms, and equipment. Maintain a list of personnel with authorized physical access.",
                "assessment_objectives": "[a] authorized individuals allowed physical access are identified;\n[b] physical access to organizational systems is limited to authorized individuals;\n[c] physical access to equipment is limited to authorized individuals; and\n[d] physical access to operating environments is limited to authorized individuals.",
                "examples": "Example\nYou manage a DoD project that requires special equipment used only by project team members [b,c]. You work with the facilities manager to put locks on the doors to the areas where the equipment is stored and used [b,c,d]. Project team members are the only individuals issued with keys to the space. This restricts access to only those employees who work on the DoD project and require access to that equipment."
            },
            {
                "requirement_id": "PE.L2-3.10.2", "title": "Monitor Facility", "domain": "PE",
                "description": "Protect and monitor the physical facility and support infrastructure for organizational systems.",
                "guidance": "Implement physical security measures including surveillance, alarms, and environmental controls to protect facilities and infrastructure.",
                "assessment_objectives": "[a] the physical facility where organizational systems reside is protected;\n[b] the support infrastructure for organizational systems is protected;\n[c] the physical facility where organizational systems reside is monitored; and\n[d] the support infrastructure for organizational systems is monitored.",
                "examples": "Example\nYou are responsible for protecting your IT facilities. You install video cameras at each entrance and exit, connect them to a video recorder, and show the camera feeds on a display at the reception desk [c,d]. You also make sure there are secure locks on all entrances, exits, and windows to the facilities [a,b]."
            },
            {
                "requirement_id": "PE.L2-3.10.3", "title": "Escort Visitors [CUI Data]", "domain": "PE",
                "description": "Escort visitors and monitor visitor activity.",
                "guidance": "Ensure all visitors are escorted by an employee at all times within the facility and wear visitor identification.",
                "assessment_objectives": "[a] visitors are escorted; and\n[b] visitor activity is monitored.",
                "examples": "Example\nComing back from a meeting, you see the friend of a coworker walking down the hallway near your office. You know this person well and trust them, but are not sure why they are in the building. You stop to talk, and the person explains that they are meeting a coworker for lunch, but cannot remember where the lunchroom is. You walk the person back to the reception area to get a visitor badge and wait until someone can escort them to the lunch room [a]. You report this incident and the company decides to install a badge reader at the main door so visitors cannot enter without an escort [a]."
            },
            {
                "requirement_id": "PE.L2-3.10.4", "title": "Physical Access Logs [CUI Data]", "domain": "PE",
                "description": "Maintain audit logs of physical access.",
                "guidance": "Use a sign-in sheet or electronic system to log all individuals entering and leaving the facility. Retain these logs for a defined period.",
                "assessment_objectives": "[a] audit logs of physical access are maintained.",
                "examples": "Example\nYou and your coworkers like to have friends and family join you for lunch at the office on Fridays. Your small company has just signed a contract with the DoD, however, and you now need to document who enters and leaves your facility. You work with the reception staff to ensure that all non-employees sign in at the reception area and sign out when they leave [a]. You retain those paper sign-in sheets in a locked filing cabinet for one year. Employees receive badges or key cards that enable tracking and logging access to company facilities."
            },
            {
                "requirement_id": "PE.L2-3.10.5", "title": "Manage Physical Access [CUI Data]", "domain": "PE",
                "description": "Control and manage physical access devices.",
                "guidance": "Keep an inventory of all physical access devices like keys and key cards. Know who has them, and revoke access when personnel leave or change roles.",
                "assessment_objectives": "[a] physical access devices are identified;\n[b] physical access devices are controlled; and\n[c] physical access devices are managed.",
                "examples": "Example\nYou are a facility manager. A team member retired today and returns their company keys to you. The project on which they were working requires access to areas that contain equipment with CUI. You receive the keys, check your electronic records against the serial numbers on the keys to ensure all have been returned, and mark each key returned [c]."
            },
            {
                "requirement_id": "PE.L2-3.10.6", "title": "Alternative Work Sites", "domain": "PE",
                "description": "Enforce safeguarding measures for CUI at alternate work sites.",
                "guidance": "Implement security measures to protect CUI at remote work locations and alternative work sites.",
                "assessment_objectives": "[a] safeguarding measures for CUI are defined for alternate work sites; and\n[b] safeguarding measures for CUI are enforced for alternate work sites.",
                "examples": "Example\nMany of your company's project managers work remotely as they often travel to sponsor locations or even work from home. Because the projects on which they work require access to CUI, you must ensure the same level of protection is afforded as when they work in the office. You ensure that each laptop is deployed with patch management and anti-virus software protection [b]. Because data may be stored on the local hard drive, you have enabled full-disk encryption on their laptops [b]. When a remote staff member needs access to the internal network you require VPN connectivity that also disconnects the laptop from the remote network (i.e., prevents split tunneling) [b]. The VPN requires multifactor authentication to verify remote users are who they claim to be [b]."
            },
            # Risk Assessment (RA) Requirements
            {
                "requirement_id": "RA.L2-3.11.1", "title": "Risk Assessments", "domain": "RA",
                "description": "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI.",
                "guidance": "Conduct regular risk assessments to identify and evaluate risks to organizational operations, assets, and individuals from system operations and CUI handling.",
                "assessment_objectives": "[a] the frequency to assess risk to organizational operations, organizational assets, and individuals is defined; and\n[b] risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizational system that processes, stores, or transmits CUI is assessed with the defined frequency.",
                "examples": "Example\nYou are a system administrator. You and your team members are working on a big government contract requiring you to store CUI. As part of your periodic (e.g., annual) risk assessment exercise, you evaluate the new risk involved with storing CUI [a,b]. When conducting the assessment you consider increased legal exposure, financial requirements of safeguarding CUI, potentially elevated attention from external attackers, and other factors. After determining how storing CUI affects your overall risk profile, you use that as a basis for a conversation on how that risk should be mitigated."
            },
            {
                "requirement_id": "RA.L2-3.11.2", "title": "Vulnerability Scan", "domain": "RA",
                "description": "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.",
                "guidance": "Implement regular vulnerability scanning of systems and applications, and conduct additional scans when new vulnerabilities are discovered.",
                "assessment_objectives": "[a] the frequency to scan for vulnerabilities in organizational systems and applications is defined;\n[b] vulnerability scans are performed on organizational systems with the defined frequency;\n[c] vulnerability scans are performed on applications with the defined frequency;\n[d] vulnerability scans are performed on organizational systems when new vulnerabilities are identified; and\n[e] vulnerability scans are performed on applications when new vulnerabilities are identified.",
                "examples": "Example\nYou are a system administrator. Your organization has assessed its risk and determined that it needs to scan for vulnerabilities in systems and applications once each quarter [a]. You conduct some tests and decide that it is important to be able to schedule scans after standard business hours. You also realize that you have remote workers and that you will need to be sure to scan their remote computers as well [b]. After some final tests, you integrate the scans into normal IT operations, running as scheduled [b,c]. You verify that the scanner application receives the latest updates on vulnerabilities and that those are included in future scans [d,e]."
            },
            {
                "requirement_id": "RA.L2-3.11.3", "title": "Vulnerability Remediation", "domain": "RA",
                "description": "Remediate vulnerabilities in accordance with risk assessments.",
                "guidance": "Implement a process to prioritize and remediate vulnerabilities based on risk assessment results and organizational priorities.",
                "assessment_objectives": "[a] vulnerabilities are identified; and\n[b] vulnerabilities are remediated in accordance with risk assessments.",
                "examples": "Example\nYou are a system administrator. Each quarter you receive a list of vulnerabilities generated by your company's vulnerability scanner [a]. You prioritize that list and note which vulnerabilities should be targeted as soon as possible as well as which vulnerabilities you can safely defer addressing at this time. You document the reasoning behind accepting the risk of the unremediated flaws and note to continue to monitor these vulnerabilities in case you need to revise the decision at a later date [b]."
            },
            # Security Assessment (CA) Requirements
            {
                "requirement_id": "CA.L2-3.12.1", "title": "Security Control Assessment", "domain": "CA",
                "description": "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.",
                "guidance": "Conduct regular assessments of security controls to ensure they are functioning effectively and meeting security requirements.",
                "assessment_objectives": "[a] the frequency of security control assessments is defined; and\n[b] security controls are assessed with the defined frequency to determine if the controls are effective in their application.",
                "examples": "Example\nYou are in charge of IT operations. You need to ensure that the security controls implemented within the system are achieving their objectives [b]. Taking the requirements outlined in your SSP as a guide, you conduct annual written reviews of the security controls to ensure they meet your organization's needs. When you find controls that do not meet requirements, you propose updated or new controls, develop a written implementation plan, document new risks, and execute the changes."
            },
            {
                "requirement_id": "CA.L2-3.12.2", "title": "Operational Plan of Action", "domain": "CA",
                "description": "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.",
                "guidance": "Create and execute remediation plans to address security deficiencies and vulnerabilities identified during assessments.",
                "assessment_objectives": "[a] deficiencies and vulnerabilities to be addressed by the plan of action are identified;\n[b] a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities; and\n[c] the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities.",
                "examples": "Example\nAs IT director, one of your duties is to develop action plans when you discover that your company is not meeting security requirements or when a security issue arises [b]. A recent vulnerability scan identified several items that need to be addressed so you develop a plan to fix them [b]. Your plan identifies the people responsible for fixing the issues, how to do it, and when the remediation will be completed [b]. You also define how to verify that the person responsible has fixed the vulnerability [b]. You document this in an operational plan of action that is updated as milestones are reached [b]. You have a separate resource review the modifications after they have been completed to ensure the plan has been implemented correctly [c]."
            },
            {
                "requirement_id": "CA.L2-3.12.3", "title": "Security Control Monitoring", "domain": "CA",
                "description": "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.",
                "guidance": "Implement continuous monitoring of security controls to ensure they remain effective over time.",
                "assessment_objectives": "[a] security controls are monitored on an ongoing basis to ensure the continued effectiveness of those controls.",
                "examples": "Example\nYou are responsible for ensuring your company fulfills all cybersecurity requirements for its DoD contracts. You review those requirements and the security controls your company has put in place to meet them. You then create a plan to evaluate each control regularly over the next year. You mark several controls to be evaluated by a third-party security assessor. You assign other IT resources in the organization to evaluate controls within their area of responsibility. To ensure progress you establish recurring meetings with the accountable IT staff to assess continuous monitoring progress, review security information, evaluate risks from gaps in continuous monitoring, and produce reports for your management [a]."
            },
            {
                "requirement_id": "CA.L2-3.12.4", "title": "System Security Plan", "domain": "CA",
                "description": "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.",
                "guidance": "Create comprehensive system security plans that document all aspects of system security implementation and operation.",
                "assessment_objectives": "[a] a system security plan is developed;\n[b] the system boundary is described and documented in the system security plan;\n[c] the system environment of operation is described and documented in the system security plan;\n[d] the security requirements identified and approved by the designated authority as non-applicable are identified;\n[e] the method of security requirement implementation is described and documented in the system security plan;\n[f] the relationship with or connection to other systems is described and documented in the system security plan;\n[g] the frequency to update the system security plan is defined; and\n[h] system security plan is updated with the defined frequency.",
                "examples": "Example\nYou are in charge of system security. You develop an SSP and have senior leadership formally approve the document [a]. The SSP explains how your organization handles CUI and defines how that data is stored, transmitted, and protected [d,e]. The criteria outlined in the SSP is used to guide configuration of the network and other information resources to meet your company's goals. Knowing that it is important to keep the SSP current, you establish a policy that requires a formal review and update of the SSP each year [g,h]."
            },
            # System and Communications Protection (SC) Requirements
            {
                "requirement_id": "SC.L2-3.13.1", "title": "Boundary Protection [CUI Data]", "domain": "SC",
                "description": "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.",
                "guidance": "Use firewalls to protect the boundary between your internal network and the internet, blocking unwanted traffic and malicious websites.",
                "assessment_objectives": "[a] the external system boundary is defined;\n[b] key internal system boundaries are defined;\n[c] communications are monitored at the external system boundary;\n[d] communications are monitored at key internal boundaries;\n[e] communications are controlled at the external system boundary;\n[f] communications are controlled at key internal boundaries;\n[g] communications are protected at the external system boundary; and\n[h] communications are protected at key internal boundaries.",
                "examples": "Example\nYou are setting up the new network and want to keep your company's information and resources safe. You start by sketching out a simple diagram that identifies the external boundary of your network and any internal boundaries that are needed [a,b]. The first piece of equipment you install is the firewall, a device to separate your internal network from the internet. The firewall also has a feature that allows you to block access to potentially malicious websites, and you configure that service as well [a,c,e,g]. Some of your coworkers complain that they cannot get onto certain websites [c,e,g]. You explain that the new network blocks websites that are known for spreading malware. The firewall sends you a daily digest of blocked activity so that you can monitor the system for attack trends [c,d]."
            },
            {
                "requirement_id": "SC.L2-3.13.2", "title": "Security Engineering", "domain": "SC",
                "description": "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.",
                "guidance": "Implement security-by-design principles throughout the system development lifecycle to build security into systems from the ground up.",
                "assessment_objectives": "[a] architectural designs that promote effective information security are identified;\n[b] software development techniques that promote effective information security are identified;\n[c] systems engineering principles that promote effective information security are identified;\n[d] identified architectural designs that promote effective information security are employed;\n[e] identified software development techniques that promote effective information security are employed; and\n[f] identified systems engineering principles that promote effective information security are employed.",
                "examples": "Example\nYou are responsible for developing strategies to protect data and harden your infrastructure. You are on a team responsible for performing a major upgrade to a legacy system. You refer to your documented security engineering principles [c]. Reviewing each, you decide which are appropriate and applicable [c]. You apply the chosen designs and principles when creating your design for the upgrade [f].\n\nYou document the security requirements for the software and hardware changes to ensure the principles are followed. You review the upgrade at critical points in the workflow to ensure the requirements are met. You assist in updating the policies covering the use of the upgraded system so user behavior stays aligned with the principles."
            },
            {
                "requirement_id": "SC.L2-3.13.3", "title": "Role Separation", "domain": "SC",
                "description": "Separate user functionality from system management functionality.",
                "guidance": "Implement role separation to prevent users from accessing system management functions and vice versa.",
                "assessment_objectives": "[a] user functionality is identified;\n[b] system management functionality is identified; and\n[c] user functionality is separated from system management functionality.",
                "examples": "Example\nAs a system administrator, you are responsible for managing a number of core systems. Policy prevents you from conducting any administration from the computer or system account you use for day-to-day work [a,b]. The servers you manage also are isolated from the main corporate network. To work with them you use a special unique account to connect to a \"jump\" server that has access to the systems you routinely administer."
            },
            {
                "requirement_id": "SC.L2-3.13.4", "title": "Shared Resource Control", "domain": "SC",
                "description": "Prevent unauthorized and unintended information transfer via shared system resources.",
                "guidance": "Implement controls to prevent information leakage through shared system resources like memory, storage, and network interfaces.",
                "assessment_objectives": "[a] unauthorized and unintended information transfer via shared system resources is prevented.",
                "examples": "Example\nYou are a system administrator responsible for creating and deploying the system hardening procedures for your company's computers. You ensure that the computer baselines include software patches to prevent attackers from exploiting flaws in the processor architecture to read data (e.g., the Meltdown and Spectre exploits). You also verify that the computer operating system is configured to prevent users from accessing other users' folders [a]."
            },
            {
                "requirement_id": "SC.L2-3.13.5", "title": "Public-Access System Separation [CUI Data]", "domain": "SC",
                "description": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
                "guidance": "Isolate publicly accessible systems (like a public website) from your internal network using a demilitarized zone (DMZ) or separate VLAN.",
                "assessment_objectives": "[a] publicly accessible system components are identified; and\n[b] subnetworks for publicly accessible system components are physically or logically separated from internal networks.",
                "examples": "Example\nThe head of recruiting at your company wants to launch a website to post job openings and allow the public to download an application form [a]. After some discussion, your team realizes it needs to use a firewall to create a perimeter network to do this [b]. You host the server separately from the company's internal network and make sure the network on which it resides is isolated with the proper firewall rules [b]."
            },
            {
                "requirement_id": "SC.L2-3.13.6", "title": "Network Communication by Exception", "domain": "SC",
                "description": "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).",
                "guidance": "Implement default-deny network policies that only allow explicitly authorized network communications.",
                "assessment_objectives": "[a] network communications traffic is denied by default; and\n[b] network communications traffic is allowed by exception.",
                "examples": "Example\nYou are setting up a new environment to house CUI. To properly isolate the CUI network, you install a firewall between it and other networks and set the firewall rules to deny all traffic [a]. You review each service and application that runs in the new environment and determine that you only need to allow http and https traffic outbound [b]. You test the functionality of the required services and make some needed adjustments, then comment each firewall rule so there is documentation of why it is required. You review the firewall rules on a regular basis to make sure no unauthorized changes were made."
            },
            {
                "requirement_id": "SC.L2-3.13.7", "title": "Split Tunneling", "domain": "SC",
                "description": "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).",
                "guidance": "Configure VPN and remote access systems to prevent split tunneling that could bypass security controls.",
                "assessment_objectives": "[a] remote devices are prevented from simultaneously establishing non-remote connections with the system and communicating via some other connection to resources in external networks (i.e., split tunneling).",
                "examples": "Example\nYou are a system administrator responsible for configuring the network to prevent remote users from using split tunneling. You review the configuration of remote user laptops. You discover that remote users are able to access files, email, database and other services through the VPN connection while also being able to print and access resources on their local network. You change the configuration settings for all company computers to disable split tunneling [a]. You test a laptop that has had the new hardening procedures applied and verify that all traffic from the laptop is now routed through the VPN connection."
            },
            {
                "requirement_id": "SC.L2-3.13.8", "title": "Data in Transit", "domain": "SC",
                "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.",
                "guidance": "Use encryption to protect CUI during transmission over networks, or implement alternative physical safeguards.",
                "assessment_objectives": "[a] cryptographic mechanisms intended to prevent unauthorized disclosure of CUI are identified;\n[b] alternative physical safeguards intended to prevent unauthorized disclosure of CUI are identified; and\n[c] either cryptographic mechanisms or alternative physical safeguards are implemented to prevent unauthorized disclosure of CUI during transmission.",
                "examples": "Example\nYou are a system administrator responsible for configuring encryption on all devices that contain CUI. Because your users regularly store CUI on laptops and take them out of the office, you encrypt the hard drives with a FIPS-validated encryption tool built into the operating system. For users who need to share CUI, you install a Secure FTP server to allow CUI to be transmitted in a compliant manner [a]. You verify that the server is using a FIPS-validated encryption module by checking the NIST Cryptographic Module Validation Program website [c]. You turn on the \"FIPS Compliance\" setting for the server during configuration because that is what is required for this product in order to use only FIPS-validated cryptography [c]."
            },
            {
                "requirement_id": "SC.L2-3.13.9", "title": "Connections Termination", "domain": "SC",
                "description": "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.",
                "guidance": "Implement automatic termination of network connections when sessions end or after periods of inactivity.",
                "assessment_objectives": "[a] a period of inactivity to terminate network connections associated with communications sessions is defined;\n[b] network connections associated with communications sessions are terminated at the end of the sessions; and\n[c] network connections associated with communications sessions are terminated after the defined period of inactivity.",
                "examples": "Example\nYou are an administrator of a server that provides remote access. Your company's policies state that network connections must be terminated after being idle for 60 minutes [a]. You edit the server configuration file and set the timeout to 60 minutes and restart the remote access software [c]. You test the software and verify that the connection is terminated appropriately."
            },
            {
                "requirement_id": "SC.L2-3.13.10", "title": "Key Management", "domain": "SC",
                "description": "Establish and manage cryptographic keys for cryptography employed in organizational systems.",
                "guidance": "Implement proper key management practices including key generation, distribution, storage, rotation, and destruction.",
                "assessment_objectives": "[a] cryptographic keys are established whenever cryptography is employed; and\n[b] cryptographic keys are managed whenever cryptography is employed.",
                "examples": "Example 1\nYou are a system administrator responsible for providing key management. You have generated a public-private key pair to exchange CUI [a]. You require all system administrators to read the key management policy before you allow them to install the private key on their machines [b]. No one else is allowed to know or have a copy of the private key per the policy. You provide the public key to the other parties who will be sending you CUI and test the Public Key Infrastructure (PKI) to ensure the encryption is working [a]. You set a revocation period of one year on all your certificates per organizational policy [b].\n\nExample 2\nYou encrypt all of your company's computers using the disk encryption utility built into the operating system. As you configure encryption on each device, it generates a cryptographic key. You associate each key with the correct computer in your inventory spreadsheet and restrict access to the spreadsheet to the system administrators whose work role requires them to manage the computers [b]."
            },
            {
                "requirement_id": "SC.L2-3.13.11", "title": "CUI Encryption", "domain": "SC",
                "description": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
                "guidance": "Use only FIPS-validated cryptographic algorithms and implementations when protecting CUI.",
                "assessment_objectives": "[a] FIPS-validated cryptography is employed to protect the confidentiality of CUI.",
                "examples": "Example\nYou are a system administrator responsible for deploying encryption on all devices that contain CUI. You must ensure that the encryption you use on the devices is FIPS-validated cryptography [a]. An employee informs you of a need to carry a large volume of CUI offsite and asks for guidance on how to do so. You provide the user with disk encryption software that you have verified via the NIST website that uses a CMVP-validated encryption module [a]. Once the encryption software is active, the user copies the CUI data onto the drive for transport."
            },
            {
                "requirement_id": "SC.L2-3.13.12", "title": "Collaborative Device Control", "domain": "SC",
                "description": "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.",
                "guidance": "Implement controls to prevent unauthorized remote activation of collaborative devices and provide clear indicators when devices are in use.",
                "assessment_objectives": "[a] collaborative computing devices are identified;\n[b] collaborative computing devices provide indication to users of devices in use; and\n[c] remote activation of collaborative computing devices is prohibited.",
                "examples": "Example\nA group of remote employees at your company routinely collaborate using cameras and microphones attached to their computers [a]. To prevent the misuse of these devices, you disable the ability to turn on cameras or microphones remotely [c]. You ensure the machines alert users when the camera or microphone are in use with a light beside the camera and an onscreen notification [b]. Although remote activation is blocked, this enables users to see if the devices are active."
            },
            {
                "requirement_id": "SC.L2-3.13.13", "title": "Mobile Code", "domain": "SC",
                "description": "Control and monitor the use of mobile code.",
                "guidance": "Implement controls to restrict and monitor the execution of mobile code like JavaScript, Java applets, and ActiveX controls.",
                "assessment_objectives": "[a] use of mobile code is controlled; and\n[b] use of mobile code is monitored.",
                "examples": "Example\nYour company has decided to prohibit the use of Flash, ActiveX, and Java plug-ins for web browsers on all of its computers [a]. To enforce this policy you configure the computer baseline configuration to disable and deny the execution of mobile code [a]. You implement an exception process to re-enable mobile code execution only for those users with a legitimate business need [a].\n\nOne department complains that a web application they need to perform their job no longer works. You meet with them and verify that the web application uses ActiveX in the browser. You submit a change request with the Change Review Board. Once the change is approved, you reconfigure the department's computers to allow the running of ActiveX in the browser. You also configure the company firewall to alert you if ActiveX is used by any website but the allowed one [b]. You set a reminder for yourself to check in with the department at the end of the year to verify they still need that web application."
            },
            {
                "requirement_id": "SC.L2-3.13.14", "title": "Voice over Internet Protocol", "domain": "SC",
                "description": "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.",
                "guidance": "Implement security controls for VoIP systems to prevent unauthorized access and monitor usage.",
                "assessment_objectives": "[a] use of Voice over Internet Protocol (VoIP) technologies is controlled; and\n[b] use of Voice over Internet Protocol (VoIP) technologies is monitored.",
                "examples": "Example\nYou are a system administrator responsible for the VoIP system. You configure VoIP for new users after being notified that they have signed the Acceptable Use Policy for VoIP technology [a]. You verify that the VoIP solution is configured to use encryption and have enabled requirements for passwords on voice mailboxes and on phone extension management. You require phone system administrators to log in using multifactor authentication when managing the system [a]. You add the VoIP software to the list of applications that are patched monthly as needed [a,b]. Finally, you configure the VoIP system to send logs to your log aggregator so that they can be correlated with those from other systems and examined for signs of suspicious activity [b]."
            },
            {
                "requirement_id": "SC.L2-3.13.15", "title": "Communications Authenticity", "domain": "SC",
                "description": "Protect the authenticity of communications sessions.",
                "guidance": "Implement mechanisms to verify the authenticity of communications sessions and prevent session hijacking.",
                "assessment_objectives": "[a] the authenticity of communications sessions is protected.",
                "examples": "Example\nYou are a system administrator responsible for ensuring that the two-factor user authentication mechanism for the servers is configured correctly. You purchase and maintain the digital certificate and replace it with a new one before the old one expires. You ensure the TLS configuration settings on the web servers, VPN solution, and other components that use TLS are correct, using secure settings that address risks against attacks on the encrypted sessions [a]."
            },
            {
                "requirement_id": "SC.L2-3.13.16", "title": "Data at Rest", "domain": "SC",
                "description": "Protect the confidentiality of CUI at rest.",
                "guidance": "Use encryption to protect CUI stored on systems and storage devices.",
                "assessment_objectives": "[a] the confidentiality of CUI at rest is protected.",
                "examples": "Example 1\nYour company has a policy stating CUI must be protected at rest and you work to enforce that policy. You research Full Disk Encryption (FDE) products that meet the FIPS encryption requirement. After testing, you deploy the encryption to all computers to protect CUI at rest [a].\n\nExample 2\nYou have used encryption to protect the CUI on most of the computers at your company, but you have some devices that do not support encryption. You create a policy requiring these devices to be signed out when needed, stay in possession of the signer when checked out, and to be signed back in and locked up in a secured closet when the user is done with the device [a]. At the end of the day each Friday, you audit the sign-out sheet and make sure all devices are returned to the closet."
            },
            # System and Information Integrity (SI) Requirements
            {
                "requirement_id": "SI.L2-3.14.1", "title": "Flaw Remediation [CUI Data]", "domain": "SI",
                "description": "Identify, report, and correct system flaws in a timely manner.",
                "guidance": "Implement a patch management process to fix software and firmware flaws within a defined timeframe based on vendor notifications.",
                "assessment_objectives": "[a] the time within which to identify system flaws is specified;\n[b] system flaws are identified within the specified time frame;\n[c] the time within which to report system flaws is specified;\n[d] system flaws are reported within the specified time frame;\n[e] the time within which to correct system flaws is specified; and\n[f] system flaws are corrected within the specified time frame.",
                "examples": "Example\nYou know that software vendors typically release patches, service packs, hot fixes, etc. and want to make sure your software is up to date. You develop a policy that requires checking vendor websites for flaw notifications every week [a]. The policy further requires that those flaws be assessed for severity and patched on end-user computers once each week and servers once each month [c,e]. Consistent with that policy, you configure the system to check for updates weekly or daily depending on the criticality of the software [b,e]. Your team reviews available updates and implements the applicable ones according to the defined schedule [f]."
            },
            {
                "requirement_id": "SI.L2-3.14.2", "title": "Malicious Code Protection [CUI Data]", "domain": "SI",
                "description": "Provide protection from malicious code at designated locations within organizational systems.",
                "guidance": "Use anti-virus and anti-malware software on workstations, servers, and firewalls to protect against malicious code like viruses and ransomware.",
                "assessment_objectives": "[a] designated locations for malicious code protection are identified; and\n[b] protection from malicious code at designated locations is provided.",
                "examples": "Example\nYou are buying a new computer and want to protect your company's information from viruses, spyware, etc. You buy and install anti-malware software [a,b]."
            },
            {
                "requirement_id": "SI.L2-3.14.3", "title": "Security Alerts & Advisories", "domain": "SI",
                "description": "Monitor system security alerts and advisories and take action in response.",
                "guidance": "Subscribe to security alert services and implement processes to respond to security advisories and alerts.",
                "assessment_objectives": "[a] response actions to system security alerts and advisories are identified;\n[b] system security alerts and advisories are monitored; and\n[c] actions in response to system security alerts and advisories are taken.",
                "examples": "Example\nYou monitor security advisories each week. You review the alert emails and online subscription service alerts to determine which ones apply [b]. You create a list of the applicable alerts and research what steps you need to take to address them. Next, you generate a plan that you review with your change management group so that the work can be scheduled [c]."
            },
            {
                "requirement_id": "SI.L2-3.14.4", "title": "Update Malicious Code Protection [CUI Data]", "domain": "SI",
                "description": "Update malicious code protection mechanisms when new releases are available.",
                "guidance": "Configure anti-malware software to update its definition files automatically and frequently (e.g., daily) to protect against the latest threats.",
                "assessment_objectives": "[a] malicious code protection mechanisms are updated when new releases are available.",
                "examples": "Example\nYou have installed anti-malware software to protect a computer from malicious code. Knowing that malware evolves rapidly, you configure the software to automatically check for malware definition updates every day and update as needed [a]."
            },
            {
                "requirement_id": "SI.L2-3.14.5", "title": "System & File Scanning [CUI Data]", "domain": "SI",
                "description": "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.",
                "guidance": "Configure anti-malware software to perform periodic full-system scans and real-time scans of files from external sources like email attachments and USB drives.",
                "assessment_objectives": "[a] the frequency for malicious code scans is defined;\n[b] malicious code scans are performed with the defined frequency; and\n[c] real-time malicious code scans of files from external sources as files are downloaded, opened, or executed are performed.",
                "examples": "Example\nYou work with your company's email provider to enable enhanced protections that will scan all attachments to identify and quarantine those that may be harmful prior to a user opening them [c]. In addition, you configure antivirus software on each computer to scan for malicious code every day [a,b]. The software also scans files that are downloaded or copied from removable media such as USB drives. It quarantines any suspicious files and notifies the security team [c]."
            },
            {
                "requirement_id": "SI.L2-3.14.6", "title": "Monitor Communications for Attacks", "domain": "SI",
                "description": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
                "guidance": "Implement network monitoring and intrusion detection systems to identify malicious activity and potential security threats.",
                "assessment_objectives": "[a] the system is monitored to detect attacks and indicators of potential attacks;\n[b] inbound communications traffic is monitored to detect attacks and indicators of potential attacks; and\n[c] outbound communications traffic is monitored to detect attacks and indicators of potential attacks.",
                "examples": "Example\nIt is your job to look for known indicators of attack or anomalous activity within your systems and communications traffic [a,b,c]. Because these indicators can show up in a variety of places on your network, you have created a checklist of places to check each week. These include the office firewall logs, the audit logs of the file server where CUI is stored, and the connection log for your VPN gateway [b].\n\nYou conduct additional reviews when you find an indicator, or something that does not perform as it should [a]."
            },
            {
                "requirement_id": "SI.L2-3.14.7", "title": "Identify Unauthorized Use", "domain": "SI",
                "description": "Identify unauthorized use of organizational systems.",
                "guidance": "Implement monitoring and detection systems to identify unauthorized access and use of organizational systems.",
                "assessment_objectives": "[a] authorized use of the system is defined; and\n[b] unauthorized use of the system is identified.",
                "examples": "Example 1\nYou are in charge of IT operations. You need to ensure that everyone using an organizational system is authorized to do so and conforms to the written authorized use policy. To do this, you deploy an application that monitors user activity and records the information for later analysis. You review the data from this application for signs of activity that does not conform to the acceptable use policy [a,b].\n\nExample 2\nYou are alerted through your Intrusion Detection System (IDS) that one of your users is connecting to a server that is from a high-risk domain (based on your commercial domain reputation service). You investigate and determine that it's not the user, but instead an unauthorized connection attempt [b]. You add the domain to your list of blocked domains to prevent connections in the future."
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
                    assessment_objectives=req_data['assessment_objectives'],
                    examples=req_data.get('examples', '')
                )
                db.session.add(requirement)

    # Add CMMC Level 3 Requirements
    if not CMMCRequirement.query.filter_by(level_id=CMMCLevel.query.filter_by(level_number=3).first().id).first():
        level_3_requirements = [
            # Access Control (AC) Requirements
            {
                "requirement_id": "AC.L3-3.1.2E", "title": "Organizationally Controlled Assets", "domain": "AC",
                "description": "Restrict access to systems and system components to only those information resources that are owned, provisioned, or issued by the organization.",
                "guidance": "Implementing this requirement ensures that an organization has control over the systems that can connect to organizational assets. This control will allow more effective and efficient application of security policy. The terms \"has control over\" provides policy for systems that are not owned outright by the organization. Control includes policies, regulations or standards that are enforced on the resource accessing contractor systems. Control may also be exercised through contracts or agreements with the external party. Provisioned includes setting configuration, whether through direct technical means or by policy or agreement. For purposes of this requirement, GFE can be considered provisioned by the OSA.",
                "assessment_objectives": "[a] Information resources that are owned, provisioned, or issued by the organization are identified; and\n[b] Access to systems and system components is restricted to only those information resources that are owned, provisioned, or issued by the organization.",
                "examples": "Example 1\nYou are the chief network architect for your company. Company policy states that all company-owned assets must be separated from all non-company-owned (i.e., guest or employee) assets. You decide the best way forward is to modify the corporate wired and wireless networks to only allow company-owned devices to connect [b]. All other devices are connected to a second (untrusted) network that non-corporate devices may use to access the internet. The two environments are physically separated and are not allowed to be connected. You also decide to limit the virtual private network (VPN) services of the company to devices owned by the corporation by installing certificate keys and have the VPN validate the configuration of connecting devices before they are allowed in [b].\n\nExample 2\nYou are a small company that uses an External Service Provider (ESP) to provide your audit logging. Access between the ESP and the organization is controlled by the agreement between the organization and the ESP. That agreement will include the policies, standards, and configuration for the required access. Technical controls should be documented and in place which limit the ESP's access to the minimum required to perform the logging service."
            },
            {
                "requirement_id": "AC.L3-3.1.3E", "title": "Secured Information Transfer", "domain": "AC",
                "description": "Employ secure information transfer solutions to control information flows between security domains on connected systems.",
                "guidance": "The organization implementing this requirement must decide on the secure information transfer solutions they will use. The solutions must be configured to have strong protection mechanisms for information flow between security domains. Secure information transfer solutions control information flow between a Level 3 enclave and other CMMC or non-CMMC enclaves. If CUI requiring Level 3 protection resides in one area of the environment or within a given enclave outside of the normal working environment, protection to prevent unauthorized personnel from accessing, disseminating, and sharing the protected information is required. Physical and virtual methods can be employed to implement secure information transfer solutions.",
                "assessment_objectives": "[ODP1] Secure information transfer solutions are defined;\n[a] Information flows between security domains on connected systems are identified; and\n[b] Secure information transfer solutions are employed to control information flows between security domains on connected systems.",
                "examples": "Example\nYou are the administrator for an enterprise that stores and processes CUI requiring Level 3 protection. The files containing CUI information are tagged by the company as CUI. To ensure secure information transfer, you use an intermediary device to check the transfer of any CUI files. The device sits at the boundary of the CUI enclave, is aware of all other CUI domains in the enterprise, and has the ability to examine the metadata in the encrypted payload. The tool checks all outbound communications paths. It first checks the metadata for all data being transferred. If that data is identified as CUI, the device checks the destination to see if the transfer is to another, sufficiently certified CUI domain. If the destination is not a sufficient CUI domain, the tool blocks the communication path and does not allow the transfer to take place. If the destination is a sufficient CUI domain, the transfer is allowed. The intermediary device logs all blocks."
            },
            # Awareness and Training (AT) Requirements
            {
                "requirement_id": "AT.L3-3.2.1E", "title": "Advanced Threat Awareness", "domain": "AT",
                "description": "Provide awareness training upon initial hire, following a significant cyber event, and at least annually, focused on recognizing and responding to threats from social engineering, advanced persistent threat actors, breaches, and suspicious behaviors; update the training at least annually or when there are significant changes to the threat.",
                "guidance": "All organizations, regardless of size, should have a cyber training program that helps employees understand threats they will face on a daily basis. This training must include knowledge about APT actors, breaches, and suspicious behaviors.",
                "assessment_objectives": "[a] Threats from social engineering, advanced persistent threat actors, breaches, and suspicious behaviors are identified;\n[b] Awareness training focused on recognizing and responding to threats from social engineering, advanced persistent threat actors, breaches, and suspicious behaviors is provided upon initial hire, following a significant cyber event, and at least annually;\n[c] Significant changes to the threats from social engineering, advanced persistent threat actors, breaches, and suspicious behaviors are identified; and\n[d] Awareness training is updated at least annually or when there are significant changes to the threat.",
                "examples": "Example\nYou are the cyber training coordinator for a small business with eight employees. You do not have your own in-house cyber training program. Instead, you use a third-party company to provide cyber training. New hires take the course when they start, and all current staff members receive refresher training at least once a year [b]. When significant changes to the threat landscape take place, the company contacts you and informs you that an update to the training has been completed [c,d] and everyone will need to receive training [b]. You keep a log of all employees who have gone through the cyber training program and the dates of training."
            },
            {
                "requirement_id": "AT.L3-3.2.2E", "title": "Practical Training Exercises", "domain": "AT",
                "description": "Include practical exercises in awareness training for all users, tailored by roles, to include general users, users with specialized roles, and privileged users, that are aligned with current threat scenarios and provide feedback to individuals involved in the training and their supervisors.",
                "guidance": "This requirement can be performed by the organization or by a third-party company. Training exercises (including unannounced exercises, such as phishing training) should be performed at various times throughout the year to encourage employee readiness. After each exercise session has been completed, the results should be recorded (date, time, what and who the training tested, and the percent of successful and unsuccessful responses). The purpose of training is to help employees in all roles act appropriately for any given training situation, which should reflect real-life scenarios. Collected results will help identify shortcomings in the cyber training and/or whether additional instructional training may be needed. General exercises can be included for all users, but exercises tailored for specific roles are important, too. Training tailored for specific roles helps make sure individuals are ready for actions and events specific to their positions in a company. Privileged users receive training that emphasizes what permissions their privileged account has in a given environment and what extra care is required when using their privileged account.",
                "assessment_objectives": "[a] Practical exercises are identified;\n[b] Current threat scenarios are identified;\n[c] Individuals involved in training and their supervisors are identified;\n[d] Practical exercises that are aligned with current threat scenarios are included in awareness training for all users, tailored by roles, to include general users, users with specialized roles, and privileged users; and\n[e] Feedback is provided to individuals involved in the training and their supervisors.",
                "examples": "Example\nYou are the cyber training coordinator for a medium-sized business. You and a coworker have developed a specialized awareness training to increase cybersecurity awareness around your organization. Your training includes social media campaigns, social engineering phone calls, and phishing emails with disguised links to staff to train them beyond the standard cybersecurity training [a,b].\n\nTo send simulated phishing emails to staff, you subscribe to a third-party service that specializes in this area [a]. The service sets up fictitious websites with disguised links to help train general staff against this TTP used by APTs [d]. The third-party company tracks the individuals who were sent phishing emails and whether they click on any of the links within the emails. After the training action is completed, you receive a report from the third-party company. The results show that 20% of the staff clicked on one or more phishing email links, demonstrating a significant risk to your company. As the cyber training coordinator, you notify the individuals, informing them they failed the training and identifying the area(s) of concern [e]. You send an email to the supervisors informing them who in their organization has received training. You also send an email out to the entire company explaining the training that just took place and the overall results [e]."
            },
            # Configuration Management (CM) Requirements
            {
                "requirement_id": "CM.L3-3.4.1E", "title": "Authoritative Repository", "domain": "CM",
                "description": "Establish and maintain an authoritative source and repository to provide a trusted source and accountability for approved and implemented system components.",
                "guidance": "Trusted software, whether securely developed in house or obtained from a trusted source, should have baseline data integrity established when first created or obtained, such as by using hash algorithms to obtain a hash value that would be used to validate the source prior to use of the software in a given system. Hardware in the repository should be stored in boxes or containers with tamper-evident seals. Hashes and seals should be checked on a regular basis employing the principle of separation of duties.",
                "assessment_objectives": "[a] Approved system components are identified;\n[b] Implemented system components are identified;\n[c] An authoritative source and repository are established to provide a trusted source and accountability for approved and implemented system components; and\n[d] An authoritative source and repository are maintained to provide a trusted source and accountability for approved and implemented system components.",
                "examples": "Example\nYou are the primary system build technician at a medium-sized company. You have been put in charge of creating, documenting, and implementing a baseline configuration for all user systems [c]. You have identified a minimum set of software that is needed by all employees to complete their work (e.g., office automation software). You acquire trusted versions of the software and build one or more baselines of all system software, firmware, and applications required by the organization. The gold version of each baseline is stored in a secure configuration management system repository and updated as required to maintain integrity and security. Access to the build repository for updates and use is carefully controlled using access control mechanisms that limit access to you and your staff. All interactions with the repository are logged. Using an automated build tool, your team builds each organizational system using the standard baseline."
            },
            {
                "requirement_id": "CM.L3-3.4.2E", "title": "Automated Detection & Remediation", "domain": "CM",
                "description": "Employ automated mechanisms to detect misconfigured or unauthorized system components; after detection, remove the components or place the components in a quarantine or remediation network to facilitate patching, re-configuration, or other mitigations.",
                "guidance": "For this requirement, the organization is required to implement automated tools to help identify misconfigured components. Once under an attacker's control, the system may be modified in some manner and the automated tool should detect this. Or, if a user performs a manual configuration adjustment, the system will be viewed as misconfigured, and that change should be detected. Another common example is if a component has been offline and not updated, the tool should detect the incorrect configuration. If any of these scenarios occurs, the automated configuration management system (ACMS) will notice a change and can take the system offline, quarantine the system, or send an alert so the component(s) can be manually removed. Quarantining a misconfigured component does not require it to be removed from the network. Quarantining only requires that a temporary limitation be put in place eliminating the component's ability to process, store, or transmit CUI until it is properly configured. If a component has the potential of disrupting business operations then the OSC should take extra care to ensure configuration updates are properly tested and that components are properly configured and tested before being added to the network. Once one of these actions is accomplished, a system technician may need to manually inspect the system or rebuild it using the baseline configuration. Another option is for an ACMS to make adjustments while the system is running rather than performing an entire rebuild. These adjustments can include replacing configuration files, executable files, scripts, or library files on the fly.",
                "assessment_objectives": "[a] Automated mechanisms to detect misconfigured or unauthorized system components are identified;\n[b] Automated mechanisms are employed to detect misconfigured or unauthorized system components;\n[c] Misconfigured or unauthorized system components are detected; and\n[d] After detection, system components are removed or placed in a quarantine or remediation network to facilitate patching, re-configuration, or other mitigations.",
                "examples": "Example 1\nAs the system administrator, you implement company policy stating that every system connecting to the company network via VPN will be checked for specific configuration settings and software versioning before it is allowed to connect to the network, after it passes authentication [a,b]. If any deviations from the authoritative baseline are identified, the system is placed in a VPN quarantine zone (remediation network) using a virtual local area network (VLAN) [b,c,d]. This VLAN is set up for system analysis, configuration changes, and rebuilding after forensic information is pulled from the system. Once the system updates are complete, the system will be removed from the quarantine zone and placed on the network through the VPN connection.\n\nExample 2\nAs the system administrator, you have chosen to use a network access control (NAC) solution to validate system configurations before they are allowed to connect to the corporate network [a]. When a system plugs into or connects to a local network port or the VPN, the NAC solution checks the hash of installed system software [b,c]. If the system does not pass the configuration check, it is put in quarantine until an administrator can examine it or the ACMS updates the system to pass the system checks [d]."
            },
            {
                "requirement_id": "CM.L3-3.4.3E", "title": "Automated Inventory", "domain": "CM",
                "description": "Employ automated discovery and management tools to maintain an up-to-date, complete, accurate, and readily available inventory of system components.",
                "guidance": "Organizations use an automated capability to discover components connected to the network and system software installed. The automated capability must also be able to identify attributes associated with those components. For systems that have already been coupled to the environment, they should allow remote access for inspection of the system software configuration and components. Another option is to place an agent on systems that performs internal system checks to identify system software configuration and components. Collection of switch and router data can also be used to identify systems on networks.",
                "assessment_objectives": "[a] Automated discovery and management tools for the inventory of system components are identified;\n[b] An up-to-date, complete, accurate, and readily available inventory of system components exists; and\n[c] Automated discovery and management tools are employed to maintain an up-to-date, complete, accurate, and readily available inventory of system components.",
                "examples": "Example\nWithin your organization, you are in charge of implementing an authoritative inventory of system components. You first create a list of the automated technologies you will use and what each technology will be responsible for identifying [a]. This includes gathering information from switches, routers, access points, primary domain controllers, and all connected systems or devices, whether wired or wireless (printers, IoT, IIoT, OT, IT, etc.) [b]. To keep the data up-to-date, you set a very short search frequency for identifying new components. To maximize availability of this data, all information will be placed in a central inventory/configuration management system, and automated reporting is performed every day [c]. A user dashboard is set up that allows you and other administrators to run reports at any time."
            },
            # Identification and Authentication (IA) Requirements
            {
                "requirement_id": "IA.L3-3.5.1e", "title": "Bidirectional Authentication", "domain": "IA",
                "description": "Identify and authenticate systems and system components, where possible, before establishing a network connection using bidirectional authentication that is cryptographically based and replay resistant.",
                "guidance": "Bidirectional authentication requires that both the client and server authenticate each other before establishing a connection. This prevents man-in-the-middle attacks and ensures that both parties are verified. The authentication should use cryptographic methods and be resistant to replay attacks.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[ODP1] Systems and system components to identify and authenticate are defined;\n[a] Bidirectional authentication that is cryptographically-based is implemented;\n[b] Bidirectional authentication that is replay-resistant is implemented; and\n[c] Systems and system components, where possible, are identified and authenticated before establishing a network connection using bidirectional authentication that is cryptographically-based and replay-resistant.",
                "examples": "Example 1\n\nYou are the network engineer in charge of implementing this requirement. You have been instructed to implement a technology that will provide mutual authentication for client server connections. You implement Kerberos.\n\nOn the server side, client authentication is implemented by having the client establish a local security context. This is initially accomplished by having the client present credentials which are confirmed by the Active Directory Domain Controller (DC). After that, the client may establish context via a session of a logged-in user. The service does not accept connections from any unauthenticated client.\n\nOn the client side, server authentication requires registration, using administrator privileges, of unique Service Provider Names (SPNs) for each service instance offered. The names are registered in the Active Directory Domain Controller. When a client requests a connection to a service, it composes an SPN for a service instance, using known data or data provided by the user. For authentication, the client presents its SPN to the Key Distribution Center (KDC), and the KDC searches for computers with the registered SPN before allowing a connection via an encrypted message passed to the client for forwarding to the server.\n\nExample 2\n\nYou are the network engineer in charge of implementing this requirement. You have been instructed to implement a technology that will provide authentication for each system prior to connecting to the environment. You implement the company-approved scheme that uses cryptographic keys installed on each system for it to authenticate to the environment, as well as user-based cryptographic keys that are used in combination with a user's password for user-level authentication [a,c]. Your authentication implementation is finalized on each system using an ACM solution. When a system connects to the network, the system uses the system-level certificate to authenticate itself to the switch before the switch will allow it to access the corporate network [a,c]. This is accomplished using 802.1x technology on the switch and by authenticating with a RADIUS server that authenticates itself with the system via cryptographic keys. If either system fails to authenticate to the other, the trust is broken, and the system will not be able to connect to or communicate on the network. You also set up a similar implementation in your wireless access point.\n\nExample 3\n\nYou are the network engineer in charge of implementing the VPN solution used by the organization. To meet this requirement, you use a VPN gateway server and public key infrastructure (PKI) certificates via a certification authority (CA) and a chain of trust. When a client starts a VPN connection, the server presents its certificate to the client and if the certificate is trusted, the client then presents its certificate to the server [a]. If the server validates the client certificate, an established communications channel is opened for the client to finish the authentication process and gain access to the network via the VPN gateway server [c]. If the client fails final authentication, fails the certification validation, or the VPN gateway server fails authentication, the connection is terminated."
            },
            {
                "requirement_id": "IA.L3-3.5.3e", "title": "Block Untrusted Assets", "domain": "IA",
                "description": "Employ automated or manual/procedural mechanisms to prohibit system components from connecting to organizational systems unless the components are known, authenticated, in a properly configured state, or in a trust profile.",
                "guidance": "Organizations must implement controls to prevent unauthorized or untrusted devices from connecting to organizational systems. This can be achieved through automated network access control (NAC) solutions, device trust profiles, or manual procedures that verify device authenticity and configuration before allowing network access.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] System components that are known, authenticated, in a properly configured state, or in a trust profile are identified;\n[b] Automated or manual/procedural mechanisms to prohibit system components from connecting to organizational systems are identified; and\n[c] Automated or manual/procedural mechanisms are employed to prohibit system components from connecting to organizational systems unless the components are known, authenticated, in a properly configured state, or in a trust profile.",
                "examples": "Example 1\n\nIn a Windows environment, you authorize devices to connect to systems by defining configuration rules in one or more Group Policy Objects (GPO) that can be automatically applied to all relevant devices in a domain [a]. This provides you with a mechanism to apply rules for which devices are authorized to connect to any given system and prevent devices that are not within the defined list from connecting [b,c]. For instance, universal serial bus (USB) device rules for authorization can be defined by using a USB device's serial number, model number, and manufacturer information. This information can be used to build a trust profile for a device and authorize it for use by a given system. You use security policies to prevent unauthorized components from connecting to systems [c].\n\nExample 2\n\nYou have been assigned to build trust profiles for all devices allowed to connect to your organization's systems. You want to test the capability starting with printers. You talk to your purchasing department, and they tell you that policy states every printer must be from a specific manufacturer; they only purchase four different models. They also collect all serial numbers from purchased printers. You gather this information and build trust profiles for each device [a,b]. Because your organization shares printers, you push the trust profiles out to organizational systems. Now, the systems are not allowed to connect to a network printer unless they are within the trust profiles you have provided [b,c].\n\nExample 3\n\nYour organization has implemented a network access control solution (NAC) to help ensure that only properly configured computers are allowed to connect to the corporate network [a,b]. The solution first checks for the presence of a certificate to indicate that the device is company-owned. It next reviews the patch state of the computer and forces the installation of any patches that are required by the organization. Finally, it reviews the computer's configuration to ensure that the firewall is active and that the appropriate security policies have been applied. Once the computer has passed all of these requirements, it is allowed access to network resources and defined as a trusted asset for the length of its session [a]. Devices that do not meet all of the requirements are automatically blocked from connecting to the network [c]."
            },
            # Incident Response (IR) Requirements
            {
                "requirement_id": "IR.L3-3.6.1e", "title": "Security Operations Center", "domain": "IR",
                "description": "Establish and maintain a security operations center capability that operates 24/7, with allowance for remote/on-call staff.",
                "guidance": "A Security Operations Center (SOC) provides continuous monitoring and rapid response to security incidents. The SOC should operate 24/7, which can be achieved through a combination of on-site staff, remote staff, and on-call personnel. Automated monitoring tools can help reduce the need for constant human presence while ensuring comprehensive coverage.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] A security operations center capability is established;\n[b] The security operations center capability operates 24/7, with allowance for remote/on-call staff; and\n[c] The security operations center capability is maintained.",
                "examples": "Example\n\nYou are the Chief Information Security Officer (CISO) of a medium-sized organization. To meet the goal of 24/7 SOC operation, you have decided to adjust the current SOC, which operates five days a week for 12 hours a day, by minimizing active staff members and hiring trusted expert consultants to have on call at all times (i.e., seven days a week, 24 hours a day) [a,b]. You design your SOC to be remotely accessible so your experts can access your environment when needed. You also decide to set up a very strong automated capability that is good at identifying questionable activities and alerting the appropriate staff. You create a policy stating that after an alert goes out, two members of the SOC team must remotely connect to the environment within 15 minutes to address the problem. All staff members also have regular working hours during which they perform other SOC activities, such as updating information to help the automated tool perform its functions [c]."
            },
            {
                "requirement_id": "IR.L3-3.6.2e", "title": "Cyber Incident Response Team", "domain": "IR",
                "description": "Establish and maintain a cyber incident response team that can be deployed by the organization within 24 hours.",
                "guidance": "Organizations must have a dedicated incident response team that can quickly respond to cyber incidents. The team should be able to deploy within 24 hours of an incident being detected. Team members should be trained, have clear roles and responsibilities, and have access to necessary tools and resources.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] A cyber incident response team is established;\n[b] The cyber incident response team can be deployed by the organization within 24 hours; and\n[c] The cyber incident response team is maintained.",
                "examples": "Example\n\nYou are the lead for an IR team within your organization. Your manager is the SOC lead, and she reports to the chief information officer (CIO). As the SOC is alerted and/or identifies incidents within the organization's environments, you lead and deploy teams to resolve the issues, including incidents involving cloud-based systems. You use a custom dashboard that was created for your team members to view and manage incidents, perform response actions, and record actions and notes for each case. You also have your team create an after action report for all incidents to which they respond; this information is used to determine if a given incident requires additional action and reporting [a].\n\nOne day, you receive a message from the SOC that your website has become corrupted. Within minutes, you have a team on the system inspecting logs, analyzing applications, preserving key information, and looking for evidence of tampering/attack [b]. Your team runs through a procedure set for this specific incident type based on a handbook the organization has created and maintains [c]. It is found that a cyberattack caused the corruption, but the corruption caused a crash, which prevented the attack from continuing. Your team takes note of all actions they perform, and at the end of the incident analysis, you send a message to the website lead to inform them of the issue, case number, and notes created by the team. The website lead has their team rebuild the system and validate that the attack no longer works. At the end of the incident, the CISO and CIO are informed of the issue."
            },
            # Personnel Security (PS) Requirements
            {
                "requirement_id": "PS.L3-3.9.2e", "title": "Adverse Information", "domain": "PS",
                "description": "Ensure that organizational systems are protected if adverse information develops or is obtained about individuals with access to CUI.",
                "guidance": "Organizations must have procedures to identify and respond to adverse information about personnel with access to CUI. This includes monitoring personnel, conducting background checks, and having mechanisms to quickly revoke or restrict access when adverse information is discovered.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] Individuals with access to CUI are identified;\n[b] Adverse information about individuals with access to CUI is defined;\n[c] Organizational systems to which individuals have access are identified; and\n[d] Mechanisms are in place to protect organizational systems if adverse information develops or is obtained about individuals with access to CUI.",
                "examples": "Example\n\nYou learn that one of your employees has been convicted on shoplifting charges. Based on organizational policy, you report this information to human resources (HR), which verifies the information with a criminal background check [a,b,c]. Per policy, you increase the monitoring of the employee's access to ensure that the employee does not exhibit patterns of behavior consistent with an insider threat [d]. You maintain contact with HR as they investigate the adverse information so that you can take stronger actions if required, such as removing access to organizational systems."
            },
            # Risk Assessment (RA) Requirements
            {
                "requirement_id": "RA.L3-3.11.1e", "title": "Threat-Informed Risk Assessment", "domain": "RA",
                "description": "Employ threat intelligence, at a minimum from open or commercial sources, and any DoD-provided sources, as part of a risk assessment to guide and inform the development of organizational systems, security architectures, selection of security solutions, monitoring, threat hunting, and response and recovery activities.",
                "guidance": "Organizations should use threat intelligence to inform risk assessments and security decisions. Threat intelligence can come from open sources, commercial feeds, and DoD-provided sources. This intelligence should be used to guide system development, architecture decisions, security solution selection, monitoring activities, threat hunting, and incident response.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[ODP1] Sources of threat intelligence are defined;\n[a] A risk assessment methodology is identified;\n[b] Threat intelligence, at a minimum from open or commercial sources, and any DoD-provided sources, are employed as part of a risk assessment to guide and inform the development of organizational systems and security architectures;\n[c] Threat intelligence, at a minimum from open or commercial sources, and any DoD-provided sources, are employed as part of a risk assessment to guide and inform the selection of security solutions;\n[d] Threat intelligence, at a minimum from open or commercial sources, and any DoD-provided sources, are employed as part of a risk assessment to guide and inform system monitoring activities;\n[e] Threat intelligence, at a minimum from open or commercial sources, and any DoD-provided sources, are employed as part of a risk assessment to guide and inform threat hunting activities; and\n[f] Threat intelligence, at a minimum from open or commercial sources, and any DoD-provided sources, are employed as part of a risk assessment to guide and inform response and recovery activities.",
                "examples": "Example\n\nYour organization receives a commercial threat intelligence feed from FIRST and government threat intelligence feeds from both USCERT and DoD/DC3 to help learn about recent threats and any additional information the threat feeds provide [b,c,d,e,f]. Your organization uses the threat intelligence for multiple purposes:\n\n• To perform up-to-date risk assessments for the organization [a];\n\n• To add rules to the automated system put in place to identify threats (indicators of compromise, or IOCs) on the organization's network [e];\n\n• To guide the organization in making informed selections of security solutions [c];\n\n• To shape the way the organization performs system monitoring activities [d];\n\n• To manage the escalation process for identified incidents, handling specific events, and performing recovery actions [f];\n\n• To provide additional information to the hunt team to identify threat activities [e];\n\n• To inform the development and design decisions for organizational systems and the overall security architecture, as well as the network architecture [b,c];\n\n• To assist in decision-making regarding systems that are part of the primary network and systems that are placed in special enclaves for additional protections [b]; and\n\n• To determine additional security measures based on current threat activities taking place in similar industry networks [c,d,e,f]."
            },
            {
                "requirement_id": "RA.L3-3.11.2e", "title": "Threat Hunting", "domain": "RA",
                "description": "Conduct cyber threat hunting activities on an on-going aperiodic basis or when indications warrant, to search for indicators of compromise in organizational systems and detect, track, and disrupt threats that evade existing controls.",
                "guidance": "Threat hunting involves proactively searching for threats and indicators of compromise that may have evaded existing security controls. Threat hunting should be conducted on an ongoing, aperiodic basis or when specific indicators warrant investigation. The process involves analyzing system logs, network traffic, and other data sources to identify suspicious activity.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[ODP4] Organizational systems to search for indicators of compromise are defined;\n[a] Indicators of compromise are identified;\n[b] Cyber threat hunting activities are conducted on an on-going aperiodic basis or when indications warrant, to search for indicators of compromise in organizational systems; and\n[c] Cyber threat hunting activities are conducted on an on-going aperiodic basis or when indications warrant, to detect, track, and disrupt threats that evade existing controls.",
                "examples": "Example\n\nYou are the lead for your organization's cyber threat hunting team. You have local and remote staff on the team to process threat intelligence. Your team is tied closely with the SOC and IR teams. Through a DoD (DC3) intelligence feed, you receive knowledge of a recent APT's attacks on defense contractors. The intelligence feed provided the indicators of compromise for a zero-day attack that most likely started within the past month. After receiving the IOCs, you use a template for your organization to place the information in a standard format your team understands. You then email the information to your team members and place the information in your hunt team's dashboard, which tracks all IOCs [a].\n\nYour team starts by using the information to hunt for IOCs on the environment [b]. One of your team members quickly responds, providing information from the SIEM that an HR system's logs show evidence that IOCs related to this threat occurred three days ago. The team contacts the owner of the system as they take the system offline into a quarantined environment. Your team pulls all logs from the system and clones the storage on the system. Members go through the logs to look for other systems that may be part of the APT's attack [c]. While the team is cloning the storage system for evidence, you alert the IR team about the issue. After full forensics of the system, your team has verified your company has been hit by the APT, but nothing was taken and no additional attacks happened. You also alert DoD (DC3) about the finding and discuss the matter with them. There is an after action report and a briefing given to management to make them aware of the issue."
            },
            {
                "requirement_id": "RA.L3-3.11.3e", "title": "Advanced Risk Identification", "domain": "RA",
                "description": "Employ advanced automation and analytics capabilities in support of analysts to predict and identify risks to organizations, systems, and system components.",
                "guidance": "Organizations should use advanced automation and analytics tools to help identify risks. These tools can analyze large volumes of data, identify patterns, and predict potential security issues. Analysts use these tools to focus their attention on the most critical risks.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] Advanced automation and analytics capabilities to predict and identify risks to organizations, systems, and system components are identified;\n[b] Analysts to predict and identify risks to organizations, systems, and system components are identified; and\n[c] Advanced automation and analytics capabilities are employed in support of analysts to predict and identify risks to organizations, systems, and system components.",
                "examples": "Example\n\nYou are responsible for information security in your organization. The organization holds and processes CUI in an enterprise. To protect that data, you want to minimize phishing attacks through the use of Security Orchestration and Automated Response (SOAR). Rather than relying on analysts to manually inspect each inbound item, emails containing links and/or attachments are processed by your automation playbook. Implementation of these processes involves sending all email links and attachments to detonation chambers or sandboxes prior to delivery to the recipient. When the email is received, SOAR extracts all URL links and attachments from the content and sends them for analysis and testing [a]. The domains in the URLs and the full URLs are processed against bad domain and URL lists. Next, a browser in a sandbox downloads the URLs for malware testing. Lastly, any attachments are sent to detonation chambers to identify if they attempt malicious activities. The hash of the attachments is sent to services to identify if it is known malware [b]. If any one of the items triggers a malware warning from the sandbox, detonation chamber, domain/URL validation service, attachment hash check services, or AV software, an alert about the original email is sent to team members with the recommendation to quarantine it. The team is given the opportunity to select a \"take action\" button, which would have the SOAR solution take actions to block that email and similar emails from being received by the organization [c]."
            },
            {
                "requirement_id": "RA.L3-3.11.4e", "title": "Security Solution Rationale", "domain": "RA",
                "description": "Document or reference in the system security plan the security solution selected, the rationale for the security solution, and the risk determination.",
                "guidance": "Organizations must document their security solution selections, including the rationale for choosing specific solutions and the risk determinations that informed those decisions. This documentation should be included in the system security plan (SSP) and follow guidance from NIST SP 800-18.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] The system security plan documents or references the security solution selected;\n[b] The system security plan documents or references the rationale for the security solution; and\n[c] The system security plan documents or references the risk determination.",
                "examples": "Example\n\nYou are responsible for information security in your organization. Following CMMC requirement RA.L3-3.11.1e – Threat Informed Risk Assessment, your team uses threat intelligence to complete a risk assessment and make a risk determination for all elements of your enterprise. Based on that view of risk, your team decides that requirement RA.L3-3.11.2e – Threat Hunting is a requirement that is very important in protecting your organization's use of CUI, and you have determined the solution selected could potentially add risk. You want to detect an adversary as soon as possible when they breach the network before any CUI can be exfiltrated. However, there are multiple threat hunting solutions, and each solution has a different set of features that will provide different success rates in identifying IOCs.\n\nAs a result, some solutions increase the risk to the organization by being less capable in detecting and tracking an adversary in your networks. To reduce risk, you evaluate five threat hunting solutions and in each case determine the number of IOCs for which there is a monitoring mechanism. You pick the solution that is cost effective, easy to operate, and optimizes IOC detection for your enterprise; purchase, install, and train SOC personnel on its use; and document the risk-based analysis of alternatives in the SSP. In creating that documentation in the SSP, you follow the guidance found in NIST SP 800-18, Guide for Developing Security Plans for Federal Information Systems [a,b,c]."
            },
            {
                "requirement_id": "RA.L3-3.11.5e", "title": "Security Solution Effectiveness", "domain": "RA",
                "description": "Assess the effectiveness of security solutions at least annually or upon receipt of relevant cyber threat information, or in response to a relevant cyber incident, to address anticipated risk to organizational systems and the organization based on current and accumulated threat intelligence.",
                "guidance": "Organizations must regularly assess whether their security solutions are effective in addressing current threats. Assessments should be conducted at least annually, when new threat intelligence is received, or in response to security incidents. The assessment should consider current and accumulated threat intelligence to determine if solutions need to be updated or replaced.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] Security solutions are identified;\n[b] Current and accumulated threat intelligence is identified;\n[c] Anticipated risk to organizational systems and the organization based on current and accumulated threat intelligence is identified; and\n[d] The effectiveness of security solutions is assessed at least annually or upon receipt of relevant cyber threat information, or in response to a relevant cyber incident, to address anticipated risk to organizational systems and the organization based on current and accumulated threat intelligence.",
                "examples": "Example\n\nYou are responsible for information security in your organization, which holds and processes CUI. The organization subscribes to multiple threat intelligence sources [b]. In order to assess the effectiveness of current security solutions, the security team analyzes any new incidents reported in the threat feed. They identify weaknesses that were leveraged by malicious actors and subsequently look for similar weaknesses in their own security architecture[a,c]. This analysis is passed to the architecture team for engineering change recommendations, including system patching guidance, new sensors, and associated alerts that should be generated, and to identify ways to mitigate, transfer, or accept the risk necessary to respond to events if they occur within their own organization [d]."
            },
            {
                "requirement_id": "RA.L3-3.11.6e", "title": "Supply Chain Risk Response", "domain": "RA",
                "description": "Assess, respond to, and monitor supply chain risks associated with organizational systems and system components.",
                "guidance": "Organizations must identify, assess, and monitor risks in their supply chain that could affect the security of organizational systems. This includes risks from vendors, suppliers, and third-party service providers. Organizations should have processes to respond to supply chain risks when they are identified.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] Supply chain risks associated with organizational systems and system components are identified;\n[b] Supply chain risks associated with organizational systems and system components are assessed;\n[c] Supply chain risks associated with organizational systems and system components are responded to; and\n[d] Supply chain risks associated with organizational systems and system components are monitored.",
                "examples": "Example\n\nYou are responsible for information security in your organization, which holds and processes CUI. One of your responsibilities is to manage risk associated with your supply chain that may provide an entry point for the adversary. First, you acquire threat information by subscribing to reports that identify supply chain attacks in enough detail that you are able to identify the risk points in your organization's supply chain [a]. You create an organization-defined prioritized list of risks the organization may encounter and determine the responses to be implemented to mitigate those risks [b,c].\n\nIn addition to incident information, the intelligence provider also makes recommendations for monitoring and auditing your supply chain. You assess, integrate, correlate, and analyze this information so you can use it to acquire monitoring tools to help identify supply chain events that could be an indicator of an incident. This monitoring tool provides visibility of the entire attack surface, including your vendors' security posture [d]. Second, you analyze the incident information in the intelligence report to help identify defensive tools that will help respond to each of those known supply chain attack techniques as soon as possible after such an incident is detected, thus mitigating risk associated with known techniques."
            },
            {
                "requirement_id": "RA.L3-3.11.7e", "title": "Supply Chain Risk Plan", "domain": "RA",
                "description": "Develop a plan for managing supply chain risks associated with organizational systems and system components; update the plan at least annually, and upon receipt of relevant cyber threat information, or in response to a relevant cyber incident.",
                "guidance": "Organizations must develop and maintain a comprehensive plan for managing supply chain risks. The plan should be updated at least annually, when new threat information is received, or in response to supply chain security incidents. The plan should document processes for identifying, assessing, monitoring, and responding to supply chain risks.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] Supply chain risks associated with organizational systems and system components are identified;\n[b] Organizational systems and system components to include in a supply chain risk management plan are identified;\n[c] A plan for managing supply chain risks associated with organizational systems and system components is developed; and\n[d] The plan for managing supply chain risks is updated at least annually, and upon receipt of relevant cyber threat information, or in response to a relevant cyber incident.",
                "examples": "Example\n\nYou are responsible for information security in your organization, and you have created a supply chain risk management plan [a,b,c]. One of the organization's suppliers determines that it has been the victim of a cyberattack. Your security team meets with the supplier to determine the nature of the attack and to understand the adversary, the attack, the potential for corruption of delivered goods or services, and current as well as future risks. The understanding of the supply chain will help protect the local environment. Subsequently, you update the risk management plan to include a description of the necessary configuration changes or upgrades to monitoring tools to improve the ability to identify the new risks, and when improved tools are available, you document the acquisition of defensive tools and associated functionality to help mitigate any of the identified techniques [d]."
            },
            # Security Assessment (CA) Requirements
            {
                "requirement_id": "CA.L3-3.12.1e", "title": "Penetration Testing", "domain": "CA",
                "description": "Conduct penetration testing at least annually or when significant security changes are made to the system, leveraging automated scanning tools and ad hoc tests using subject matter experts.",
                "guidance": "Organizations must conduct regular penetration testing to identify vulnerabilities and test the effectiveness of security controls. Testing should be performed at least annually or when significant security changes are made. Testing should combine automated tools with manual testing by security experts.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] Automated scanning tools are identified;\n[b] Ad hoc tests using subject matter experts are identified; and\n[c] Penetration testing is conducted at least annually or when significant security changes are made to the system, leveraging automated scanning tools and ad hoc tests using subject matter experts.",
                "examples": "Example\n\nYou are responsible for information security in your organization. Leveraging a contract managed by the CIO, you hire an external expert penetration team annually to test the security of the organization's enclave that stores and processes CUI [a,c]. You hire the same firm annually or on an ad hoc basis when significant changes are made to the architecture or components that affect security [b,c]."
            },
            # System and Communications Protection (SC) Requirements
            {
                "requirement_id": "SC.L3-3.13.4e", "title": "Isolation", "domain": "SC",
                "description": "Employ physical isolation techniques or logical isolation techniques or both in organizational systems and system components.",
                "guidance": "Organizations should isolate systems and system components to limit the impact of security incidents and prevent unauthorized access. Isolation can be achieved through physical separation, logical separation (e.g., network segmentation, VLANs), or a combination of both. The choice of isolation technique should be based on risk assessment and system requirements.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[ODP1] One or more of the following is/are selected: physical isolation techniques; logical isolation techniques;\n[ODP2] Physical isolation techniques are defined (if selected);\n[ODP3] Logical isolation techniques are defined (if selected);\n[a] Physical isolation techniques or logical isolation techniques or both are employed in organizational systems and system components.",
                "examples": "Example\n\nYou are responsible for information security in your organization, which holds and processes CUI. You have decided to isolate the systems processing CUI by limiting all communications in and out that enclave with cross-domain interface devices that implement access control [a]. Your security team has identified all the systems containing such CUI, documented network design details, developed network diagrams showing access control points, documented the logic for the access control enforcement decisions, described the interface and protocol to the identification and authentication mechanisms, and documented all details associated with the ACLs, including review, updates, and credential revocation procedures."
            },
            # System and Information Integrity (SI) Requirements
            {
                "requirement_id": "SI.L3-3.14.1e", "title": "Integrity Verification", "domain": "SI",
                "description": "Verify the integrity of security critical and essential software using root of trust mechanisms or cryptographic signatures.",
                "guidance": "Organizations must verify the integrity of security-critical and essential software to ensure it has not been tampered with. This can be achieved through root of trust mechanisms (e.g., Trusted Platform Module) or cryptographic signatures. Software integrity verification should occur before execution and when software is updated.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[ODP1] Security critical or essential software is defined;\n[a] Root of trust mechanisms or cryptographic signatures are identified; and\n[b] The integrity of security critical and essential software is verified using root of trust mechanisms or cryptographic signatures.",
                "examples": "Example 1\n\nYou are responsible for information security in your organization. Your security team has identified the software used to process CUI, and the organization has decided it is mission-critical software that must be protected. You take three actions. First, you ensure all of the platform's configuration information used at boot is hashed and stored in a TPM [a]. Second, you ensure that the platforms used to execute the software are started with a digitally signed software chain to a secure boot process using the TPM. Finally, you ensure the essential applications are cryptographically protected with a digital signature when stored and the signature is verified prior to execution [b].\n\nExample 2\n\nYour organization has a software security team, and they are required to validate unsigned essential software provided to systems that do not have TPM modules. The organization has a policy stating no software can be executed on a system unless its hash value matches that of a hash stored in the approved software library kept by the software security team [a]. This action is performed by implementing software restriction policies on systems. The team tests the software on a sandbox system, and once it is proven safe, they run a hashing function on the software to create a hash value. This hash value is placed in a software library so the system will know it can execute the software [b]. Any changes to the software without the software security team's approval will result in the software failing the security tests, and it will be prevented from executing."
            },
            {
                "requirement_id": "SI.L3-3.14.3e", "title": "Specialized Asset Security", "domain": "SI",
                "description": "Ensure that specialized assets including IoT, IIoT, OT, GFE, Restricted Information Systems and test equipment are included in the scope of the specified enhanced security requirements or are segregated in purpose-specific networks.",
                "guidance": "Specialized assets such as IoT devices, operational technology (OT), government furnished equipment (GFE), and test equipment may have unique security requirements or limitations. Organizations must either apply enhanced security requirements to these assets or segregate them in purpose-specific networks to limit their exposure and impact on other systems.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[a] Specialized assets including IoT, IIoT, OT, GFE, Restricted Information Systems and test equipment are included in the scope of the specified enhanced security requirements; and\n[b] Systems and system components that are not included in specialized assets including IoT, IIoT, OT, GFE, Restricted Information Systems and test equipment are segregated in purpose-specific networks.",
                "examples": "Example\n\nYou are responsible for information security in your organization, which processes CUI on the network, and this same network includes GFE for which the configuration is mandated by the government. The GFE is needed to process CUI information [a]. Because the company cannot manage the configuration of the GFE, it has been augmented by placing a bastion host between it and the network. The bastion host meets the requirements that the GFE cannot, and is used to send CUI files to and from the GFE for processing. You and your security team document in the SSP all of the GFE to include GFE connectivity diagrams, a description of the isolation mechanism, and a description of how your organization manages risk associated with that GFE [a]."
            },
            {
                "requirement_id": "SI.L3-3.14.6e", "title": "Threat-Guided Intrusion Detection", "domain": "SI",
                "description": "Use threat indicator information and effective mitigations obtained from, at a minimum, open or commercial sources, and any DoD-provided sources, to guide and inform intrusion detection and threat hunting.",
                "guidance": "Organizations should use threat intelligence to improve their intrusion detection and threat hunting capabilities. Threat indicators and mitigations from open sources, commercial feeds, and DoD-provided sources should be integrated into security monitoring tools and processes to enhance detection of advanced threats.",
                "assessment_objectives": "ASSESSMENT OBJECTIVES [NIST SP 800-172A]\n\nDetermine if:\n\n[ODP1] External organizations from which to obtain threat indicator information and effective mitigations are defined;\n[a] Threat indicator information is identified;\n[b] Effective mitigations are identified;\n[c] Intrusion detection approaches are identified;\n[d] Threat hunting activities are identified; and\n[e] Threat indicator information and effective mitigations obtained from, at a minimum, open or commercial sources and any DoD-provided sources, are used to guide and inform intrusion detection and threat hunting.",
                "examples": "Example\n\nYou are responsible for information security in your organization. You have maintained an effective intrusion detection capability for some time, but now you decide to introduce a threat hunting capability informed by internal and external threat intelligence [a,c,d,e]. You install a SIEM system that leverages threat information to provide functionality to:\n\n• analyze logs, data sources, and alerts;\n\n• query data to identify anomalies;\n\n• identify variations from baseline threat levels;\n\n• provide machine learning capabilities associated with the correlation of anomalous data characteristics across the enterprise; and\n\n• categorize data sets based on expected data values.\n\nYour team also manages an internal mitigation plan (playbook) for all known threats for your environment. This playbook is used to implement effective mitigation strategies across the environment [b]. Some of the mitigation strategies are developed by team members, and others are obtained by threat feed services."
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
                    assessment_objectives=req_data['assessment_objectives'],
                    examples=req_data.get('examples', '')
                )
                db.session.add(requirement)

    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_database()
    app.run(debug=True)



