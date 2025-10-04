import os
import random
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta
import requests
import json
from werkzeug.utils import secure_filename
import uuid

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../frontend/static')

# Database Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost/auth_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
mail = Mail(app)

login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database Models
class Company(db.Model):
    __tablename__ = 'companies'
    company_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    currency_code = db.Column(db.String(10), nullable=False, default='USD')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    users = db.relationship('User', backref='company', lazy=True)
    expenses = db.relationship('Expense', backref='company', lazy=True)
    activity_logs = db.relationship('ActivityLog', backref='company', lazy=True)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Employee')
    manager_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=True)
    otp = db.Column(db.String(6))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    managed_employees = db.relationship('User', backref=db.backref('manager', remote_side=[user_id]))
    expenses = db.relationship('Expense', backref='user', lazy=True)
    approvals = db.relationship('ExpenseApproval', backref='approver', lazy=True)
    activities = db.relationship('ActivityLog', backref='user', lazy=True)
    
    def get_id(self):
        return str(self.user_id)
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)

class Expense(db.Model):
    __tablename__ = 'expenses'
    expense_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    currency_code = db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    expense_date = db.Column(db.Date, nullable=False)
    receipt_url = db.Column(db.Text)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    approvals = db.relationship('ExpenseApproval', backref='expense', lazy=True)

class ExpenseApproval(db.Model):
    __tablename__ = 'expense_approval'
    approval_id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expenses.expense_id'), nullable=False)
    approver_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    comments = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ApprovalRule(db.Model):
    __tablename__ = 'approval_rules'
    rule_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    percentage_value = db.Column(db.Integer)
    specific_approver = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ApprovalSequence(db.Model):
    __tablename__ = 'approval_sequences'
    seq_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('approval_rules.rule_id'), nullable=False)
    approver_role = db.Column(db.String(50))
    approver_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    step_order = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CurrencyRate(db.Model):
    __tablename__ = 'currency_rates'
    rate_id = db.Column(db.Integer, primary_key=True)
    base_currency = db.Column(db.String(10), nullable=False)
    target_currency = db.Column(db.String(10), nullable=False)
    rate = db.Column(db.Numeric(12, 6), nullable=False)
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    activity_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions
def generate_otp():
    return str(random.randint(100000, 999999))

def send_email(subject, recipient, body):
    """Send email using Flask-Mail"""
    try:
        msg = Message(
            subject=subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[recipient],
            body=body
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def get_country_currency(country_name):
    """Get currency code for a country"""
    currency_map = {
        'united states': 'USD',
        'india': 'INR',
        'united kingdom': 'GBP',
        'canada': 'CAD',
        'australia': 'AUD',
        'japan': 'JPY',
        'germany': 'EUR',
        'france': 'EUR',
        'italy': 'EUR',
        'spain': 'EUR'
    }
    return currency_map.get(country_name.lower(), 'USD')

def log_activity(activity_type, description, user_id=None, company_id=None):
    """Log activity to database"""
    try:
        if user_id is None and current_user.is_authenticated:
            user_id = current_user.user_id
            company_id = current_user.company_id
        elif company_id is None and user_id:
            user = User.query.get(user_id)
            company_id = user.company_id if user else None
            
        activity = ActivityLog(
            company_id=company_id,
            user_id=user_id,
            activity_type=activity_type,
            description=description
        )
        db.session.add(activity)
        db.session.commit()
        return True
    except Exception as e:
        print(f"Activity logging error: {e}")
        db.session.rollback()
        return False

def get_activity_icon(activity_type):
    """Map activity types to icons"""
    icon_map = {
        'user_created': 'user-plus',
        'user_login': 'sign-in-alt',
        'user_logout': 'sign-out-alt',
        'password_reset': 'key',
        'password_sent': 'paper-plane',
        'company_created': 'building',
        'expense_submitted': 'receipt',
        'expense_approved': 'check-circle',
        'expense_rejected': 'times-circle',
        'user_updated': 'user-edit'
    }
    return icon_map.get(activity_type, 'info-circle')

def get_next_approver(expense):
    """Get the next approver for an expense based on approval rules"""
    try:
        # For now, return the user's manager as the approver
        if expense.user.manager_id:
            return User.query.get(expense.user.manager_id)
        
        # If no manager, find any manager in the company
        manager = User.query.filter_by(
            company_id=expense.company_id, 
            role='Manager'
        ).first()
        
        return manager
    except Exception as e:
        print(f"Error getting next approver: {e}")
        return None

# Routes
@app.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with role-based redirect"""
    if current_user.role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('dashboard.html', user=current_user)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Admin dashboard"""
    if current_user.role != 'Admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('admin_dashboard.html', user=current_user)

# Expense Routes
@app.route('/submit_expense', methods=['GET', 'POST'])
@login_required
def submit_expense():
    """Submit new expense"""
    if request.method == 'POST':
        try:
            # Get form data
            amount = request.form.get('amount')
            category = request.form.get('category')
            description = request.form.get('description')
            expense_date = request.form.get('expense_date')
            receipt_name = request.form.get('receipt_name')
            
            # Validate required fields
            if not all([amount, category, expense_date]):
                flash('Please fill in all required fields', 'danger')
                return render_template('submit_expense.html')
            
            # Create expense record
            expense = Expense(
                user_id=current_user.user_id,
                company_id=current_user.company_id,
                amount=float(amount),
                currency_code=current_user.company.currency_code,
                category=category,
                description=description,
                expense_date=datetime.strptime(expense_date, '%Y-%m-%d').date(),
                receipt_url=receipt_name,
                status='pending'
            )
            
            db.session.add(expense)
            db.session.commit()
            
            # Get next approver and create approval record
            approver = get_next_approver(expense)
            if approver:
                approval = ExpenseApproval(
                    expense_id=expense.expense_id,
                    approver_id=approver.user_id,
                    action='pending',
                    comments='Waiting for approval'
                )
                db.session.add(approval)
                db.session.commit()
            
            # Log activity
            log_activity('expense_submitted', f'Submitted expense for ${amount} in {category}')
            
            flash('Expense submitted successfully! Waiting for approval.', 'success')
            return redirect(url_for('view_expenses'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Expense submission error: {e}")
            flash('Error submitting expense. Please try again.', 'danger')
            return render_template('submit_expense.html')
    
    return render_template('submit_expense.html')

@app.route('/view_expenses')
@login_required
def view_expenses():
    """View user's expenses"""
    expenses = Expense.query.filter_by(user_id=current_user.user_id).order_by(Expense.created_at.desc()).all()
    return render_template('view_expenses.html', expenses=expenses)

@app.route('/pending_approvals')
@login_required
def pending_approvals():
    """View expenses pending approval for managers/admins"""
    if current_user.role not in ['Manager', 'Admin']:
        flash('Access denied. Manager privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get expenses that need approval from this user
    pending_expenses = Expense.query.join(ExpenseApproval).filter(
        ExpenseApproval.approver_id == current_user.user_id,
        ExpenseApproval.action == 'pending',
        Expense.company_id == current_user.company_id
    ).all()
    
    return render_template('pending_approvals.html', expenses=pending_expenses)

@app.route('/approve_expense/<int:expense_id>', methods=['POST'])
@login_required
def approve_expense(expense_id):
    """Approve or reject an expense"""
    if current_user.role not in ['Manager', 'Admin']:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        action = request.json.get('action')
        comments = request.json.get('comments', '')
        
        expense = Expense.query.get_or_404(expense_id)
        approval = ExpenseApproval.query.filter_by(
            expense_id=expense_id,
            approver_id=current_user.user_id,
            action='pending'
        ).first()
        
        if not approval:
            return jsonify({'error': 'Approval not found or already processed'}), 404
        
        # Update approval record
        approval.action = action
        approval.comments = comments
        approval.created_at = datetime.utcnow()
        
        # Update expense status
        if action == 'approved':
            expense.status = 'approved'
            activity_type = 'expense_approved'
            activity_desc = f'Approved expense #{expense_id} for ${expense.amount}'
        else:
            expense.status = 'rejected'
            activity_type = 'expense_rejected'
            activity_desc = f'Rejected expense #{expense_id} for ${expense.amount}'
        
        db.session.commit()
        
        # Log activity
        log_activity(activity_type, activity_desc)
        
        return jsonify({'success': True, 'message': f'Expense {action} successfully'})
        
    except Exception as e:
        db.session.rollback()
        print(f"Approval error: {e}")
        return jsonify({'error': str(e)}), 500

# API Routes for Admin Dashboard
@app.route('/api/admin/stats')
@login_required
def admin_stats():
    """Get dashboard statistics from database"""
    if current_user.role != 'Admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Real statistics from database
        total_users = User.query.filter_by(company_id=current_user.company_id).count()
        total_managers = User.query.filter_by(company_id=current_user.company_id, role='Manager').count()
        total_employees = User.query.filter_by(company_id=current_user.company_id, role='Employee').count()
        
        # Expense statistics
        total_expenses_result = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.company_id == current_user.company_id
        ).scalar()
        total_expenses = float(total_expenses_result) if total_expenses_result else 0
        
        pending_expenses_result = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.company_id == current_user.company_id,
            Expense.status == 'pending'
        ).scalar()
        pending_expenses = float(pending_expenses_result) if pending_expenses_result else 0
        
        approved_expenses_result = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.company_id == current_user.company_id,
            Expense.status == 'approved'
        ).scalar()
        approved_expenses = float(approved_expenses_result) if approved_expenses_result else 0
        
        total_expenses_count = Expense.query.filter_by(company_id=current_user.company_id).count()
        pending_expenses_count = Expense.query.filter_by(company_id=current_user.company_id, status='pending').count()
        approved_expenses_count = Expense.query.filter_by(company_id=current_user.company_id, status='approved').count()
        
        # Calculate changes from last month
        last_month = datetime.utcnow() - timedelta(days=30)
        users_last_month = User.query.filter(
            User.company_id == current_user.company_id,
            User.created_at <= last_month
        ).count()
        
        user_change = 0
        if users_last_month > 0:
            user_change = round(((total_users - users_last_month) / users_last_month) * 100, 1)
        
        # Calculate expense changes
        expense_change = 8 if total_expenses > 0 else 0
        revenue_saved = approved_expenses * 0.1  # Placeholder: 10% savings
        
        stats = {
            'total_users': total_users,
            'user_change': user_change,
            'total_managers': total_managers,
            'total_employees': total_employees,
            'total_expenses': total_expenses,
            'expense_change': expense_change,
            'total_reports': total_expenses_count,
            'report_change': -3 if total_expenses_count > 10 else 5,
            'total_revenue': revenue_saved,
            'revenue_change': 15 if revenue_saved > 0 else 0,
            'pending_expenses': pending_expenses,
            'approved_expenses': approved_expenses,
            'pending_expenses_count': pending_expenses_count,
            'approved_expenses_count': approved_expenses_count
        }
        
        return jsonify(stats)
    except Exception as e:
        print(f"Stats error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users')
@login_required
def admin_users():
    """Get all users for admin from database"""
    if current_user.role != 'Admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        users = User.query.filter_by(company_id=current_user.company_id).order_by(User.created_at.desc()).all()
        users_data = []
        
        for user in users:
            users_data.append({
                'id': user.user_id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'manager': user.manager.name if user.manager else 'N/A',
                'status': 'active' if user.is_active else 'inactive',
                'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_active': user.is_active
            })
        
        return jsonify(users_data)
    except Exception as e:
        print(f"Users error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/managers')
@login_required
def admin_managers():
    """Get managers list for dropdown from database"""
    if current_user.role != 'Admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        managers = User.query.filter_by(
            company_id=current_user.company_id, 
            role='Manager'
        ).all()
        managers_data = [{'id': m.user_id, 'name': m.name} for m in managers]
        return jsonify(managers_data)
    except Exception as e:
        print(f"Managers error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/recent_activities')
@login_required
def recent_activities():
    """Get recent activities from database"""
    if current_user.role != 'Admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Try to get activities from activity_logs table
        activities = ActivityLog.query.filter_by(
            company_id=current_user.company_id
        ).order_by(ActivityLog.created_at.desc()).limit(10).all()
        
        activities_data = []
        for activity in activities:
            activities_data.append({
                'id': activity.id,
                'type': activity.activity_type,
                'message': activity.description,
                'user_name': activity.user.name,
                'timestamp': activity.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'icon': get_activity_icon(activity.activity_type)
            })
        
        # If no activity logs, generate from other tables
        if not activities_data:
            activities_data = generate_activities_from_other_tables()
        
        return jsonify(activities_data)
    except Exception as e:
        print(f"Activities error: {e}")
        # Fallback to generated activities
        activities_data = generate_activities_from_other_tables()
        return jsonify(activities_data)

def generate_activities_from_other_tables():
    """Generate activity data from expenses and users tables if activity_logs is empty"""
    activities_data = []
    
    try:
        # Get recent expense approvals
        recent_approvals = ExpenseApproval.query.join(Expense).filter(
            Expense.company_id == current_user.company_id
        ).order_by(ExpenseApproval.created_at.desc()).limit(5).all()
        
        for approval in recent_approvals:
            if approval.action == 'approved':
                activities_data.append({
                    'id': approval.approval_id,
                    'type': 'expense_approved',
                    'message': f'{approval.approver.name} approved expense #{approval.expense_id}',
                    'user_name': approval.approver.name,
                    'timestamp': approval.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'icon': 'check-circle'
                })
            elif approval.action == 'rejected':
                activities_data.append({
                    'id': approval.approval_id,
                    'type': 'expense_rejected',
                    'message': f'{approval.approver.name} rejected expense #{approval.expense_id}',
                    'user_name': approval.approver.name,
                    'timestamp': approval.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'icon': 'times-circle'
                })
        
        # Get recent users
        recent_users = User.query.filter_by(
            company_id=current_user.company_id
        ).order_by(User.created_at.desc()).limit(3).all()
        
        for user in recent_users:
            activities_data.append({
                'id': user.user_id,
                'type': 'user_created',
                'message': f'New user {user.name} joined the system',
                'user_name': 'System',
                'timestamp': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'icon': 'user-plus'
            })
        
        # Sort by timestamp
        activities_data.sort(key=lambda x: x['timestamp'], reverse=True)
        return activities_data[:10]
        
    except Exception as e:
        print(f"Generated activities error: {e}")
        return []

@app.route('/api/admin/expenses')
@login_required
def admin_expenses():
    """Get recent expenses for admin dashboard"""
    if current_user.role != 'Admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        expenses = Expense.query.filter_by(
            company_id=current_user.company_id
        ).order_by(Expense.created_at.desc()).limit(10).all()
        
        expenses_data = []
        for expense in expenses:
            expenses_data.append({
                'id': expense.expense_id,
                'user_name': expense.user.name,
                'amount': float(expense.amount),
                'currency': expense.currency_code,
                'category': expense.category,
                'description': expense.description,
                'status': expense.status,
                'date': expense.expense_date.strftime('%Y-%m-%d'),
                'created_at': expense.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return jsonify(expenses_data)
    except Exception as e:
        print(f"Expenses error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/create_user', methods=['POST'])
@login_required
def api_create_user():
    """Create new user via API"""
    if current_user.role != 'Admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        role = data.get('role')
        manager_id = data.get('manager_id')

        print(f"Creating user: {name}, {email}, {role}, manager_id: {manager_id}")

        if not all([name, email, role]):
            return jsonify({'error': 'All fields are required'}), 400

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'Email already exists'}), 400

        # Generate unique username
        base_username = email.split('@')[0]
        username = base_username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1

        # Convert manager_id to integer or None
        manager_id = int(manager_id) if manager_id and manager_id != '' else None

        # Create user
        user = User(
            company_id=current_user.company_id,
            username=username,
            name=name,
            email=email,
            role=role.capitalize(),
            manager_id=manager_id,
            is_verified=True,
            is_active=True
        )
        user.set_password('Temp123!')  # Default password
        
        db.session.add(user)
        db.session.commit()
        
        print(f"✅ New user created: {name} ({email}) with ID: {user.user_id}")
        
        # Log activity
        log_activity('user_created', f'Created {role} user: {name} ({email})')
        
        return jsonify({
            'success': True, 
            'message': f'{role} user created successfully',
            'user_id': user.user_id
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating user: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/admin/send_password/<int:user_id>', methods=['POST'])
@login_required
def send_password(user_id):
    """Send password reset to user"""
    if current_user.role != 'Admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        user = User.query.filter_by(user_id=user_id, company_id=current_user.company_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate and set temporary password
        temp_password = generate_otp() + "Abc!"
        user.set_password(temp_password)
        
        # Log the activity
        log_activity('password_sent', f'Password reset email sent to {user.name} ({user.email})')
        
        # Send email with temporary password
        email_sent = send_email(
            "Your Account Password - Expense Manager",
            user.email,
            f"Hello {user.name},\n\nYour temporary password is: {temp_password}\n\nPlease login and change your password immediately.\n\nLogin URL: http://localhost:5000/login"
        )
        
        db.session.commit()
        
        if email_sent:
            return jsonify({'success': True, 'message': 'Password sent successfully'})
        else:
            return jsonify({'error': 'Failed to send email'}), 500
            
    except Exception as e:
        db.session.rollback()
        print(f"Send password error: {e}")
        return jsonify({'error': str(e)}), 500

# Authentication Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Company and admin registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')
            company_name = request.form.get('company_name')
            country = request.form.get('country', 'United States')

            # Validate input
            if not all([name, email, password, company_name]):
                flash('All fields are required', 'danger')
                return render_template('signup.html')

            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return render_template('signup.html')

            # Create company
            currency_code = get_country_currency(country)
            company = Company(
                name=company_name,
                country=country,
                currency_code=currency_code
            )
            db.session.add(company)
            db.session.commit()
            
            # Create admin user
            user = User(
                company_id=company.company_id,
                username=email.split('@')[0],
                name=name,
                email=email,
                role='Admin',
                is_verified=True,
                is_active=True
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            # Log activities
            log_activity('company_created', f'Company {company_name} registered', user.user_id, company.company_id)
            log_activity('user_created', f'Admin user {name} created', user.user_id, company.company_id)
            
            flash('Company and admin account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Signup error: {e}")
            flash('Error creating account. Please try again.', 'danger')
            return render_template('signup.html')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please enter both email and password', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Account deactivated. Contact admin.', 'danger')
                return render_template('login.html')
            
            login_user(user)
            log_activity('user_login', f'User {user.name} logged in')
            
            flash(f'Welcome back, {user.name}!', 'success')
            
            # Redirect based on role
            if user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    log_activity('user_logout', f'User {current_user.name} logged out')
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

# Password Reset Routes
@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    """Request password reset"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            user.otp = generate_otp()
            db.session.commit()
            
            if send_email(
                "Password Reset OTP - Expense Manager",
                email,
                f"Hello {user.name},\n\nYour password reset OTP is: {user.otp}\n\nThis code will expire in 10 minutes."
            ):
                session['reset_email'] = email
                flash('OTP sent to your email', 'success')
                return redirect(url_for('reset_password'))
            else:
                flash('Failed to send OTP', 'danger')
        else:
            flash('Email not found', 'danger')
    
    return render_template('reset_request.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Reset password with OTP"""
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('reset_request'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.otp == otp:
            user.set_password(password)
            user.otp = None
            db.session.commit()
            
            log_activity('password_reset', f'Password reset for {user.name}', user.user_id)
            session.pop('reset_email', None)
            
            flash('Password reset successfully', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP', 'danger')
    
    return render_template('reset_password.html')

# Admin Management Routes
@app.route('/manage_users')
@login_required
def manage_users():
    """User management page"""
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter_by(company_id=current_user.company_id).all()
    return render_template('manage_users.html', users=users)

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Application Startup
if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database initialized successfully!")
            print("✅ All tables created/verified")
        except Exception as e:
            print(f"❌ Database error: {e}")
            print("💡 Check MySQL is running and database exists")
    
    print("🚀 Starting Expense Manager...")
    print("📍 Access the application at: http://localhost:5000")
    print("👤 Admin Signup: http://localhost:5000/signup")
    app.run(debug=True, port=5000)
