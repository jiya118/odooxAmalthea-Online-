import os
import random
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# Initialize Flask app with correct paths to frontend folder
app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../frontend/static')

# MySQL Database Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost/auth_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
mail = Mail(app)

login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Models
class Company(db.Model):
    __tablename__ = 'companies'
    company_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    currency_code = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    users = db.relationship('User', backref='company', lazy=True)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Employee')
    manager_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    managed_employees = db.relationship('User', backref=db.backref('manager', remote_side=[user_id]))
    
    def get_id(self):
        return str(self.user_id)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def generate_otp():
    return str(random.randint(100000, 999999))

def send_email(subject, recipient, body):
    try:
        msg = Message(subject, sender=os.getenv("MAIL_USERNAME"), recipients=[recipient])
        msg.body = body
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def get_country_currency(country_name):
    """Get currency for a country using REST Countries API"""
    try:
        import requests
        response = requests.get('https://restcountries.com/v3.1/all?fields=name,currencies')
        countries = response.json()
        
        for country in countries:
            if country['name']['common'].lower() == country_name.lower():
                currencies = country.get('currencies', {})
                if currencies:
                    return list(currencies.keys())[0]
        return 'USD'  # default
    except:
        return 'USD'

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Only for Admin registration - creates company and admin user"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        company_name = request.form.get('company_name')
        country = request.form.get('country', 'United States')

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return render_template('signup.html')

        # Create company
        currency_code = get_country_currency(country)
        company = Company(
            name=company_name,
            country=country, 
            currency_code=currency_code
        )
        db.session.add(company)
        db.session.flush()  # Get company ID without committing

        # Create admin user
        user = User(
            company_id=company.company_id,
            name=name,
            email=email,
            role='Admin',
            is_verified=False,
            otp=generate_otp()
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()

        # Send OTP email
        if send_email("Your OTP Verification Code - Expense Manager", email, 
                     f"Hello {name},\n\nYour OTP code is: {user.otp}\n\nThis code will expire in 10 minutes."):
            flash('OTP sent to your email! Please verify.', 'success')
            session['email_for_verification'] = email
            return redirect(url_for('verify_otp'))
        else:
            flash('Failed to send OTP email. Please try again.', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    """OTP verification for admin signup"""
    email = session.get('email_for_verification')
    if not email:
        return redirect(url_for('signup'))

    if request.method == 'POST':
        input_otp = request.form.get('otp')
        user = User.query.filter_by(email=email).first()
        
        if user and user.otp == input_otp:
            user.is_verified = True
            user.otp = None
            db.session.commit()
            
            flash('Email verified successfully! You can now login.', 'success')
            session.pop('email_for_verification', None)
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP! Try again.', 'danger')

    return render_template('verify_otp.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login for Admin, Manager, and Employee"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please verify your email first!', 'warning')
                return redirect(url_for('login'))
            
            if not user.is_active:
                flash('Your account has been deactivated. Please contact admin.', 'danger')
                return redirect(url_for('login'))
            
            login_user(user)
            flash(f'Welcome {user.name}, you are logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    """Only Admin can create Manager and Employee users"""
    if current_user.role != 'Admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        manager_id = request.form.get('manager_id')

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('create_user'))

        # Create user
        user = User(
            company_id=current_user.company_id,
            name=name,
            email=email,
            role=role,
            manager_id=manager_id if manager_id else None,
            is_verified=True  # No OTP required for admin-created users
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()

        flash(f'{role} user created successfully!', 'success')
        return redirect(url_for('manage_users'))

    # Get managers for dropdown
    managers = User.query.filter_by(company_id=current_user.company_id, role='Manager').all()
    return render_template('create_user.html', managers=managers)

@app.route('/manage_users')
@login_required
def manage_users():
    """Admin can view all users"""
    if current_user.role != 'Admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter_by(company_id=current_user.company_id).all()
    return render_template('manage_users.html', users=users)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("🚀 Starting Expense Manager...")
    print("📱 Access the application at: http://localhost:5000")
    print("💡 Admin Signup: http://localhost:5000/signup")
    app.run(debug=True, port=5000)