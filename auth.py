from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from .model import db, User, Company
from . import mail
import requests
import random

auth = Blueprint('auth', __name__)

def generate_otp():
    return str(random.randint(100000, 999999))

def send_email(subject, recipient, body):
    try:
        msg = Message(subject, sender='noreply@expensemanager.com', recipients=[recipient])
        msg.body = body
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def get_country_currency(country_name):
    """Get currency for a country using REST Countries API"""
    try:
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

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    """Only for Admin registration - creates company and admin user"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
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
            return redirect(url_for('auth.verify_otp'))
        else:
            flash('Failed to send OTP email. Please try again.', 'danger')
            return redirect(url_for('auth.signup'))

    return render_template('signup.html')

@auth.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    """OTP verification for admin signup"""
    email = session.get('email_for_verification')
    if not email:
        return redirect(url_for('auth.signup'))

    if request.method == 'POST':
        input_otp = request.form.get('otp')
        user = User.query.filter_by(email=email).first()
        
        if user and user.otp == input_otp:
            user.is_verified = True
            user.otp = None
            db.session.commit()
            
            flash('Email verified successfully! You can now login.', 'success')
            session.pop('email_for_verification', None)
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid OTP! Try again.', 'danger')

    return render_template('verify_otp.html', email=email)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Login for Admin, Manager, and Employee"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please verify your email first!', 'warning')
                return redirect(url_for('auth.login'))
            
            if not user.is_active:
                flash('Your account has been deactivated. Please contact admin.', 'danger')
                return redirect(url_for('auth.login'))
            
            login_user(user)
            flash(f'Welcome {user.name}, you are logged in!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('auth.login'))

@auth.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    """Only Admin can create Manager and Employee users"""
    if current_user.role != 'Admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        manager_id = request.form.get('manager_id')

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('auth.create_user'))

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
        return redirect(url_for('auth.manage_users'))

    # Get managers for dropdown
    managers = User.query.filter_by(company_id=current_user.company_id, role='Manager').all()
    return render_template('create_user.html', managers=managers)

@auth.route('/manage_users')
@login_required
def manage_users():
    """Admin can view all users"""
    if current_user.role != 'Admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    users = User.query.filter_by(company_id=current_user.company_id).all()
    return render_template('manage_users.html', users=users)