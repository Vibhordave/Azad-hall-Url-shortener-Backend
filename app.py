from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
secret_key = secrets.token_hex(16)  # Generates a 32-character hexadecimal string

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'vibhor.dave03@gmail.com'
app.config['MAIL_PASSWORD'] = 'divashvib@123'

mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    verified = db.Column(db.Boolean, default=False)

# Google Blueprint
google_bp = make_google_blueprint(
    client_id="876096187874-5dpmo9bitehpl1ijbfs085etn9b4vj2i.apps.googleusercontent.com",
    client_secret="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",
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        email = resp.json()['email']
        user = User.query.filter_by(email=email).first()
        if user:
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('You are not registered. Please sign up first.', 'warning')
            return redirect(url_for('register'))
    else:
        return 'Could not fetch your information from Google.', 400

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(email=email, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            token = serializer.dumps(email, salt='email-confirmation')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            msg = Message('Confirm Email', sender='vibhor.dave03@gmail.com', recipients=[email])
            msg.body = f'Please click the link to confirm your email: {confirm_url}'
            mail.send(msg)
            flash('An email has been sent with instructions to confirm your email.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirmation', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.verified = True
            db.session.commit()
            flash('Email verified successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email verification failed.', 'danger')
            return redirect(url_for('register'))
    except SignatureExpired:
        flash('The confirmation link has expired.', 'warning')
        return redirect(url_for('register'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
