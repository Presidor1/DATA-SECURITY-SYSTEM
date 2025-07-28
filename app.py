from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# Database configuration
db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://")

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///local.db'  # fallback for local dev
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ph = PasswordHasher()

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Route: Home
@app.route('/')
def home():
    return render_template("index.html")

# Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'warning')
            return redirect(url_for('register'))

        hashed_password = ph.hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))

        try:
            if ph.verify(user.password_hash, password):
                session['user'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
        except VerifyMismatchError:
            flash('Incorrect password.', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html')

# Route: Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

# Route: Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# Database initializer (runs once per app boot)
@app.before_first_request
def initialize_database():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
