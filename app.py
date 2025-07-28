from flask import Flask, request, render_template, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# Convert DATABASE_URL to correct format for SQLAlchemy if needed
db_url = os.getenv("DATABASE_URL", "sqlite:///local.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://")

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
ph = PasswordHasher()

# ================== Models =====================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)

# Run create_all() only once
tables_initialized = False

@app.before_request
def initialize_tables_once():
    global tables_initialized
    if not tables_initialized:
        db.create_all()
        tables_initialized = True

# ================ Routes ===================

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not username or not password:
            flash("Both fields are required.", "danger")
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

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

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# ========== REPORT SUBMISSION ========= #
@app.route('/submit-report', methods=['GET', 'POST'])
def submit_report():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form.get('content').strip()
        if content:
            report = Report(username=session['user'], content=content)
            db.session.add(report)
            db.session.commit()
            flash("Report submitted successfully!", "success")
            return redirect(url_for('dashboard'))
        flash("Report cannot be empty.", "warning")

    return render_template('submit_report.html')

@app.route('/view-reports')
def view_reports():
    if 'user' not in session:
        return redirect(url_for('login'))

    reports = Report.query.order_by(Report.timestamp.desc()).all()
    return render_template('view_reports.html', reports=reports)

# ========== REAL FILE UPLOAD ========= #
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('File name is empty.', 'warning')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        new_upload = Upload(username=session['user'], filename=filename)
        db.session.add(new_upload)
        db.session.commit()

        flash('File uploaded successfully!', 'success')
        return redirect(url_for('my_uploads'))

    return render_template('upload.html')

@app.route('/my-uploads')
def my_uploads():
    if 'user' not in session:
        return redirect(url_for('login'))

    uploads = Upload.query.filter_by(username=session['user']).order_by(Upload.upload_time.desc()).all()
    return render_template('my_uploads.html', uploads=uploads)

@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# ===================================

if __name__ == '__main__':
    app.run(debug=True)
