from flask import Flask, request, render_template, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import traceback
import mimetypes  # ✅ Added for MIME type guessing

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
        try:
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
        except Exception as e:
            print("UPLOAD ERROR:", traceback.format_exc())
            flash('Unexpected error during file upload.', 'danger')
            return redirect(request.url)

    return render_template('upload.html')

@app.route('/my-uploads')
def my_uploads():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        uploads = Upload.query.filter_by(username=session['user']).order_by(Upload.upload_time.desc()).all()
        return render_template('my_uploads.html', uploads=uploads)
    except Exception as e:
        print("MY UPLOADS ERROR:", traceback.format_exc())
        flash("Error loading uploads.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        print("DOWNLOAD ERROR:", traceback.format_exc())
        flash("File could not be downloaded.", "danger")
        return redirect(url_for('my_uploads'))

# ✅ UPDATED ROUTE FOR VIEWING FILES WITH MIME TYPE SUPPORT
@app.route('/view/<filename>')
def view_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if not os.path.isfile(file_path):
            flash("File does not exist.", "danger")
            return redirect(url_for('my_uploads'))

        mime_type, _ = mimetypes.guess_type(file_path)
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            mimetype=mime_type,
            as_attachment=False  # View in browser
        )

    except Exception as e:
        print("VIEW FILE ERROR:", traceback.format_exc())
        flash("File could not be viewed.", "danger")
        return redirect(url_for('my_uploads'))

# ========== Error Handler ========= #
@app.errorhandler(500)
def internal_error(error):
    print("INTERNAL SERVER ERROR:", traceback.format_exc())
    return render_template('500.html'), 500

# ========== Start Server ========= #
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
