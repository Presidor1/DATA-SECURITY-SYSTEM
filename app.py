from flask import Flask, request, render_template, redirect, url_for, flash, session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")  # You should set this in Render ENV

# Simulated in-memory "database"
users_db = {}

# Initialize Argon2 Password Hasher
ph = PasswordHasher()

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users_db:
            flash('Username already exists. Please choose another.', 'warning')
            return redirect(url_for('register'))

        # Hash the password using Argon2
        hashed_password = ph.hash(password)
        users_db[username] = hashed_password
        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        hashed = users_db.get(username)
        if not hashed:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))

        try:
            if ph.verify(hashed, password):
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

if __name__ == '__main__':
    app.run(debug=True)
