from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# Upload folder
app.config['UPLOAD_FOLDER_PLAIN'] = 'plain_files'
app.config['UPLOAD_FOLDER_ENCRYPTED'] = 'encrypted_files'

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Encryption key
KEY_FILE = 'filekey.key'
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

fernet = Fernet(key)

@app.before_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match.')

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists.')
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already registered.')

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user'] = user.username
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))

    uploaded_file = request.files['file']
    encrypt = request.form.get('encrypt') == 'on'

    if uploaded_file:
        filename = uploaded_file.filename
        file_data = uploaded_file.read()

        if encrypt:
            encrypted_data = fernet.encrypt(file_data)
            save_path = os.path.join(app.config['UPLOAD_FOLDER_ENCRYPTED'], filename)
            with open(save_path, 'wb') as f:
                f.write(encrypted_data)
        else:
            save_path = os.path.join(app.config['UPLOAD_FOLDER_PLAIN'], filename)
            with open(save_path, 'wb') as f:
                f.write(file_data)

    return redirect(url_for('index'))

@app.route('/files')
def view_files():
    if 'user' not in session:
        return redirect(url_for('login'))

    plain_files = os.listdir(app.config['UPLOAD_FOLDER_PLAIN'])
    encrypted_files = os.listdir(app.config['UPLOAD_FOLDER_ENCRYPTED'])
    return render_template('files.html', plain_files=plain_files, encrypted_files=encrypted_files)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            return redirect(url_for('reset_password', username=user.username))
        else:
            return render_template('forgot_password.html', message="Email not found")
    return render_template('forgot_password.html')

@app.route('/reset_password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            return render_template('reset_password.html', username=username, message="Passwords do not match.")
        user.password = generate_password_hash(password)
        db.session.commit()
        flash("Password successfully reset.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', username=username)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)