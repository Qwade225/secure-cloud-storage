from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'  # Replace this in production

# Token generator for password reset
serializer = URLSafeTimedSerializer(app.secret_key)

# Set up SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# File upload folders
app.config['UPLOAD_FOLDER_PLAIN'] = 'plain_files'
app.config['UPLOAD_FOLDER_ENCRYPTED'] = 'encrypted_files'

# ------------------ MODELS ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    encrypted = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------ ENCRYPTION ------------------

KEY_FILE = 'filekey.key'
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

fernet = Fernet(key)

# ------------------ TABLE INIT ------------------

@app.before_request
def create_tables():
    db.create_all()

# ------------------ ROUTES ------------------

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
        user = User.query.filter_by(username=session['user']).first()

        if encrypt:
            encrypted_data = fernet.encrypt(file_data)
            save_path = os.path.join(app.config['UPLOAD_FOLDER_ENCRYPTED'], filename)
            with open(save_path, 'wb') as f:
                f.write(encrypted_data)
        else:
            save_path = os.path.join(app.config['UPLOAD_FOLDER_PLAIN'], filename)
            with open(save_path, 'wb') as f:
                f.write(file_data)

        # Save to DB
        new_file = File(filename=filename, encrypted=encrypt, user_id=user.id)
        db.session.add(new_file)
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/files')
def view_files():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['user']).first()
    files = File.query.filter_by(user_id=user.id).all()
    return render_template('files.html', files=files)

# ------------------ PASSWORD RESET ------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='email-confirm')
            reset_url = url_for('reset_password', token=token, _external=True)
            print(f"[DEBUG] Password reset link: {reset_url}")
        return render_template('forgot_password.html', message='Check your email for a reset link.')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except:
        return "The reset link is invalid or has expired."

    if request.method == 'POST':
        new_password = generate_password_hash(request.form['password'])
        user = User.query.filter_by(email=email).first()
        user.password = new_password
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('reset_password.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)