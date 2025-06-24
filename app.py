from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'  # Replace this in production

# Set up SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# File upload folders
app.config['UPLOAD_FOLDER_PLAIN'] = 'plain_files'
app.config['UPLOAD_FOLDER_ENCRYPTED'] = 'encrypted_files'

# User model for authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

# Encryption key setup
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
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='Username already exists.')
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
