from flask import Flask, request, render_template, redirect, url_for, session
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this to something strong in production

app.config['UPLOAD_FOLDER_PLAIN'] = 'plain_files'
app.config['UPLOAD_FOLDER_ENCRYPTED'] = 'encrypted_files'
# Load or generate encryption key

KEY_FILE = 'filekey.key'
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

fernet = Fernet(key)

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Simple hardcoded check
        if username == 'admin' and password == '1234':
            session['user'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True) 




