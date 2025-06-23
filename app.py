from flask import Flask, request, render_template, redirect, url_for
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
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
    plain_files = os.listdir(app.config['UPLOAD_FOLDER_PLAIN'])
    encrypted_files = os.listdir(app.config['UPLOAD_FOLDER_ENCRYPTED'])
    return render_template('files.html', plain_files=plain_files, encrypted_files=encrypted_files)

if __name__ == '__main__':
    app.run(debug=True) 
