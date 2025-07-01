# Cloud Project – Encrypted File Storage

This project is a Flask-based cloud file storage system with built-in AES encryption. It allows users to securely upload, store, and retrieve files via a web interface.

## Features

- Flask backend
- AES file encryption and decryption
- File key management
- Upload/download functionality
- User session handling

## Setup

1. **Clone the repository**  
   ```bash
   git clone https://github.com/Qwade225/secure-cloud-storage.git
   cd secure-cloud-storage

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

flask run
