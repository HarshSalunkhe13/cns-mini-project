import base64
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = Flask(__name__)

# In-memory storage for demo key pairs
KEYS = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    user = request.json.get('username', 'default_user')
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    KEYS[user] = {'private': private_key, 'public': public_key}
    return jsonify({"status": "success", "message": f"RSA-2048 Key pair generated successfully for {user}!"})

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.json
    recipient = data.get('username')
    message = data.get('message').encode('utf-8')
    
    if recipient not in KEYS:
        return jsonify({"status": "error", "message": "Recipient keys not found. Generate keys first!"}), 400
        
    pub_key = KEYS[recipient]['public']
    
    # 1. Generate AES Session Key & IV
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    
    # 2. Encrypt Message with AES-CBC
    pad_len = 16 - (len(message) % 16)
    padded_message = message + bytes([pad_len] * pad_len)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # 3. Encrypt AES Key with RSA (Digital Envelope)
    encrypted_aes_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # 4. Generate SHA-256 Hash for Integrity
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    msg_hash = digest.finalize()

    return jsonify({
        "status": "success",
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "hash": base64.b64encode(msg_hash).decode('utf-8')
    })

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    data = request.json
    recipient = data.get('username')
    
    try:
        priv_key = KEYS[recipient]['private']
        encrypted_aes_key = base64.b64decode(data.get('encrypted_key'))
        ciphertext = base64.b64decode(data.get('ciphertext'))
        iv = base64.b64decode(data.get('iv'))
        
        # 1. Decrypt AES Key using RSA Private Key
        aes_key = priv_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        # 2. Decrypt Message using AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        
        pad_len = padded_message[-1]
        message = padded_message[:-pad_len].decode('utf-8')
        
        return jsonify({"status": "success", "message": message})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)