from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///keyquorum.db'
db = SQLAlchemy(app)

# System master key for encrypting AES keys (in production, this should be securely stored)
SYSTEM_MASTER_KEY = b'system_master_key_32_bytes_long!'  # Exactly 32 bytes for AES-256

# Configuration for n and m - can be changed here
N = 3  # number of team members
M = 2  # number of supervisors

class DecryptionRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_id = db.Column(db.Integer, db.ForeignKey('encrypted_data.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # member requesting
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # supervisor to approve
    status = db.Column(db.String(20), default='pending')  # pending, approved, denied
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    viewed = db.Column(db.Boolean, default=False)  # if one-time view, mark as viewed after first access
    
    requester = db.relationship('User', foreign_keys=[requester_id], backref='requests_made')
    approver = db.relationship('User', foreign_keys=[approver_id], backref='requests_to_approve')
    data = db.relationship('EncryptedData', backref='requests')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'member' or 'supervisor'
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)  # In real app, this should be encrypted and stored securely

class EncryptedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # user-defined name for the data
    data = db.Column(db.Text, nullable=False)  # encrypted data
    symmetric_key_encrypted = db.Column(db.Text, nullable=True)  # JSON of encrypted symmetric keys (for backward compatibility)
    use_proxy = db.Column(db.Boolean, default=False)  # if True, uses proxy key encryption
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    one_time_view = db.Column(db.Boolean, default=False)  # if True, can only be viewed once per approval

class ProxyKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_id = db.Column(db.Integer, db.ForeignKey('encrypted_data.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)  # AES key encrypted with user's public key
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    data = db.relationship('EncryptedData', backref='proxy_keys')
    user = db.relationship('User', backref='proxy_keys')

class MasterKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_id = db.Column(db.Integer, db.ForeignKey('encrypted_data.id'), nullable=False)
    encrypted_master_key = db.Column(db.Text, nullable=False)  # Master AES key encrypted with system key
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    data = db.relationship('EncryptedData', backref='master_key')

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    data_id = db.Column(db.Integer, db.ForeignKey('encrypted_data.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='logs')

def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    return base64.b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    ).decode()

def serialize_public_key(public_key):
    return base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()

def deserialize_private_key(pem_data):
    return serialization.load_pem_private_key(
        base64.b64decode(pem_data),
        password=None,
        backend=default_backend()
    )

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(
        base64.b64decode(pem_data),
        backend=default_backend()
    )

def encrypt_data(data, symmetric_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b'\0' * (16 - len(data) % 16)  # Simple padding
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_data(encrypted_data, symmetric_key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_padded.rstrip(b'\0')

def encrypt_symmetric_key(symmetric_key, public_key):
    encrypted = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_symmetric_key(encrypted_key, private_key):
    encrypted_key = base64.b64decode(encrypted_key)
    decrypted = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def encrypt_with_system_key(data, system_key):
    """Encrypt data with system master key using AES"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(system_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b'\0' * (16 - len(data) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_with_system_key(encrypted_data, system_key):
    """Decrypt data with system master key using AES"""
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(system_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_padded.rstrip(b'\0')

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', n=N, m=M)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))
        flash('User not found')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/add_data', methods=['GET', 'POST'])
def add_data():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        data = request.form['data'].encode()
        one_time_view = 'one_time_view' in request.form
        use_proxy = 'use_proxy' in request.form  # New checkbox for proxy layer

        if use_proxy:
            # Enhanced Proxy layer: Store master AES key encrypted with system key
            aes_key = os.urandom(32)
            encrypted_data = encrypt_data(data, aes_key)

            new_data = EncryptedData(name=name, data=encrypted_data, symmetric_key_encrypted=None, use_proxy=True, one_time_view=one_time_view)
            db.session.add(new_data)
            db.session.commit()

            # Store master AES key encrypted with system key
            encrypted_master_key = encrypt_with_system_key(aes_key, SYSTEM_MASTER_KEY)
            master_key_record = MasterKey(data_id=new_data.id, encrypted_master_key=encrypted_master_key)
            db.session.add(master_key_record)
            db.session.commit()

            # Encrypt AES key for each team member (members and supervisors)
            all_users = User.query.all()
            for user in all_users:
                pub_key = deserialize_public_key(user.public_key)
                encrypted_aes_key = encrypt_symmetric_key(aes_key, pub_key)

                proxy_key = ProxyKey(data_id=new_data.id, user_id=user.id, encrypted_aes_key=encrypted_aes_key)
                db.session.add(proxy_key)
            db.session.commit()

            log = Log(action='Data encrypted with enhanced proxy layer', user_id=session['user_id'], data_id=new_data.id)
        else:
            # Original flow: Encrypt data with symmetric key, encrypt symmetric key for each user
            symmetric_key = os.urandom(32)
            encrypted_data = encrypt_data(data, symmetric_key)

            members = User.query.filter_by(role='member').all()
            supervisors = User.query.filter_by(role='supervisor').all()

            encrypted_keys = {}
            for member in members:
                pub_key = deserialize_public_key(member.public_key)
                encrypted_keys[f'member_{member.id}'] = encrypt_symmetric_key(symmetric_key, pub_key)

            for supervisor in supervisors:
                pub_key = deserialize_public_key(supervisor.public_key)
                encrypted_keys[f'supervisor_{supervisor.id}'] = encrypt_symmetric_key(symmetric_key, pub_key)

            import json
            new_data = EncryptedData(name=name, data=encrypted_data, symmetric_key_encrypted=json.dumps(encrypted_keys), one_time_view=one_time_view)
            db.session.add(new_data)
            db.session.commit()

            log = Log(action='Data encrypted', user_id=session['user_id'], data_id=new_data.id)

        db.session.add(log)
        db.session.commit()

        flash('Data encrypted successfully')
        return redirect(url_for('index'))
    return render_template('add_data.html')

@app.route('/decrypt_data', methods=['GET', 'POST'])
def decrypt_data_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        if 'data_id' in request.form and 'supervisor_id' in request.form:
            # Member creating a new request
            data_id = int(request.form['data_id'])
            supervisor_id = int(request.form['supervisor_id'])
            # Create decryption request
            request_obj = DecryptionRequest(data_id=data_id, requester_id=user.id, approver_id=supervisor_id)
            db.session.add(request_obj)
            db.session.commit()
            log = Log(action='Decryption request created', user_id=user.id, data_id=data_id)
            db.session.add(log)
            db.session.commit()
            flash('Decryption request sent to supervisor')
            return redirect(url_for('index'))
        elif 'request_id' in request.form:
            # Handling existing request (approval or viewing)
            request_id = int(request.form['request_id'])
            req = DecryptionRequest.query.get(request_id)
            data = EncryptedData.query.get(req.data_id)

            if data.use_proxy:
                # Proxy layer decryption flow
                if req.status == 'approved':
                    # Member viewing approved data using proxy keys
                    if req.requester_id == user.id:
                        # Get member's proxy key
                        member_proxy_key = ProxyKey.query.filter_by(data_id=req.data_id, user_id=user.id).first()
                        if not member_proxy_key:
                            flash('Proxy key not found')
                            return redirect(url_for('decrypt_data_route'))

                        # Decrypt AES key with member's private key
                        member_priv = deserialize_private_key(user.private_key)
                        aes_key = decrypt_symmetric_key(member_proxy_key.encrypted_aes_key, member_priv)

                        # Decrypt data with AES key
                        decrypted = decrypt_data(data.data, aes_key)

                        # Mark as viewed if one-time view
                        if req.data.one_time_view:
                            req.viewed = True
                            db.session.commit()
                            flash('This was a one-time view. The data can no longer be accessed with this approval.')

                        log = Log(action='Data viewed by member (proxy)', user_id=user.id, data_id=req.data_id)
                        db.session.add(log)
                        db.session.commit()
                        return render_template('decrypted.html', data=decrypted.decode(), one_time_view=req.data.one_time_view)
                    else:
                        flash('Access denied')
                        return redirect(url_for('decrypt_data_route'))
                elif req.approver_id == user.id and req.status == 'pending':
                    # Supervisor approving request (no decryption needed for proxy layer)
                    action = request.form.get('action', 'approve')
                    if action == 'approve':
                        req.status = 'approved'
                        req.approved_at = datetime.utcnow()
                        db.session.commit()
                        log = Log(action='Decryption request approved (proxy)', user_id=user.id, data_id=req.data_id)
                        db.session.add(log)
                        db.session.commit()
                        flash('Request approved. Member can now access the data.')
                        return redirect(url_for('decrypt_data_route'))
                    elif action == 'decline':
                        req.status = 'declined'
                        req.approved_at = datetime.utcnow()
                        db.session.commit()
                        log = Log(action='Decryption request declined (proxy)', user_id=user.id, data_id=req.data_id)
                        db.session.add(log)
                        db.session.commit()
                        flash('Request declined')
                        return redirect(url_for('decrypt_data_route'))
                else:
                    flash('Invalid request')
                    return redirect(url_for('decrypt_data_route'))
            else:
                # Original decryption flow
                if req.status == 'approved':
                    # Member viewing approved data
                    if req.requester_id == user.id:
                        import json
                        encrypted_keys = json.loads(data.symmetric_key_encrypted)
                        member_key = encrypted_keys[f'member_{req.requester_id}']
                        supervisor_key = encrypted_keys[f'supervisor_{req.approver_id}']
                        member_priv = deserialize_private_key(user.private_key)
                        supervisor_priv = deserialize_private_key(User.query.get(req.approver_id).private_key)
                        sym_key1 = decrypt_symmetric_key(member_key, member_priv)
                        sym_key2 = decrypt_symmetric_key(supervisor_key, supervisor_priv)
                        if sym_key1 == sym_key2:
                            symmetric_key = sym_key1
                            decrypted = decrypt_data(data.data, symmetric_key)
                            # Mark as viewed if one-time view
                            if req.data.one_time_view:
                                req.viewed = True
                                db.session.commit()
                                flash('This was a one-time view. The data can no longer be accessed with this approval.')

                            log = Log(action='Data viewed by member', user_id=user.id, data_id=req.data_id)
                            db.session.add(log)
                            db.session.commit()
                            return render_template('decrypted.html', data=decrypted.decode(), one_time_view=req.data.one_time_view)
                        else:
                            flash('Key mismatch')
                            return redirect(url_for('decrypt_data_route'))
                    else:
                        flash('Access denied')
                        return redirect(url_for('decrypt_data_route'))
                elif req.approver_id == user.id and req.status == 'pending':
                    # Supervisor approving or declining a request
                    action = request.form.get('action', 'approve')
                    if action == 'approve':
                        req.status = 'approved'
                        req.approved_at = datetime.utcnow()
                        db.session.commit()
                        # Now decrypt the data
                        import json
                        encrypted_keys = json.loads(data.symmetric_key_encrypted)
                        member_key = encrypted_keys[f'member_{req.requester_id}']
                        supervisor_key = encrypted_keys[f'supervisor_{user.id}']
                        member_priv = deserialize_private_key(User.query.get(req.requester_id).private_key)
                        supervisor_priv = deserialize_private_key(user.private_key)
                        sym_key1 = decrypt_symmetric_key(member_key, member_priv)
                        sym_key2 = decrypt_symmetric_key(supervisor_key, supervisor_priv)
                        if sym_key1 == sym_key2:
                            symmetric_key = sym_key1
                            decrypted = decrypt_data(data.data, symmetric_key)
                            log = Log(action='Data decrypted by supervisor', user_id=user.id, data_id=req.data_id)
                            db.session.add(log)
                            db.session.commit()
                            return render_template('decrypted.html', data=decrypted.decode())
                        else:
                            flash('Key mismatch')
                            return redirect(url_for('decrypt_data_route'))
                    elif action == 'decline':
                        req.status = 'declined'
                        req.approved_at = datetime.utcnow()
                        db.session.commit()
                        log = Log(action='Decryption request declined', user_id=user.id, data_id=req.data_id)
                        db.session.add(log)
                        db.session.commit()
                        flash('Request declined')
                        return redirect(url_for('decrypt_data_route'))
                else:
                    flash('Invalid request')
                    return redirect(url_for('decrypt_data_route'))
        else:
            flash('Invalid form data')
            return redirect(url_for('decrypt_data_route'))
    
    datas = EncryptedData.query.all()
    members = User.query.filter_by(role='member').all()
    supervisors = User.query.filter_by(role='supervisor').all()
    if user.role == 'supervisor':
        pending_requests = DecryptionRequest.query.filter_by(approver_id=user.id, status='pending').all()
    else:
        pending_requests = []
    
    # For members, show their own requests
    if user.role == 'member':
        my_requests = DecryptionRequest.query.filter_by(requester_id=user.id).all()
    else:
        my_requests = []
    
    return render_template('decrypt_data.html', datas=datas, members=members, supervisors=supervisors, user=user, pending_requests=pending_requests, my_requests=my_requests)

@app.route('/logs')
def logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    # Create a dict of data_id -> data for quick lookup
    datas = {data.id: data for data in EncryptedData.query.all()}
    return render_template('logs.html', logs=logs, datas=datas)
@app.route('/add_user', methods=['POST'])
def add_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    username = request.form['username']
    role = request.form['role']

    # Check if user already exists
    if User.query.filter_by(username=username).first():
        flash('User already exists')
        return redirect(url_for('index'))

    # Generate keypair for new user
    priv, pub = generate_keypair()

    # Create new user
    new_user = User(
        username=username,
        role=role,
        public_key=serialize_public_key(pub),
        private_key=serialize_private_key(priv)
    )
    db.session.add(new_user)
    db.session.commit()

    # For proxy-encrypted data, generate proxy keys for the new user
    proxy_datas = EncryptedData.query.filter_by(use_proxy=True).all()
    for data in proxy_datas:
        # Get the master AES key from MasterKey table
        master_key_record = MasterKey.query.filter_by(data_id=data.id).first()
        if master_key_record:
            # Decrypt master key with system key
            aes_key = decrypt_with_system_key(master_key_record.encrypted_master_key, SYSTEM_MASTER_KEY)

            # Encrypt AES key with new user's public key
            pub_key = deserialize_public_key(new_user.public_key)
            encrypted_aes_key = encrypt_symmetric_key(aes_key, pub_key)

            # Create proxy key for new user
            proxy_key = ProxyKey(data_id=data.id, user_id=new_user.id, encrypted_aes_key=encrypted_aes_key)
            db.session.add(proxy_key)

    # For non-proxy data, we need to add the new user to existing encrypted keys
    non_proxy_datas = EncryptedData.query.filter_by(use_proxy=False).all()
    for data in non_proxy_datas:
        if data.symmetric_key_encrypted:
            import json
            encrypted_keys = json.loads(data.symmetric_key_encrypted)

            # Add new user to the encrypted keys
            if new_user.role == 'member':
                pub_key = deserialize_public_key(new_user.public_key)
                # Get the original symmetric key by decrypting with any existing member's key
                existing_member_key = None
                for key_name, enc_key in encrypted_keys.items():
                    if key_name.startswith('member_'):
                        existing_member_key = enc_key
                        break

                if existing_member_key:
                    # Find an existing member to get the symmetric key
                    existing_member_id = None
                    for key_name in encrypted_keys.keys():
                        if key_name.startswith('member_'):
                            existing_member_id = int(key_name.split('_')[1])
                            break

                    if existing_member_id:
                        existing_member = User.query.get(existing_member_id)
                        if existing_member:
                            existing_priv = deserialize_private_key(existing_member.private_key)
                            symmetric_key = decrypt_symmetric_key(existing_member_key, existing_priv)

                            # Encrypt with new user's public key
                            new_encrypted_key = encrypt_symmetric_key(symmetric_key, pub_key)
                            encrypted_keys[f'member_{new_user.id}'] = new_encrypted_key

                            # Update the data record
                            data.symmetric_key_encrypted = json.dumps(encrypted_keys)
                            db.session.commit()
            elif new_user.role == 'supervisor':
                pub_key = deserialize_public_key(new_user.public_key)
                # Get the original symmetric key by decrypting with any existing supervisor's key
                existing_supervisor_key = None
                for key_name, enc_key in encrypted_keys.items():
                    if key_name.startswith('supervisor_'):
                        existing_supervisor_key = enc_key
                        break

                if existing_supervisor_key:
                    # Find an existing supervisor to get the symmetric key
                    existing_supervisor_id = None
                    for key_name in encrypted_keys.keys():
                        if key_name.startswith('supervisor_'):
                            existing_supervisor_id = int(key_name.split('_')[1])
                            break

                    if existing_supervisor_id:
                        existing_supervisor = User.query.get(existing_supervisor_id)
                        if existing_supervisor:
                            existing_priv = deserialize_private_key(existing_supervisor.private_key)
                            symmetric_key = decrypt_symmetric_key(existing_supervisor_key, existing_priv)

                            # Encrypt with new user's public key
                            new_encrypted_key = encrypt_symmetric_key(symmetric_key, pub_key)
                            encrypted_keys[f'supervisor_{new_user.id}'] = new_encrypted_key

                            # Update the data record
                            data.symmetric_key_encrypted = json.dumps(encrypted_keys)
                            db.session.commit()

    db.session.commit()

    log = Log(action=f'New user {username} added with role {role}', user_id=session['user_id'])
    db.session.add(log)
    db.session.commit()

    flash(f'User {username} added successfully')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create sample users if not exist
        if not User.query.first():
            for i in range(N):
                priv, pub = generate_keypair()
                user = User(username=f'member{i+1}', role='member', public_key=serialize_public_key(pub), private_key=serialize_private_key(priv))
                db.session.add(user)
            for i in range(M):
                priv, pub = generate_keypair()
                user = User(username=f'supervisor{i+1}', role='supervisor', public_key=serialize_public_key(pub), private_key=serialize_private_key(priv))
                db.session.add(user)
            db.session.commit()
    app.run(host='0.0.0.0', port=5001, debug=True)
