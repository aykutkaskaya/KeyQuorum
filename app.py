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
    symmetric_key_encrypted = db.Column(db.Text, nullable=False)  # JSON of encrypted symmetric keys
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    one_time_view = db.Column(db.Boolean, default=False)  # if True, can only be viewed once per approval

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
            if req.status == 'approved':
                # Member viewing approved data
                if req.requester_id == user.id:
                    data = EncryptedData.query.get(req.data_id)
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
                    data = EncryptedData.query.get(req.data_id)
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
            # Supervisor approving a request or member viewing approved data
            request_id = int(request.form['request_id'])
            req = DecryptionRequest.query.get(request_id)
            if req.status == 'approved':
                # Member viewing approved data
                if req.requester_id == user.id:
                    data = EncryptedData.query.get(req.data_id)
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
                        log = Log(action='Data viewed by member', user_id=user.id, data_id=req.data_id)
                        db.session.add(log)
                        db.session.commit()
                        return render_template('decrypted.html', data=decrypted.decode())
                    else:
                        flash('Key mismatch')
                        return redirect(url_for('decrypt_data_route'))
                else:
                    flash('Access denied')
                    return redirect(url_for('decrypt_data_route'))
            elif req.approver_id == user.id and req.status == 'pending':
                # Supervisor approving a request
                req.status = 'approved'
                req.approved_at = datetime.utcnow()
                db.session.commit()
                # Now decrypt the data
                data = EncryptedData.query.get(req.data_id)
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
            else:
                flash('Invalid request')
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
    app.run(debug=True)