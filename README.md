# 🔐 KeyQuorum - Multi-Key Encryption Demo

A Flask-based web application demonstrating a multi-key encryption system with dynamic n+m quorum structure. This project showcases secure data encryption where decryption requires collaboration between team members and supervisors.

## 🌟 Features

- **Multi-Key Encryption**: Data is encrypted with AES using a randomly generated symmetric key
- **Quorum System**: Configurable n (team members) + m (supervisors) structure
- **Request-Approval Flow**: Members request decryption, supervisors approve/decline
- **One-Time View Option**: Data can be configured for single-use access per approval
- **Activity Logging**: Complete audit trail of all encryption/decryption activities
- **Modern UI**: Beautiful, responsive web interface with glassmorphism design

## 🏗️ Architecture

### Security Model
- **Team Members (n)**: Can encrypt data and request decryption
- **Supervisors (m)**: Can approve/decline decryption requests
- **Decryption**: Requires both member and supervisor keys to work
- **One-Time View**: Optional security feature for sensitive data

### Database Models
- `User`: Team members and supervisors with RSA key pairs
- `EncryptedData`: Encrypted content with metadata
- `DecryptionRequest`: Approval workflow management
- `Log`: Complete audit trail

## 🚀 Quick Start

### Option 1: Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/aykutkaskaya/KeyQuorum.git
   cd KeyQuorum
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Open in browser**
   ```
   http://127.0.0.1:5000
   ```

### Option 2: Docker

1. **Using Docker Compose (Recommended)**
   ```bash
   docker-compose up --build
   ```

2. **Using Docker directly**
   ```bash
   docker build -t keyquorum .
   docker run -p 5000:5000 keyquorum
   ```

## 👥 Default Users

The application creates sample users automatically:

**Team Members:**
- member1, member2, member3

**Supervisors:**
- supervisor1, supervisor2

## 🔧 Configuration

Modify the quorum structure in `app.py`:

```python
# Configuration for n and m - can be changed here
N = 3  # number of team members
M = 2  # number of supervisors
```

## 📖 Usage Guide

### 1. Login
Use any of the default usernames to log in.

### 2. Add Encrypted Data
- Go to "Add Data"
- Enter a descriptive name and content
- Optionally enable "One-time view only"
- Data is encrypted and stored securely

### 3. Request Decryption
- Members can request decryption from supervisors
- Select data and choose which supervisor to ask

### 4. Approve Requests
- Supervisors see pending requests in "Decrypt Data"
- Can approve (decrypts data) or decline requests

### 5. View Data
- Approved requests allow members to view decrypted data
- One-time view data can only be accessed once per approval

### 6. Activity Logs
- Complete audit trail of all actions
- Shows who did what and when

## 🔒 Security Features

- **RSA Key Pairs**: Each user has unique public/private keys
- **AES Encryption**: Symmetric encryption for data
- **OAEP Padding**: Secure RSA encryption padding
- **Key Verification**: Ensures both keys match during decryption
- **One-Time Access**: Optional single-use data viewing
- **Session Management**: Secure user sessions

## 🛠️ Technologies Used

- **Backend**: Flask, SQLAlchemy, Cryptography
- **Frontend**: HTML5, CSS3 (Modern responsive design)
- **Database**: SQLite (development) / PostgreSQL (production)
- **Containerization**: Docker & Docker Compose

## 📁 Project Structure

```
KeyQuorum/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker container definition
├── docker-compose.yml    # Docker Compose configuration
├── templates/            # Jinja2 HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── add_data.html
│   ├── decrypt_data.html
│   ├── decrypted.html
│   └── logs.html
└── README.md
```

## 🔍 API Endpoints

- `GET /` - Home page
- `GET/POST /login` - User authentication
- `GET/POST /add_data` - Add encrypted data
- `GET/POST /decrypt_data` - Request/approve decryption
- `GET /logs` - View activity logs
- `POST /logout` - User logout

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is for educational and demonstration purposes. Use appropriate security measures for production deployments.

## ⚠️ Security Notice

This is a demonstration application. In production:
- Store private keys securely (not in database)
- Use proper session management
- Implement rate limiting
- Add input validation and sanitization
- Use HTTPS
- Regular security audits

---

**Built with ❤️ for demonstrating advanced encryption concepts**
