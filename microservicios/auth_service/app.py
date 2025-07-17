from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import bcrypt
from datetime import datetime, timedelta
import sqlite3
import os
import logging
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
CORS(app)

# Configuración
SECRET_KEY = "miclavesecreta123"
DATABASE = 'auth.db'

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    """Inicializar la base de datos"""
    conn = sqlite3.connect(DATABASE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mfa_secret TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Agregar columna mfa_secret si no existe
    try:
        conn.execute('ALTER TABLE users ADD COLUMN mfa_secret TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass  # La columna ya existe
    
    # Crear usuario admin por defecto si no existe
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
        mfa_secret = pyotp.random_base32()
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, mfa_secret) VALUES (?, ?, ?, ?)',
            ('admin', 'admin@example.com', admin_password.decode('utf-8'), mfa_secret)
        )
        conn.commit()
        logger.info("Usuario admin creado: admin/admin123")
    
    conn.close()

def generate_token(user_id, username):
    """Generar JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    """Verificar JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_qr_code(username, secret):
    """Generar código QR para MFA"""
    try:
        # Crear URI para Google Authenticator
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="Fullstack App"
        )
        
        # Generar código QR
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Crear imagen del QR
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convertir a base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        logger.error(f"Error generando QR: {str(e)}")
        return None

def verify_otp(secret, otp_code):
    """Verificar código OTP"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(otp_code, valid_window=1)
    except Exception as e:
        logger.error(f"Error verificando OTP: {str(e)}")
        return False

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        otp_code = data.get('otp_code')
        
        if not username or not password:
            return jsonify({'error': 'Username y password son requeridos'}), 400
        
        if not otp_code:
            return jsonify({'error': 'Código OTP requerido'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, username, password_hash, mfa_secret, is_active FROM users WHERE username = ? OR email = ?',
            (username, username)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        user_id, username, password_hash, mfa_secret, is_active = user
        
        if not is_active:
            return jsonify({'error': 'Usuario desactivado'}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        # Verificar código OTP
        if not mfa_secret or not verify_otp(mfa_secret, otp_code):
            return jsonify({'error': 'Código OTP inválido'}), 401
        
        token = generate_token(user_id, username)
        
        return jsonify({
            'access_token': token,
            'token_type': 'Bearer',
            'user': {
                'id': user_id,
                'username': username
            }
        })
        
    except Exception as e:
        logger.error(f"Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400
            
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        mfa_secret = pyotp.random_base32()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, mfa_secret) VALUES (?, ?, ?, ?)',
                (username, email, password_hash.decode('utf-8'), mfa_secret)
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            # Generar código QR para MFA
            qr_code = generate_qr_code(username, mfa_secret)
            
            return jsonify({
                'message': 'Usuario registrado exitosamente',
                'user': {
                    'id': user_id,
                    'username': username,
                    'email': email
                },
                'qr_code': qr_code,
                'mfa_secret': mfa_secret  # Solo para propósitos de desarrollo, remover en producción
            }), 201
            
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username o email ya existe'}), 409
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Error en registro: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/verify', methods=['POST'])
def verify():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token requerido'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_token(token)
        
        if not payload:
            return jsonify({'error': 'Token inválido o expirado'}), 401
        
        return jsonify({
            'valid': True,
            'user': {
                'id': payload['user_id'],
                'username': payload['username']
            }
        })
        
    except Exception as e:
        logger.error(f"Error en verificación: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'Auth Service is running',
        'mfa_enabled': True
    })

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)
