import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
# import bcrypt # Descomentar cuando estés listo para usar bcrypt
# import jwt # Descomentar cuando estés listo para usar pyjwt
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuración de la base de datos SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Modelo de usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Función incompleta para hashear una contraseña
# TODO: Completa esta función usando bcrypt.hashpw
# Referencia: https://pypi.org/project/bcrypt/
def hash_password(password: str) -> str:
    """
    Hashea la contraseña usando bcrypt.
    Parámetros:
        password (str): La contraseña en texto plano.
    Retorna:
        str: La contraseña hasheada.
    """
    # return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    pass  # Completa aquí

# Función incompleta para verificar una contraseña
# TODO: Completa esta función usando bcrypt.checkpw
def verify_password(password: str, hashed: str) -> bool:
    """
    Verifica una contraseña usando bcrypt.
    Parámetros:
        password (str): Contraseña en texto plano.
        hashed (str): Contraseña hasheada desde la base de datos.
    Retorna:
        bool: True si coincide, False si no.
    """
    # return bcrypt.checkpw(password.encode(), hashed.encode())
    pass  # Completa aquí

# Función incompleta para generar un token JWT
# TODO: Completa esta función usando jwt.encode (pyjwt)
def generate_token(user_id: int) -> str:
    """
    Genera un token JWT.
    Parámetros:
        user_id (int): El ID del usuario.
    Retorna:
        str: El token JWT.
    """
    # payload = {
    #     'user_id': user_id,
    #     'exp': datetime.utcnow() + timedelta(hours=1)
    # }
    # return jwt.encode(payload, 'clave_secreta', algorithm='HS256')
    pass  # Completa aquí

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Faltan datos'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'El usuario ya existe'}), 409
    
    # Hashear la contraseña (completa la función hash_password)
    hashed_password = hash_password(password)
    user = User(username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'mensaje': 'Usuario registrado exitosamente'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    # Verificar la contraseña (completa la función verify_password)
    if not verify_password(password, user.password):
        return jsonify({'error': 'Contraseña incorrecta'}), 401
    # Generar y devolver el token JWT (completa la función generate_token)
    token = generate_token(user.id)
    return jsonify({'token': token})

if __name__ == '__main__':
    # Crea la base de datos si no existe
    if not os.path.exists('users.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)


