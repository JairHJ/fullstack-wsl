import jwt
SECRET_KEY = 'miclavesecreta123'

def token_required(f):
    from functools import wraps
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token requerido', 'status': 'error'}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if decoded.get('permission') != 'admin':
                return jsonify({'message': 'Permiso de admin requerido', 'status': 'error'}), 403
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado', 'status': 'error'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido', 'status': 'error'}), 401
        return f(*args, **kwargs)
    return wraps(f)(decorated)
from flask import Flask, jsonify, request

app = Flask(__name__)

users = [
    {"id": 1, "username": "user1", "email": "user1@example.com"},
]

@app.route('/users', methods=['GET'])
@token_required
def get_users():
    return jsonify({"users": users})

@app.route('/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    user = next((u for u in users if u['id'] == user_id), None)
    if user is None:
        return jsonify({"error": "Usuario no encontrado"}), 404
    return jsonify({"user": user})

@app.route('/users', methods=['POST'])
@token_required
def create_user():
    if not request.is_json or 'username' not in request.json or 'email' not in request.json:
        return jsonify({"error": "Username y email requeridos"}), 400

    new_user = {
        "id": max([u['id'] for u in users]) + 1 if users else 1,
        "username": request.json['username'],
        "email": request.json['email']
    }
    users.append(new_user)
    return jsonify({"message": "Usuario creado con éxito!", "user": new_user}), 201

@app.route('/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    user = next((u for u in users if u['id'] == user_id), None)
    if user is None:
        return jsonify({"error": "Usuario no encontrado"}), 404

    if request.is_json:
        user['username'] = request.json.get('username', user['username'])
        user['email'] = request.json.get('email', user['email'])

    return jsonify({"message": "Usuario actualizado con éxito!", "user": user})

@app.route('/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    global users
    user = next((u for u in users if u['id'] == user_id), None)
    if user is None:
        return jsonify({"error": "Usuario no encontrado"}), 404

    users = [u for u in users if u['id'] != user_id]
    return jsonify({"message": "Usuario eliminado con éxito!", "user": user['username']})

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5002, debug=True)
