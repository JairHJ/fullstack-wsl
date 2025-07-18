# 🔐 Fullstack App con Multi-Factor Authentication (MFA)

Aplicación fullstack con autenticación de dos factores usando Google Authenticator.

## 🚀 Características

- ✅ **Multi-Factor Authentication (MFA)** con Google Authenticator
- ✅ **Frontend**: Angular 19 + PrimeNG
- ✅ **Backend**: Python Flask (Microservicios)
- ✅ **Base de Datos**: SQLite
- ✅ **Gestión de Tareas**: CRUD completo
- ✅ **Seguridad**: JWT + TOTP (Time-based OTP)

## 🏗️ Arquitectura

```
fullstack/
├── frontend/gui/          # Angular 19 + PrimeNG
├── microservicios/        # Python Flask Services
│   ├── auth_service/      # Autenticación con MFA
│   ├── user_service/      # Gestión de usuarios
│   ├── task_service/      # Gestión de tareas
│   └── api_gateway/       # Proxy y enrutamiento
└── requirements.txt       # Dependencias Python
```

## 🔧 Instalación y Uso

### Backend (Python)
```bash
cd microservicios
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt

# Iniciar todos los servicios
./start_services.sh
```

### Frontend (Angular)
```bash
cd frontend/gui
npm install
ng serve
```

## 📱 Flujo MFA

1. **Registro**: Usuario crea cuenta → Recibe código QR
2. **Configuración**: Escanea QR con Google Authenticator
3. **Login**: Username + Password + Código OTP (6 dígitos)
4. **Acceso**: Solo con credenciales válidas + código MFA

## 🛠️ Tecnologías

### Backend
- **Python Flask**: Framework web
- **pyotp**: Generación y validación OTP
- **qrcode**: Generación de códigos QR
- **bcrypt**: Hashing de contraseñas
- **JWT**: Tokens de autenticación

### Frontend
- **Angular 19**: Framework SPA
- **PrimeNG**: Componentes UI
- **RxJS**: Programación reactiva
- **TypeScript**: Tipado estático

## 🔒 Seguridad

- **Doble Factor**: Algo que sabes (password) + Algo que tienes (móvil)
- **Estándar TOTP**: Compatible con RFC 6238
- **JWT Tokens**: Autenticación stateless
- **Interceptor Automático**: Manejo transparente de tokens

## 🌐 Endpoints

### Auth Service (Puerto 5001)
- `POST /register` - Registro con generación QR
- `POST /login` - Login con validación OTP
- `POST /verify` - Verificación de tokens

### Task Service (Puerto 5003)
- `GET /tasks` - Listar tareas
- `POST /register_task` - Crear tarea
- `PUT /update_task/:id` - Actualizar tarea
- `DELETE /delete_task/:id` - Eliminar tarea

