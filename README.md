# Aplicación Web con Autenticación MFA

Sistema de gestión de tareas con autenticación de dos factores usando Google Authenticator.

## Descripción

Esta aplicación permite a los usuarios registrarse, configurar autenticación de dos factores mediante códigos QR, y gestionar tareas personales. Implementa MFA para mayor seguridad en el acceso.

## Tecnologías utilizadas

**Frontend:**
- Angular 19
- PrimeNG
- TypeScript

**Backend:**
- Python Flask
- SQLite
- JWT para autenticación
- pyotp para códigos OTP
- qrcode para generar códigos QR

## Instalación

### Configurar el backend

```bash
cd microservicios
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./start_services.sh
```

### Configurar el frontend

```bash
cd frontend/gui
npm install
ng serve
```

## Cómo usar

1. **Registro**: Crear una cuenta nueva
2. **Configurar MFA**: Escanear el código QR con Google Authenticator
3. **Iniciar sesión**: Usar usuario, contraseña y código de 6 dígitos
4. **Gestionar tareas**: Crear, editar y eliminar tareas

## Estructura del proyecto

```
fullstack/
├── frontend/gui/          # Aplicación Angular
├── microservicios/        # Servicios Flask
│   ├── auth_service/      # Manejo de autenticación
│   ├── user_service/      # Gestión de usuarios
│   ├── task_service/      # Gestión de tareas
│   └── api_gateway/       # Gateway principal
└── requirements.txt       # Dependencias Python
```

## Endpoints principales

**Autenticación:**
- POST /register - Crear cuenta
- POST /login - Iniciar sesión
- POST /verify - Verificar token

**Tareas:**
- GET /tasks - Ver todas las tareas
- POST /register_task - Crear nueva tarea
- PUT /update_task/:id - Modificar tarea
- DELETE /delete_task/:id - Eliminar tarea
