Requisitos

- Python 3.8+
- Instalar dependencias:

```
pip install -r requirements.txt
```

Cómo completar las funciones

El archivo `app.py` contiene 3 funciones incompletas:

- `hash_password(password: str) -> str`: debe usar `bcrypt.hashpw()` para devolver la contraseña hasheada (tip: revisa la documentación de [bcrypt](https://pypi.org/project/bcrypt/)).
- `verify_password(password: str, hashed: str) -> bool`: debe usar `bcrypt.checkpw()` para verificar la contraseña ingresada contra el hash almacenado.
- `generate_token(user_id: int) -> str`: debe usar `jwt.encode()` de pyjwt para crear un token JWT con el id del usuario y una expiración de 1 hora.

Ejemplo de uso de bcrypt:
```python
import bcrypt
hashed = bcrypt.hashpw('tu_password'.encode(), bcrypt.gensalt())
# Para verificar:
correcto = bcrypt.checkpw('tu_password'.encode(), hashed)
```

Ejemplo de uso de pyjwt:
```python
import jwt
from datetime import datetime, timedelta
payload = { 'user_id': 1, 'exp': datetime.utcnow() + timedelta(hours=1) }
token = jwt.encode(payload, 'clave_secreta', algorithm='HS256')
```

Probar el proyecto

1. Ejecuta el servidor con:

```
python app.py
```
2. Haz peticiones POST a las rutas `/register` y `/login` con JSON usando herramientas como Postman o curl.

Ejemplo de petición para registro:
```
curl -X POST http://localhost:5000/register -H "Content-Type: application/json" -d "{ \"username\": \"prueba\", \"password\": \"1234\" }"
```


