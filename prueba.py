import requests

# Define la URL de tu endpoint
url = "https://flask-stripe-server.onrender.com/create-checkout-session"  # Cambia a tu URL de producción si aplica

# Datos a enviar en el cuerpo de la solicitud
data = {
    "user": "prueba_usuario"
}

# Envía la solicitud POST
response = requests.post(url, json=data)

# Muestra la respuesta
if response.status_code == 200:
    print("URL de Stripe Checkout:", response.json().get("url"))
else:
    print("Error:", response.status_code, response.json())
