import stripe

stripe.api_key = 'sk_test_51QfUyjG4Og1KI6OFFdnGycLum4dgpBqyWg2fSSRSPcsW8rcOc6s6p1R2AnAw17UnkVwUntnqrjJETYKbW0Yte2qn00lGjpWUoW'

session = stripe.checkout.Session.create(
    payment_method_types=['card'],
    line_items=[{
        'price_data': {
            'currency': 'usd',
            'product_data': {
                'name': 'Nombre del Producto',
            },
            'unit_amount': 1000,  # Monto en centavos (1000 = $10.00)
        },
        'quantity': 1,
    }],
    mode='payment',
    success_url='https://flask-stripe-server.onrender.com/success?session_id={CHECKOUT_SESSION_ID}',
    cancel_url='https://flask-stripe-server.onrender.com/cancel',
)
