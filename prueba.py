import psycopg2

connection = psycopg2.connect("postgresql://postgres:woTCfdaWchoxcsKAmCaAxOBzHusEdLLj@postgres.railway.internal:5432/railway")
print("Conexión exitosa")
connection.close()
