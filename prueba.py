import psycopg2

connection = psycopg2.connect("postgresql://postgres:woTCfdaWchoxcsKAmCaAxOBzHusEdLLj@junction.proxy.rlwy.net:5432/railway")
print("Conexión exitosa")
connection.close()
