from app.storage.database import initialize_database, get_connection


initialize_database()

connection = get_connection()

tables = connection.execute(
    """
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    ORDER BY name
    """
).fetchall()

connection.close()

print("\n=== CYBERSENTINEL DATABASE ===")

for table in tables:
    print(f"Table: {table['name']}")