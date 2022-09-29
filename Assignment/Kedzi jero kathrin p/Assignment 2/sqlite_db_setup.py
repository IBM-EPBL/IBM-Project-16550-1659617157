import sqlite3

conn = sqlite3.connect('User_database.db')
print("Opened database successfully")

conn.execute('CREATE TABLE users (email TEXT, username TEXT, rollnumber INTEGER, pin INTEGER)')
print("Table created successfully")
conn.close()
