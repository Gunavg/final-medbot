from pymongo import MongoClient
from flask_bcrypt import Bcrypt

# Initialize MongoDB client
client = MongoClient('mongodb://localhost:27017/')
db = client['medbot']

# Initialize Bcrypt
bcrypt = Bcrypt()

# Check if admin user already exists
if not db.users.find_one({'username': 'admin'}):
    # Create hashed password
    hashed_password = bcrypt.generate_password_hash('admin_password').decode('utf-8')
    
    # Insert admin user
    db.users.insert_one({
        'username': 'admin',
        'password': hashed_password,
        'role': 'admin'
    })
    print("Admin user created successfully!")
else:
    print("Admin user already exists!")