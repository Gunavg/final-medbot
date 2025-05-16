from pymongo import MongoClient
import bcrypt
import re

# Initialize MongoDB client
client = MongoClient('mongodb://localhost:27017/')
db = client['medical_db']
users_collection = db['users']

# Admin credentials
username = 'admin'
plain_password = 'Admin123'
email = 'admin@medbot.com'

# Check password strength: min 6 chars, one upper, one lower, one digit
password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$'

if not re.match(password_regex, plain_password):
    print("Password does not meet the required criteria.")
else:
    # Check if admin already exists
    if not users_collection.find_one({'username': username}):
        # Hash the password
        hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())

        # Insert admin user with hashed password
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password_hash': hashed_password.decode('utf-8'),  # store as string
            'role': 'admin',
            'firstname': 'Admin',
            'age': 30,
            'gender': 'Other',
            'security_answer1': 'admin1',
            'security_answer2': 'admin2',
            'security_answer3': 'admin3'
        })

        print("✅ Admin user created successfully in users collection!")
    else:
        print("ℹ️ Admin user already exists in users collection!")
