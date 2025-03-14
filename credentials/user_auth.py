import hashlib
from utilities.database import add_user, get_user

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password, email):
    user = get_user(username)
    if user:
        print("Username already exists.")
        return False
    hashed_password = hash_password(password)
    add_user(username, hashed_password, email)
    print("User registered successfully.")
    return True

def login_user(username, password):
    user = get_user(username)
    if user and user[2] == hash_password(password):
        print("Login successful.")
        return True
    print("Invalid username or password.")
    return False