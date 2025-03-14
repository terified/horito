from utilities.database import add_password as db_add_password, get_password as db_get_password
from utilities.database import get_user

def add_password(username, account, password):
    user = get_user(username)
    if user:
        user_id = user[0]
        db_add_password(user_id, account, password)
        print(f"Password for account '{account}' added successfully.")
    else:
        print(f"User '{username}' not found.")

def get_password(username, account):
    user = get_user(username)
    if user:
        user_id = user[0]
        password = db_get_password(user_id, account)
        if password:
            return password[0]
        else:
            return "No password found for this account."
    else:
        print(f"User '{username}' not found.")
        return None