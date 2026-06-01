"""Fleet multi-user authentication."""
import json, logging, os, bcrypt
logger = logging.getLogger(__name__)
FLEET_USERS_FILE = '/mnt/workspace/shared/fleet_users.json'

def _load_fleet_users():
    try:
        with open(FLEET_USERS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def fleet_auth_enabled():
    return os.path.exists(FLEET_USERS_FILE)

def verify_fleet_user(username, password):
    users = _load_fleet_users()
    user = users.get(username)
    if not user:
        return None
    try:
        if bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            return user
    except Exception:
        pass
    return None

def get_fleet_user_home(username):
    users = _load_fleet_users()
    user = users.get(username)
    return user.get('hermes_home') if user else None
