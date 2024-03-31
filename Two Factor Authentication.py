import pyotp
import qrcode
import random
import string
import time

# Simulated database
users_db = {}
backup_codes_db = {}
failed_attempts = {}

# Rate limiting parameters
TIME_WINDOW = 300  # 5 minutes in seconds
MAX_ATTEMPTS = 3
BLOCK_DURATION = 600  # 10 minutes in seconds

def generate_secret_key():
    """Generate a unique secret key for a user."""
    return pyotp.random_base32()

def generate_backup_codes():
    """Generate a set of backup codes."""
    return [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(5)]

def generate_qr_code(secret_key, user_email):
    """Generate a QR code based on the secret key."""
    totp = pyotp.TOTP(secret_key)
    provision_uri = totp.provisioning_uri(name=user_email, issuer_name="YourAppName")
    img = qrcode.make(provision_uri)
    img.show()

def register_user(email):
    """Register a new user."""
    if email in users_db:
        print("User already exists!")
        return
    secret_key = generate_secret_key()
    users_db[email] = secret_key
    backup_codes = generate_backup_codes()
    backup_codes_db[email] = backup_codes
    print(f"User {email} registered with secret key: {secret_key}")
    print("Backup Codes:")
    for code in backup_codes:
        print(code)
    print("Generating QR Code for 2FA setup...")
    generate_qr_code(secret_key, email)

def verify_totp(email, provided_totp):
    """Verify the provided TOTP against the current TOTP for the secret key."""
    if email not in users_db:
        return False
    secret_key = users_db[email]
    totp = pyotp.TOTP(secret_key)
    return totp.verify(provided_totp)

def verify_backup_code(email, provided_code):
    """Verify the provided backup code."""
    if email not in backup_codes_db:
        return False
    if provided_code in backup_codes_db[email]:
        backup_codes_db[email].remove(provided_code)
        return True
    return False

def is_user_blocked(email):
    """Check if a user is blocked due to exceeding login attempts."""
    if email not in failed_attempts:
        return False
    last_attempt_time, attempts = failed_attempts[email]
    if time.time() - last_attempt_time < BLOCK_DURATION and attempts >= MAX_ATTEMPTS:
        return True
    return False

def record_failed_attempt(email):
    """Record a failed login attempt for a user."""
    if email not in failed_attempts:
        failed_attempts[email] = (time.time(), 1)
    else:
        last_attempt_time, attempts = failed_attempts[email]
        if time.time() - last_attempt_time > TIME_WINDOW:
            failed_attempts[email] = (time.time(), 1)
        else:
            failed_attempts[email] = (last_attempt_time, attempts + 1)

def login(email, provided_totp_or_code):
    """Simulate a login process."""
    if is_user_blocked(email):
        print("Too many failed attempts. Please wait and try again later.")
        return

    if verify_totp(email, provided_totp_or_code) or verify_backup_code(email, provided_totp_or_code):
        print("Login successful!")
        # Reset failed attempts after a successful login
        if email in failed_attempts:
            del failed_attempts[email]
    else:
        print("Invalid TOTP or backup code. Please try again.")
        record_failed_attempt(email)

if __name__ == "__main__":
    while True:
        print("\nOptions:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            email = input("Enter email to register: ")
            register_user(email)
        elif choice == "2":
            email = input("Enter email to login: ")
            provided_totp_or_code = input("Enter the TOTP from your authenticator app or a backup code: ")
            login(email, provided_totp_or_code)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")
