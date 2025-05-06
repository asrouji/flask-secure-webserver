import sqlite3
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
from flask import request, g
import jwt

# Secret key for JWT signing; should be cryptographically random in production
SECRET = 'bfg28y7efg238re7r6t32gfo23vfy7237yibdyo238do2v3'


def get_user_with_credentials(email, password):
    # Verify user credentials securely
    try:
        # Connect to SQLite database
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        # SQL Injection Prevention: Use parameterized query to safely query email
        cur.execute('''
            SELECT email, name, password FROM users where email=?''',
                    (email,))
        row = cur.fetchone()
        if row is None:
            # User Enumeration Defense (Timing): Perform dummy PBKDF2 verification to match timing of valid email case
            # This prevents attackers from detecting invalid emails via response time differences
            pbkdf2_sha256.verify(
                password, "$pbkdf2-sha256$29000$.oydkyLkXIsxZg0BACAEwA$5pM/JQeW5uC3oW1ZQbI3qKn1fI7zYqGRDHuG7iS2aOs")
            # User Enumeration Defense (Message): Return None to trigger consistent "Invalid credentials" message
            return None
        email, name, hash = row
        # Verify password using PBKDF2-SHA256 (salted hash)
        if not pbkdf2_sha256.verify(password, hash):
            # User Enumeration Defense (Message): Return None for incorrect password, ensuring same error message
            return None
        # Success: Generate JWT token for authenticated user
        return {"email": email, "name": name, "token": create_token(email)}
    finally:
        # Error Handling: Always close database connection to prevent resource leaks
        con.close()


def logged_in():
    # Check if user is authenticated via JWT cookie
    token = request.cookies.get('auth_token')  # Safe access to cookie
    try:
        # Validate JWT token
        data = jwt.decode(token, SECRET, algorithms=['HS256'])
        g.user = data['sub']  # Store user email in Flask's global context
        return True
    except jwt.InvalidTokenError:
        # Error Handling: Handle invalid or expired tokens gracefully
        # Return False to redirect user to login
        return False


def create_token(email):
    # Generate JWT token for authenticated user
    now = datetime.utcnow()
    # Include subject (email), issued-at, and expiration (60 minutes)
    payload = {'sub': email, 'iat': now, 'exp': now + timedelta(minutes=60)}
    # Sign token with secret key
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    # Return token as string
    return token
