# Flask Secure Web Server

A secure banking web application built with Flask that implements industry-standard security practices.

## Security Features

### Authentication & Session Management

- **Password Security**: PBKDF2-SHA256 hashing with salt, secure storage
- **Session Security**: JWT-based authentication with 60-minute expiration
- **Authorization**: Account ownership verification and least privilege access

### Protection Against Common Attacks

- **XSS Prevention**: Jinja2 auto-escaping, Content Security Policy headers
- **CSRF Protection**: Flask-WTF CSRF tokens, double-submit cookie pattern
- **SQL Injection Prevention**: Parameterized queries, input validation
- **User Enumeration Defense**: Consistent error messages, timing attack prevention

### Input Validation & Error Handling

- Strict type checking and input sanitization
- Comprehensive error handling with appropriate HTTP status codes
- Secure error messages and logging

## Implementation Details

### Database Schema

```sql
CREATE TABLE users (
    email text primary key,
    name text,
    password text
);

CREATE TABLE accounts (
    id text primary key,
    owner text,
    balance integer,
    FOREIGN KEY (owner) REFERENCES users(email)
);
```

### Security Headers

- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security

## Setup Instructions

1. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Initialize the database:

```bash
# First create the users table and initial users
python bin/createdb.py
# Then create the accounts table and initial accounts
python bin/makeaccounts.py
```

4. Run the application:

```bash
python app.py
```
