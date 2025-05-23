from flask import Flask, request, make_response, redirect, render_template, g, abort, flash
from flask_wtf.csrf import CSRFProtect
from user_service import get_user_with_credentials, logged_in
from account_service import get_balance, do_transfer, get_user_accounts
from dotenv import load_dotenv
import os
from functools import wraps

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app with a secret key for session and CSRF protection
# XSS Prevention: All templates use Jinja2, which auto-escapes output to prevent cross-site scripting attacks
app = Flask(__name__, static_folder='static')
# Secret key for CSRF and session security from environment variable
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
# Enable CSRF protection for all POST forms to prevent cross-site request forgery attacks
csrf = CSRFProtect(app)


# Login required decorator to simplify authentication checks
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not logged_in():
            return render_template("login.html")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/", methods=['GET'])
def home():
    # Check if user is authenticated using JWT cookie
    if not logged_in():
        # If not authenticated, render login page
        return render_template("login.html")
    # Redirect authenticated users to dashboard
    return redirect('/dashboard')


@app.route("/login", methods=["POST"])
def login():
    # Handle user login with email and password
    # Safe access to form data; Flask validates form input
    email = request.form.get("email")
    password = request.form.get("password")
    # CSRF Protection: Flask-WTF automatically validates CSRF token in the form
    user = get_user_with_credentials(
        email, password)  # Verify credentials securely
    if not user:
        # User Enumeration Defense: Consistent "Invalid credentials" message for both invalid email and password
        # Error Handling: Render login page with error message instead of raising an exception
        return render_template("login.html", error="Invalid credentials")
    # Successful login: Set JWT auth token in cookie
    response = make_response(redirect("/dashboard"))
    # Store JWT in cookie for session management
    response.set_cookie("auth_token", user["token"])
    return response, 303  # Use 303 redirect to ensure proper POST-to-GET transition


@app.route("/dashboard", methods=['GET'])
@login_required
def dashboard():
    # Display user dashboard with their accounts
    # Fetch user's accounts to display dynamically
    # SQL Injection Prevention: Parameterized query in get_user_accounts
    accounts = get_user_accounts(g.user)
    # Error Handling: No explicit error handling needed here, as get_user_accounts is robust
    return render_template("dashboard.html", email=g.user, accounts=accounts)


@app.route("/details", methods=['GET'])
@login_required
def details():
    # Display account details for a specific account
    # Safe access to query parameter
    account_number = request.args.get('account')
    # Authorization Check: get_balance ensures account belongs to the user
    # SQL Injection Prevention: Parameterized query in get_balance
    balance = get_balance(account_number, g.user)
    if balance is None:
        # Error Handling: Return 404 if account doesn't exist or isn't owned by user
        # Prevents unauthorized access to other users' accounts
        abort(404, "Account not found")
    return render_template("details.html", user=g.user, account_number=account_number, balance=balance)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    # Handle account transfers (GET for form, POST for processing)
    if request.method == "GET":
        # Get user's accounts for the transfer form
        accounts = get_user_accounts(g.user)
        # Render transfer form with accounts list
        return render_template("transfer.html", accounts=accounts)
    # Process transfer (POST)
    try:
        # Safe access to form data
        source = request.form.get("from")
        target = request.form.get("to")
        # Validation: Convert amount to integer, ensuring valid input
        amount = int(request.form.get("amount"))

        # Validation: Prevent negative amounts to avoid stealing
        if amount < 0:
            flash("NO STEALING", "error")
            accounts = get_user_accounts(g.user)
            return render_template("transfer.html", accounts=accounts)
        # Validation: Limit transfer amount to prevent abuse
        if amount > 1000:
            flash("WOAH THERE TAKE IT EASY", "error")
            accounts = get_user_accounts(g.user)
            return render_template("transfer.html", accounts=accounts)

        # Authorization Check: Ensure source account belongs to user
        # SQL Injection Prevention: Parameterized query
        available_balance = get_balance(source, g.user)
        if available_balance is None:
            # Error Handling: Return error message instead of 404
            flash("Account not found", "error")
            accounts = get_user_accounts(g.user)
            return render_template("transfer.html", accounts=accounts)
        # Validation: Ensure sufficient funds
        if amount > available_balance:
            flash("You don't have that many SRFBOARDS", "error")
            accounts = get_user_accounts(g.user)
            return render_template("transfer.html", accounts=accounts)

        # Perform transfer
        # SQL Injection Prevention: Parameterized queries in do_transfer
        if not do_transfer(source, target, amount):
            # Error Handling: Return error message instead of 400
            flash("Transfer failed - please verify the destination account", "error")
            accounts = get_user_accounts(g.user)
            return render_template("transfer.html", accounts=accounts)

        # Success: Use flash instead of query params to provide feedback
        flash(
            f"Successfully transferred {amount} SRFBOARDS to quiver #{target}", "success")
        return redirect("/dashboard"), 303
    except ValueError:
        # Error Handling: Handle non-integer amounts gracefully
        # Validation: Prevent server crash from invalid input
        flash("Invalid amount", "error")
        accounts = get_user_accounts(g.user)
        return render_template("transfer.html", accounts=accounts)


@app.route("/logout", methods=['GET'])
def logout():
    # Clear authentication cookie to log out
    response = make_response(redirect("/dashboard"))
    response.delete_cookie('auth_token')  # Securely remove JWT cookie
    return response, 303
