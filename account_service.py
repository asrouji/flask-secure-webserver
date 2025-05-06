import sqlite3


def get_balance(account_number, owner):
    # Retrieve balance for a specific account, ensuring user ownership
    try:
        # Connect to SQLite database
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        # SQL Injection Prevention: Use parameterized query to safely query account
        # Authorization: Include owner in query to prevent access to other users' accounts
        cur.execute('''
            SELECT balance FROM accounts where id=? and owner=?''',
                    (account_number, owner))
        row = cur.fetchone()
        if row is None:
            # Error Handling: Return None if account doesn't exist or isn't owned by user
            # This triggers a 404 in the calling route
            return None
        return row[0]  # Return balance
    finally:
        # Error Handling: Always close database connection to prevent resource leaks
        con.close()


def do_transfer(source, target, amount):
    # Perform transfer between accounts
    try:
        # Connect to SQLite database
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        # SQL Injection Prevention: Use parameterized query to check target account
        cur.execute('''
            SELECT id FROM accounts where id=?''',
                    (target,))
        row = cur.fetchone()
        if row is None:
            # Error Handling: Return False if target account doesn't exist
            # This triggers a 400 in the calling route
            return False
        # SQL Injection Prevention: Use parameterized queries for balance updates
        cur.execute('''
            UPDATE accounts SET balance=balance-? where id=?''',
                    (amount, source))
        cur.execute('''
            UPDATE accounts SET balance=balance+? where id=?''',
                    (amount, target))
        # Commit transaction to ensure atomicity
        con.commit()
        return True  # Indicate success
    finally:
        # Error Handling: Always close database connection
        con.close()


def get_user_accounts(owner):
    # Retrieve all account IDs owned by a user
    try:
        # Connect to SQLite database
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        # SQL Injection Prevention: Use parameterized query to safely query accounts
        cur.execute('''
            SELECT id FROM accounts where owner=?''',
                    (owner,))
        rows = cur.fetchall()
        # Return list of account IDs
        return [row[0] for row in rows]
    finally:
        # Error Handling: Always close database connection
        con.close()
