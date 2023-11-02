import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Personal touch 1
@app.route("/home")
@login_required
def home():
    """Show home page"""
    return render_template("index.html")


# Personal Touch 2
@app.route("/delete_account", methods=["GET", "POST"])
@login_required
def delete_account():
    username = request.form.get("username")
    password = request.form.get("password")

    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

    if request.method == "POST":
        if not username or not password:
            return apology("INVALID USERNAME AND/OR PASSWORD")
        if username != user[0]["username"]:
            return apology("USERNAME DOES NOT EXIST", 400)
        if not check_password_hash(user[0]["hash"], password):
            return apology("INVALID PASSWORD", 400)
        db.execute("DELETE FROM histories WHERE person_id = ?", session["user_id"])
        db.execute("DELETE FROM transactions WHERE person_id = ?", session["user_id"])
        db.execute("DELETE FROM users WHERE id = ?", session["user_id"])

        session.clear()
        return redirect("/login")

    return render_template("delete_account.html")


# Personal touch 3
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    new_password_confirmation = request.form.get("new_password_confirmation")

    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

    if request.method == "POST":
        if not current_password or not new_password or not new_password_confirmation:
            return apology("INVALID PASSWORD", 400)
        if not check_password_hash(user[0]["hash"], current_password):
            return apology("INCORRECT CURRENCT PASSWORD", 400)
        if new_password != new_password_confirmation:
            return apology("NEW PASSWORDS DO NOT MATCH", 400)
        if new_password == current_password:
            return apology("NEW PASSWORD CANNOT BE THE SAME AS CURRENT PASSWORD", 400)

        has_letter = any(c.isalpha() for c in new_password)
        has_digit = any(c.isdigit() for c in new_password)
        has_special = any(not c.isalnum() for c in new_password)

        if not (has_letter and has_digit and has_special):
            return apology(
                "PASSWORD MUST CONTAIN AT LEAST ONE LETTER, ONE NUMBER, AND ONE SPECIAL CHARACTER"
            )
        if len(new_password) < 6:
            return apology("PASSWORD MUST BE AT LEAST 6 CHARACTERS")

        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?",
            generate_password_hash(new_password),
            session["user_id"],
        )
        return redirect("/login")
    return render_template("change_password.html")


# Personal touch 4
@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    cash = request.form.get("cash")

    if request.method == "POST":
        if not cash:
            return apology("MUST ENTER AN AMOUNT", 400)
        try:
            cash = int(cash)
        except ValueError:
            return apology("AMOUNT MUST BE NUMBER", 400)
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?", cash, session["user_id"]
        )
        return redirect("/")
    return render_template("add_cash.html")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    transactions = db.execute(
        """SELECT symbol, price, shares, SUM(shares) AS total_shares FROM transactions
                              WHERE person_id = ? GROUP BY symbol""",
        session["user_id"],
    )

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
        "cash"
    ]
    grand_total = cash
    for transaction in transactions:
        stock = lookup(transaction["symbol"])
        price = stock["price"]
        transaction["price"] = price
        transaction["total"] = transaction["total_shares"] * price
        grand_total += transaction["total"]

    return render_template(
        "index.html", transactions=transactions, grand_total=grand_total, cash=cash
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    symbol = request.form.get("symbol")
    shares = request.form.get("shares")

    # If method is post
    if request.method == "POST":
        if symbol is None or shares is None:
            return apology("MISSING SYMBOL AND/OR SHARES", 400)

        symbol_info = lookup(symbol)

        if symbol_info is None:
            return apology("Invalid symbol", 400)
        else:
            price = symbol_info["price"]

        try:
            shares = int(shares)
        except ValueError:
            return apology("SHARES MUST BE A NUMBER", 400)

        if shares < 1:
            return apology("SHARES MUST BE EQUAL OR GREATER THAN 1", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
            "cash"
        ]

        if cash < (shares * price):
            return apology("CANNOT AFFORD", 400)

        existing_stock = db.execute(
            """SELECT * FROM transactions
                                    WHERE person_id = ? AND symbol = ?""",
            session["user_id"],
            symbol,
        )

        if existing_stock:
            db.execute(
                """UPDATE transactions SET shares = shares + ? WHERE person_id = ? AND symbol = ?""",
                shares,
                session["user_id"],
                symbol,
            )
        else:
            db.execute(
                """
                    INSERT INTO transactions (person_id, symbol, shares, price, time)
                        VALUES (?, ?, ?, ?, datetime('now'))""",
                session["user_id"],
                symbol,
                shares,
                price,
            )

        db.execute(
            """
                    INSERT INTO histories (person_id, symbol, shares, price, time)
                    VALUES (?, ?, ?, ?, datetime('now'))""",
            session["user_id"],
            symbol,
            shares,
            price,
        )

        # Update user's cash after transaction is made
        db.execute(
            "UPDATE users SET cash = cash - ? WHERE id = ?",
            shares * price,
            session["user_id"],
        )
        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    histories = db.execute(
        "SELECT * FROM histories WHERE person_id = ?", session["user_id"]
    )
    return render_template("history.html", histories=histories)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("INVALID SYMBOL.", 400)

        symbol = lookup(symbol)

        if symbol is None:
            return apology("INAVLID SYMBOL", 400)

        return render_template("quoted.html", quote=symbol)
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if request.method == "POST":
        if not username:
            return apology("INVALID USERNAME", 400)

        user = db.execute("SELECT * FROM users WHERE username = ?", username)

        if user:
            return apology("USERNAME ALREADY EXISTS", 400)
        if not password or not confirmation:
            return apology("INVALID PASSWORD", 400)
        if password != confirmation:
            return apology("PASSWORDS DO NOT MATCH", 400)

        has_letter = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if not (has_letter and has_digit and has_special):
            return apology(
                "PASSWORD MUST CONTAIN AT LEAST ONE LETTER, ONE NUMBER, AND ONE SPECIAL CHARACTER"
            )
        if len(password) < 6:
            return apology("PASSWORD MUST BE AT LEAST 6 CHARACTERS")

        password = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", username, password
        )

        id = db.execute(
            "SELECT id FROM users WHERE username = ? AND hash = ?", username, password
        )
        session["user_id"] = id[0]["id"]
        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    shares = request.form.get("shares")
    symbol = request.form.get("symbol")
    transaction = db.execute(
        """SELECT * FROM transactions
                              WHERE person_id = ? AND symbol = ?""",
        session["user_id"],
        symbol,
    )

    if request.method == "POST":
        if not shares:
            return apology("MISSING SHARES", 400)

        shares = int(shares)

        if not transaction or not (shares <= transaction[0]["shares"]):
            return apology("TOO MANY SHARES", 400)

        if shares < 1:
            return apology("SHARES MUST BE POSITIVE", 400)

        stock = lookup(symbol)
        price = stock["price"]

        db.execute(
            """UPDATE transactions SET shares = shares - ?
                    WHERE person_id = ? AND symbol = ?""",
            shares,
            session["user_id"],
            symbol,
        )

        db.execute(
            """INSERT INTO histories (person_id, symbol, shares, price, time)
                    VALUES (?, ?, ?, ?, datetime('now'))
                   """,
            session["user_id"],
            symbol,
            -shares,
            price,
        )

        price = lookup(symbol)["price"]
        total = price * shares
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?", total, session["user_id"]
        )

        transaction = db.execute(
            """SELECT * FROM transactions
                    WHERE person_id = ? AND symbol = ?""",
            session["user_id"],
            symbol,
        )

        if transaction[0]["shares"] == 0:
            db.execute(
                """DELETE FROM transactions
                        WHERE person_id = ? AND  symbol = ?""",
                session["user_id"],
                symbol,
            )
        return redirect("/")

    transactions = db.execute(
        """SELECT * FROM transactions
                              WHERE person_id = ?""",
        session["user_id"],
    )
    return render_template("sell.html", transactions=transactions)
