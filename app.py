#!/usr/bin/python3

''' References and sources added
https://github.com/cs50
https://github.com/pyauth/pyotp
https://github.com/tornikenats/flask-pyotp
https://github.com/toshima/binance
'''

import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, send_file
from flask_session import Session
from flask_otp import OTP
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from time import sleep
import pyotp

from helpers import apology, login_required, get_articles, get_crypto
import base64

# Configure application
app = Flask(__name__)
otp = OTP()
otp.init_app(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SECRET_KEY"] = "w00t"
app.config["DOMAIN"] = "localhost"

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():

    return crypto()


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

        elif not request.form.get("otp"):
            return apology("must provide OTP", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")) or not otp.authenticate(rows[0]["otp"], request.form.get("otp")):
            return apology("invalid username and/or password - OTP", 403)

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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # check if method is correct
    if request.method == "POST":
        # get variables from post
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        otp_key = request.form.get("otp-key")
        otp_code = request.form.get("otp-confirmation")
        otp_auth = pyotp.TOTP(otp_key).now()

        # Check input
        if len(username) == 0 or len(password) == 0 or len(otp_code) != 6:
            return apology("INVALID INPUT")

        if not otp.authenticate(otp_key, otp_code):
            return apology("INVALID OTP ")

        # Check if passwords match
        if password == confirmation:
            pw_hash = generate_password_hash(password)

            # try adding new user to db
            insert = db.execute("INSERT INTO users (username, hash, otp) VALUES (:username, :pw_hash, :otp_key)", username=username, pw_hash=pw_hash, otp_key=otp_key)

            if not insert:
                # user already exists
                return apology("Username already taken !", 400)
            else:
                # user created succesfully set session id and redirect
                rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=username)

                # wait for quert to exec
                sleep(0.2)

                # log user in
                session["user_id"] = rows[0]["id"]

                return redirect("/")
        else:
            # send apology for mismatching pws
            return apology("Passwords do not match !")
    else:
        # Clear current session variables
        session.clear()
        key = otp.get_key()
        # display register form
        img = otp.qr(key)
        img_enc = base64.encodebytes(img.read()).decode("utf-8").replace('\n','')
        img_64 = img_enc

        return render_template("register.html", img="data:image/png;base64, " + img_64, key=key)

# For News Feed
@app.route("/news")
@login_required
def news():
    """Show News Feed"""
    # Get articles
    articles = get_articles()

    # send articles for rendering
    return render_template("news.html", articles=articles)

# For Crypto Tickers
@app.route("/crypto")
#@login_required
def crypto():
    # Get Crypto Tickers
    coins = get_crypto()

    # send tickers for rendering
    return render_template("crypto.html", coins=coins)


# For Charts
@app.route("/chart")
#@login_required
def chart():

    # send for rendering
    return render_template("chart.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
