import csv
import os
import urllib.request

from flask import redirect, render_template, request, session
from functools import wraps
from news import NewsAPI
import binance


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def get_articles():
    # Initiate API Connection to NewsAPI
    feed = NewsAPI("62e250ee06c84c6487c3c2e8783522ca") # You may enter your own API key

    # Set params for query
    params = {"sources":"crypto-coins-news"}

    # get artlices
    articles = feed.request('top-headlines', params)['articles']

    return articles

def get_crypto():
    tickers = binance.tickers()

    coins={}

    coins['usdt'] = {}
    coins['btc'] = {}
    coins['eth'] = {}

    for key in tickers:
        if key.endswith('USDT'):
            coins['usdt'][key.replace('USDT', ' / USDT')] = tickers[key]
            coins['usdt'] = {key:coins['usdt'][key] for key in sorted(coins['usdt'].keys())}

        if key.endswith('BTC'):
            coins['btc'][key.replace('BTC', ' / BTC')] = tickers[key]
            coins['btc'] = {key:coins['btc'][key] for key in sorted(coins['btc'].keys())}

        if key.endswith('ETH'):
            coins['eth'][key.replace('ETH', ' / ETH')] = tickers[key]
            coins['eth'] = {key:coins['eth'][key] for key in sorted(coins['eth'].keys())}

    return coins