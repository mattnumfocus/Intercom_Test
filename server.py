import os
import json
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from datetime import datetime
import hmac
import hashlib
from flask import Flask, redirect, render_template, session, url_for

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")


@app.template_filter('to_unix_time')
def to_unix_time(date_str):
  """Converts a date string in ISO 8601 format (with timezone) to Unix timestamp."""
  if not date_str:
    return None
  try:
    dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    return int(dt.timestamp())
  except ValueError:
    return None  # Handle invalid date format gracefully


# Auth0 setup
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# Routes
@app.route("/")
def home():
    if 'user' in session:
        # Replace 'your_intercom_secret_key' with your actual Intercom Identity Verification secret key
        secret_key = bytes(os.getenv("INTERCOM_SECRET_KEY"), encoding="utf-8")
        user_email = session['user']['userinfo']['email']  # Adjust based on actual session structure
        # Generate user hash
        user_hash = hmac.new(
            secret_key,
            bytes(user_email, encoding='utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest()
        # Pass the user hash to the frontend
        return render_template('home.html', user_hash=user_hash)
    else:
        # Handle non-logged in users
        return render_template('home.html')

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))

@app.route("/callback")
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + os.getenv("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode({"returnTo": url_for("home", _external=True), "client_id": os.getenv("AUTH0_CLIENT_ID")}, quote_via=quote_plus)
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="8000")
