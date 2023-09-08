import os
from flask import Flask
from werkzeug.debug import DebuggedApplication
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__, static_folder='static')
# this DEBUG config here will be overridden by FLASK_DEBUG shell environment
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'bde092f73cf49e79fdff64de554f26ac20b3bff790564d0d'
app.config['JSON_AS_ASCII'] = False

app.config['GOOGLE_CLIENT_ID'] = os.getenv("GOOGLE_CLIENT_ID", None)
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv("GOOGLE_CLIENT_SECRET", None)
app.config['GOOGLE_DISCOVERY_URL'] = os.getenv("GOOGLE_DISCOVERY_URL", None)

app.config['FACEBOOK_CLIENT_ID'] = os.getenv("FACEBOOK_CLIENT_ID", None)
app.config['FACEBOOK_CLIENT_SECRET'] = os.getenv("FACEBOOK_CLIENT_SECRET", None)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite://")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if app.debug:
    app.wsgi_app = DebuggedApplication(app.wsgi_app, evalex=True)

# Creating an SQLAlchemy instance
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

from app import views  # noqa
