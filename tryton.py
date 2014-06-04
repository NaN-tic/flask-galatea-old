from flask import current_app
from flask_tryton import Tryton

with current_app.app_context():
    tryton = Tryton(current_app)
