#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains 
#the full copyright notices and license terms.
from flask import current_app
from flask_wtf.csrf import CsrfProtect

with current_app.app_context():
    csrf = CsrfProtect()
    csrf.init_app(current_app)
