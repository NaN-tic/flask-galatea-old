#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains 
#the full copyright notices and license terms.
from flask.signals import _signals

#: Login signal - triggered when a succesful login takes place
login = _signals.signal('login')

#: Failed Login - raised when a login fails
failed_login = _signals.signal('failed-login')

#: Logout - triggered when a logout occurs
logout = _signals.signal('logout')

#: Registration - triggered when a user registers
registration = _signals.signal('registration')
