#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains 
#the full copyright notices and license terms.
from flask import Blueprint, request, render_template, current_app, session, \
    redirect, url_for, flash, abort, g
from flask.ext.babel import gettext as _
from flask.ext.mail import Mail, Message
from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, HiddenField, validators
from .tryton import tryton
from .signals import login as slogin, failed_login as sfailed_login, logout as slogout
from .helpers import login_required

import random
import string

try:
    import hashlib
except ImportError:
    hashlib = None
    import sha

galatea = Blueprint('galatea', __name__, template_folder='templates')

GalateaUser = tryton.pool.get('galatea.user')
Website = tryton.pool.get('galatea.website')
Party = tryton.pool.get('party.party')
ContactMechanism = tryton.pool.get('party.contact_mechanism')

galatea_website = current_app.config.get('TRYTON_GALATEA_SITE')


class LoginForm(Form):
    "Login Password form"
    email = TextField(_('Email'), [validators.Required(), validators.Email()])
    password = PasswordField(_('Password'), [validators.Required()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True


class NewPasswordForm(Form):
    "New Password form"
    password = PasswordField(_('Password'), [validators.Required(),
        validators.EqualTo('confirm', message=_('Passwords must match'))])
    confirm = PasswordField(_('Confirm Password'), [validators.Required()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True

    def reset(self):
        self.password.data = ''
        self.confirm.data = ''


class ResetPasswordForm(Form):
    "Reset Password form"
    email = TextField(_('Email'), [validators.Required(), validators.Email()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True

    def reset(self):
        self.email.data = ''


class RegistrationForm(Form):
    "Registration form"
    name = TextField(_('Name'), [validators.Required()])
    email = TextField(_('Email'), [validators.Required(), validators.Email()])
    password = PasswordField(_('Password'), [validators.Required(),
        validators.EqualTo('confirm', message=_('Passwords must match'))])
    confirm = PasswordField(_('Confirm Password'))

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True

    def reset(self):
        self.password.data = ''
        self.confirm.data = ''


class ActivateForm(Form):
    "Activate form"
    act_code = HiddenField(_('Activation Code'), [validators.Required()])
    email = HiddenField(_('Email'), [validators.Required(), validators.Email()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True


def create_act_code(code_type="new"):
    """Create activation code
    A 12 character activation code indicates reset while 16
    character activation code indicates a new registration
    :param code_type: string
    return activation code
    """
    assert code_type in ("new", "reset")
    length = 16 if code_type == "new" else 12
    act_code = ''.join(random.sample(string.letters + string.digits, length))

    return act_code

def send_reset_email(user):
    """
    Send an account reset email to the user
    :param user: dict
    """
    mail = Mail(current_app)

    subject =  '%s - %s' % (current_app.config.get('TITLE'), _('Account Password Reset'))
    msg = Message(subject,
            body = render_template('emails/reset-text.jinja', user=user),
            html = render_template('emails/reset-html.jinja', user=user),
            sender = current_app.config.get('DEFAULT_MAIL_SENDER'),
            recipients = [user['email']])
    mail.send(msg)

def send_activation_email(user):
    """
    Send an new account email to the user
    :param user: dict
    """
    mail = Mail(current_app)

    subject =  '%s - %s' % (current_app.config.get('TITLE'), _('New Account Activation'))
    msg = Message(subject,
            body = render_template('emails/activation-text.jinja', user=user),
            html = render_template('emails/activation-html.jinja', user=user),
            sender = current_app.config.get('DEFAULT_MAIL_SENDER'),
            recipients = [user['email']])
    mail.send(msg)

def send_new_password(user):
    """
    Send an new password account to the user
    :param user: dict
    """
    mail = Mail(current_app)

    subject =  '%s - %s' % (current_app.config.get('TITLE'), _('New Account Password'))
    msg = Message(subject,
            body = render_template('emails/new-password-text.jinja', user=user),
            html = render_template('emails/new-password-html.jinja', user=user),
            sender = current_app.config.get('DEFAULT_MAIL_SENDER'),
            recipients = [user['email']])
    mail.send(msg)

@galatea.route("/login", methods=["GET", "POST"], endpoint="login")
@tryton.transaction()
def login(lang):
    '''Login App'''
    data = {}

    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    def _get_user(email):
        '''Search user by email
        :param email: string
        return user list[dict]
        '''
        users = GalateaUser.search_read([
            ('email', '=', email),
            ], limit=1, fields_names=[
                'display_name',
                'email',
                'password',
                'salt',
                'activation_code',
                ])
        return users

    def _validate_user(user, password):
        '''Validate user and password
        :param user: string
        :param password: string
        return Bool
        '''
        activation_code = user['activation_code']
        if activation_code and len(activation_code) == 16:
            flash(_("Your account has not been activated yet!"))
            return False

        password += user.get('salt', '')
        if hashlib:
            digest = hashlib.sha1(password).hexdigest()
        else:
            digest = sha.new(password).hexdigest()
        if digest != user['password']:
            flash(_("The password is invalid"), "danger")
            return False

        return True

    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        users = _get_user(email)

        if users:
            user, = users
            login = _validate_user(user, password)
            if login:
                session['logged_in'] = True
                session['user'] = user['id']
                session['display_name'] = user['display_name']
                flash(_('You are logged in'))
                slogin.send()
                return redirect(url_for('index', lang=g.language))
        else:
            flash(_("Email user don't exist"))

        data['email'] = email
        sfailed_login.send(form=form)

    return render_template('login.html', form=form, data=data)

@galatea.route('/logout', endpoint="logout")
@login_required
@tryton.transaction()
def logout(lang):
    '''Logout App'''
    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    # Remove all sessions
    session.pop('logged_in', None)
    session.pop('user', None)
    session.pop('display_name', None)

    slogout.send()

    flash(_('You are logged out.'))
    return redirect(url_for('index', lang=g.language))

@galatea.route('/new-password', methods=["GET", "POST"], endpoint="new-password")
@login_required
@tryton.transaction()
def new_password(lang):
    '''New Password User Account'''

    def _save_password(password):
        '''Save new password user
        :param password: string
        return user dict
        '''
        user = None
        users = GalateaUser.search([
            ('id', '=', session['user']),
            ], limit=1)
        if users:
            user, = users
            GalateaUser.write([user], {
                    'password': password,
                    })
            data = {
                'display_name': user.display_name,
                'email': user.email,
                'password': password,
                }
            return data
        return user

    form = NewPasswordForm()
    if form.validate_on_submit():
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        if password == confirm and \
                len(password) >= current_app.config.get('LEN_PASSWORD', 6):
            user = _save_password(password)
            if user:
                send_new_password(user)
            flash(_('Saved password!'))
        else:
            flash(_("Password don't match or length not valid! " \
                "Repeat add new password and save"), "danger")
        form.reset()

    return render_template('new-password.html', form=form)

@galatea.route('/reset-password', methods=["GET", "POST"], endpoint="reset-password")
@tryton.transaction()
def reset_password(lang):
    '''Reset Password User Account'''
    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    def _get_user(email):
        '''Search user by email
        :param email: string
        return user list[dict]
        '''
        user = None
        users = GalateaUser.search_read([
            ('email', '=', email),
            ], limit=1, fields_names=[
                'display_name',
                'email',
                'password',
                'salt',
                'activation_code',
                ])
        if users:
            user, = users
        return user

    def _save_act_code(user, act_code):
        '''Write user activation code
        :param user: dict
        :param act_code: string
        '''
        user = GalateaUser(int(user['id']))
        GalateaUser.write([user], {'activation_code': act_code})

    form = ResetPasswordForm()
    if form.validate_on_submit():
        email = request.form.get('email')

        user = _get_user(email)
        if not user:
            flash(_('Not found email address'))
            return render_template('reset-password.html', form=form)

        # save activation code
        act_code = create_act_code(code_type="reset")
        _save_act_code(user, act_code)

        # send email activation code
        user['act_code'] = act_code
        send_reset_email(user)

        flash('%s: %s' % (
            _('An email has been sent to your account for resetting your password'),
            user['email']))
        form.reset()

    return render_template('reset-password.html', form=form)

@galatea.route('/activate', methods=["GET", "POST"], endpoint="activate")
@tryton.transaction()
def activate(lang):
    '''Activate user account'''
    act_code = request.args.get('act_code')
    email = request.args.get('email')

    form = ActivateForm()
    if request.form.get('act_code'):
        act_code = request.form.get('act_code')
        email = request.form.get('email')

    def _get_user(email, act_code):
        '''Search user by email
        :param email: string
        return user list[dict]
        '''
        user = None
        users = GalateaUser.search_read([
            ('email', '=', email),
            ('activation_code', '=', act_code),
            ], limit=1, fields_names=[
                'display_name',
                'email',
                'password',
                'salt',
                'activation_code',
                ])
        if users:
            user, = users
        return user

    def _reset_act_code(user):
        '''Add null activation code
        :param user: dict
        '''
        user = GalateaUser(int(user['id']))
        GalateaUser.write([user], {'activation_code': None})

    user = _get_user(email, act_code)

    # active new user
    if user and len(act_code) == 16:
        if request.method == 'POST':
            _reset_act_code(user) # reset activation code
            session['logged_in'] = True
            session['user'] = user['id']
            session['display_name'] = user['display_name']
            flash(_('Your account has been activated'))
            slogin.send()
        else:
            data = {
                'act_code': act_code,
                'email': email,
                }
            return render_template('activate.html', form=form, data=data)

    # active new password
    if user and len(act_code) == 12:
        session['logged_in'] = True
        session['user'] = user['id']
        session['display_name'] = user['display_name']
        flash(_('You are logged in'))
        slogin.send()

        return redirect(url_for('.new-password', lang=g.language))

    return redirect('/%s/' % g.language)

@galatea.route('/registration', methods=["GET", "POST"], endpoint="registration")
@tryton.transaction()
def registration(lang):
    '''Registration User Account'''
    if not current_app.config.get('ACTIVE_REGISTRATION'):
        abort(404)

    def _get_user(email):
        '''Search user by email
        :param email: string
        return user list[dict]
        '''
        user = None
        users = GalateaUser.search_read([
            ('email', '=', email),
            ], limit=1, fields_names=[
                'display_name',
                'email',
                'password',
                'salt',
                'activation_code',
                ])
        if users:
            user, = users
        return user

    def _save_user(data):
        '''Save user values
        :param data: dict
        '''
        party = None

        websites = Website.search([
            ('id', '=', galatea_website),
            ], limit=1)
        if not websites:
            abort(404)
        website, = websites

        # search if email exist
        contacts = ContactMechanism.search([
            ('type', '=', 'email'),
            ('value', '=', data.get('email')),
            ], limit=1)
        if contacts:
            contact, = contacts
            party = contact.party

        if not party:
            party_data = {
                'name': data.get('display_name'),
                'addresses': [],
                }
            party, = Party.create([party_data])

            contact_data = {
                'party': party.id,
                'type': 'email',
                'value': data.get('email'),
                }
            ContactMechanism.create([contact_data])

        data['company'] = website.company.id
        data['party'] = party.id
        GalateaUser.create([data])

    form = RegistrationForm()
    if form.validate_on_submit():
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        if not (password == confirm and \
                len(password) >= current_app.config.get('LEN_PASSWORD', 6)):
            flash(_("Password don't match or length not valid! " \
                "Repeat add new password and save"), "danger")
            form.reset()
            return render_template('registration.html', form=form)

        user = _get_user(email)
        if user:
            flash(_('Email account exist. Do you forget password?'))
            return render_template('registration.html', form=form)

        act_code = create_act_code(code_type="new")

        # save new account - user
        data = {
            'display_name': name,
            'email': email,
            'password': password,
            'activation_code' : act_code,
            }
        _save_user(data)

        # send email activation account
        send_activation_email(data)

        flash('%s: %s' % (
            _('An email has been sent to your email for active your account'),
            email))
        form.reset()

    return render_template('registration.html', form=form)
