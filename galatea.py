#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains
#the full copyright notices and license terms.
from flask import (Blueprint, request, render_template, current_app, session,
    jsonify, redirect, url_for, flash, abort, g)
from flask_babel import gettext as _, lazy_gettext as __
from flask_mail import Mail, Message
from flask_wtf import FlaskForm as Form
from wtforms import TextField, PasswordField, SelectField, HiddenField, validators
from flask_login import (UserMixin, login_user, logout_user, login_required,
    current_user)
from .tryton import tryton
from .signals import (login as slogin, failed_login as sfailed_login,
    logout as slogout, registration as sregistration)
from .helpers import manager_required
from .utils import get_tryton_language
from trytond.transaction import Transaction

import stdnum.eu.vat as vat
import random
import string

try:
    import hashlib
except ImportError:
    hashlib = None
    import sha

galatea = Blueprint('galatea', __name__, template_folder='templates')

GALATEA_WEBSITE = current_app.config.get('TRYTON_GALATEA_SITE')
REGISTRATION_VAT = current_app.config.get('REGISTRATION_VAT')
REGISTRATION_VAT_CHECK_CUSTOMER = current_app.config.get(
    'REGISTRATION_VAT_CHECK_CUSTOMER', False)
DEFAULT_COUNTRY = current_app.config.get('DEFAULT_COUNTRY')
REDIRECT_AFTER_LOGIN = current_app.config.get('REDIRECT_AFTER_LOGIN')
REDIRECT_AFTER_LOGOUT = current_app.config.get('REDIRECT_AFTER_LOGOUT')
LOGIN_REMEMBER_ME = current_app.config.get('LOGIN_REMEMBER_ME', False)
LOGIN_EXTRA_FIELDS = current_app.config.get('LOGIN_EXTRA_FIELDS', [])
SEND_NEW_PASSWORD = current_app.config.get('SEND_NEW_PASSWORD', True)
AUTOLOGIN_POSTREGISTRATION = current_app.config.get('AUTOLOGIN_POSTREGISTRATION')

VAT_COUNTRIES = [('', '')]
for country in sorted(vat._country_codes):
    VAT_COUNTRIES.append((country, country.upper()))

GalateaUser = tryton.pool.get('galatea.user')
Website = tryton.pool.get('galatea.website')
Party = tryton.pool.get('party.party')
ContactMechanism = tryton.pool.get('party.contact_mechanism')
Subdivision = tryton.pool.get('country.subdivision')
Lang = tryton.pool.get('ir.lang')


class User(UserMixin):
    "Login User Mixin"
    pass


class LoginForm(Form):
    "Login form"
    email = TextField(__('Email'), [validators.Required(), validators.Email()])
    password = PasswordField(__('Password'), [validators.Required()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True


class NewPasswordForm(Form):
    "New Password form"
    password = PasswordField(__('Password'), [validators.Required(),
        validators.EqualTo('confirm', message=_('Passwords must match'))])
    confirm = PasswordField(__('Confirm'), [validators.Required()])

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


def _get_vat_code(vat_country, vat_number):
    eu_vat = False
    if vat_country and vat_number:
        eu_vat = True
        vat_code = '%s%s' % (vat_country.upper(), vat_number)
        vat_code = vat.compact(vat_code)
    elif vat_number:
        vat_code = vat_number
    return vat_code, eu_vat


class RegistrationForm(Form):
    "Registration form"
    vat_required = None
    if REGISTRATION_VAT:
        vat_required = [validators.Required()]

    name = TextField(__('Name'), [validators.Required()])
    email = TextField(__('Email'), [validators.Required(), validators.Email()])
    password = PasswordField(__('Password'), [validators.Required()])
    confirm = PasswordField(__('Confirm'))
    phone = TextField(__('Phone'))
    vat_country = SelectField(__('VAT Country'), choices=VAT_COUNTRIES)
    vat_number = TextField(__('VAT Number'), vat_required)
    code = TextField(__('Code'))
    language = SelectField(__('Language'))

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
        self.vat_number.data = ''

    def check(self):
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        email = request.form.get('email')
        vat_country = request.form.get('vat_country')
        vat_number = request.form.get('vat_number')

        if not (password == confirm and
                len(password) >= current_app.config.get('LEN_PASSWORD', 6)):
            flash(_("Password doesn't match or length not valid! "
                    "Add new password again and save"), "danger")
            self.reset()
            return False
        if _get_user(email, active=False):
            flash(_('Email address already exists. Do you forget the '
                    'password?'), 'danger')
            return False

        vat_code, eu_vat = _get_vat_code(vat_country, vat_number)
        if not vat.is_valid(vat_code):
            flash(_('VAT number is not valid.'), 'danger')
            return False
        parties = Party.search([
            ('vat_code', '=', vat_code),
            ], limit=1)
        if parties:
            if REGISTRATION_VAT_CHECK_CUSTOMER:
                flash(_('A customer exists with your VAT. Please, '
                        'login or contact us to create a new user.'),
                    'danger')
                return False
        return True

    def save(self, send_act_code=True):
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone')
        vat_country = request.form.get('vat_country')
        vat_number = request.form.get('vat_number')
        language = request.form.get('language')

        user = _get_user(email, active=False)

        if AUTOLOGIN_POSTREGISTRATION or not send_act_code:
            act_code = None
        else:
            act_code = create_act_code(code_type="new")
        party = None
        # search if email exist
        contacts = ContactMechanism.search([
            ('type', '=', 'email'),
            ('value', '=', email),
            ], limit=1)
        if contacts:
            contact, = contacts
            party = contact.party
        # search if vat exist
        vat_code, eu_vat = _get_vat_code(vat_country, vat_number)
        if eu_vat and vat_code:
            parties = Party.search([
                ('vat_code', '=', vat_code),
                ], limit=1)
            if parties:
                party, = parties

        if not party:
            party_data = {
                'name': name,
                'addresses': [],
                }
            if language:
                lang = Lang.search([('code', '=', language)], limit=1)
                if lang:
                    party_data['lang'] = lang[0].id
            # identifiers
            if vat_code:
                if eu_vat:
                    vat_party = {
                        'type': 'eu_vat',
                        'code': vat_code,
                        }
                else:
                    vat_party = {
                        'type': None, # not eu vat
                        'code': vat_code,
                        }
                party_data['identifiers'] = [('create', [vat_party])]
            # contact mechanisms
            contact_datas = []
            if email:
                contact_datas.append({
                    'type': 'email',
                    'value': email,
                    })
            if phone:
                contact_datas.append({
                    'type': 'phone',
                    'value': phone,
                    })
            party_data['contact_mechanisms'] = [('create', contact_datas)]
            # save party
            party, = Party.create([party_data])

        user_data = {
            'display_name': name,
            'email': email,
            'password': password,
            'activation_code': act_code,
            'company': Website(GALATEA_WEBSITE).company.id,
            'party': party.id
            }
        user, = GalateaUser.create([user_data])
        return {'user': user}


class ActivateForm(Form):
    "Activate form"
    act_code = HiddenField(__('Activation Code'), [validators.Required()])
    email = HiddenField(__('Email'), [validators.Required(), validators.Email()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True


class Galatea(object):
    '''
    This object is used to hold the settings used for galatea configuration.
    '''
    def __init__(self, app=None):
        self.login_form = LoginForm
        self.new_password_form = NewPasswordForm
        self.reset_password_form = ResetPasswordForm
        self.registration_form = RegistrationForm
        self.activate_form = ActivateForm

        self.login_error = _("User email don't exist or disabled user.")
        self.logout_message = _('You are logged out.')

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['Galatea'] = self


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
    :param user: GalateaUser object
    """
    mail = Mail(current_app)

    subject =  '%s - %s' % (current_app.config.get('TITLE'), _('New Account Activation'))
    msg = Message(subject,
            body = render_template('emails/activation-text.jinja', user=user),
            html = render_template('emails/activation-html.jinja', user=user),
            sender = current_app.config.get('DEFAULT_MAIL_SENDER'),
            recipients = [user.email])
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

def _get_user(email, active=True):
    '''Get user
    :param email: string
    :param active: bool
    return user or None
    '''
    user = None
    fields = [
        'party',
        'display_name',
        'email',
        'password',
        'salt',
        'activation_code',
        'manager',
        ]
    if LOGIN_EXTRA_FIELDS:
        fields = fields+LOGIN_EXTRA_FIELDS
    domain = [
        ('email', '=', email),
        ('websites', 'in', [GALATEA_WEBSITE]),
        ]
    with Transaction().set_context(active_test=active):
        users = GalateaUser.search_read(domain, limit=1, fields_names=fields)
        if users:
            user, = users
    return user

@galatea.route("/login", methods=["GET", "POST"], endpoint="login")
@tryton.transaction()
def login(lang):
    '''Login App'''
    data = {}

    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    if current_user.is_authenticated:
        if REDIRECT_AFTER_LOGIN:
            return redirect(url_for(REDIRECT_AFTER_LOGIN, lang=g.language))
        else:
            return redirect(url_for(g.language))

    def _validate_user(user, password):
        '''Validate user and password
        :param user: object
        :param password: string
        return Bool
        '''
        activation_code = user.activation_code
        if activation_code and len(activation_code) == 16:
            flash(_("Your account has not been activated yet!"))
            return False

        if isinstance(password, unicode):
            password = password.encode('utf-8')
        salt = user.salt.encode('utf-8') if user.salt else ''
        if salt:
            password += salt
        if hashlib:
            digest = hashlib.sha1(password).hexdigest()
        else:
            digest = sha.new(password).hexdigest()
        if digest != user.password:
            flash(_("The password is invalid"), "danger")
            return False
        return True

    form = current_app.extensions['Galatea'].login_form()

    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        users = GalateaUser.get_user(GALATEA_WEBSITE, request)
        if users:
            user, = users
            login = _validate_user(user, password)
            if login:
                login_user(user, remember=LOGIN_REMEMBER_ME)
                if (current_app.config.get('USE_SESSION_FOR_NEXT')
                        and session.get('next')):
                    return redirect(session['next'])
                elif REDIRECT_AFTER_LOGIN:
                    return redirect(
                        url_for(REDIRECT_AFTER_LOGIN, lang=g.language))
                else:
                    return redirect(url_for(g.language))
        else:
            flash(current_app.extensions['Galatea'].login_error, 'danger')

        data['email'] = email
        sfailed_login.send(form=form)

    return render_template('login.html', form=form, data=data,
        website=Website(GALATEA_WEBSITE))


@galatea.route('/logout', endpoint="logout")
@login_required
@tryton.transaction()
def logout(lang):
    '''Logout App'''

    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    logout_user()

    slogout.send(current_app._get_current_object(),
        user=current_user,
        website=current_app.config.get('TRYTON_GALATEA_SITE', None),
        )

    flash(current_app.extensions['Galatea'].logout_message)

    if REDIRECT_AFTER_LOGOUT:
        return redirect(url_for(REDIRECT_AFTER_LOGOUT, lang=g.language))
    else:
        return redirect(url_for(g.language))

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
            ('id', '=', current_user.get_id()),
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

    form = current_app.extensions['Galatea'].new_password_form()
    if form.validate_on_submit():
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if password == confirm and \
                len(password) >= current_app.config.get('LEN_PASSWORD', 6):
            user = _save_password(password)
            if user and SEND_NEW_PASSWORD:
                send_new_password(user)
            flash(_('The password has been saved.'))
        else:
            flash(_("The passwords don't match or length is not valid! " \
                "Add the new password another time and save."), "danger")
        form.reset()

    return render_template('new-password.html', form=form)

@galatea.route('/reset-password', methods=["GET", "POST"], endpoint="reset-password")
@tryton.transaction()
def reset_password(lang):
    '''Reset Password User Account'''
    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    def _save_act_code(user, act_code):
        '''Write user activation code
        :param user: dict
        :param act_code: string
        '''
        user = GalateaUser(int(user['id']))
        GalateaUser.write([user], {'activation_code': act_code})

    form = current_app.extensions['Galatea'].reset_password_form()
    if form.validate_on_submit():
        email = request.form.get('email')

        user = _get_user(email)
        if not user:
            flash(_('Not found email address.'))
            return render_template('reset-password.html', form=form)

        # save activation code
        act_code = create_act_code(code_type="reset")
        _save_act_code(user, act_code)

        # send email activation code
        user['act_code'] = act_code
        send_reset_email(user)

        flash('%s: %s' % (
            _('An email has been sent to reset your password'),
            user['email']))
        form.reset()

    return render_template('reset-password.html', form=form)

@galatea.route('/activate', methods=["GET", "POST"], endpoint="activate")
@tryton.transaction()
def activate(lang):
    '''Activate user account'''
    act_code = request.args.get('act_code')
    email = request.args.get('email')

    form = current_app.extensions['Galatea'].activate_form()
    if request.form.get('act_code'):
        act_code = request.form.get('act_code')
        email = request.form.get('email')

    users = GalateaUser.search([
        ('email', '=', email),
        ('active', '=', True),
        ('activation_code', '=', act_code),
        ], limit=1)
    if users:
        user, = users
        if user:
            # active new user
            if len(act_code) == 16:
                if request.method == 'POST':
                    user.activation_code = None
                    user.save()
                    login_user(user, remember=LOGIN_REMEMBER_ME)
                    flash(_('Your account has been activated.'))
                    slogin.send(current_app._get_current_object(),
                        user=user.id,
                        session=session.sid,
                        website=current_app.config.get('TRYTON_GALATEA_SITE',
                            None),
                        )
                else:
                    data = {
                        'act_code': act_code,
                        'email': email,
                        }
                    return render_template('activate.html', form=form,
                        data=data)

            # active new password
            if len(act_code) == 12:
                login_user(user, remember=LOGIN_REMEMBER_ME)
                flash(_('You are logged in'))
                # Not signal login because cannot execute UPDATE in a read-only
                # transaction
                return redirect(url_for('.new-password', lang=g.language))

    flash(_('Activation code is not valid.'))
    return redirect('/%s/' % g.language)

@galatea.route('/registration', methods=["GET", "POST"], endpoint="registration")
@tryton.transaction()
def registration(lang):
    '''Registration User Account'''

    if not current_app.config.get('ACTIVE_REGISTRATION'):
        abort(404)

    website = Website(GALATEA_WEBSITE)

    form = current_app.extensions['Galatea'].registration_form()

    lang = get_tryton_language(g.language)
    form.language.data = lang
    if website.languages:
        form.language.choices = [(l.code, l.name) for l in website.languages]
    else:
        form.language.choices = [(lang, lang)]

    if hasattr(form, 'country'):
        if website.countries:
            countries = [(c.id, c.name) for c in website.countries]
        else:
            countries = [(website.country.id, website.country.name)]
        form.country.choices = countries
        form.country.data = website.country.id

    if form.validate_on_submit() and form.check():
        result = form.save()
        user = result and result.get('user')
        if user:
            # signal registration
            sregistration.send(
                current_app._get_current_object(),
                user=user,
                data=request.form,
                website=current_app.config.get('TRYTON_GALATEA_SITE', None),
                )
            if AUTOLOGIN_POSTREGISTRATION:
                flash(_('You have a new account and you are logged in'))
                login_user(user, remember=LOGIN_REMEMBER_ME)
                return redirect(url_for('.login', lang=g.language))
            else:
                # send email activation account
                send_activation_email(user)
                flash('%s: %s' % (
                    _('An email has been sent to activate your account'),
                    user.email))
                return redirect(url_for('index', lang=g.language))

    form.vat_country.data = DEFAULT_COUNTRY.upper() or ''
    return render_template('registration.html', form=form, website=website)

@galatea.route('/subdivisions', methods=['GET'], endpoint="subdivisions")
@tryton.transaction()
def subdivisions(lang):
    '''Return all subdivisions by country (Json)'''
    country = int(request.args.get('country', 0))
    subdivisions = Subdivision.search([('country', '=', country)])

    return jsonify(
        result=[{
            'id': s.id,
            'name': s.name,
            'code': s.code,
            } for s in subdivisions
            ]
        )

@galatea.route('/json/search', methods=['GET'], endpoint="jsonsearch")
@manager_required
@tryton.transaction()
def jsonsearch(lang):
    '''Search rec_name in model (Json)

    Example:
    /json/search?model=party.party&query=%QUERY
    '''
    model = request.args.get('model')
    query = request.args.get('query')

    if not model:
        return jsonify(result=[])

    Model = tryton.pool.get(model)
    rows = Model.search_read([
        ('rec_name', 'ilike', '%'+query+'%'),
        ], fields_names=['name'])

    return jsonify(results=rows)
