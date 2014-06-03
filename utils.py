#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains 
#the full copyright notices and license terms.
from flask import current_app

def get_tryton_locale(locale):
    '''
    Convert locale to tryton locales
    Example: ca -> ca_ES
    '''
    languages = current_app.config.get('ACCEPT_LANGUAGES')
    for k, v in languages.iteritems():
        l = k.split('_')[0]
        if l == locale:
            return k
