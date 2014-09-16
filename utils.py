#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains 
#the full copyright notices and license terms.
from flask import current_app
from trytond.config import CONFIG as tryton_config
from slug import slug

import os
try:
    from PIL import Image, ImageOps
except ImportError:
    raise RuntimeError('Image module of PIL needs to be installed')

def get_tryton_language(lang):
    '''
    Convert language to tryton languages
    Example: ca -> ca_ES
    '''
    languages = current_app.config.get('ACCEPT_LANGUAGES')
    for k, v in languages.iteritems():
        l = k.split('_')[0]
        if l == lang:
            return k

def get_tryton_locale(lang):
    '''
    Get locale options from lang
    '''
    languages = {
        'en': {'date': '%m/%d/%Y', 'thousands_sep': ',', 'decimal_point': '.',
            'grouping': [3, 3, 0]},
        'ca': {'date': '%d/%m/%Y', 'thousands_sep': ' ', 'decimal_point': ',',
            'grouping': [3, 3, 0]},
        'es': {'date': '%d/%m/%Y', 'thousands_sep': ',', 'decimal_point': '.',
            'grouping': [3, 3, 0]},
        'fr': {'date': '%d.%m.%Y', 'thousands_sep': ' ', 'decimal_point': ',',
            'grouping': [3, 0]},
        }
    if languages.get(lang):
        return languages.get(lang)
    return languages.get('en')

def slugify(value):
    """Convert value to slug: az09 and replace spaces by -"""
    try:
        if isinstance(value, unicode):
            name = slug(value)
        else:
            name = slug(unicode(value, 'UTF-8'))
    except:
        name = ''
    return name

def thumbnail(filename, thumbname, size, crop=None, bg=None, quality=85):
    '''Create thumbnail image

    :param filename: image digest - '2566a0e6538be8e094431ff46ae58950'
    :param thumbname: file name image - 'test.jpg'
    :param size: size return thumb - '100x100'
    :param crop: crop return thumb - 'fit' or None
    :param bg: tuple color or None - (255, 255, 255, 0)
    :param quality: JPEG quality 1-100
    :return: :thumb_url:
    '''

    def _bg_square(img, color=0xff):
        size = (max(img.size),) * 2
        layer = Image.new('L', size, color)
        layer.paste(img, tuple(map(lambda x: (x[0] - x[1]) / 2, zip(size, img.size))))
        return layer

    def _get_name(name, fm, *args):
        for v in args:
            if v:
                name += '_%s' % v
        name += fm
        return name

    width, height = [int(x) for x in size.split('x')]
    name, fm = os.path.splitext(thumbname)

    miniature = _get_name(name, fm, size, crop, bg, quality)
    
    original_filename = os.path.join(tryton_config['data_path'], current_app.config['TRYTON_DATABASE'], filename[0:2], filename[2:4], filename)
    thumb_filename = os.path.join(current_app.config['MEDIA_CACHE_FOLDER'], miniature)

    thumb_url = os.path.join(current_app.config['MEDIA_CACHE_URL'], miniature)

    if os.path.exists(thumb_filename):
        return thumb_url
    else:
        thumb_size = (width, height)

        try:
            image = Image.open(original_filename)  
        except IOError:
            return current_app.config['BASE_IMAGE']

        if crop == 'fit':
            img = ImageOps.fit(image, thumb_size, Image.ANTIALIAS)
        else:
            img = image.copy()
            img.thumbnail((width, height), Image.ANTIALIAS)

        if bg:
            img = _bg_square(img, bg)

        img.save(thumb_filename, image.format, quality=quality)

        return thumb_url
