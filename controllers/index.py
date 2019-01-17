# -*- coding: utf-8 -*-

from .. import app, __version__ as app_version
from flask import render_template, request, send_from_directory
import os

@app.route('/')
@app.route('/<pagina>')
def index(pagina=None):
    if pagina=="android-chrome-144x144.png":
        return send_from_directory(os.path.join(app.root_path, "static", 'favicons'),
                           "android-chrome-144x144.png")
    if not pagina:
        return render_template('page-layout.html')
    else:
        return render_template(pagina)