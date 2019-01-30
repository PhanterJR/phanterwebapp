# -*- coding: utf-8 -*-
from .. import (app, __version__ as app_version)
from flask import send_from_directory, abort
import os


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static", "favicons"),
                           "favicon.ico")


@app.route('/static-versioned/<version>/<path>/<file>')
def static_versioned(version, path, file):
    if app_version == version:
        return send_from_directory(os.path.join(app.root_path, "static", path),
                           file)
    else:
        return abort(404)
