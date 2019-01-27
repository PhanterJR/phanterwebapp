# -*- coding: utf-8 -*-

from . import app_version
from phanterweb.helpers import (
    LINK,
    CONCATENATE
)
html = CONCATENATE(
    LINK(
        _rel="stylesheet",
        _href="/static-versioned/%s/css/fonts.css" %
        (app_version)
    ),
    LINK(
        _rel="stylesheet",
        _href="/static-versioned/%s/css/materialize.min.css" %
        (app_version)
    ),
    LINK(
        _rel="stylesheet",
        _href="/static-versioned/%s/css/all.min.css" %
        (app_version)
    ),
    LINK(
        _rel="stylesheet",
        _href="/static-versioned/%s/css/main.css" %
        (app_version)
    ),
    LINK(
        _rel="stylesheet",
        _href="/static-versioned/%s/css/calendar.css" %
        (app_version)
    ),
    LINK(
        _rel="stylesheet",
        _href="/static-versioned/%s/css/application.css" %
        (app_version)
    ),
)
