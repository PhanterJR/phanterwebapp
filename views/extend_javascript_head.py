# -*- coding: utf-8 -*-

from . import app_version
from phanterweb.helpers import (
    SCRIPT,
    CONCATENATE
)
html = CONCATENATE(
    SCRIPT(
        _src="/static-versioned/%s/js/jquery.min.js" %
        (app_version)
    ),
    SCRIPT(
        _src="/static-versioned/%s/js/materialize.min.js" %
        (app_version)
    ),
    SCRIPT(
        _src="/static-versioned/%s/js/calendar.js" %
        (app_version)
    ),
    SCRIPT(
        _src="/static-versioned/%s/js/hammer.min.js" %
        (app_version)
    ),
    SCRIPT(
        _src="/static-versioned/%s/js/touch-emulator.js" %
        (app_version)
    ),
    SCRIPT(
        _src="/static-versioned/%s/js/jquery.hammer.js" %
        (app_version)
    ),
    SCRIPT(
        _src="/static-versioned/%s/js/phanterwebcachedatajs.js" %
        (app_version)
    ),
    SCRIPT(
        _src="/static-versioned/%s/js/phanterweb.js" %
        (app_version)
    ),
)
