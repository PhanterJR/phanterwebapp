# -*- coding: utf-8 -*-

from . import app_version
from phanterweb.helpers import (
    SCRIPT,
    CONCATENATE
)
html = CONCATENATE(
    SCRIPT(
        _src="/static-versioned/%s/js/application.js" %
        (app_version)
    ),
)
