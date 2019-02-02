# -*- coding: utf-8 -*-

from . import app_version

from phanterweb.helpers import (
    DIV,
    IMG,
    SCRIPTMINIFY,
    CONCATENATE
)

html = CONCATENATE(
    DIV(
        DIV(
            DIV(_id="titulo-warning"),
            _class='warnings-title'
        ),
        DIV(
            DIV(
                IMG(
                    _src="/static-versioned/%s/images/warning.png" %
                    (app_version),
                    _class='image-warnings'
                ),
                _class="image-warnings-container"
            ),
            DIV(_id='content-warning'),
            _class='content-warnings card'
        ),
        _class="warnings-container container"
    ),
    SCRIPTMINIFY("phanterwebpages.warning();")
)
