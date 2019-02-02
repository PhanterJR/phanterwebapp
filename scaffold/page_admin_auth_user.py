# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    SCRIPTMINIFY,
    CONCATENATE,
    H3,
)


html = CONCATENATE(
    H3(DIV("Auth Users", _class="phanterweb-container"), _class="titulo_maincontainer"),
    DIV(
        DIV(
            DIV(
                DIV(
                    DIV(_id="lista_auth_user", _class="simple-border"),
                    _class="phanterweb-card-container phanterwebpages-card_buttons-container"),
                _class="card"
            ),
            _class="new-container"
        ),
        _class="phanterweb-container"
    ),
    SCRIPTMINIFY("phanterwebpages.admin_auth_user();"),
)
