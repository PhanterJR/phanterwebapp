# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    SCRIPTMINIFY,
    CONCATENATE,
    H3,
)


html = CONCATENATE(
    H3(DIV("Auth Groups", _class="phanterweb-container"), _class="titulo_maincontainer"),
    DIV(
        DIV(
            DIV(
                DIV(
                    DIV(_id="lista_auth_group", _class="simple-border"),
                    _class="phanterweb-card-container phanterpages-card_buttons-container"),
                _class="card"
            ),
            _class="new-container"
        ),
        _class="phanterweb-container"
    ),
    SCRIPTMINIFY("phanterpages.admin_groups();"),
)
