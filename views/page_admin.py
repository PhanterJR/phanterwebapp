# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    SCRIPTMINIFY,
    CONCATENATE,
    I,
    SPAN,
    H3,
)

botoes = [
    (
        "Usuários",
        I(
            "local_library",
            _class="material-icons large administracao_card_material-icons"
        ),
        "auth_user",
        "Adicionar/Editar clientes"
    ),
    (
        "Papeis",
        I(
            _class="fas fa-boxes large administracao_card_material-icons"
        ),
        "auth_role",
        "Adicionar/Editar produtos ao estoque"
    ),
    (
        "Configurações",
        I(
            _class="fas fa-cog large administracao_card_material-icons"
        ),
        "phanterwebconfig",
        "Configurações do sistema"
    ),
]

html_botoes = DIV(_class="container-card-buttons row")

for x in botoes:
    html_botoes.append(
        DIV(
            DIV(
                DIV(
                    x[1],
                    SPAN(
                        x[0],
                        _class="card-title phanterweb-card-title"
                    ),
                    _class="card-content"
                ),
                _class="card link_href card_link card_button waves-effect waves-light",
                _link_href=x[2],
                _title=x[3],
            ),
            _class="col s12 m4 l3"
        )
    )

html = CONCATENATE(
    H3(DIV("Application Admin", _class="phanterweb-container"), _class="titulo_maincontainer"),
    DIV(
        DIV(
            DIV(
                DIV(
                    html_botoes,
                    _class="phanterweb-card-container phanterpages-card_buttons-container"),
                _class="card"
            ),
            _class="new-container"
        ),
        _class="phanterweb-container"
    ),
    SCRIPTMINIFY("phanterpages.admin();"),
)
