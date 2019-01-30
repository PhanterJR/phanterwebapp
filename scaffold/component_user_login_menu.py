# -*- coding: utf-8 -*-

from phanterweb.materialize import (
    MaterializeButtonLeftUserMenu,
)

html = MaterializeButtonLeftUserMenu("user")

html.addSubmenu(
    "profile",
    "Perfil",
    _class="command_user",
    _link_href="page_profile"
)

html.addSubmenu(
    "lock",
    "Bloquear",
    _class="command_user",
    _link_href="page_lock"
)

html.addSubmenu(
    "logout",
    "Sair",
    _class="command_user"
)
