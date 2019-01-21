# -*- coding: utf-8 -*-

from phanterweb.materialize import (
    MaterializeButtonLeftMenu,
)

html = MaterializeButtonLeftMenu(
    "user",
    "Início",
    "person"
)

html.addSubmenu(
    "login",
    "Login",
    _class="command_user"
)

html.addSubmenu(
    "register",
    "Criar Conta",
    _class="command_user"
)

html.addSubmenu(
    "request-password",
    "Esqueci a Senha",
    _class="command_user"
)
