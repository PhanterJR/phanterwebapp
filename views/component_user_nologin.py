# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    I,
    SPAN
)

html = DIV(
    DIV(
        DIV("INICIAR", _class="cmd-bar-start"),
        DIV(
            DIV(
                I("expand_less", _class="material-icons cmd-bar-user-expand-icon less"),
                I("expand_more", _class="material-icons cmd-bar-user-expand-icon more"),
                _class="cmd-bar-user-expands"),
            _class="cmd-bar-user-expand-container"),
        _id="toggle-cmp-bar-user",
        _class="cmp-bar-user-container black link waves-effect waves-teal"),
    DIV(
        DIV(
            DIV(
                I("power_settings_new", _class="material-icons"),
                SPAN("Login"),
                _class="option-label-menu"
            ),
            _id="cmp-bar-usermenu-option-login",
            _class='cmp-bar-usermenu-option link'
        ),
        DIV(
            DIV(
                I("person_add", _class="material-icons"),
                SPAN("Criar Conta"),
                _class="option-label-menu"
            ),
            _id="cmp-bar-usermenu-option-register",
            _class='cmp-bar-usermenu-option link'
        ),
        DIV(
            DIV(
                I("lock", _class="material-icons"),
                SPAN("Esqueci a senha"),
                _class="option-label-menu"
            ),
            _id="cmp-bar-usermenu-option-request-password",
            _class='cmp-bar-usermenu-option link'
        ),
        _class="cmp-bar-usermenu-container"),
    _class="cmp-bar-user_and_menu-container"
)
