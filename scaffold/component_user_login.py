# -*- coding: utf-8 -*-

from . import app_version

from phanterweb.helpers import (
    DIV,
    IMG,
    I,
    SPAN
)

html = DIV(
    DIV(
        DIV(
            DIV(
                DIV(
                    IMG(
                        _id="url_image_user",
                        _src="/static-versioned/%s/images/user.png" %
                        (app_version),
                        _alt='user avatar'
                    ),
                    _class='cmp-bar-user-img'),
                _class='cmp-bar-user-img-container'),
            DIV(
                DIV(
                    DIV(_id="user_first_and_last_name_login", _class='cmp-bar-user-name'),
                    DIV(_id="user_role_login", _class='cmp-bar-user-role'),
                    _class='cmp-bar-user-name-role'),
                _class='cmp-bar-user-name-role-container'),
            DIV(
                DIV(
                    I("expand_less", _class="material-icons cmd-bar-user-expand-icon less"),
                    I("expand_more", _class="material-icons cmd-bar-user-expand-icon more"),
                    _class="cmd-bar-user-expands"),
                _class="cmd-bar-user-expand-container"),
            _class="cmp-bar-user-info-container"),
        _id="toggle-cmp-bar-user",
        _class="cmp-bar-user-container black link waves-effect waves-teal"),
    DIV(
        DIV(
            DIV(
                I("face", _class="material-icons"),
                SPAN("Perfil"),
                _class="option-label-menu"
            ),
            _id="cmp-bar-usermenu-option-profile",
            _class='cmp-bar-usermenu-option link',
            _link_href="page_profile"
        ),
        DIV(
            DIV(
                I("https", _class="material-icons"),
                SPAN("Bloquear"),
                _class="option-label-menu"
            ),
            _id="cmp-bar-usermenu-option-lock",
            _class='cmp-bar-usermenu-option link',
            _link_href="page_lock"
        ),
        DIV(
            DIV(
                I("power_settings_new", _class="material-icons"),
                SPAN("Sair"),
                _class="option-label-menu"),
            _id="cmp-bar-usermenu-option-logout",
            _class='cmp-bar-usermenu-option link'
        ),
        _class="cmp-bar-usermenu-container"),
    _class="cmp-bar-user_and_menu-container"
)
