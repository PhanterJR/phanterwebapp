# -*- coding: utf-8 -*-
from . import app_version, app_name
from phanterweb.helpers import (
    DIV,
    A,
    CONCATENATE,
    I,
    HTML,
    HEAD,
    BODY,
    META,
    LINK,
    TITLE,
    NAV,
    UL,
    LI,
    MAIN,
    FOOTER,
)

from ..views.extend_left_bar import html as MENU_PRINCIPAL_LEFT_BAR
from ..views.extend_svg_logo import html as SVG_LOGO
from ..views.extend_javascript_head import html as JAVASCRIPT_HEAD
from ..views.extend_css_head import html as CSS_HEAD
from ..views.extend_javascript_footer import html as JAVASCRIPT_FOOTER
from .component_preloader_circle_small import html as LOAD_SMALL
from .component_preloader_circle_big import html as LOAD_BIG

FAVICONS = CONCATENATE(
    LINK(
        _rel="apple-touch-icon",
        _sizes="180x180",
        _href="/static-versioned/%s/favicons/apple-touch-icon.png" %
        (app_version)
    ),
    LINK(
        _rel="icon",
        _type="image/png",
        _sizes="32x32",
        _href="/static-versioned/%s/favicons/favicon-32x32.png" %
        (app_version)
    ),
    LINK(
        _rel="icon",
        _type="image/png",
        _sizes="16x16",
        _href="/static-versioned/%s/favicons/favicon-16x16.png" %
        (app_version)
    ),
    LINK(
        _rel="manifest",
        _href="/static-versioned/%s/favicons/manifest.json" %
        (app_version)
    ),
    LINK(
        _rel="mask-icon",
        _href="/static-versioned/%s/favicons/safari-pinned-tab.svg" %
        (app_version),
        _color="#5bbad5"
    )
)

html = HTML(
    HEAD(
        META(_charset="utf-8"),
        META(
            _name="viewport",
            _content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"
        ),
        TITLE(app_name),
        META(_name="aplication-name", _content="Flask, Nginx, Cordova"),
        META(_name="aplication-version", _content=app_version),
        META(_name="msapplication-tap-highlight", _content="no"),
        CSS_HEAD,
        JAVASCRIPT_HEAD,
        FAVICONS
    ),
    BODY(
        DIV(_id="alert-top"),
        NAV(
            DIV(
                DIV(
                    DIV(
                        I(
                            "menu",
                            _class="large material-icons"
                        ),
                        _id="menu-button-main-page",
                        _class="main-menu-layout"),
                    _class='link'),
                DIV(
                    DIV(
                        SVG_LOGO,
                        _class="logo-empresa-svg"
                    ),
                    _class="brand-logo link",
                    _onclick="phanterpages.principal();"
                ),
                UL(
                    LI(
                        DIV(
                            DIV(
                                LOAD_SMALL,
                                _class="cmp-bar-user_and_menu-container",
                                _style="text-align:center; margin-top:7px;"
                            ),
                            _id="echo-user-cmp-login"
                        )
                    ),
                    _id="nav-mobile",
                    _class="right hide-on-med-and-down"
                ),
                _class="nav-wrapper"
            ),
            _class="grey darken-4 main-nav"
        ),
        DIV(
            DIV(
                DIV(
                    DIV(
                        DIV(
                            DIV(
                                LOAD_SMALL,
                                _id="materialize-component-left-menu-user"),
                            _id="echo-user-cmp-login-menu"),
                        _id="options-top-main-bar-left"),
                    DIV(
                        MENU_PRINCIPAL_LEFT_BAR,
                        _id="options-middle-main-bar-left"),
                    DIV(
                        _id="options-bottom-main-bar-left"),
                    _id="left-bar",
                    _class="left-bar"),
                _class="left-bar-container"),
            MAIN(
                DIV(
                    LOAD_BIG,
                    _style="width:100%;text-align: center;padding-top: 100px;"
                ),
                _id="main-container"
            ),
            _class="main-and-left-bar"
        ),
        DIV(
            _id="modal_layout",
            _class="modal"),
        FOOTER(
            DIV(
                DIV(
                    DIV(
                        DIV(_class="phantergallery_progressbar-movement"),
                        _class="phantergallery_progressbar"
                    ),
                    _class="main-progress-bar enabled"
                ),
                _class="main-progress-bar-container"
            ),
            DIV(
                DIV(_class="row"),
                _class='container'
            ),
            DIV(
                DIV(
                    "Conexão Didata © 2011-2018",
                    A(
                        "PhanterJR",
                        _class="grey-text text-lighten-4 right",
                        _href="#!"
                    ),
                    _class="container"
                ),
                _class="footer-copyright grey darken-3"
            ),
            _class="page-footer main-footer grey darken-4"
        ),
        JAVASCRIPT_FOOTER,
    ),
    _lang="pt-BR"
)
