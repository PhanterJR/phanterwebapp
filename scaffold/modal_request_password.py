# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    H3,
    FORM,
    I
)
from phanterweb.materialize import (
    MaterializeInputText,
    MaterializePreloaderCircle,
    MaterializeInputHidden,
    MaterializeButtonForm
)

html = DIV(
    DIV(
        DIV(
            I("close", _class="material-icons"),
            _class='fechar_modal_layout'),
        H3("Recuperar Senha", _class="titulo-user-form"),
        DIV(
            DIV(
                DIV(
                    FORM(
                        MaterializeInputHidden(
                            "csrf_token",
                            "csrf token",
                            default="",
                            error="",
                            _phanterwebformvalidator_isnotempty="",
                            _phanterwebformvalidator_group="request-password"),
                        DIV(
                            MaterializeInputText(
                                "email-request-password",
                                "Email",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_isemail="",
                                _phanterwebformvalidator_group="request-password",
                                _class="col s12"
                            ),
                            _class="row reset-css-row"
                        ),
                        DIV(
                            MaterializePreloaderCircle('profile-ajax', "big"),
                            _class='captcha-ajax-container',
                            _id="captcha-request-password-container"),
                        DIV(
                            DIV(
                                DIV(
                                    DIV(_class="phantergallery_progressbar-movement"),
                                    _class="phantergallery_progressbar"),
                                _id="progressbar-form-request-password",
                                _class="progressbar-form-modal"),
                            _class="progressbar-container-form-modal"),
                        DIV(
                            DIV(
                                MaterializeButtonForm(
                                    "request-password-ajax-button-submit",
                                    "Requisitar Nova Senha",
                                    _class="waves-effect waves-teal",
                                     _phanterwebformvalidator_submit="",
                                    _phanterwebformvalidator_group="request-password"
                                ),
                                MaterializeButtonForm(
                                    "request-password-ajax-button-login",
                                    "Login",
                                    _class="waves-effect waves-teal"
                                ),
                                MaterializeButtonForm(
                                    "request-password-ajax-button-registrar",
                                    "Criar Conta",
                                    _class="waves-effect waves-teal"
                                ),
                                _class='buttons-form-container'
                            ),
                            _class="input-field col s12"
                        ),
                        _action="",
                        _phanterwebformvalidator_group="request-password",
                        _id="form-request-password",
                        _class="form-request-password",
                        _enctype="multipart/form-data",
                        _method="pt",
                        _autocomplete="off"
                    ),
                    _class="col-12"
                ),
                _class="row"
            ),
            _class='request-password-container'
        ),
        _class="subcontainer-request-password"
    ),
    _class="main-container-request-password"
)
