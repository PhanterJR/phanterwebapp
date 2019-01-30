# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    H3,
    FORM,
    I
)
from phanterweb.materialize import (
    MaterializeInputText,
    MaterializeInputPassword,
    MaterializePreloaderCircle,
    MaterializeInputHidden,
    MaterializeButtonForm
)

html = DIV(
    DIV(
        DIV(
            I("close", _class="material-icons"),
            _class='fechar_modal_layout'),
        H3("Criar nova conta", _class="titulo-user-form"),
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
                            _phanterwebformvalidator_group="register",
                        ),
                        DIV(
                            MaterializeInputText(
                                "first_name",
                                "Nome",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_group="register",
                                _class="col s12 m6"),
                            MaterializeInputText(
                                "last_name",
                                "Sobrenome",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_group="register",
                                _class="col s12 m6"),
                            _class="row reset-css-row"
                        ),
                        DIV(
                            MaterializeInputText(
                                "email",
                                "Email",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_isemail="",
                                _phanterwebformvalidator_group="register",
                                _class="col s12"),
                            _class="row reset-css-row"
                        ),
                        DIV(
                            MaterializeInputPassword(
                                "password",
                                "Senha",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_isequals="password_repeat",
                                _phanterwebformvalidator_group="register",
                                _class="col s12 m6"),
                            MaterializeInputPassword(
                                "password_repeat",
                                "Repetir Senha",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_isequals="password",
                                _phanterwebformvalidator_group="register",
                                _class="col s12 m6"),
                            _class="row reset-css-row"
                        ),
                        DIV(
                            MaterializePreloaderCircle('profile-ajax', "big"),
                            _class='captcha-ajax-container',
                            _id="captcha-register-container"),
                        DIV(
                            DIV(
                                DIV(
                                    DIV(_class="phantergallery_progressbar-movement"),
                                    _class="phantergallery_progressbar"),
                                _id="progressbar-form-register",
                                _class="progressbar-form-modal"),
                            _class="progressbar-container-form-modal"),
                        DIV(
                            DIV(
                                MaterializeButtonForm(
                                    "register-ajax-button-submit",
                                    "Cadastrar",
                                    _phanterwebformvalidator_group="register",
                                    _phanterwebformvalidator_submit="",
                                    _class="waves-effect waves-teal"
                                ),
                                MaterializeButtonForm(
                                    "register-ajax-button-login",
                                    "Login",
                                    _class="waves-effect waves-teal"
                                ),
                                MaterializeButtonForm(
                                    "register-ajax-button-esqueci-minha-senha",
                                    "Recuperar Senha",
                                    _class="waves-effect waves-teal"
                                ),
                                _class='buttons-form-container'
                            ),
                            _class="input-field col s12"
                        ),
                        _action="#",
                        _id="form-register",
                        _class="form-register",
                        _phanterwebformvalidator_group="register",
                        _enctype="multipart/form-data",
                        _method="post",
                        _autocomplete="off"
                    ),
                    _class="col-12"
                ),
                _class="row"
            ),
            _class='register-container'
        ),
        _class="subcontainer-register"
    ),
    _class="main-container-register"
)
