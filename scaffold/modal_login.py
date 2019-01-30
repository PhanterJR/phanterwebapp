# -*- coding: utf-8 -*-

from . import app_version

from phanterweb.helpers import (
    DIV,
    IMG,
    I,
    H3,
    FORM
)

from phanterweb.materialize import (
    MaterializeInputText,
    MaterializeInputPassword,
    MaterializeInputHidden,
    MaterializeButtonForm,
    MaterializeInputCheckBox,
    MaterializePreloaderCircle
)

attr_input_email = {
    "_id": "form-login-input-email-hidden-switch",
    "_phanterwebformvalidator_isnotempty": "",
    "_phanterwebformvalidator_isemail": "",
    "_phanterwebformvalidator_group": "login",
}
input_email = MaterializeInputText(
    "email",
    "E-mail",
    id_input="form-login-input-email",
    default="",
    error="",
    **attr_input_email
)

html = DIV(
    DIV(
        DIV(
            I("close", _class="material-icons"),
            _class='fechar_modal_layout'),
        H3(DIV("Login", _id="form-login-input-tittle-hidden-switch"),
            _class="titulo-user-form"),
        DIV(
            DIV(
                DIV(
                    FORM(
                        DIV(
                            DIV(
                                DIV(
                                    DIV(
                                        IMG(
                                            _src="/static-versioned/%s/images/user.png" %
                                            (app_version),
                                            _id="form-login-image-user-url"),
                                        _class="form-image-user-img"),
                                    _class="form-image-user-img-container"),
                                DIV(
                                    DIV("Nome Sobrenome",
                                        _id='form-login-profile-user-name',
                                        _class="form-profile-user-name"),
                                    DIV("Usuário",
                                        _id='form-login-profile-user-role',
                                        _class="form-profile-user-role"),
                                    _class="form-profile-user-info"),
                                _class="form-profile-container"),
                            _id="form-login-image-user-container",
                            _class="form-image-user-container",
                            _style="display:none;"),
                        DIV(
                            DIV(
                                MaterializeButtonForm(
                                    "form-login-button-other-user",
                                    "Usar outra conta",
                                    _class="waves-effect waves-teal btn-small"
                                ),
                                _class='buttons-form-container'),
                            _id="form-login-button-other-user-container",
                            _class="input-field col s12",
                            _style="display:none;"),
                        MaterializeInputHidden(
                            "csrf_token",
                            "csrf token",
                            id_input="form-login-input-csrf_token",
                            default="",
                            error="",
                            _phanterwebformvalidator_isnotempty="",
                            _phanterwebformvalidator_group="login",
                        ),
                        input_email,
                        MaterializeInputPassword(
                            "password",
                            "Senha",
                            id_input="form-login-input-password",
                            default="",
                            error="",
                            _phanterwebformvalidator_isnotempty="",
                            _phanterwebformvalidator_group="login",
                        ),
                        MaterializeInputCheckBox(
                            "remember_me",
                            "Mantenha-me conectado",
                            id_input="form-login-input-remember_me"
                        ),
                        DIV(
                            MaterializePreloaderCircle('profile-ajax', "big"),
                            _class='captcha-ajax-container', _id="captcha-login-container"),
                        DIV(
                            DIV(
                                DIV(
                                    DIV(_class="phantergallery_progressbar-movement"),
                                    _class="phantergallery_progressbar"),
                                _class="progressbar-form-modal",
                                _id="progressbar-form-user"),
                            _class="progressbar-container-form-modal"),
                        DIV(
                            DIV(
                                MaterializeButtonForm(
                                    "form-login-button-login",
                                    "Login",
                                    _class="waves-effect waves-teal",
                                    _phanterwebformvalidator_submit="",
                                    _phanterwebformvalidator_group="login"
                                ),
                                MaterializeButtonForm(
                                    "form-login-button-register",
                                    "Criar Conta",
                                    _class="waves-effect waves-teal"
                                ),
                                MaterializeButtonForm(
                                    "form-login-button-request-password",
                                    "Recuperar Senha",
                                    _class="waves-effect waves-teal"
                                ),
                                _class='buttons-form-container'
                            ),
                            _class="input-field col s12"
                        ),
                        _action="#",
                        _class="form-login",
                        _id="form-login-user",
                        _enctype="multipart/form-data",
                        _phanterwebformvalidator_group="login",
                        _method="post",
                        _autocomplete="off"
                    ),
                    _class="col s12"
                ),
                _class="row"
            ),
            _class='login-container'
        ),
        _class="subcontainer-login"
    ),
    _class="main-container-login"
)
