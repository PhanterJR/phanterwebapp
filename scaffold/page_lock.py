# -*- coding: utf-8 -*-

from . import app_version

from phanterweb.helpers import (
    DIV,
    IMG,
    H3,
    FORM,
    CONCATENATE,
    SCRIPT
)

from phanterweb.materialize import (
    MaterializeInputPassword,
    MaterializeInputCheckBox,
    MaterializeInputHidden,
    MaterializeButtonForm
)

html = CONCATENATE(
    DIV(
        DIV(
            H3("Desbloquear", _class="titulo-user-form"),
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
                                                _id="form-lock-image-user-url"
                                            ),
                                            _class="form-image-user-img"
                                        ),
                                        _class="form-image-user-img-container"
                                    ),
                                    DIV(
                                        DIV(
                                            "Nome Sobrenome",
                                            _id='form-lock-profile-user-name',
                                            _class="form-profile-user-name"
                                        ),
                                        DIV(
                                            "Usuário",
                                            _id='form-lock-profile-user-role',
                                            _class="form-profile-user-role"
                                        ),
                                        _class="form-profile-user-info"
                                    ),
                                    _class="form-profile-container"
                                ),
                                _id="form-lock-image-user-container",
                                _class="form-image-user-container"
                            ),
                            MaterializeInputHidden(
                                "csrf_token",
                                "csrf token",
                                id_input="form-lock-input-csrf",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_group="lock",
                            ),
                            MaterializeInputHidden(
                                "email",
                                "E-mail",
                                id_input="form-lock-input-email",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_isemail="",
                                _phanterwebformvalidator_group="lock",
                            ),
                            MaterializeInputPassword(
                                "password",
                                "Senha",
                                id_input="form-lock-input-password",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_group="lock",
                            ),
                            MaterializeInputCheckBox(
                                "remember_me",
                                "Mantenha-me conectado",
                                id_input="form-lock-input-remember_me"),
                            DIV(
                                DIV(
                                    DIV(
                                        DIV(
                                            _class="phantergallery_progressbar-movement"
                                        ),
                                        _class="phantergallery_progressbar"),
                                    _class="progressbar-form-modal"),
                                _class="progressbar-container-form-modal"),
                            DIV(
                                DIV(
                                    MaterializeButtonForm(
                                        "form-lock-button-unlock",
                                        "Desbloquear",
                                        _class="waves-effect waves-teal",
                                        _phanterwebformvalidator_submit="",
                                        _phanterwebformvalidator_group="lock"
                                    ),
                                    MaterializeButtonForm(
                                        "form-lock-button-outher-user",
                                        "Logar com outra conta",
                                        _class="waves-effect waves-teal"
                                    ),
                                    _class='buttons-form-container'
                                ),
                                _class="input-field col s12"
                            ),
                            _action="#",
                            _class="form-lock",
                            _id="form-lock-user",
                            _phanterwebformvalidator_group="lock",
                            _enctype="multipart/form-data",
                            _method="pt",
                            _autocomplete="off"
                        ),
                        _class="col s12"
                    ),
                    _class="row"
                ),
                _class='lock-container'
            ),
            _class="card"
        ),
        _class="container"
    ),
    SCRIPT(
        "phanterpages.lock();",
        _type="text/javascript"
    ),
)
