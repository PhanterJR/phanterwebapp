# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    H3,
    FORM,
    CONCATENATE,
    SCRIPTMINIFY
)
from phanterweb.materialize import (
    MaterializeInputPassword,
    MaterializeInputHidden,
    MaterializeButtonForm
)

html = CONCATENATE(
    H3(DIV("Mudar Senha", _class="phanterweb-container"), _class="titulo_maincontainer"),
    DIV(
        DIV(
            DIV(
                DIV(
                    DIV(
                        _id="aviso_change_password",
                        _class="simple-alerts"
                    ),
                    FORM(
                        MaterializeInputHidden(
                            "csrf_token",
                            "csrf token",
                            default="",
                            error="",
                            _phanterwebformvalidator_isnotempty="",
                            _phanterwebformvalidator_group="change-password",
                        ),
                        DIV(
                            MaterializeInputPassword(
                                "old_password",
                                "Senha Atual",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_group="change-password",
                                _class="col 12"
                            ),
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
                                _phanterwebformvalidator_group="change-password",
                                _class="col m6 s12"
                            ),
                            MaterializeInputPassword(
                                "password_repeat",
                                "Repetir Senha",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_isequals="password",
                                _phanterwebformvalidator_group="change-password",
                                _class="col m6 s12"
                            ),
                            _class="row reset-css-row"
                        ),
                        DIV(
                            DIV(
                                DIV(
                                    DIV(_class="phantergallery_progressbar-movement"),
                                    _class="phantergallery_progressbar"),
                                _class="progressbar-form-modal"),
                            _class="progressbar-container-form-modal"),
                        DIV(
                            DIV(
                                MaterializeButtonForm(
                                    "change-password-ajax-button-submit",
                                    "Mudar Senha",
                                    _class="waves-effect waves-teal",
                                    _phanterwebformvalidator_submit="",
                                    _phanterwebformvalidator_group="change-password"
                                ),
                                _class='buttons-form-container'
                            ),
                            _class="input-field col s12"
                        ),
                        _action="#",
                        _id="form-change-password",
                        _phanterwebformvalidator_group="change-password",
                        _class="form-change-password",
                        _enctype="multipart/form-data",
                        _method="pt",
                        _autocomplete="off"
                    ),
                    _class="phanterweb-card-container",
                ),
                _class="card"
            ),
            _class="new-container"
        ),
        _class="phanterweb-container"
    ),
    SCRIPTMINIFY(
        "phanterpages.changePassword();",
        _type="text/javascript"
    ),
)
