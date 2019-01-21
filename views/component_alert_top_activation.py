# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    FORM
)

from phanterweb.materialize import (
    MaterializeInputText,
    MaterializeButtonForm
)

html = DIV(
    DIV(
        "Sua conta ainda não foi ativada, ao criá-la,",
        " foi enviado um email com o código de ativação. ",
        "Check seu email e adicione o código no campo abaixo.",
        _class="alerta-top-ajax-activation-text"
    ),
    FORM(
        DIV(
            DIV(
                MaterializeInputText(
                    "code_activation",
                    "Digite aqui seu código de ativação",
                    default="",
                    _phanterwebformvalidator_isnotempty="",
                    _phanterwebformvalidator_isactivationcode="",
                    _phanterwebformvalidator_group="alert-top",
                    error="", _class=""
                ),
                _class="alerta-top-ajax-activation-action-input"
            ),
            DIV(
                DIV(
                    MaterializeButtonForm(
                        "alert-top-activate",
                        "Ativar",
                        _title="Ativar Conta",
                        _class="waves-effect waves-teal btn-small",
                        _phanterwebformvalidator_submit="",
                        _phanterwebformvalidator_group="alert-top"),
                    _class="alerta-top-ajax-activation-action-activate"
                ),
                DIV(
                    MaterializeButtonForm(
                        "alert-top-new-code",
                        "Solicitar Código",
                        _title="Solicitar um novo código",
                        _class="waves-effect waves-teal btn-small"
                    ),
                    _class="alerta-top-ajax-activation-action-send"
                ),
                _class='alerta-top-ajax-activation-phone-center'
            ),
            _class="alerta-top-ajax-activation-actions-activate"
        ),
        _id="alert-top-activation",
        _phanterwebformvalidator_group="alert-top",
        _class="alerta-top-ajax-activation-actions-container"
    ),
    _class="alerta-top-ajax-activation-container"
)