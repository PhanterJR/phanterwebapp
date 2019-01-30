# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    H3,
    FORM,
    CONCATENATE,
    SCRIPTMINIFY
)

from phanterweb.phantergallery import (
    PhanterGalleryInput)

from phanterweb.materialize import (
    MaterializeInputText,
    MaterializeInputHidden,
    MaterializeButtonForm,
    MaterializeInputCheckBox,
    MaterializeChips,
)
INPUT_PASSWORD_HASH = MaterializeInputText(
    "password_hash",
    "Password Hash",
    default="",
    error="",
    _phanterwebformvalidator_group="auth_user",
    _class="col s12 m12")

INPUT_PASSWORD_HASH.disable()

TEMPORARY_PASSWORD = MaterializeInputText(
    "temporary_password",
    "Senha temporária",
    default="",
    error="",
    _phanterwebformvalidator_group="auth_user",
    _class="col s12 m12")

TEMPORARY_PASSWORD.disable()

TEMPORARY_PASSWORD_HASH = MaterializeInputText(
    "temporary_password_hash",
    "Hash senha temporária",
    default="",
    error="",
    _phanterwebformvalidator_group="auth_user",
    _class="col s12 m12")

TEMPORARY_PASSWORD_HASH.disable()

TEMPORARY_PASSWORD_EXPIRE = MaterializeInputText(
    "temporary_password_expire",
    "Expiração da senha temporária",
    default="",
    error="",
    _phanterwebformvalidator_group="auth_user",
    _class="col s12 m6")



ACTIVATE_HASH = MaterializeInputText(
    "activate_hash",
    "Hash código de ativação",
    default="",
    error="",
    _phanterwebformvalidator_group="auth_user",
    _class="col s12 m12")

ACTIVATE_HASH.disable()

RETRIEVE_HASH = MaterializeInputText(
    "retrieve_hash",
    "Hash senha temporária",
    default="",
    error="",
    _phanterwebformvalidator_group="auth_user",
    _class="col s12 m12")

RETRIEVE_HASH.disable()

REST_KEY = MaterializeInputText(
    "rest_key",
    "Chave token",
    default="",
    error="",
    _phanterwebformvalidator_group="auth_user",
    _class="col s12 m12")

REST_KEY.disable()

REST_TOKEN = MaterializeInputText(
    "rest_token",
    "Token",
    default="",
    error="",
    _phanterwebformvalidator_group="auth_user",
    _class="col s12 m7")

REST_TOKEN.disable()


html = CONCATENATE(
    H3(DIV("User", _class="phanterweb-container"), _class="titulo_maincontainer"),
    DIV(
        DIV(
            DIV(
                DIV(
                    FORM(
                        DIV(
                            DIV(
                                DIV(
                                    PhanterGalleryInput(
                                        cut_size=(256, 256),
                                        global_id='auth_user',
                                        zindex=2000
                                    ).just_buttom,
                                    _class="phantergallery-image-auth_user-container"),
                                _id="auth_user-image-user-container",
                                _class='row'
                            ),
                            _class="col s12 m12 l4"
                        ),
                        DIV(
                            MaterializeInputHidden(
                                "csrf_token",
                                "csrf token",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_group="auth_user",
                            ),
                            DIV(
                                MaterializeInputText(
                                    "first_name",
                                    "Nome",
                                    default="",
                                    error="",
                                    _phanterwebformvalidator_isnotempty="",
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12 m6"
                                ),
                                MaterializeInputText(
                                    "last_name",
                                    "Sobrenome",
                                    default="",
                                    error="",
                                    _phanterwebformvalidator_isnotempty="",
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12 m6"
                                ),
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
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12"
                                ),
                                _class="row reset-css-row"
                            ),
                            DIV(
                                MaterializeInputCheckBox(
                                    "remember_me",
                                    "Manter-se conectado",
                                    _class="col s12 m6"
                                ),
                                MaterializeInputCheckBox(
                                    "permit_double_login",
                                    "Permitir Múltiplos Logins",
                                    _class="col s12 m6"
                                ),
                                _class="row reset-css-row row-auth_user-checkboxs"
                            ),
                            DIV(
                                INPUT_PASSWORD_HASH,

                                _class="row reset-css-row"
                            ),
                            _class="col s12 m12 l8"
                        ),
                        DIV(
                            MaterializeChips(
                                "chips-groups-auth_user",
                                "Grupos do Usuário",
                                default="",
                                error="",
                                _id="chips_auth_user",
                                _phanterwebformvalidator_group="auth_user",
                            ),
                            _class='inputs-adicionais-auth_user',
                            _id="inputs-adicionais-auth_user1"
                        ),
                        DIV(
                            DIV(
                                MaterializeInputText(
                                    "attempts_to_login",
                                    "Tentativas para login",
                                    default="",
                                    error="",
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12 m6"
                                ),
                                MaterializeInputText(
                                    "datetime_next_attempt_to_login",
                                    "Datahora da próxima tentativa",
                                    default="",
                                    error="",
                                    _phanterwebformvalidator_canisequals="__/__/____ __:__:__",
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12 m6"
                                ),
                                _class="row reset-css-row"
                            ),
                            DIV(
                                TEMPORARY_PASSWORD,
                                _class="row reset-css-row"
                            ),
                            DIV(
                                TEMPORARY_PASSWORD_HASH,

                                _class="row reset-css-row"
                            ),

                            # DIV(
                            #     ACTIVATE_HASH,
                            #     _class="row reset-css-row"
                            # ),
                            DIV(
                                TEMPORARY_PASSWORD_EXPIRE,
                                MaterializeInputText(
                                    "activate_code",
                                    "Código de ativação",
                                    default="",
                                    error="",
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12 m6"
                                ),
                                _class="row reset-css-row"
                            ),
                            DIV(
                                MaterializeInputText(
                                    "attempts_to_activate",
                                    "Tentativas de ativação",
                                    default="",
                                    error="",
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12 m6"
                                ),
                                MaterializeInputText(
                                    "activate_date_expire",
                                    "Expiração do código de ativação",
                                    default="",
                                    error="",
                                    _phanterwebformvalidator_canisequals="__/__/____ __:__:__",
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12 m6"
                                ),
                                _class="row reset-css-row"
                            ),
                            DIV(
                                RETRIEVE_HASH,

                                _class="row reset-css-row"
                            ),



                            DIV(
                                REST_KEY,

                                _class="row reset-css-row"
                            ),
                            DIV(
                                REST_TOKEN,
                                MaterializeInputText(
                                    "rest_date",
                                    "Data do token",
                                    default="",
                                    error="",
                                    _phanterwebformvalidator_group="auth_user",
                                    _class="col s12 m5"
                                ),
                                # MaterializeInputText(
                                #     "rest_expire",
                                #     "Datahora expiração do token",
                                #     default="",
                                #     error="",
                                #     _phanterwebformvalidator_isnotempty="",
                                #     _phanterwebformvalidator_isemail="",
                                #     _phanterwebformvalidator_group="auth_user",
                                #     _class="col s12 m6"
                                # ),
                                _class="row reset-css-row"
                            ),
                            DIV(
                                MaterializeInputCheckBox(
                                    "activated",
                                    "Conta ativada",
                                    _class="col s12"
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
                                        "auth_user-ajax-button-save",
                                        "Salvar Mudanças",
                                        _class="waves-effect waves-teal",
                                        _phanterwebformvalidator_submit="",
                                        _phanterwebformvalidator_group="auth_user"
                                    ),
                                    _class='buttons-form-container'
                                ),
                                _class="input-field col s12"
                            ),
                            _class="col s12 m12 l12"
                        ),
                        _action="#",
                        _id="form-auth_user",
                        _class="form-auth_user row",
                        _enctype="multipart/form-data",
                        _method="post",
                        _phanterwebformvalidator_group="auth_user",
                        _autocomplete="off"
                    ),
                    _class='auth_user-container phanterweb-card-container'
                ),
                _class="card"
            ),
            _class="new-container"
        ),
    _class="phanterweb-container"),
    PhanterGalleryInput(
        cut_size=(256, 256),
        global_id='auth_user',
        zindex=2005
    ).just_cutter_panel,
    SCRIPTMINIFY(
        "phanterpages.admin_auth_user_form();",
        _type="text/javascript"
    ),
)
