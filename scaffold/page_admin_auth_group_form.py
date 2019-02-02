# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    H3,
    FORM,
    CONCATENATE,
    SCRIPTMINIFY
)

from phanterweb.materialize import (
    MaterializeInputText,
    MaterializeInputHidden,
    MaterializeButtonForm
)

html = CONCATENATE(
    H3(DIV("Auth Group", _class="phanterweb-container"), _class="titulo_maincontainer"),
    DIV(
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
                            _phanterwebformvalidator_group="groups",
                        ),
                        DIV(
                            MaterializeInputText(
                                "role",
                                "Papel",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_group="groups",
                                _class="col s12 m6"
                            ),
                            MaterializeInputText(
                                "description",
                                "Descrição",
                                default="",
                                error="",
                                _phanterwebformvalidator_isnotempty="",
                                _phanterwebformvalidator_group="groups",
                                _class="col s12 m6"
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
                                    "groups-ajax-button-save",
                                    "Salvar Mudanças",
                                    _class="waves-effect waves-teal",
                                    _phanterwebformvalidator_submit="",
                                    _phanterwebformvalidator_group="groups"
                                ),
                                _class='buttons-form-container'
                            ),
                            _class="input-field col s12"
                        ),
                        _action="#",
                        _id="form-groups",
                        _class="form-groups row",
                        _enctype="multipart/form-data",
                        _method="post",
                        _phanterwebformvalidator_group="groups",
                        _autocomplete="off"
                    ),
                    _class='groups-container phanterweb-card-container'
                ),
                _class="card"
            ),
            _class="new-container"
        ),
    _class="phanterweb-container"),
    SCRIPTMINIFY(
        "phanterwebpages.admin_auth_group_form();",
        _type="text/javascript"
    ),
)
