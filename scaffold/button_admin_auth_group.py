# -*- coding: utf-8 -*-

from phanterweb.fontawesome import (
    FontawesomeButtonLeftMenu,
    FontawesomeButtonLeftMenuPlus
)

from phanterweb.helpers import (
    CONCATENATE
)

html = CONCATENATE(
    FontawesomeButtonLeftMenu(
        "edit_admin_auth_group",
        "Edit Group",
        "fab fa-black-tie",
        _title="Adicionar editar fabricos",
        _class="link_href",
        _link_href="page_admin_auth_group"
    ),

    FontawesomeButtonLeftMenuPlus(
        "add_admin_auth_group",
        "New Group",
        "fab fa-black-tie",
        _title="Novo fabrico",
        _class="link_href",
        _link_href="page_admin_auth_group_form"
    )
)
