# -*- coding: utf-8 -*-

from phanterweb.materialize import (
    MaterializeButtonLeftMenu,
    MaterializeButtonLeftMenuPlus
)

from phanterweb.helpers import (
    CONCATENATE
)

html = CONCATENATE(
    MaterializeButtonLeftMenu(
        "edit_admin_auth_user",
        "Auth Users",
        "local_library",
        _class="link_href",
        _link_href="page_admin_auth_user"
    ),
    MaterializeButtonLeftMenuPlus(
        "add_admin_auth_user",
        "New User",
        "local_library",
        _class="link_href",
        _link_href="page_admin_auth_user_form"
    )
)
