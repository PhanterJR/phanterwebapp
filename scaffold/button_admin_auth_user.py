# -*- coding: utf-8 -*-

from phanterweb.materialize import (
    MaterializeButtonLeftMenu
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
    )
)
