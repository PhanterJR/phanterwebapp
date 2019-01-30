# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV
)

from phanterweb.phantergallery import (
    PhanterGalleryInput
)

html = DIV(
    PhanterGalleryInput(
        cut_size=(256, 256),
        global_id='profile',
        zindex=2000
    ),
    _class="phantergallery-image-user-container"
)
