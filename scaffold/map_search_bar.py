# -*- coding: utf-8 -*-

from phanterweb.helpers import (
    DIV,
    P,

)

from phanterweb.materialize import (
    MaterializeSearchBar
)

search_bar = MaterializeSearchBar("§table_name§")
search_bar.showSelect()

html = DIV(
    DIV(
        P(_id="phantertables-title-flow-§table_name§", _class="flow-text phantertables-title-flow"),
        search_bar,
        _class="phantertables-head-container"),
    DIV("§phantertable_table§",
        _id="phantertable-table-container-§table_name§",
        _class="phantertable-table-container"),
    _id='phantertable-tables-and-searchbar-§table_name§',
    _class='phantertable-tables-and-searchbar')
