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
        P(_id="phanterwebtables-title-flow-§table_name§", _class="flow-text phanterwebtables-title-flow"),
        search_bar,
        _class="phanterwebtables-head-container"),
    DIV("§phanterwebtable_table§",
        _id="phanterwebtable-table-container-§table_name§",
        _class="phanterwebtable-table-container"),
    _id='phanterwebtable-tables-and-searchbar-§table_name§',
    _class='phanterwebtable-tables-and-searchbar')
