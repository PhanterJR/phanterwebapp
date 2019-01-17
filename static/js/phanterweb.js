//global vars
var remoteHostAddress = phanterwebCacheDataJS.application.remote_host_address
var application_debug = phanterwebCacheDataJS.application.debug;
var application_version = phanterwebCacheDataJS.application.version
var application_name = phanterwebCacheDataJS.application.name


function verifyAppInDebug(){
    var xhttp;
    xhttp = new XMLHttpRequest();
    xhttp.onload = function(){
        var response = JSON.parse(this.response)
        if(isNotEmpty(response.application.debug)){
            application_debug = response.application.debug;
        }
    };
    xhttp.open("GET", remoteHostAddress+"/api/server", true);
    xhttp.send();
}

verifyAppInDebug();
function _print(texto, titulo, stack){
    var titulo = (typeof titulo !== 'undefined') ? titulo : false;
    var stack = (typeof stack !== 'undefined') ? stack : false;
    if(application_debug){
        if(stack){
            var stack = new Error()
            console.info(stack.stack)
            if (titulo){
                console.log(titulo)
            }  
        } else {
            if (titulo){
                console.info(titulo)
            }  
        }
        console.log(texto)
    }
}

_print(remoteHostAddress, "Endereço Remoto:")

var modal_layout = $("#modal_layout")

//functions helpers
function isNotEmpty(value){
    if((value!==null)&&(value!="")&&(value!==undefined)){
        return true
    } else {
        return false
    }   
}
function enabled_switch(select_jquery){
    if (select_jquery.hasClass("enabled")){
        select_jquery.removeClass("enabled");
    } else {
        select_jquery.addClass("enabled");
    }
};
var stringFilter = function(value, you_want_array = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]){
    var value = new String(value)
    var perm_values = you_want_array
    var new_value = ""
    for (var x = 0; x < value.length; x++) {
        var num = value[x]
        if (perm_values.indexOf(num)>=0){
            new_value+=num
        }
    }
    return new_value
};
var hasCaracter = function(value, caracter="."){
    var value = new String(value)
    var has_caractere = false;
    for (var i = 0; i < value.length; i++) {
        if(caracter==value[i]){
            has_caractere=true;
        }
    }
    return has_caractere
}
var stringForceToFloatstring = function (value, force_dot=false, localeBR=true){
    var value = new String(value);
    if(isNotEmpty(value)){
        if(localeBR){
            value = value.replace(",",".");
        }
        value = stringFilter(value, ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "."]);
        value = justSearchedCaracter(value);
        if(value!=""){
            if(value=="."){
                if (force_dot){
                    value="0."  
                } else{
                    value=""
                }
            } else {
                if (!force_dot){
                    value = new String(parseFloat(value));
                }
            }
        }
        return value
    }else{
        return ""
    }
};

var justSearchedCaracter = function(value, caractere="."){
    var has_caractere = false;
    var value = new String(value)
    var new_value = "";
    for (var i = 0; i < value.length; i++) {
        if(value[i]==caractere){
            if(!has_caractere){
                new_value+=value[i]
                has_caractere=true;
            }
        } else {
            new_value+=value[i]
        }
    }
    return new_value
};

var stringToFloatstringLimitDecimals = function (value, casas_decimais=2, localeBR=true){
    var value = new String(value);
    if(isNotEmpty(value)){
        if(localeBR){
            value = value.replace(",",".");
        }
        value = stringFilter(value, ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "."]);
        value = justSearchedCaracter(value);
        if(value!=""){
            value = new String(parseFloat(value));
            var p_inteiro = value.split(".")[0];
            var p_decimal = value.split(".")[1];
            if (!isNotEmpty(p_decimal)){
                p_decimal="0"
            }
            if (p_decimal.length<casas_decimais){
                var np_decimal = "";
                for (var i = 0; i < (casas_decimais-p_decimal.length); i++) {
                    np_decimal+="0"
                }
                p_decimal = p_decimal+np_decimal
            } else {
                var np_decimal = "";
                for (var i = 0; i < casas_decimais; i++) {
                    np_decimal+=p_decimal[i]
                }
                p_decimal = np_decimal
            }       
            return p_inteiro.concat("."+p_decimal)
        }
        return value
    }else{
        return ""
    }
};

var floatToCurrency = function(value, casas_decimais=2, separador_decimal=",", separador_milhar=".", currency=""){
    var casas_decimais = casas_decimais;
    var separador_decimal = separador_decimal;
    var separador_milhar = separador_milhar;
    var value = new String(value);
    var p_m_inteiro = "0";
    var p_m_decimal = "";
    for (var i = 0; i < casas_decimais; i++) {
        p_m_decimal+="0";
    };
    if(hasCaracter(value, ".")){
        let p_inteiro = value.split(".")[0];
        let p_decimal = value.split(".")[1];
        if(isNotEmpty(p_inteiro)){
            p_inteiro = p_inteiro.split("").reverse().join("");
            let str_inteiro="";
            let tamanho_inteiro = p_inteiro.length;
            adicionar_separador=false;
            if (tamanho_inteiro>3){
                for (let i = 0; i < tamanho_inteiro; i++) {
                    if (((i+1)%3)==0){
                        str_inteiro+=p_inteiro[i];
                        adicionar_separador=true;
                    } else {
                        if(adicionar_separador){
                            adicionar_separador=false;
                            str_inteiro+=separador_milhar+p_inteiro[i];
                        } else {
                            str_inteiro+=p_inteiro[i];
                        };
                    };
                };               
            } else {
                for (var i = 0; i < tamanho_inteiro; i++) {
                    str_inteiro+=p_inteiro[i]
                };
            };
            p_m_inteiro=str_inteiro.split("").reverse().join("");
        };

        if(isNotEmpty(p_decimal)){
            let str_cd = "";
            if (p_decimal.length>casas_decimais){
                for (var i = 0; i < casas_decimais; i++) {
                    str_cd+=p_decimal[i];
                };
            } else {
                for (var i = 0; i < p_decimal.length; i++) {
                    str_cd+=p_decimal[i];
                };
                var diferenca = casas_decimais-p_decimal.length;
                var tracos = "";
                for (var i = 0; i < diferenca; i++) {
                    tracos+="0";
                };
                str_cd+=tracos ;     
            };
            p_m_decimal=str_cd;
        }           
    } else {
        if(value!=""){
            let t_m_inteiro = parseInt(value);
            if(isNotEmpty(t_m_inteiro)){
                p_m_inteiro=new String(t_m_inteiro);
            }
        }
    }
    if(isNotEmpty(currency)){
        return currency+" "+p_m_inteiro+separador_decimal+p_m_decimal;
    } else {
        return p_m_inteiro+separador_decimal+p_m_decimal;
    }
};

function isEmail(email) {
    var regex = /^([a-zA-Z0-9_.+-])+\@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
};
function isCNPJ(cnpj){
    var regex = /^\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}$/
    return regex.test(cnpj)
}
function isCPF(cpf){
    var regex = /^\d{3}\.\d{3}\.\d{3}-\d{2}$/
    return regex.test(cpf)
}
function isCEP(cep){
    var regex = /^\d{2}\.\d{3}-\d{3}$/
    return regex.test(cep)
}
function isDATE(date){
    var regex = /^\d{2}\/\d{2}\/\d{4}$/
    if(regex.test(date)){
        var array_data = date.split("/")
        var dia = parseInt(array_data[0])
        var mes = parseInt(array_data[2])
        var ano = parseInt(array_data[3])
        if (dia<1){
            return false
        }
        if (mes==2){
            if ((ano % 4 === 0)){
                if(ano % 100 !== 0){
                    if(dia>29){
                        return false
                    }
                } else{
                    if(dia>28){
                        return false
                    } 
                }

            } else {
                if (ano % 400 !==0){
                    if(dia>28){
                        return false
                    } 
                } else {
                    if(dia>29){
                        return false
                    }   
                }
            }
        } else if(((mes==1)||(mes==3)||(mes==5)||(mes==7)||(mes==8)||(mes==10)||(mes==12))&&(dia>31)){
            return false
        } else if(((mes==4)||(mes==6)||(mes==9)||(mes==11))&&(dia>30)){
            return false
        } else{
            return true
        }
    }else {
        return false
    }
}
function isACTIVATIONCODE(code){
    var regex = /^\d{5}/
    return regex.test(code)
}
//phantermask
$.fn.phanterMask = function(mask, parameters) {
    var custom_mask = "";
    var casas_decimais = 2;
    var separador_decimal = ","
    var separador_milhar = "."
    var currency = "R$";
    var value = "";
    var apply_on_init = true;
    var date_format = "%d/%m/%Y";
    var datetime_format = "%d/%m/%Y %H:%M:%S"
    if(isNotEmpty(parameters)){
        if ("mask" in parameters){
            custom_mask=parameters.mask
        }
        if ("casas_decimais" in parameters){
            casas_decimais=parseInt(parameters.casas_decimais);
        }
        if("separador_decimal" in parameters){
            separador_decimal=new String(parameters.separador_decimal)
        }
        if("separador_milhar" in parameters){
            separador_milhar=new String(parameters.separador_milhar)
        }
        if("currency" in parameters){
            currency=new String(parameters.currency)
        }
        if("value" in parameters){
            $(this).val(parameters.value)
        }
        if("date_format" in parameters){
            date_format=parameters.date_format
        }
        if("datetime_format" in parameters){
            datetime_format=parameters.datetime_format
        }

    }
    var cursorPosition = 0;
    $(this).removeClass("masked_input")
    var just_numbers = function(value){
            var value = new String(value)
            var perm_values = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
            var new_value = ""
            for (var x = 0; x < value.length; x++) {
                var num = value[x]
                if (perm_values.indexOf(num)>=0){
                    new_value+=num
                }
            }
            return new_value
        };
    var phanterMaskFone = function(valor){
            var valor = new String(valor)
            var tamanho = valor.length;
            if (tamanho==10){
                custom_mask = "(##) ####-####";
            } else if (tamanho==11){
                custom_mask = "(##) # ####-####";
            } else if (tamanho>11){
                custom_mask = "(##) #####-#########";
            } else {
                custom_mask = "(##) # ####-####";
            }
            return phanterMaskCustom(valor)
        };
    var phanterMaskCNPJ = function(valor){
            custom_mask = "##.###.###/####-##"
            return phanterMaskCustom(valor)
        };
    var phanterMaskCPF = function(valor){
            custom_mask = "###.###.###-##";
            return phanterMaskCustom(valor)
        };
    var phanterMaskDate = function(valor){
            custom_mask = "##/##/####";
            return phanterMaskCustom(valor)
        };
    var phanterMaskDatetime = function(valor){
            custom_mask = "##/##/#### ##:##:##";
            return phanterMaskCustom(valor)
        };
    var phanterMaskCEP = function(valor){
            custom_mask = "##.###-###";
            return phanterMaskCustom(valor)
        };
    var phanterMaskCustom = function(valor){
            var valor = new String(valor)
            var tamanho = valor.length;
            var mascara = custom_mask;
            var char_plus = 0;
            var pos_num=0;
            var new_valor = "";
            var new_valor_ignore = "";
            var cont_int = 0;
            for (var i = 0; i < mascara.length; i++) {
                if (mascara[i]=="#"){
                    if (pos_num<tamanho){
                        new_valor+=valor[pos_num];
                        pos_num+=1;
                    } else {
                        new_valor+="_";
                        pos_num+=1;
                    }
                } else {
                    if(i<(tamanho+char_plus)){
                        char_plus+=1
                    }
    
                    new_valor+=mascara[i]
                }
            }
            cursorPosition=parseInt(tamanho)+char_plus
            return new_valor
        };
    var applyMask = function(selector, maskfunction, reverse=false){
        $(selector).each(function(){
            var element = $(this)
            var value = element.val();
            var new_value = maskfunction(just_numbers(value));
            if(apply_on_init){
                element.val(new_value);
                if(reverse){
                    element[0].selectionStart=-new_value.length;
                    element[0].selectionEnd=-new_value.length;                  
                } else {
                    element[0].selectionStart=cursorPosition;
                    element[0].selectionEnd=cursorPosition;                     
                }
            }
            element
                .off("keypress.phantermask")
                .on("keypress.phantermask", function(event){
                    var code = event.keyCode || event.which;
                    var value = element.val();
                    if(reverse){
                        if (just_numbers(value)!=""){
                            value = new String(parseInt(just_numbers(value)))
                        }
                    }
                    var new_value = "";
                    if(code == 8){
                        new_value = maskfunction(just_numbers(value).slice(0,-1));
                    } else if(code == 46&&event.key=="Delete"){

                        new_value = maskfunction(just_numbers(value).slice(1));
                    }else{
                        value = value + String.fromCharCode(code);
                        new_value = maskfunction(just_numbers(value));
                    }
                    element.val(new_value); 
                    if(reverse){
                        element[0].selectionStart=-new_value.length;
                        element[0].selectionEnd=-new_value.length;                  
                    } else {
                        element[0].selectionStart=cursorPosition;
                        element[0].selectionEnd=cursorPosition;                 
                    }
                    if(code!=9){
                        event.preventDefault();
                    }
                });
            
            element
                .off("focusout.phantermask")
                .on("focusout.phantermask", function(event){
                    var value = element.val();
                    var new_value = maskfunction(just_numbers(value));
                    element.val(new_value);
                })
                .off("paste.phantermask")
                .on("paste.phantermask", function(event){
                    setTimeout(function () {
                        var value = element.val();
                        var new_value = maskfunction(just_numbers(value));
                        element.val(new_value);
                     }, 100);
                })
                .off("focusin.phantermask")
                .on("focusin.phantermask", function(event){
                    var value = element.val();
                    var new_value = maskfunction(just_numbers(value));
                    element.val(new_value);
                    if(reverse){
                        element[0].selectionStart=-new_value.length;
                        element[0].selectionEnd=-new_value.length;                  
                    } else {
                        element[0].selectionStart=cursorPosition;
                        element[0].selectionEnd=cursorPosition;                     
                    }
                });
        });
        return $(selector);
    };

    var phanterCurrency = function(selector){
            return phanterDecimals(selector, currency=currency)
        }

    var phanterDecimals = function(selector, v_currency=""){
        selector.each(function(){
            var l_currency = "";
            if(v_currency!=""){
                l_currency = v_currency
            }
            var element = $(this);
            if(element.is('input')){
                var defaults = element.val();
            } else {
                var defaults = element.text();
            }
            var value = stringForceToFloatstring(defaults)
            element.attr("phantermaskTemp", value)
            value = stringToFloatstringLimitDecimals(value, casas_decimais)
            var new_value="";
            if (value==""){
                var qu_decs="";
                for (var i = 0; i < casas_decimais; i++) {
                    qu_decs+="0"
                }
                new_value = "0"+separador_decimal+qu_decs
                if(element.is('input')){
                    element.val(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                } else {
                    element.text(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                }
                element.attr("phantermaskValue", stringToFloatstringLimitDecimals(value, casas_decimais))
            } else{
                new_value = value.replace(".", separador_decimal)
                if(element.is('input')){
                    element.val(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                } else {
                    element.text(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                }
                element.attr("phantermaskValue", stringToFloatstringLimitDecimals(value, casas_decimais))
            }
            element[0].selectionStart=-new_value.length;
            element[0].selectionEnd=-new_value.length;  
            element
                .off('keypress.phantermask')
                .on('keypress.phantermask', function(event){
                    var code = event.keyCode || event.which;
                    var value = element.attr("phantermaskTemp");
                    key_value = String.fromCharCode(code)
                    if(code == 8){
                        if(hasCaracter(value, ".")){
                            value = stringToFloatstringLimitDecimals(value, casas_decimais)
                        }
                        value = just_numbers(value)
                        value = value.slice(0,-1);
                    } else if((code == 46)&&event.key=="Delete"){
                        value = just_numbers(value)
                        value = value.slice(1);
                    }else{
                        var contat_value = value.concat(key_value)
                        if (((key_value==separador_decimal)||(event.key==separador_decimal))&&(!hasCaracter(value, "."))){
                            value = stringForceToFloatstring(contat_value, true)
                        } else {
                            if (hasCaracter(value, ".")){
                                value = stringForceToFloatstring(contat_value, true)
                            } else {
                                value = stringForceToFloatstring(contat_value)
                            }
                        }
                    }
                    element.attr("phantermaskTemp", value)
                    if (!hasCaracter(value, ".")){
                        if(value.length>=casas_decimais){
                            let p_inteiro = value.slice(0,(-1)*casas_decimais);
                            if (!isNotEmpty(p_inteiro)){
                                p_inteiro = "0"
                            }
                            let p_decimal = value.slice((-1)*casas_decimais);
                            value = p_inteiro.concat("."+p_decimal)
                        } else{
                            let diferenca = casas_decimais-value.length
                            let add_decs = ""
                            for (var i = 0; i < diferenca; i++) {
                                add_decs+="0"
                            }

                            let p_inteiro = "0"
                            value = p_inteiro.concat("."+add_decs+value)
                        }
                    }
                    value = stringToFloatstringLimitDecimals(value, casas_decimais)
                    var new_value="";
                    if (value==""){
                        var qu_decs="";
                        for (var i = 0; i < casas_decimais; i++) {
                            qu_decs+="0"
                        }
                        new_value = "0"+separador_decimal+qu_decs
                        if(element.is('input')){
                            element.val(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        } else {
                            element.text(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        }
                        element.attr("phantermaskValue", stringToFloatstringLimitDecimals(new_value, casas_decimais))
                    } else{
                        new_value = value.replace(".", separador_decimal)
                        if(element.is('input')){
                            element.val(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        } else {
                            element.text(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        }
                        element.attr("phantermaskValue", stringToFloatstringLimitDecimals(new_value, casas_decimais))
                    }
                    element[0].selectionStart=-new_value.length;
                    element[0].selectionEnd=-new_value.length;
                    if(code!=9){
                        event.preventDefault();
                    }
                })
                .off('focusin.phantermask')
                .on('focusin.phantermask', function(){
                    var value = $(this).attr("phantermaskValue");
                    value = stringToFloatstringLimitDecimals(value, casas_decimais)
                    var new_value="";
                    if (value==""){
                        var qu_decs="";
                        for (var i = 0; i < casas_decimais; i++) {
                            qu_decs+="0"
                        }
                        new_value = "0"+separador_decimal+qu_decs
                        if(element.is('input')){
                            element.val(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        } else {
                            element.text(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        }
                        element.attr("phantermaskValue", stringToFloatstringLimitDecimals(value, casas_decimais))
                    } else{
                        new_value = value.replace(".", separador_decimal)
                        if(element.is('input')){
                            element.val(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        } else {
                            element.text(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        }
                        element.attr("phantermaskValue", stringToFloatstringLimitDecimals(value, casas_decimais))
                    }
                    element[0].selectionStart=-new_value.length;
                    element[0].selectionEnd=-new_value.length;  
                })
                .off("paste.phantermask")
                .on("paste.phantermask", function(event){
                    var othis = this;
                    setTimeout(function () {
                        $(othis).trigger("focusout");
                     }, 100);
                })
                .off('focusout.phantermask')
                .on('focusout.phantermask', function(){
                    var value = $(this).attr("phantermaskValue");
                    value = stringToFloatstringLimitDecimals(value, casas_decimais)
                    var new_value="";
                    if (value==""){
                        var qu_decs="";
                        for (var i = 0; i < casas_decimais; i++) {
                            qu_decs+="0"
                        }
                        new_value = "0"+separador_decimal+qu_decs
                        if(element.is('input')){
                            element.val(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        } else {
                            element.text(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        }
                        element.attr("phantermaskValue", stringToFloatstringLimitDecimals(value, casas_decimais))
                    } else{
                        new_value = value.replace(".", separador_decimal)
                        if(element.is('input')){
                            element.val(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        } else {
                            element.text(floatToCurrency(stringToFloatstringLimitDecimals(new_value, casas_decimais), casas_decimais, separador_decimal, separador_milhar, l_currency));
                        }
                        element.attr("phantermaskValue", stringToFloatstringLimitDecimals(value, casas_decimais))
                    }
                    element[0].selectionStart=-new_value.length;
                    element[0].selectionEnd=-new_value.length;         
                });
        });
        return $(selector)
    };
    if(mask=="fone"){
        $(this).addClass("masked_input")
        applyMask(this, phanterMaskFone)
    } else if(mask=="cnpj"){
        $(this).addClass("masked_input")
        applyMask(this, phanterMaskCNPJ)
    } else if(mask=="cpf"){
        $(this).addClass("masked_input")
        applyMask(this, phanterMaskCPF)
    } else if(mask=="date"){
        $(this)
            .off('click.phantermaskdata focusin.phantermaskdata')
            .on('click.phantermaskdata focusin.phantermaskdata', function(){
                var dateativa = $(this).attr("phanterwebdateanddatetime");
                if (dateativa === undefined) {
                    Calendar.setup({
                        inputField:this,
                        ifFormat: date_format,
                        showsTime:false,
                    });
                    $(this).attr("phanterwebdateanddatetime",1)
                }              
            });

        $(this).addClass("masked_input")
        applyMask(this, phanterMaskDate)
    } else if(mask=="datetime"){
        $(this)
            .off('click.phantermaskdatahora focusin.phantermaskdatahora')
            .on('click.phantermaskdatahora focusin.phantermaskdatahora', function(){
                var dateativa = $(this).attr("phanterwebdateanddatetime");
                if (dateativa === undefined) {
                    Calendar.setup({
                        inputField:this,
                        ifFormat: datetime_format,
                        showsTime:true,
                        timeFormat: '24'   
                    });
                    $(this).attr("phanterwebdateanddatetime",1)
                }              
            });
        $(this).addClass("masked_input")
        applyMask(this, phanterMaskDatetime)
    } else if(mask=="cep"){
        $(this).addClass("masked_input")
        applyMask(this, phanterMaskCEP)
    } else if(mask=="real"){
        $(this).addClass("masked_input")
        phanterCurrency(this)
    } else if(mask=="decimal"){
        $(this).addClass("masked_input")
        phanterDecimals(this)
    } else if(mask=="off"){
        $(this).removeClass("masked_input").off("keypress.phantermask focusout.phantermask focusin.phantermask")
    } else if(mask=="custom"){
        $(this).addClass("masked_input")
        applyMask(this, phanterMaskCustom)
        custom_mask=parameters.mask
    }
    return this
};

//phanterwebformvalidators

function validate_data(form){
    var group = $(form).attr('phanterwebformvalidator_group')
    var hasErrorToButton = false;
    $(form).find('[phanterwebformvalidator_group]').each(function(){
        var can_empty = true;
        var hasError = false;
        var main_element = $(this)
        var element = main_element.find('input')
        var inputname = element.attr('name')
        var hasattr_isnotempty = main_element.attr("phanterwebformvalidator_isnotempty")
        var hasattr_isemail = main_element.attr("phanterwebformvalidator_isemail")
        var hasattr_iscnpj = main_element.attr("phanterwebformvalidator_iscnpj")
        var hasattr_isactivationcode = main_element.attr("phanterwebformvalidator_isactivationcode")
        var hasattr_iscpf = main_element.attr("phanterwebformvalidator_iscpf")
        var hasattr_iscep = main_element.attr("phanterwebformvalidator_iscep")
        var hasattr_isequals = main_element.attr("phanterwebformvalidator_isequals")
        var hasattr_isnotequals = main_element.attr("phanterwebformvalidator_isnotequals")
        var hasattr_valisdifferentof = main_element.attr("phanterwebformvalidator_valisdifferentof")
        if (typeof hasattr_isnotempty !== typeof undefined && hasattr_isnotempty !== false){
            can_empty = false;
            var value = element.val();
           
            if (value===""){
                hasError=true;
                hasErrorToButton=true;
            }
        }
        if (typeof hasattr_isemail !== typeof undefined && hasattr_isemail !== false){
            var value = element.val();
            if (can_empty){
                if(value!=""){
                    if (!isEmail(value)){
                        hasError=true;
                        hasErrorToButton=true;
                    }                   
                }
            } else {
                if (!isEmail(value)){
                    hasError=true;
                    hasErrorToButton=true;
                }
            }
        }
        if (typeof hasattr_iscnpj !== typeof undefined && hasattr_iscnpj !== false){
            var value = element.val();
            if (can_empty){
                if(value!=""){
                    if (!isCNPJ(value)){
                        hasError=true;
                        hasErrorToButton=true;
                    }                   
                }
            } else {
                if (!isCNPJ(value)){
                    hasError=true;
                    hasErrorToButton=true;
                }
            }
        }

        if (typeof hasattr_isactivationcode !== typeof undefined && hasattr_isactivationcode !== false){
            var value = element.val();
            if (can_empty){
                if(value!=""){
                    if (!isACTIVATIONCODE(value)){
                        hasError=true;
                        hasErrorToButton=true;
                    }                   
                }
            } else {
                if (!isACTIVATIONCODE(value)){
                    hasError=true;
                    hasErrorToButton=true;
                }
            }
        }

        if (typeof hasattr_iscpf !== typeof undefined && hasattr_iscpf !== false){
            var value = element.val();
            if (can_empty){
                if(value!=""){
                    if (!isCPF(value)){
                        hasError=true;
                        hasErrorToButton=true;
                    }                   
                }
            } else {
                if (!isCPF(value)){
                    hasError=true;
                    hasErrorToButton=true;
                }
            }
        }
        if (typeof hasattr_iscep !== typeof undefined && hasattr_iscep !== false){
            var value = element.val();
            if (can_empty){
                if(value!=""){
                    if (!isCEP(value)){
                        hasError=true;
                        hasErrorToButton=true;
                    }                   
                }
            } else {
                if (!isCEP(value)){
                    hasError=true;
                    hasErrorToButton=true;
                }
            }
        }
        if (typeof hasattr_isequals !== typeof undefined && hasattr_isequals !== false){
            var value = element.val();
            var val_equals = $("[phanterwebformvalidator_group='"+group+"'] input[name='"+hasattr_isequals+"']").val()
            if (value!=val_equals){                             
                hasError=true;
                hasErrorToButton=true;
            }
        }
        if (typeof hasattr_isnotequals !== typeof undefined && hasattr_isnotequals !== false){
            var value = element.val();
            var val_equals = $("[phanterwebformvalidator_group='"+group+"'] input[name='"+hasattr_isnotequals+"']").val()
            if (value==val_equals){                             
                hasError=true;
                hasErrorToButton=true;
            }
        }
        if (typeof hasattr_valisdifferentof !== typeof undefined && hasattr_valisdifferentof !== false){
            var value = element.val();
            var val_notequals = main_element.attr("phanterwebformvalidator_valisdifferentof")
            
            if (value==val_notequals){                             
                hasError=true;
                hasErrorToButton=true;
            }
        }
        if (hasError){
           
            main_element.find("#phanterwebformvalidator-input-check-"+inputname).addClass('disable');
        } else{
            main_element.find("#phanterwebformvalidator-input-check-"+inputname).removeClass('disable');
        }
        if (hasErrorToButton){
            $("[phanterwebformvalidator_submit][phanterwebformvalidator_group='"+group+"']").attr("disabled","")
        } else{
            $("[phanterwebformvalidator_submit][phanterwebformvalidator_group='"+group+"']").removeAttr("disabled")
        }
    });
};

$.fn.phanterwebFormValidator = function(){
    MainObj = this
    var group = $(MainObj).attr('phanterwebformvalidator_group')
    validate_data(MainObj)
    var main_element = this
    $("[phanterwebformvalidator_group='"+group+"'] input")
        .off('keypress.validator_'+group+' keyup.validator_'+group)
        .on('keypress.validator_'+group+' keyup.validator_'+group, function(){
            validate_data(MainObj)
        });
    $("[phanterwebformvalidator_group='"+group+"'] input")
        .off('change.validator_'+group)
        .on('change.validator_'+group, function(){
            setInterval(function() {
            validate_data(MainObj)
             }, 100);
            
        });
    return this
};

//check application
function check_application(){
    var local_application_info = localStorage.getItem("application")
    if(isNotEmpty(local_application_info)){
        var local_application_info_data = JSON.parse(local_application_info)
        var local_application_version = local_application_info_data.version
        var local_application_name = local_application_info_data.name
        if ((local_application_name!=application_name)||(local_application_version!=application_version)){
            console.error("version and name of application in server change")
            localStorage.clear();
            alert("version and name of application in server change")
            location.reload()
        }
    } else {
        console.error("version and name of application in server change")
        localStorage.clear();
        alert("version and name of application in server change")
        localStorage.setItem("application", JSON.stringify(phanterwebCacheDataJS.application))
        location.reload()
    }
}
check_application();
//phanterquery
var phanterQuery = function(seletor){
    var cm_car=['.', '\\', '#', '*', ',', '>', '+', '~', '[', ']', '=', '|', '^', '"', '$', ':', '(', ')'];
    
    var isID = seletor.startsWith("#");
    var isClass = seletor.startsWith(".");
    var hasCm_car = false;
    var hasSp_car = false;
    if (isID||isClass){
        for (var i = 0; i < cm_car.length; i++) {
            if (cm_car[i]==":"){
                if (seletor.slice(1).indexOf(cm_car[i])>=0){
                    hasCm_car = true;
                    hasSp_car = true;
                }
            } else if (cm_car[i]=="\\"){
                if (seletor.slice(1).indexOf(cm_car[i])>=0){
                    hasCm_car = true;
                    hasSp_car = true;
                }
            } else if (seletor.slice(1).indexOf(cm_car[i])>=0){
                hasCm_car = true;
            };
        };
    };
    var elements = undefined
    if (isID&&!hasCm_car){
        var result = document.getElementById(seletor.slice(1))
        if(result!=null){
            elements = [result]
        }
    } else if (isClass&&!hasCm_car){
        var result = document.getElementsByClassName(seletor.slice(1))
        if(result.length!=0){
            elements = result       
        }
    } else {
        if (hasSp_car){
            var transform="";
            for (var i = 0; i < seletor.length; i++) {
                if (seletor[i]==":"){
                    transform=transform+"\\:"
                } else if (seletor[i]=="\\"){
                    transform=transform+"\\\\"
                } else {
                    transform=transform+seletor[i];
                };
            };
            seletor=transform
        }
        result = document.querySelectorAll(seletor)
        if(result.length!=0){
            elements = result       
        }
    }
    var phanterQueryElements=[]
    if (elements!=undefined){
        for (var i = 0; i < elements.length; i++) {
            phanterQueryElements.push(elements[i])
        }
    }
    var obj_result={
        0:phanterQueryElements, 
        seletor:seletor, 
        length:phanterQueryElements.length,
        on: function(comand, callback){
            for (var i = 0; i < this.length; i++) {
                var el=this[0][i];
                var comands={
                    click: function(){el.onclick = callback},
                    change: function(){el.onchange = callback},
                    mousedown: function(){el.onmousedown = callback},
                    mouseup: function(){el.onmouseup = callback},
                    mousemove: function(){el.onmousemove = callback},
                    mouseleave: function(){el.onmouseleave = callback},
                };
                comands[comand](el, callback);
            };
            return this         
        },
        addClass: function(class_name){
            for (var i = 0; i < this.length; i++) {
                el=this[0][i];
                if (!el.classList.contains(class_name)){
                    el.classList.add(class_name);
                };              

            };              
            return this
        },
        removeClass: function(class_name){
            for (var i = 0; i < this.length; i++) {
                el=this[0][i];
                if (el.classList.contains(class_name)){
                    el.classList.remove(class_name);
                };
            };              
            return this
        },
        html: function(html){
            for (var i = 0; i < this.length; i++) {
                el=this[0][i];
                el.innerHTML = html
            };              
            return this
        },
        trigger: function(comand){
            for (var i = 0; i < this.length; i++) {
                var el=this[0][i];
                var comands={
                    click: function(){el.click();},
                };
                comands[comand]();
            };
            return this 
        }
    }
    return obj_result
};

//phantersvg
var phanterSvgs = new (function() {
    this.icons={
        'close-circle': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-close-circle" class="phantersvg-ico-layer0" d="m24.948 0.70545c13.443 0 24.346 10.903 24.346 24.346 0 13.443-10.903 24.346-24.346 24.346-13.443 0-24.346-10.903-24.346-24.346 0-13.443 10.903-24.346 24.346-24.346zm-17.228 14.689 7.571-7.571 9.6569 9.6569 9.6569-9.6569 7.571 7.571-9.6569 9.6569 9.6569 9.6569-7.571 7.571-9.6569-9.6569-9.6569 9.6569-7.571-7.571 9.6569-9.6569z"/></svg>',
        'download-cloud': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-download-cloud" class="phantersvg-ico-layer0" d="m37.606 31.561c6.7342-1.0923 11.822-6.0609 11.822-12.024 0-6.7636-6.5432-12.248-14.612-12.248-0.3496 0-0.69686 0.011655-1.0403 0.031807-2.1429-4.0181-6.9525-6.8202-12.542-6.8202-7.5831 0-13.732 5.1546-13.732 11.511 0 1.0705 0.17615 2.108 0.50285 3.0916-4.2788 0.96187-7.4309 4.2346-7.4309 8.124 0 4.2144 3.7004 7.7064 8.5255 8.3171 0.876 0.1103 2.1379 0.10286 3.4031-0.02648l-1.8812-2.5083h7.225v-8.5992h14.45v8.5992h7.225l-1.9141 2.5522zm-7.9704-8.4919v8.5992h4.5656l-9.1308 12.175-9.1311-12.175h4.5656v-8.5992h9.1312-4.1e-4zm-14.45 20.774h2.6595v3.0372h14.45v-3.0372h2.6595v5.6569h-19.769v-5.6569z"/></svg>',
        'image-cut': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-image-cut" class="phantersvg-ico-layer0" d="m0.52114 21.29c-0.29869 3.1641 2.6023 6.0267 6.4779 6.3926 3.8756 0.36599 7.2615-1.9032 7.5602-5.0672 0.0048-0.04967 0.0084-0.09894 0.01166-0.14814 1.8291 0.23665 3.5993 0.46089 5.3351 0.67792 2.9983 4.8402 5.9974 9.6908 8.7879 14.201 1.0455 1.6897 3.7687 3.5881 6.3922 2.6395 1.0359-0.37443 1.1192-0.40126 0.57781-1.269-3.3291-5.3343-6.1841-10.025-9.0618-14.746 5.4881 0.67188 10.939 1.3354 17.172 2.165 1.0134 0.13496 1.0034 0.04803 0.91691-1.0499-0.21943-2.7813-3.0728-4.4779-5.0432-4.7321-5.2602-0.6795-10.916-1.4078-16.562-2.1406-0.91416-1.4916-1.8495-3.0115-2.8201-4.5795 0.04364-0.02326 0.08687-0.04727 0.1301-0.0717 2.7585-1.5784 3.4272-5.599 1.4936-8.9777-1.9336-3.3791-5.7384-4.839-8.4969-3.2606-2.5642 1.4675-3.3222 5.0448-1.8627 8.2558-0.01283 0.00762-0.02607 0.01441-0.03843 0.022435l0.2182 0.34959c0.06004 0.11727 0.1233 0.23419 0.18938 0.34994 0.17819 0.3111 0.37238 0.60622 0.5798 0.8837 1.2461 1.9997 2.5259 4.0578 3.8216 6.1448-2.4357-0.31837-4.8386-0.63427-7.1742-0.9438-0.33875-0.074451-0.68752-0.12934-1.0443-0.16296-0.13297-0.012418-0.26547-0.022024-0.39721-0.028058l-0.40846-0.05442c-0.00199 0.01441-0.00316 0.02964-0.00439 0.04405-3.5269-0.0036-6.4723 2.1638-6.7502 5.1053v-4.11e-4zm20.136-1.0147c-0.34918 0.54178-0.19301 1.2641 0.34877 1.6137 0.54178 0.34918 1.2641 0.19301 1.6137-0.34877 0.34912-0.54178 0.19295-1.2641-0.34877-1.6133-0.54178-0.34918-1.2641-0.19301-1.6133 0.34877l-4.1e-4 -4.1e-4zm-5.1281-15.217c1.0751-0.61547 2.5579-0.046042 3.3114 1.2705 0.7536 1.317 0.49293 2.8838-0.5822 3.4989-1.0751 0.61541-2.5578 0.046042-3.3114-1.2705-0.75354-1.317-0.49287-2.8838 0.5822-3.4988zm-10.724 16.636c-0.11651 1.2333 1.0143 2.3488 2.5246 2.4914 1.5103 0.14258 2.8297-0.74194 2.9463-1.9748 0.11651-1.2333-1.0139-2.3488-2.5246-2.4914-1.5103-0.14252-2.8297 0.74159-2.9463 1.9749zm44.695-7.3028h-26.998c0.49773 0.80684 0.99423 1.6145 1.49 2.4225 0.90209 0.11692 1.8042 0.23384 2.7064 0.35035h20.016v29.374h-36.313v-17.666c-0.90572 0.24743-1.8515 0.36359-2.7849 0.34836v20.09h41.883v-34.92zm-36.797 0h-5.0861v0.27666l0.20502 0.02724c0.13373 0.0072 0.26711 0.01722 0.40043 0.02964 0.39001 0.03685 0.77802 0.09607 1.1612 0.17737 1.3206 0.17497 2.6415 0.34918 3.9625 0.52257l-0.64306-1.0339v4.1e-4zm-5.0861 6.8262v1.4751c0.42287-0.006794 1.1188-0.17298 1.1612-0.62344 0.047623-0.50452-0.77644-0.81247-1.1612-0.85171zm28.188 5.406c0.5566 0.90133 1.5532 1.5023 2.69 1.5023 0.84849 0 1.6193-0.33471 2.1871-0.8793-1.6253-0.21099-3.251-0.41842-4.8771-0.62262v-4.1e-4zm-13.607 3.0808-10.725 15.215h33.313l-4.7849-6.7886-4.7849-6.7887-1.2521 1.7766c0.98785 1.6029 1.9793 3.2034 2.9763 4.801 0.40483 0.64827 0.73638 1.309 0.4545 2.0958-0.30355 0.8465-1.0375 1.1096-1.7967 1.3838-3.03 1.0956-6.558-0.63627-8.1829-3.2626-1.7394-2.8109-3.4776-5.6222-5.217-8.4327z"/></svg>',
        'image-decrease': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-image-decrease" class="phantersvg-ico-layer0" d="m28.718 20.59 7.0983 14.74h-21.481l4.7989-9.24 3.8841 4.05 0.4559-0.64zm-8.9857-4.13c1.865 0 3.3776 1.51 3.3776 3.38 0 1.86-1.5126 3.37-3.3776 3.37s-3.3776-1.51-3.3776-3.37c0-1.87 1.5126-3.38 3.3776-3.38zm-7.9313 21.74h26.398v-26.4h-26.398zm1.8558-1.86h22.686v-22.68h-22.686zm-2.1776 2.18h-10.806l4.5231 4.52-4.5231 4.53v1.93h1.9332l4.5231-4.52 4.3499 4.35v-10.81zm27.042 0h10.805l-4.5231 4.52 4.5231 4.53v1.93h-1.9332l-4.5231-4.52-4.3499 4.35v-10.81zm0-27.04h10.805l-4.5231-4.52 4.5231-4.53v-1.93h-1.9332l-4.5231 4.52-4.3499-4.35v10.81zm-27.042 0h-10.806l4.5231-4.52-4.5231-4.53v-1.93h1.9332l4.5231 4.52 4.3499-4.35v10.81z"/></svg>',
        'image-increase': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-image-increase" class="phantersvg-ico-layer0" d="m0.67314 0.5h10.806l-4.5232 4.5232 4.5232 4.5232v1.9332h-1.9332l-4.5232-4.5232-4.35 4.35v-10.806l7.6132e-4 -7.4396e-4zm48.654 0h-10.806l4.5232 4.5232-4.5232 4.5232v1.9332h1.9332l4.5232-4.5232 4.35 4.35v-10.806l-7.43e-4 -7.4396e-4zm0 49h-10.806l4.5232-4.5232-4.5232-4.5232v-1.9332h1.9332l4.5232 4.5232 4.35-4.35v10.806l-7.43e-4 7.44e-4zm-48.654 0h10.806l-4.5232-4.5232 4.5232-4.5232v-1.9332h-1.9332l-4.5232 4.5232-4.35-4.35v10.806l7.6132e-4 7.44e-4zm12.983-13.157h22.686v-22.686h-22.686zm-1.8559 1.8566h26.398v-26.398h-26.398zm7.9315-21.741c1.8651 0 3.3776 1.5125 3.3776 3.3776 0 1.8651-1.5126 3.3776-3.3776 3.3776-1.8651 0-3.3776-1.5126-3.3776-3.3776 0-1.8651 1.5125-3.3776 3.3776-3.3776zm8.9858 4.1354 7.0985 14.739h-21.481l4.799-9.2394 3.8841 4.0488 0.45592-0.6459 5.2435-8.903z"/></svg>',
        'image-reload': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-image-reload" class="phantersvg-ico-layer0" d="m27.029 30.285 7.4052 15.377h-22.41l5.0068-9.6383 4.0521 4.2238 0.47526-0.6742 5.4704-9.2876zm-9.3745-4.3144c1.9456 0 3.5235 1.5778 3.5235 3.5235 0 1.9455-1.5778 3.5233-3.5235 3.5233-1.9455 0-3.5234-1.5778-3.5234-3.5233 0-1.9456 1.5778-3.5235 3.5234-3.5235zm-8.2738 22.681h27.539v-27.539h-27.539zm1.9362-1.9362h23.666v-23.666h-23.666zm6.0978-44.586c12.169-3.2605 24.681 3.9635 27.941 16.132 0.76551 2.857 0.9514 5.7325 0.63264 8.5032l3.511 0.45715-6.7857 8.8693-2.1441-5.1557-2.144-5.1556 2.7125 0.35321c0.2386-2.1538 0.08911-4.387-0.50545-6.606-2.5618-9.5605-12.392-15.237-21.953-12.675-9.5605 2.5618-15.237 12.392-12.675 21.953 0.1315 0.49078 0.28235 0.97119 0.4512 1.4408l-4.658 1.4956c-0.19159-0.54579-0.36414-1.1029-0.51635-1.6709-3.2605-12.169 3.9635-24.681 16.132-27.941z"/></svg>',
        'image-view': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-image-view" class="phantersvg-ico-layer0" d="m31.536 4.4942c3.8398 0 6.9537 3.1139 6.9537 6.9537 0 3.8398-3.1139 6.9537-6.9537 6.9537-3.8398 0-6.9537-3.1139-6.9537-6.9537 0-3.8398 3.1139-6.9537 6.9537-6.9537zm-4.1513 14.591c-2.7047-1.4735-4.5407-4.3415-4.5407-7.6377 0-2.5272 1.0793-4.8025 2.8019-6.3907-5.1484 2.086-8.4936 5.5149-9.5141 6.633 1.3778 2.0448 5.2232 5.7008 11.253 7.3957l3.49e-4 -4.08e-4zm10.117-13.959c1.6787 1.585 2.7272 3.8307 2.7272 6.3215 0 3.2539-1.789 6.0898-4.4368 7.5795 5.9143-1.7187 9.6896-5.3161 11.052-7.338-1.009-1.1059-4.2913-4.4712-9.3425-6.5627v-4.077e-4zm-6.0617-3.9153c-9.9193 0-16.461 8.2857-17.964 10.334 1.8349 3.3883 8.0445 10.334 17.964 10.334 0.03246 0 0.06443-4.07e-4 0.09648-7.26e-4 9.9193 0 16.129-6.9454 17.964-10.334-1.502-2.0484-8.0441-10.334-17.964-10.334-0.02489 0-0.04944 4.072e-4 -0.07392 7.552e-4h-0.0236zm0.09648 6.5666c2.0266 0 3.6702 1.6436 3.6702 3.6702 0 2.0266-1.6436 3.6698-3.6702 3.6698s-3.6702-1.6435-3.6702-3.6698c0-2.0266 1.6436-3.6702 3.6702-3.6702zm-6.2717 18.964 6.2535 8.8716 6.2535 8.8716h-32.651l4.6898-6.6536 4.6902-6.6536 3.8188 5.4181 0.69229-0.9825 6.2535-8.8716h-4.07e-4zm-13.978-4.9112c1.7103 0 3.0973 1.3869 3.0973 3.0973 0 1.7103-1.3869 3.0973-3.0973 3.0973-1.7103 0-3.0973-1.387-3.0973-3.0973 0-1.7103 1.3869-3.0973 3.0973-3.0973zm-10.786-7.2672h13.215c0.75515 0.96469 1.6174 1.8835 2.5217 2.7177h-13.008v28.791h35.591v-23.963c0.93229-0.33016 1.8436-0.72434 2.7296-1.1806v27.862h-41.05v-34.227z"/></svg>',
        'recycle': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-recycle" class="phantersvg-ico-layer0" d="m46.857 17.996-3.6732 26.401c-0.37124 2.6682-2.858 4.8512-5.5262 4.8512h-24.704c-2.6682 0-5.1549-2.183-5.5261-4.8512l-3.6733-26.401h43.103zm-38.978 3.049c0.72418 0 1.3887 0.59245 1.4768 1.3166l2.6801 22.036c0.08808 0.72415-0.43233 1.3166-1.1565 1.3166-0.72418 0-1.3887-0.59247-1.4768-1.3166l-2.6801-22.036c-0.088105-0.72418 0.43231-1.3166 1.1565-1.3166zm7.0482 0c0.72415 0 1.3595 0.59245 1.412 1.3166 0.53205 7.3453 1.0641 14.691 1.5961 22.036 0.05246 0.72415-0.49708 1.3166-1.2213 1.3166-0.72418 0-1.3595-0.59247-1.412-1.3166-0.53205-7.3454-1.0641-14.691-1.5962-22.036-0.05244-0.72418 0.49711-1.3166 1.2213-1.3166zm7.0482 0c0.72415 0 1.3304 0.59245 1.3472 1.3166 0.17071 7.3453 0.34146 14.691 0.51217 22.036 0.01685 0.72415-0.56183 1.3166-1.286 1.3166-0.72418 0-1.3304-0.59247-1.3472-1.3166-0.17072-7.3454-0.34146-14.691-0.51217-22.036-0.01685-0.72418 0.56183-1.3166 1.286-1.3166zm7.0482 0c0.72418 0 1.3012 0.59245 1.2825 1.3166-0.19057 7.3453-0.38116 14.691-0.57174 22.036-0.01877 0.72415-0.62661 1.3166-1.3508 1.3166s-1.3012-0.59247-1.2825-1.3166c0.19057-7.3454 0.38117-14.691 0.57174-22.036 0.01879-0.72418 0.62661-1.3166 1.3508-1.3166zm7.0482 0c0.72418 0 1.2721 0.59245 1.2177 1.3166-0.55193 7.3453-1.1038 14.691-1.6557 22.036-0.05438 0.72415-0.69136 1.3166-1.4155 1.3166s-1.2721-0.59247-1.2177-1.3166c0.55191-7.3454 1.1038-14.691 1.6557-22.036 0.05438-0.72418 0.69136-1.3166 1.4155-1.3166zm7.0482 0c0.72415 0 1.243 0.59245 1.1529 1.3166l-2.7396 22.036c-0.09002 0.72415-0.75614 1.3166-1.4803 1.3166-0.72415 0-1.243-0.59247-1.1529-1.3166l2.7396-22.036c0.09005-0.72418 0.75614-1.3166 1.4803-1.3166zm-37.224-17.3h12.803v-1.3125c0-0.92421 0.75627-1.6806 1.6802-1.6806h9.242c0.92397 0 1.6802 0.75637 1.6802 1.6806v1.3125h12.803c2.7263 0 4.9569 2.2306 4.9569 4.9569v7.4354h-48.122v-7.4354c0-2.7263 2.2306-4.9569 4.9569-4.9569zm-3.2634 9.1228h43.934v0.83154h-43.934z"/></svg>',
        'upload-cloud': '<svg style="clip-rule:evenodd;fill-rule:evenodd;image-rendering:optimizeQuality;shape-rendering:geometricPrecision;text-rendering:geometricPrecision" version="1.1" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg"><path id="phantersvg-ico-upload-cloud" class="phantersvg-ico-layer0" d="m16.572 30.412 8.498-11.33 9.5261 12.701 0.21926 0.0016c8.0689 0 14.612-5.4849 14.612-12.248s-6.5433-12.248-14.612-12.248c-0.3496 0-0.69684 0.011655-1.0402 0.031807-2.1429-4.0181-6.9525-6.8201-12.542-6.8201-7.5829 0-13.732 5.1546-13.732 11.51 0 1.0706 0.17615 2.108 0.50286 3.0916-4.2788 0.96188-7.4311 4.2346-7.4311 8.124 0 4.2144 3.7004 7.7064 8.5257 8.3169 1.9963 0.25142 5.9958-0.10784 7.4738-1.131zm13.063 13.808v-8.5991h4.5656l-9.1308-12.175-9.1313 12.175h4.5656v8.5991h9.1313-4.1e-4zm-14.45-0.37772h2.6595v3.0372h14.45v-3.0372h2.6595v5.657h-19.769v-5.657z" style="stroke-width:.49597"/></svg>',
    },
    this.setIcon=function(name, svg){
        this.icons[name]=svg;
        this.update();
    };
    this.getIcon=function(name){
        return this.icons[name]
    };
    this.getClassName=function(name){
        hasName=false;
        for (var key in this.icons) {
            if(name==key){
                hasName=true
            }
        };
        if (hasName){
            return ".phantersvg."+name
        } else {
            throw "phantersvgs: there is no icon named '"+name+"'"
        };
    };
    this.update=function(){
        for (var key in this.icons) {
            phanterQuery(".phantersvg."+key).html(this.icons[key])
        };  
    }
    this.update()
})();

//phantergallery
var phanterGalleryObj = function(elementPhanterGalleryObj, config, messages){
    var MainObj = this
    MainObj.el = elementPhanterGalleryObj;
    MainObj.imageName = "";
    MainObj.imageType = "";
    MainObj.uploadArea = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-object"));
    MainObj.uploadFormContainer = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-upload-form-container"));
    MainObj.uploadInput = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-upload-input"));
    MainObj.panelCutterContainer = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-panel-cutter-container"));
    MainObj.cutterShadow = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-cutter-shadow"));
    MainObj.cutterControlClose = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-cutter-control-close"));
    MainObj.cutterControlView = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-cutter-control-view"));
    MainObj.cutterControlCut = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-cutter-control-cut"));
    MainObj.cutterPad = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-cutter-pad"));
    MainObj.cutterBackground = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-cutter-background"));
    MainObj.cutterZoomControl = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-cutter-zoom-control"));
    MainObj.panelCutterSizeContainer = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-panel-cutter-size-container"));
    MainObj.panelCutterImage = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-panel-cutter-image"));
    MainObj.targetView = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-target-view"));
    MainObj.targetViewContainer = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-target-view-container"));
    MainObj.imagecutedControlErase = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-imagecuted-control-erase"));
    MainObj.imagecutedControlChange = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-imagecuted-control-change"));
    MainObj.uploadMessages = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-upload-messages"));
    MainObj.uploadAreaProgress = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-upload-area-progress"));
    MainObj.uploadImageButton = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-upload-image-button"));
    MainObj.uploadTitleButton = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-upload-title-button"));
    MainObj.inputNameCutterSizeX = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-input-name-cutterSizeX"));
    MainObj.inputNameCutterSizeY = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-input-name-cutterSizeY"));
    MainObj.inputNamePositionX = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-input-name-positionX"));
    MainObj.inputNamePositionY = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-input-name-positionY"));
    MainObj.inputNameNewSizeX = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-input-name-newSizeX"));
    MainObj.inputNameNewSizeY = phanterQuery("#"+elementPhanterGalleryObj.getAttribute("data-input-name-newSizeY"));
    MainObj.cutterSizeX = elementPhanterGalleryObj.getAttribute("data-cutter-size-x");
    MainObj.cutterSizeY = elementPhanterGalleryObj.getAttribute("data-cutter-size-y");
    MainObj.uploadSrcImg = elementPhanterGalleryObj.getAttribute("data-upload-src-img");
    MainObj.config = config;
    MainObj.messages = messages;
    MainObj.phanterGalleryCutterObj = undefined;
    MainObj.error = false;
    MainObj._callAfterCut = "";
    MainObj.cuttedImage = null;
    MainObj.getCuttedImage = function(){
        return MainObj.cuttedImage
    }
    MainObj.showProgress = function(){
        MainObj.uploadAreaProgress.addClass("actived");
        return MainObj
    };
    MainObj.hideProgress = function(){
        MainObj.uploadAreaProgress.removeClass("actived");
        return MainObj
    };
    MainObj.showMessage = function(message){
        MainObj.uploadMessages.html(message);
        MainObj.uploadMessages.addClass("actived");
        return MainObj
    };
    MainObj.hideMessage = function(){
        MainObj.uploadMessages.html("");
        MainObj.uploadMessages.removeClass("actived");
        return MainObj
    };
    MainObj.click = function(){
        MainObj.setTitleButton(MainObj.config.titleButtonWaiting)
        MainObj.uploadInput.trigger('click')
        return MainObj
    };
    MainObj.setImgButton = function(img){
        MainObj.uploadImageButton.html(img);
        return MainObj
    };
    MainObj.setTitleButton = function(title){
        MainObj.uploadTitleButton.html(title);
        return MainObj
    };
    MainObj.inputChange = function(){
        MainObj.showProgress();
        var blob = MainObj.uploadInput[0][0].files;
        MainObj.imageBlob = blob[0]
        var fileslength = blob.length;
        for (var i = fileslength - 1; i >= 0; i--) {
            var img_type = blob[i]['type'];
            var img_name= blob[i]['name'];
            MainObj.imageName = img_name;
            MainObj.imageType = img_type;
            if (img_type=="image/png"||img_type=="image/bmp"||img_type=="image/gif"||img_type=="image/jpeg"){
                if(img_name.length<50){
                    var reader = new FileReader();

                    reader.readAsDataURL(blob[0])
                    MainObj.targetView.html("")
                    MainObj.hideProgress()
                    reader.onloadend = function(){
                        var base64data = reader.result;
                        MainObj.phanterGalleryCutterObj= new phanterGalleryCutterObj(base64data, MainObj)
                        window.onresize = function(event){
                        }
                    }
                } else {
                    var message = MainObj.messages.nameOfFileLong
                    MainObj.showMessage(message);
                };
            } else{
                var message = MainObj.messages.FileCouldNotBeUploaded.replace("%(name_file)s", img_name);
                throw message
                MainObj.showMessage(message);
            }
        }
        return MainObj
    };
    MainObj.el=elementPhanterGalleryObj
    MainObj.uploadInput.on('change', function(){
        MainObj.inputChange();
    });
    MainObj.el.onclick = function(){
        MainObj.hideProgress();
        MainObj.hideMessage();
        MainObj.click();
    };
    return MainObj
};

var phanterGalleryCutterObj = function(base64data, PG){
    var selfObj = this
    var PG=PG
    var base64data=base64data
    var img1=document.createElement("IMG");
    var img2=document.createElement("IMG");
    img1.onerror = function(){
        PG.error=true;
        throw "invalid image!"
    }
    PG.panelCutterImage.html("");
    PG.cutterBackground.html("");
    PG.panelCutterImage[0][0].appendChild(img1)
    PG.cutterBackground[0][0].appendChild(img2)
    selfObj.base64data = base64data;
    selfObj.originalWidthImg = 0;
    selfObj.originalHeightImg = 0;
    selfObj.widthImg = 0;
    selfObj.heightImg = 0;
    selfObj.widthScreen = 0;
    selfObj.heightScreen = 0;
    selfObj.widthCutter = 0;
    selfObj.heightCutter = 0;
    selfObj.inicialPositionXBackground = 0;
    selfObj.inicialPositionYBackground = 0;
    selfObj.inicialPositionXImgToCut = 0;
    selfObj.inicialPositionYImgToCut = 0;
    selfObj.deslocationPositionXBackground = 0;
    selfObj.deslocationPositionYBackground = 0;
    selfObj.deslocationPositionXImgToCut = 0;
    selfObj.deslocationPositionYImgToCut = 0;
    selfObj.deslocationPositionZoom = 0;
    selfObj.positionDefaultZoom = 89.0;
    selfObj.widthImgAfterZoom = 0;
    selfObj.heightImgAfterZoom = 0;
    selfObj.positionXAfterZoom = 0;
    selfObj.positionYAfterZoom = 0;
    selfObj.activeViewImage = false;
    selfObj.calcMidPosition =function(sizeContainer, sizeContent, positionContent){
        var midsize1=sizeContainer/2.0
        var midsize2=sizeContent/2.0
        var relativeposition=midsize1-midsize2
        var finalPosition=relativeposition-positionContent
        return finalPosition
    };
    selfObj.moveImage =function(x,y){
        selfObj.deslocationPositionXBackground=x*(-1)
        selfObj.deslocationPositionYBackground=y*(-1)
        selfObj.deslocationPositionXImgToCut=x*(-1)
        selfObj.deslocationPositionYImgToCut=y*(-1)
        selfObj.calcPosition()
    };
    selfObj.viewImage =function(){
        if (selfObj.activeViewImage){
            selfObj.activeViewImage=false
            PG.cutterControlView.removeClass("actived")
            PG.cutterShadow.removeClass("actived")
        } else{
            selfObj.activeViewImage=true
            PG.cutterControlView.addClass("actived")
            PG.cutterShadow.addClass("actived")
        };
    };
    selfObj.closeImage = function(){
        PG.panelCutterContainer.removeClass("actived")
        PG.setTitleButton(PG.config.titleButton)
        PG.panelCutterContainer.addClass("close")
    };
    selfObj.cutImage = function(){
        var canvas = PG.targetView[0][0]
        canvas.width = selfObj.widthCutter
        canvas.height = selfObj.heightCutter
        var ctx = canvas.getContext('2d');
        var ratio = selfObj.originalWidthImg/parseFloat(selfObj.widthImgAfterZoom)
        var positionX = selfObj.positionXAfterZoom * (-1) * ratio
        var positionY = selfObj.positionYAfterZoom * (-1) * ratio
        var wX = PG.cutterSizeX * ratio
        var wY = PG.cutterSizeY * ratio
        PG.inputNameCutterSizeX[0][0].value = selfObj.widthCutter
        PG.inputNameCutterSizeY[0][0].value = selfObj.heightCutter
        PG.inputNamePositionX[0][0].value = positionX
        PG.inputNamePositionY[0][0].value = positionY
        PG.inputNameNewSizeX[0][0].value = wX
        PG.inputNameNewSizeY[0][0].value = wY
        PG.uploadArea.removeClass("actived")
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img1, positionX, positionY, wX, wY, 0, 0, selfObj.widthCutter, selfObj.widthCutter)
        var imageCutObj={
            originalImage:{
                imageName:PG.imageName,
                imageType:PG.imageType,
                imageBytes:PG.imageBlob,
                imagemBase64Data:selfObj.base64data,
                cutterSizeX:PG.cutterSizeX, 
                cutterSizeY:PG.cutterSizeY,
                positionX:selfObj.positionXAfterZoom,
                positionY:selfObj.positionYAfterZoom,
                newSizeX:selfObj.widthImgAfterZoom,
                newSizeY:selfObj.heightImgAfterZoom, 
            },
            cuttedImage:{
                imageName:PG.imageName,
                imageType:PG.imageType,
                //imageBase64Data:canvas.toDataURL(),
                imageBytes:"",
            }
        }
        if (PG._callAfterCut){
            canvas.toBlob(function(blob){
                var new_name = imageCutObj.originalImage.imageName
                var pos = new_name.lastIndexOf(".");
                new_name = new_name.substr(0, pos < 0 ? new_name.length : pos) + ".png";
                imageCutObj.cuttedImage.imageName = new_name
                imageCutObj.cuttedImage.imageType = "image/png"
                var file = new File([blob], new_name)
                imageCutObj.cuttedImage.imageBytes = file
                PG.cuttedImage = file
            })
            PG._callAfterCut(imageCutObj)
        }
        PG.panelCutterContainer.removeClass("actived")
        PG.setTitleButton(PG.config.titleButton)
        PG.panelCutterContainer.addClass("close")
        PG.targetViewContainer.addClass("actived")
        PG.imagecutedControlErase.on('click', function(){
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            PG.targetViewContainer.removeClass("actived")                
            PG.uploadArea.addClass("actived")
        });
        PG.imagecutedControlChange.on('click', function(){
            PG.uploadArea.trigger('click');
        });
    };
    selfObj.movecutterZoom =function(x, zoominicial, width, height){
        selfObj.deslocationPositionZoom=x*(-1)
        selfObj.calcZoomPosition(zoominicial, width, height)
    };
    selfObj.changeSizeImage =function(ratio, width, height){
        width = parseFloat(width)*ratio
        height = parseFloat(height)*ratio
        img1.style.width=width+"px"
        img1.style.height=height+"px"
        img2.style.width=width+"px"
        img2.style.height=height+"px"
        selfObj.widthImg=width
        selfObj.heightImg=height
        selfObj.widthImgAfterZoom=width
        selfObj.heightImgAfterZoom=height
        selfObj.calcPosition();
    };
    selfObj.calcZoomPosition =function(zoominicial, width, height){
        var position = selfObj.positionDefaultZoom-selfObj.deslocationPositionZoom
        var ratio=position/zoominicial
        selfObj.changeSizeImage(ratio, width, height)
        PG.cutterZoomControl[0][0].style.left=position+"px"
    };
    selfObj.calcPosition =function(){
        var widthImg=selfObj.widthImg;
        var heightImg=selfObj.heightImg;
        var widthScreen=window.innerWidth;
        var heightScreen=window.innerHeight
        var widthCutter=selfObj.widthCutter;
        var heightCutter=selfObj.heightCutter;
        if((widthImg>0)&&(heightImg>0)&&(widthScreen>0)&&(heightScreen>0)){
            var fCalc = selfObj.calcMidPosition;
            var iPXB = selfObj.inicialPositionXBackground+selfObj.deslocationPositionXBackground;
            var iPYB = selfObj.inicialPositionYBackground+selfObj.deslocationPositionYBackground;
            var iPXITC = selfObj.inicialPositionXImgToCut+selfObj.deslocationPositionXImgToCut;
            var iPYITC = selfObj.inicialPositionYImgToCut+selfObj.deslocationPositionYImgToCut;
            var relativePositionXBackground=fCalc(widthScreen, widthImg, iPXB);
            var relativePositionYBackground=fCalc(heightScreen, heightImg, iPYB);
            var relativePositionXImgToCut=fCalc(widthCutter, widthImg, iPXITC);
            var relativePositionYImgToCut=fCalc(heightCutter, heightImg, iPYITC);
            PG.panelCutterSizeContainer[0][0].style.left=fCalc(widthScreen, widthCutter, 0)+"px";
            PG.panelCutterSizeContainer[0][0].style.top=fCalc(heightScreen, heightCutter, 0)+"px";
            PG.cutterBackground[0][0].style.left=relativePositionXBackground+"px";
            PG.cutterBackground[0][0].style.top=relativePositionYBackground+"px";
            PG.panelCutterImage[0][0].style.left=relativePositionXImgToCut+"px";
            PG.panelCutterImage[0][0].style.top=relativePositionYImgToCut+"px";
            selfObj.positionXAfterZoom=relativePositionXImgToCut;
            selfObj.positionYAfterZoom=relativePositionYImgToCut;
        };
    };
    selfObj.saveinicialPosition =function(){
        selfObj.inicialPositionXBackground+=selfObj.deslocationPositionXBackground
        selfObj.inicialPositionYBackground+=selfObj.deslocationPositionYBackground
        selfObj.inicialPositionXImgToCut+=selfObj.deslocationPositionXImgToCut
        selfObj.inicialPositionYImgToCut+=selfObj.deslocationPositionYImgToCut
        selfObj.deslocationPositionXBackground=0
        selfObj.deslocationPositionYBackground=0
        selfObj.deslocationPositionXImgToCut=0
        selfObj.deslocationPositionYImgToCut=0
    };
    selfObj.savePositionZoom = function(){
        selfObj.positionDefaultZoom-=selfObj.deslocationPositionZoom
        selfObj.deslocationPositionZoom=0;
    };
    selfObj.setBase64 = function(value){
        selfObj.setBase64=value
    };
    selfObj.activeViewImage = false
    PG.cutterControlView.removeClass("actived")
    PG.cutterShadow.removeClass("actived")
    PG.cutterZoomControl[0][0].style.left=89+"px"
    PG.cutterControlView.on('click', function(){
        selfObj.viewImage();
    });
    PG.cutterControlClose.on('click', function(){
        selfObj.closeImage();
    });
    PG.cutterControlCut.on('click', function(){
        selfObj.cutImage();
    });
    img1.onload = function(){
        imgWidth = this.width
        imgHeight = this.height
        selfObj.widthImg = imgWidth
        selfObj.heightImg = imgHeight
        selfObj.originalWidthImg = imgWidth
        selfObj.originalHeightImg = imgHeight
        selfObj.widthImgAfterZoom = imgWidth
        selfObj.heightImgAfterZoom = imgHeight

        selfObj.widthCutter = parseFloat(PG.cutterSizeX)
        selfObj.heightCutter = parseFloat(PG.cutterSizeY)
        if (PG.error){
            PG.showMessage(PG.messages.invalidImage)
            PG.setTitleButton(PG.config.titleButton)
            PG.error=false
        } else {
            selfObj.calcPosition()
            PG.panelCutterContainer.removeClass("close")
            PG.panelCutterContainer.addClass("actived")

        }
    }
    img1.src=base64data
    img2.src=base64data
    window.addEventListener("resize", function(){
        selfObj.calcPosition()
    });
    PG.cutterPad.on('mousedown', function(event){
        var xInicial = event.clientX;
        var yInicial = event.clientY;
        PG.cutterPad.on('mousemove', function(event){
            var xDeslocamento = event.clientX-xInicial;
            var yDeslocamento = event.clientY-yInicial;
            selfObj.moveImage(xDeslocamento, yDeslocamento)
        });
        PG.cutterPad.on('mouseup', function(event){
            selfObj.saveinicialPosition()
            PG.cutterPad.on('mousemove', '');
            PG.cutterPad.on('mouseleave', '');
        });
        PG.cutterPad.on('mouseleave', function(event){
            selfObj.saveinicialPosition()
            PG.cutterPad.on('mousemove', '');
            PG.cutterPad.on('mouseleave', '');
        });
    });
    PG.cutterZoomControl.on('mousedown', function(event){
        var xInicial = event.clientX;
        var inicialPosition = selfObj.positionDefaultZoom;
        var width = selfObj.widthImg
        var height = selfObj.heightImg
        PG.cutterZoomControl.on('mousemove', function(event){
            var xDeslocamento = event.clientX-xInicial;
            if (((inicialPosition+xDeslocamento)>0)&&(inicialPosition+xDeslocamento)<179){
                selfObj.movecutterZoom(xDeslocamento, inicialPosition, width, height)
            }
        });
        PG.cutterZoomControl.on('mouseup', function(event){
            selfObj.savePositionZoom()
            PG.cutterZoomControl.on('mousemove', '');
            PG.cutterZoomControl.on('mouseleave', '');
        });
        PG.cutterZoomControl.on('mouseleave', function(event){
            selfObj.savePositionZoom()
            PG.cutterZoomControl.on('mousemove', '');
            PG.cutterZoomControl.on('mouseleave', '');
        });
    });
    return selfObj
};

var phanterGallery = new (function(){
    this.phanterGalleryObjs=[]
    this._config = {
            titleButton:"Upload Image",
            titleButtonSend:"Send Image",
            titleButtonProcessing:"Process...",
            titleButtonWaiting:"Upload Image",
            imgButton:"<i class=\"phantersvg upload-cloud\"></i>",
        };
    this._messages = {
            invalidImage:"The image is invalid!",
            nameOfFileLong:"The filename is too long! Please demote before upload",
            fileCouldNotBeUploaded:"File could not be uploaded: %(name_file)s",
        };
    this._callAfterCut = ""
    this.setCallAfterCut = function(script){
        this._callAfterCut = script
        this.update();
    };
    this.config = function(obj){
        for (x in obj) {
                this._config[x]=obj[x]
        }
        this.update();
        return this._config          
    };
    this.messages = function(obj){
        for (y in obj) {
                this._messages[y]=obj[y]
        }
        this.update();
        return this._messages   
    };
    this.update = function(init){
        if (init===false){
            var elements = phanterQuery(".phantergallery_object")[0];
                for (var i = 0; i < elements.length; i++) {
                    var PG = new phanterGalleryObj(elements[i], this._config, this._messages)
                    if(PG.uploadSrcImg!=""){
                        var img = new Image;
                        img.src = PG.uploadSrcImg
                        img.onload = function(){
                            var canvas = PG.targetView[0][0]
                            canvas.width = PG.cutterSizeX
                            canvas.height = PG.cutterSizeY
                            var ctx = canvas.getContext("2d")
                            ctx.drawImage(img, 0, 0)
                            PG.imagecutedControlErase.on('click', function(){
                                ctx.clearRect(0, 0, canvas.width, canvas.height);
                                PG.targetViewContainer.removeClass("actived")                
                                PG.uploadArea.addClass("actived")
                            });
                            PG.imagecutedControlChange.on('click', function(){
                                PG.uploadArea.trigger('click');
                            });
                        }
                    }
                    var objArray = this.phanterGalleryObjs
                    objArray.push(PG);
                }
        } else {
            var elements = phanterQuery(".phantergallery_object")[0];
                for (var i = 0; i < elements.length; i++) {
                    var PG = new phanterGalleryObj(elements[i], this._config, this._messages)
                    PG._callAfterCut = this._callAfterCut
                    PG.setImgButton(this._config.imgButton)
                    PG.setTitleButton(this._config.titleButton)
                    phanterSvgs.update()
                    if(PG.uploadSrcImg!=""){
                        var img = new Image;
                        img.src = PG.uploadSrcImg
                        img.onload = function(){
                            PG.targetViewContainer.addClass("actived")                
                            PG.uploadArea.removeClass("actived")
                            var canvas = PG.targetView[0][0]
                            canvas.width = PG.cutterSizeX
                            canvas.height = PG.cutterSizeY
                            var ctx = canvas.getContext("2d")
                            ctx.drawImage(img, 0, 0)
                            PG.imagecutedControlErase.on('click', function(){
                                ctx.clearRect(0, 0, canvas.width, canvas.height);
                                PG.targetViewContainer.removeClass("actived")                
                                PG.uploadArea.addClass("actived")
                            });
                            PG.imagecutedControlChange.on('click', function(){
                                PG.uploadArea.trigger('click');
                            });
                        }
                    }
                    var objArray = this.phanterGalleryObjs
                    objArray.push(PG);
                }
        }
    }
    this.update(true)
    return this
})();

var phanterGalleryAjaxObj = function(url, objectToSend, callback){
    var xhttp;
    xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            callback(this);
        } else{
            throw "error in ajax send"
        }
    };
    var imageBlob = ""
    var fd = new FormData();
    for (x in objectToSend){
        if (objectToSend[x] instanceof Blob){
            imageBlob=objectToSend[x]
        } else {
            fd.append(x, objectToSend[x]);
        }
    }
    xhttp.open("POST", url, true);
    xhttp.send(fd,  imageBlob);
};

function ajustar_imagem(){
    var altura = $(window).height()-128;
    _print(altura, "Altura:");
    $(".background-empresa").css('height', altura)
}

$(window).on('resize', function(){ajustar_imagem()})

var ComponenteMenu = new function(){
    var MainThis = this
    this.toggleMenu = function(){
        if($("#left-bar").hasClass("expanded")){
            this.menuDecrease();
        } else {
            this.menuExpand();
        }   
    };
    this.menuExpand = function(){
            $("#left-bar").addClass("expanded");
            $(".materialize-component-left-menu-label").addClass("expanded");
            $(".materialize-component-left-menu-submenu-container").slideUp();
            $(".fontawesome-component-left-menu-label").addClass("expanded");
            $(".fontawesome-component-left-menu-submenu-container").slideUp();
    };
    this.menuDecrease = function(){
            $("#left-bar").removeClass("expanded");
            $(".materialize-component-left-menu-label").removeClass("expanded");
            $(".materialize-component-left-menu-submenu-container").slideUp();
            $(".fontawesome-component-left-menu-label").removeClass("expanded");
            $(".fontawesome-component-left-menu-submenu-container").slideUp();
    };
    this.expandSubMenu = function(submenu){
        MainThis.menuExpand()
        var el = $("#"+submenu)
        if(el.hasClass('expanded')){
            el.removeClass('expanded')
            el.slideUp();           
        } else {
            $(".materialize-component-left-menu-submenu-container").removeClass("expanded");
            $(".fontawesome-component-left-menu-submenu-container").removeClass("expanded");
            el.addClass('expanded');
            el.slideDown();
        }
    };
    this.actionBtnMainMenu = function(){
        $("#menu-button-main-page")
            .off("click.menu-button-main-page")
            .on("click.menu-button-main-page", function(){
                MainThis.toggleMenu();
            });
    };
    this.actionBtnMenuCmdSubMenu = function(){
        $(".materialize-component-left-menu-button[target_submenu]")
            .off("click.materialize-component-left-menu-button")
            .on("click.materialize-component-left-menu-button", function(){
                var submenu = $(this).attr("target_submenu")
                MainThis.expandSubMenu(submenu)
            });
        $(".materialize-component-left-menu-submenu-button")
            .off("click.materialize-component-left-menu-submenu-button")
            .on("click.materialize-component-left-menu-submenu-button", function(){
                MainThis.menuDecrease()
                $(".materialize-component-left-menu-submenu-container").removeClass("expanded")
            })
        $(".fontawesome-component-left-menu-button[target_submenu]")
            .off("click.fontawesome-component-left-menu-button")
            .on("click.fontawesome-component-left-menu-button", function(){
                var submenu = $(this).attr("target_submenu")
                MainThis.expandSubMenu(submenu)
            });
        $(".fontawesome-component-left-menu-submenu-button")
            .off("click.fontawesome-component-left-menu-submenu-button")
            .on("click.fontawesome-component-left-menu-submenu-button", function(){
                MainThis.menuDecrease()
                $(".fontawesome-component-left-menu-submenu-container").removeClass("expanded")
            })
    }
    this.init = function(){
        this.actionBtnMainMenu()
        this.actionBtnMenuCmdSubMenu()
    }
}();


var PhanterPages = function(){
    var MainThis = this
    MainThis.id_user = "";
    MainThis.token = "";
    MainThis.dataPage = {};
    MainThis.setCurrentPage = function(pagina, parameters){
        var currentpage = JSON.parse(localStorage.getItem("currentPage"));
        if (isNotEmpty(currentpage)){
            localStorage.setItem("lastPage",  JSON.stringify(currentpage));
        };
        if (isNotEmpty(parameters)){
            localStorage.setItem("currentPage", JSON.stringify({"page":pagina, "parameters":parameters}))
        } else{
            localStorage.setItem("currentPage", JSON.stringify({"page":pagina, "parameters":null}))
        };
    }
    if(isNotEmpty(localStorage.getItem('token'))){
        MainThis.token = localStorage.getItem('token');
    }
    if(isNotEmpty(localStorage.getItem('id_user'))){
        MainThis.id_user = localStorage.getItem('id_user');
    }
    MainThis.principal = function(){
        _print("Principal Acionado")
        MainThis.setCurrentPage("page-layout.html");
        MainThis.getLocalHtml("page-layout.html");
    }
    MainThis.reload = function(){
         _print("Reload Acionado")
        var current = localStorage.getItem("currentPage")
        if(isNotEmpty(current)){
            current = JSON.parse(current)
            var page="page-layout.html";
            var parameters=null;
            if("page" in current){
                page = current.page
            }
            if("parameters" in current){
                parameters = current.parameters
            }
             MainThis.getLocalHtml(page, parameters);
        } else {
            MainThis.getLocalHtml("page-layout.html");
            
        }
    }
    MainThis.responseValidator = function(data){
        for(x in data.validators){
            var error_men = data.validators[x]
            if (error_men!="OK"){
                $("#phanterwebformvalidator-input-error-"+x).html(data.validators[x]).slideDown()
            }
        }
    };
    MainThis.getRemoteJson = function(parameters){
        var obj_param = parameters
        var url = remoteHostAddress+obj_param.url
        _print(url);
        $(".progressbar-form-modal").addClass("enabled");
        $(".main-progress-bar").addClass("enabled");
        $.ajax({url:url,
            type: "GET",
            crossOrigin: true,
            success: function(data, textStatus){
                _print(data, remoteHostAddress+obj_param.url);
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                if ("success" in obj_param){
                    obj_param.success(data);
                }
            },
            headers:{
                    'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                    'Authorization':localStorage.getItem('token')
            },
            error: function(data){
                M.toast({html: "Erro na conexão"})
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                _print(data, "getRemoteJson: "+remoteHostAddress+obj_param.url);
                if ("error" in obj_param){
                    obj_param.error(data);
                }
            },
            dataType:"json",
        });

    };
    MainThis.getLocalHtml = function(pagina, parameters){
        _print(pagina, "abrindo a página:")
        if((pagina=="page-layout.html")||(pagina=="page-main.html")){
            $(".progressbar-form-modal").addClass("enabled");
            $(".main-progress-bar").addClass("enabled");
            $.ajax({url:"page-main.html",
                type: "GET",
                crossOrigin: true,
                success: function(data, textStatus){
                    $(".progressbar-form-modal").removeClass("enabled");
                    $(".main-progress-bar").removeClass("enabled");
                    MainThis.setCurrentPage(pagina);
                    $("#main-container").html(data);
                    ajustar_imagem();
                    phanterpages.getLoginCmp()
                    phanterpages.getAdminButton();
                },
                headers:{
                        'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                },
                error: function(data){
                    M.toast({html: "Erro na conexão"})
                    $(".progressbar-form-modal").removeClass("enabled");
                    $(".main-progress-bar").removeClass("enabled");
                    _print(data, "getLocalHtml: "+"page-main.html");
                },
            });         
        }else{
            var get_page = function(){
                $("#options-bottom-main-bar-left").html("");
                $(".progressbar-form-modal").addClass("enabled");
                $(".main-progress-bar").addClass("enabled");
                $.ajax({url:pagina,
                    type: "GET",
                    crossOrigin: true,
                    success: function(data, textStatus){
                        $(".progressbar-form-modal").removeClass("enabled");
                        $(".main-progress-bar").removeClass("enabled");
                        var l_parameters = MainThis.getPamameters(pagina);
                        var currentpage = JSON.parse(localStorage.getItem("currentPage"));
                        if(isNotEmpty(currentpage)){
                            if(pagina==currentpage.page){
                                MainThis.setCurrentPage(pagina, l_parameters);
                            } else {
                                if (isNotEmpty(parameters)){
                                    MainThis.setCurrentPage(pagina, parameters)
                                } else{
                                    MainThis.setCurrentPage(pagina, null);
                                }
                            };
                        } else{
                            if (isNotEmpty(parameters)){
                                MainThis.setCurrentPage(pagina, parameters)
                            } else{
                                MainThis.setCurrentPage(pagina, null);
                            }
                        }
                        $("#main-container").html(data);
                        phanterpages.getLoginCmp();
                    },
                    headers:{
                            'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                    },
                    error: function(data){
                        M.toast({html: "Erro na conexão"})
                        $(".progressbar-form-modal").removeClass("enabled");
                        $(".main-progress-bar").removeClass("enabled");
                        _print(data, "getLocalHtml: "+pagina);
                    },
                });
            }
            if (isNotEmpty(parameters)){
                if("permitted_roles" in  parameters){
                    var permitted_roles = parameters.permitted_roles
                    MainThis.getRemoteJson({
                        url:"/api/user/info",
                        success:function(data){
                            if(data.status=="OK"){
                                var has_authorization = false;
                                if (data.authenticated){
                                    for (var i = 0; i < data.info.roles.length; i++) {
                                        var role = data.info.roles[i]
                                        _print(role, "role atual")
                                        _print(JSON.stringify(permitted_roles), "lista de permitidos")
                                        if(permitted_roles.indexOf(role)>-1){
                                            has_authorization = true;
                                        }

                                    }
                                    if(has_authorization){
                                        get_page();
                                    }else{
                                        MainThis.getLocalHtml("page-warning.html")
                                    }
                                } else {
                                    MainThis.getLocalHtml("page-warning.html")
                                }
                            } else {

                            };
                        },
                        error: function(data){
                            M.toast({html: "Erro na conexão"})
                            $(".progressbar-form-modal").removeClass("enabled");
                            $(".main-progress-bar").removeClass("enabled");
                            _print(data, "getRemoteJson: "+remoteHostAddress+"/api/user/info")
                        }
                    });  

                }
            } else {
                get_page();
            }

        }
    };
    MainThis.login = function () {
        $(".progressbar-form-modal").addClass("enabled");
        $(".phantervalidator-input-error").each(function(){
            $(this).slideUp();
        });
        var login_pass_b64 = btoa($("#form-login-input-email").val()+":"+$("#form-login-input-password").val())
        var remember_me = 'on';
        if($("#form-login-input-remember_me:checked").length==0){
            remember_me = 'off';
        }
        var data_form = {
            'basic_authorization':login_pass_b64,
            'remember_me':remember_me,
            'csrf_token':$("#form-login-input-csrf_token").val()
        }
        $.ajax({url:remoteHostAddress+"/api/user/login",
                type: "POST",
                crossOrigin: true,
                data:data_form,
                success: function(data, textStatus){
                    $(".progressbar-form-modal").removeClass("enabled");
                    if(data.status=="OK"){
                        $("#modal_layout").modal("close");
                        localStorage.removeItem('lockUser');
                        localStorage.removeItem('lockLastPage');
                        localStorage.setItem("token", data.token)
                        M.toast({html: "Login efetuado com sucesso"});
                        localStorage.setItem("lastUser", JSON.stringify({
                            "url_image_user":data.data_user.url_image_user,
                            "user_name":data.data_user.user_name,
                            "remember_me":data.data_user.remember_me,
                            "user_role":data.data_user.user_role,
                            "email":data.data_user.email
                        }));
                        if(data.temporary_password){
                            phanterpages.getLocalHtml("page-change-password.html", {'aviso':'A senha temporária irá expirar, utilize-a como senha atual para adicionar uma nova senha.'})
                        }else{
                            phanterpages.reload();
                        }

                    } else if(data.status=="ERROR"){
                        $("#form-login-input-csrf_token").val("")
                        M.toast({html: data.message})
                        MainThis.responseValidator(data)
                        MainThis.getCaptcha("login")
                    }
                    MainThis.getLoginCmp();
                },
                headers:{
                    'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                    'Authorization': localStorage.getItem("token")
                    },
                error: function(data){
                    M.toast({html: "Erro na conexão"})
                    $(".progressbar-form-modal").removeClass("enabled");
                    $(".main-progress-bar").removeClass("enabled");
                    _print(data, "login: "+remoteHostAddress+"/api/user/login");
                },
                dataType:"json",
            });
    };
    MainThis.openModalLogin = function(){
        modal_layout.modal({
            "onOpenStart":function(){
                var html_login = JSON.parse(phanterwebCacheDataJS.modals.modal_login);
                modal_layout.html(html_login);
                var last_user = JSON.parse(localStorage.getItem("lastUser"))
                if((last_user!==null)&&(last_user!="")&&(last_user!==undefined)){
                    var url_image_user = last_user.url_image_user
                    var user_name = last_user.user_name
                    var remember_me = last_user.remember_me
                    var user_role = last_user.user_role
                    var email = last_user.email
                    $("#form-login-input-email").val(email);
                    $("#form-login-image-user-url").attr("src", url_image_user);
                    $("#form-login-profile-user-name").html(user_name);
                    $("#form-login-profile-user-role").html(user_role);
                    $("#form-login-input-email-hidden-switch").hide();
                    $("#form-login-input-tittle-hidden-switch").hide();
                    $("#form-login-image-user-container").show();
                    $("#form-login-button-other-user-container")
                        .show()
                        .off('click.form-login-button-other-user-container')
                        .on('click.form-login-button-other-user-container', function(){
                            $("#form-login-input-remember_me").removeAttr('checked')
                            $("#form-login-input-email").val("").focus();
                            $("#form-login-input-email-hidden-switch").slideDown();
                            $("#form-login-input-tittle-hidden-switch").slideDown();
                            $("#form-login-image-user-container").fadeOut();
                            $(this).slideUp();
                            $("#form-login-button-other-user-container");
                            M.updateTextFields();
                            localStorage.removeItem("lastUser")
                        });
                    if(remember_me===true){
                        $("#form-login-input-remember_me").attr('checked', 'checked')
                    }
                }
            },
            "endingTop": '7%',
            "onOpenEnd": function(){
                function loginbykey(event){
                    if(event.which==13){
                        var hasDisabled = $("#form-login-button-login").attr('disabled')
                        if (!(typeof hasDisabled !== typeof undefined && hasDisabled !== false)) {
                            MainThis.login()
                        }                       
                    }
                };
                $(".fechar_modal_layout")
                    .off("click.fechar_modal_layout")
                    .on("click.fechar_modal_layout", function(){
                        modal_layout.modal("close");
                    });
                $("#form-login-button-register")
                    .off("click.form-login-button-register")
                    .on("click.form-login-button-register", function(){
                        modal_layout.modal("close");
                        MainThis.openModalRegister()
                    });
                $("#form-login-button-request-password")
                    .off("click.form-login-button-request-password")
                    .on("click.form-login-button-request-password", function(){
                        modal_layout.modal("close");
                        MainThis.openModalRequestPassword()
                    });
                $("#form-login-button-login")
                    .off("click.form-login-button-login")
                    .on("click.form-login-button-login", MainThis.login);
                $("#form-login-input-email")
                    .off("keyup.form-login-input-email")
                    .on("keyup.form-login-input-email", loginbykey);
                $("#form-login-input-password")
                    .off("keyup.form-login-input-password")
                    .on("keyup.form-login-input-password", loginbykey);
                MainThis.getCaptcha("login");
                var id_parent_input_email = $("#form-login-input-email").parent().parent().is(":hidden")
                if(id_parent_input_email=="form-login-input-email-hidden-switch"){
                    console.log("ooouuu")
                    $("#form-login-input-password").focus();
                } else {
                    $("#form-login-input-email").focus();
                    console.log("ieieie")
                }
            },
        });

        modal_layout.modal("open");
        $("#form-login-user").phanterwebFormValidator()
        $(".progressbar-form-modal").removeClass("enabled");
    };
    MainThis.openModalRegister = function(){
            modal_layout.modal({"onOpenStart":function(){
                    var html_register = JSON.parse(phanterwebCacheDataJS.modals.modal_register);
                    modal_layout.html(html_register);
                    $("#form-register").phanterwebFormValidator();
                },
                "endingTop": '5%',
                "onOpenEnd": function(){
                    function registerbykey(event){
                        if(event.which==13){
                            var hasDisabled = $("#register-ajax-button-submit").attr('disabled')
                            if (!(typeof hasDisabled !== typeof undefined && hasDisabled !== false)) {
                                $("#register-ajax-button-submit").trigger("click")
                            }                       
                        }
                    };
                    $(".fechar_modal_layout")
                        .off("click.fechar_modal_layout")
                        .on("click.fechar_modal_layout", function(){
                            modal_layout.modal("close");
                        });
                    $("#register-ajax-button-login")
                        .off("click.register-ajax-button-login")
                        .on("click.register-ajax-button-login", function(){
                            modal_layout.modal("close");
                            MainThis.openModalLogin()
                        });
                    $("#register-ajax-button-esqueci-minha-senha")
                        .off("click.register-ajax-button-esqueci-minha-senha")
                        .on("click.register-ajax-button-esqueci-minha-senha", function(){
                            modal_layout.modal("close");
                            MainThis.openModalRequestPassword()
                        });
                    $("#register-ajax-button-submit")
                        .off("click.register-ajax-button-submit")
                        .on("click.register-ajax-button-submit", function(){
                            $(".phantervalidator-input-error").each(function(){
                                $(this).slideUp();
                            });
                            $(".progressbar-form-modal").addClass("enabled");
                            $.ajax({url:remoteHostAddress+"/api/user/register",
                                type: "POST",
                                crossOrigin: true,
                                data: $("#form-register").serialize(),
                                success: function(data, textStatus){
                                    if(data.status=="OK"){
                                        M.toast({html: "Registro efetuado com sucesso"});
                                        modal_layout.modal("close");
                                        localStorage.setItem("token", data.token)
                                        localStorage.setItem("lastUser", JSON.stringify({
                                            "url_image_user":data.data_user.url_image_user,
                                            "user_name":data.data_user.user_name,
                                            "remember_me":data.data_user.remember_me,
                                            "user_role":data.data_user.user_role,
                                            "email":data.data_user.email
                                        }));
                                        phanterpages.reload();
                                    } else if(data.status=="ERROR"){
                                        M.toast({html: data.message})
                                        MainThis.responseValidator(data)
                                        MainThis.getCaptcha("register")
                                    }
                                    $(".progressbar-form-modal").removeClass("enabled");
                                },
                                headers:{
                                    'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                                    'Authorization': localStorage.getItem("token")
                                    },
                                error: function(data){
                                    M.toast({html: "Erro na conexão"})
                                    $(".progressbar-form-modal").removeClass("enabled");
                                    $(".main-progress-bar").removeClass("enabled");
                                    _print(data, "openModalRegister: "+remoteHostAddress+"/api/user/register")
                                },
                                dataType:"json"
                            });
                        });
                    var cont=0
                    $("[phanterwebformvalidator_group='register']").each(function(){
                        cont+=1
                        $(this).find("input.form-control")
                            .off("keyup.input"+cont+"-group-register")
                            .on("keyup.input"+cont+"-group-register", registerbykey);
                    });
                    MainThis.getCaptcha("register")
                }
            });
            modal_layout.modal("open");
            $(".progressbar-form-modal").removeClass("enabled");
    };
    MainThis.openModalRequestPassword = function(){
        
            var modal_layout = $("#modal_layout")

            modal_layout.modal({"onOpenStart":function(){
                    var html_request_password = JSON.parse(phanterwebCacheDataJS.modals.modal_request_password);
                    modal_layout.html(html_request_password);
                    $("#form-request-password").phanterwebFormValidator();
                },
                "onOpenEnd": function(){
                    function requestpasswordbykey(event){
                        if(event.which==13){
                            event.preventDefault();
                            var hasDisabled = $("#request-password-ajax-button-submit").attr('disabled')
                            if (!(typeof hasDisabled !== typeof undefined && hasDisabled !== false)) {
                                $("#request-password-ajax-button-submit").trigger('click');
                            }   
                        }
                    };
                    $(".fechar_modal_layout")
                        .off("click.fechar_modal_layout")
                        .on("click.fechar_modal_layout", function(){
                            modal_layout.modal("close");
                        });
                    $("#request-password-ajax-button-login")
                        .off("click.request-password-ajax-button-login")
                        .on("click.request-password-ajax-button-login", function(){
                            modal_layout.modal("close");
                            MainThis.openModalLogin()
                        });
                    $("#request-password-ajax-button-registrar")
                        .off("click.request-password-ajax-button-registrar")
                        .on("click.request-password-ajax-button-registrar", function(){
                            modal_layout.modal("close");
                            MainThis.openModalRegister()
                        });
                    $("#request-password-ajax-button-submit")
                        .off("click.request-password-ajax-button-submit")
                        .on("click.request-password-ajax-button-submit", function(){
                            $(".progressbar-form-modal").addClass("enabled");
                            $.ajax({url:remoteHostAddress+"/api/user/request-password",
                                type: "POST",
                                crossOrigin: true,
                                data: {'email': $("#input-email-request-password").val(),
                                'csrf_token': $("#input-csrf_token").val()},
                                success: function(data, textStatus){
                                    if(data.status=="OK"){
                                        M.toast({html: "Solicitação de nova senha enviada"});
                                        phanterpages.principal()
                                    } else if(data.status=="ERROR"){
                                        M.toast({html: data.message})
                                         MainThis.getCaptcha("request-password") 
                                    }
                                    $(".progressbar-form-modal").removeClass("enabled");
                                },
                                error: function(data){
                                    M.toast({html: "Erro na conexão"})
                                    $(".progressbar-form-modal").removeClass("enabled");
                                    $(".main-progress-bar").removeClass("enabled");
                                    _print(data, "openModalRequestPassword: "+remoteHostAddress+"/api/user/request-password")
                                },
                                headers:{
                                    'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                                    'Authorization': localStorage.getItem("token")
                                    },
                                dataType:"json"
                            }); 
                        });
                    $("#input-email-request-password")
                        .off("keyup.input-email-request-password")
                        .on("keyup.input-email-request-password", requestpasswordbykey);
                    MainThis.getCaptcha("request-password")
                }
            });
            modal_layout.modal("open");
            $(".progressbar-form-modal").removeClass("enabled");
    };
    MainThis.getPhantergaleryProfileUser = function(img_src){
        var html = JSON.parse(phanterwebCacheDataJS.components.component_user_phantergallery)
        $("#profile-image-user-container").html(html)
        $("#phantergallery_object-profile").attr("data-upload-src-img", img_src)
        phanterSvgs.update()
        phanterGallery.update(true)
    };
    MainThis.profile = function(){
        phanterpages.getAdminButton();
        MainThis.getRemoteJson({
            url:"/api/user/info",
            success:function(data){
                if(data.status=="OK"){
                    if (data.authenticated){
                        $("#input-first_name").val(data.info.first_name)
                        $("#input-last_name").val(data.info.last_name)
                        $("#input-email").val(data.info.email)
                        MainThis.getPhantergaleryProfileUser(data.info.url_image_user);

                        phanterpages.getCsrfToInput(
                            "profile",
                            "#form-profile-input-csrf_token", 
                            function(){
                                $("#form-profile").phanterwebFormValidator();
                            });
                        M.updateTextFields();
                        links_href();
                        $("#profile-ajax-button-save")
                            .off('click.profile-ajax-button-save')
                            .on('click.profile-ajax-button-save', function(){
                                $(".main-progress-bar").addClass("enabled");
                                var formData = new FormData($("form.form-profile")[0]);
                                //formData.set("phantergallery_upload-input-file-profile", phanterGallery.phanterGalleryObjs[0].getCuttedImage())
                                $.ajax({url:remoteHostAddress+"/api/user/profile",
                                    type: "POST",
                                    crossOrigin: true,
                                    data: formData,
                                    cache: false,
                                    contentType: false,
                                    processData: false,
                                    success: function(data, textStatus){
                                        if(data.status=="OK"){
                                            if(data.change_email==true){
                                                M.toast({html: "Seu email foi alterado!"})
                                                phanterpages.principal()
                                            } else{
                                                M.toast({html: "Perfil atualizado com sucesso!"})
                                                phanterpages.reload()
                                            }
                                        } else if (data.status=="ATTENTION"){
                                            M.toast({html: data.message})
                                             if('csrf' in data){
                                                $("#form-profile-input-csrf_token").val(data.csrf)
                                            }
                                        } else if (data.status=="ERROR"){
                                            M.toast({html: data.message})
                                            if('csrf' in data){
                                                $("#form-profile-input-csrf_token").val(data.csrf)
                                            }
                                        }
                                        $(".main-progress-bar").removeClass("enabled");
                                    },
                                    headers:{
                                        'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                                        'Authorization': localStorage.getItem("token")
                                        },
                                    error: function(data){
                                        M.toast({html: "Erro na conexão"})
                                        $(".progressbar-form-modal").removeClass("enabled");
                                        $(".main-progress-bar").removeClass("enabled");
                                        _print(data, "profile: "+remoteHostAddress+"/api/user/profile")
                                    },
                                });


                            });
                        /*MainThis.actionBtnChangePassword();*/
                    } else {
                        phanterpages.principal();
                    }
                } else {

                };
            },
            error: function(data){
                M.toast({html: "Erro na conexão"})
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                _print(data, "getRemoteJson: "+remoteHostAddress+"/api/user/info")
            }
        });  
    };
    MainThis.lock = function(){
        MainThis.getRemoteJson({
            url:"/api/user/info",
            success:function(data){
                if(data.status=="OK"){
                    var component_user_nologin = phanterwebCacheDataJS.components.component_user_nologin
                    var component_user_nologin_menu = phanterwebCacheDataJS.components.component_user_nologin_menu
                    $("#echo-user-cmp-login").html(JSON.parse(component_user_nologin));
                    $("#options-top-main-bar-left").html(JSON.parse(component_user_nologin_menu));
                    if (data.authenticated){
                        localStorage.setItem("lockLastPage", localStorage.getItem("lastPage"))
                        localStorage.setItem("lockUser", JSON.stringify(data.info))
                        $("#form-lock-image-user-url").attr('src', data.info.url_image_user)
                        $("#form-lock-profile-user-name").html(data.info.name)
                        $("#form-lock-input-email").val(data.info.email)
                        if(data.info.roles.indexOf("root")>-1){
                            $("#form-lock-profile-user-role").text("Super Administrador")
                        } else if(data.info.roles.indexOf("administrator")>-1){
                            $("#form-lock-profile-user-role").text("Administrador")
                        } else {
                            $("#form-lock-profile-user-role").text("Usuário")
                        }
                        if(data.info.remember_me==true){
                            $("#form-lock-input-remember_me").attr("checked", "checked");
                        }
                        localStorage.removeItem('token');
                        localStorage.removeItem('lastUser');
                    } else {
                        var datalocal = JSON.parse(localStorage.getItem("lockUser"))
                        $("#form-lock-image-user-url").attr('src', datalocal.url_image_user)
                        $("#form-lock-profile-user-name").html(datalocal.name)
                        $("#form-lock-input-email").val(datalocal.email)
                        if(datalocal.roles.indexOf("root")>-1){
                            $("#form-lock-profile-user-role").text("Super Administrador")
                        } else if(datalocal.roles.indexOf("administrator")>-1){
                            $("#form-lock-profile-user-role").text("Administrador")
                        } else {
                            $("#form-lock-profile-user-role").text("Usuário")
                        }
                        if(datalocal.remember_me==true){
                            $("#form-lock-input-remember_me").attr("checked", "checked");
                        }
                    }
                    ComponenteMenu.init();
                    $("#alert-top").slideUp();
                    MainThis.getCsrfToInput("lock", "#form-lock-input-csrf", function(){$("#form-lock-user").phanterwebFormValidator()})
                    $("#form-lock-button-outher-user").on("click", function(){
                        MainThis.openModalLogin();
                        $("#modal_layout").modal("open")
                    });
                    $("#options-bottom-main-bar-left").html("");
                    $("#options-top-main-bar-left").html("");
                    M.toast({html: "Bloqueado"})
                    $(".cmp-bar-user_and_menu-container").fadeOut();
                    $("#materialize-component-left-menu-user").slideUp();
                    $("#fontawesome-component-left-menu-user").slideUp();
                    $("body").css({"background-color":"#424141"}); 
                    $("#form-lock-button-unlock")
                        .off('click.form-lock-button-unlock')
                        .on('click.form-lock-button-unlock', function(){
                            $(".main-progress-bar").addClass("enabled");
                            $(".phantervalidator-input-error").each(function(){
                                $(this).slideUp();
                            });
                            var login_pass_b64 = btoa($("#form-lock-input-email").val()+":"+$("#form-lock-input-password").val())
                            var remember_me = 'on';
                            if($("#form-lock-input-remember_me:checked").length==0){
                                remember_me = 'off';
                            }
                            var data_form = {
                                'basic_authorization':login_pass_b64,
                                'remember_me':remember_me,
                                'csrf_token':$("#form-lock-input-csrf").val()
                            }
                            $.ajax({url:remoteHostAddress+"/api/user/login",
                                    type: "POST",
                                    crossOrigin: true,
                                    data:data_form,
                                    success: function(data, textStatus){
                                        if(data.status=="OK"){
                                            $("body").css({"background-color":"#E0E0E0"}); 
                                            $(".main-progress-bar").removeClass("enabled");
                                            localStorage.setItem("currentPage",localStorage.getItem("lockLastPage"))
                                            localStorage.removeItem('lockUser');
                                            localStorage.removeItem('lockLastPage');
                                            localStorage.setItem("token", data.token)
                                            M.toast({html: "Desbloqueado!"});
                                            localStorage.setItem("lastUser", JSON.stringify({
                                                "url_image_user":data.data_user.url_image_user,
                                                "user_name":data.data_user.user_name,
                                                "remember_me":data.data_user.remember_me,
                                                "user_role":data.data_user.user_role,
                                                "email":data.data_user.email
                                            }));
                                            phanterpages.reload();


                                        } else if(data.status=="ERROR"){
                                            $(".main-progress-bar").removeClass("enabled");
                                            M.toast({html: data.message})
                                            MainThis.responseValidator(data)
                                            MainThis.getCsrfToInput("lock", "#form-lock-input-csrf")
                                        }
                                    },
                                    headers:{
                                        'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                                        'Authorization': localStorage.getItem("token")
                                        },
                                    error: function(data){
                                        M.toast({html: "Erro na conexão"})
                                        $(".progressbar-form-modal").removeClass("enabled");
                                        $(".main-progress-bar").removeClass("enabled");
                                        _print(data, "lock: "+remoteHostAddress+'/api/user/login')
                                    },
                                    dataType:"json",
                                });
                        });
                } else {

                };
            },
            error: function(data){
                M.toast({html: "Erro na conexão"})
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                _print(data, "getRemoteJson: "+remoteHostAddress+"/api/user/info")
            }
        });  
    };
    MainThis.changePassword = function(){
        var aviso = phanterpages.getPamameters()
        if(isNotEmpty(aviso)){
            if("aviso" in aviso){
                $("#aviso_change_password").text(aviso.aviso)
                $("#input-old_password").focus()
            }
        }
        $(".progressbar-form-modal").removeClass("enabled");
        M.updateTextFields();
        $("#form-change-password").phanterwebFormValidator();
        MainThis.getCsrfToInput(
            "change-password",
            "#input-csrf_token",
            function(){
                $("#form-change-password").phanterwebFormValidator();
            });
        $("#change-password-ajax-button-submit")
            .off('click.change-password-ajax-button-submit')
            .on('click.change-password-ajax-button-submit', function(){
                $(".progressbar-form-modal").addClass("enabled");
                $.ajax({url:remoteHostAddress+"/api/user/change-password",
                    type: "POST",
                    crossOrigin: true,
                    data: $(".form-change-password").serialize(),
                    success: function(data, textStatus){
                        if(data.status=="OK"){
                            M.toast({html: "Senha alterada com sucesso!"})
                            phanterpages.getLocalHtml("page-profile.html")
                        } else if(data.status=="ERROR"){
                            M.toast({html: data.message})
                            if("csrf" in data){
                                $("#input-csrf_token").val(data.csrf)
                            }
                        }
                        $(".progressbar-form-modal").removeClass("enabled");
                    },
                    headers:{
                        'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                        'Authorization': localStorage.getItem("token")
                        },
                    error: function(data){
                        M.toast({html: "Erro na conexão"})
                        $(".progressbar-form-modal").removeClass("enabled");
                        $(".main-progress-bar").removeClass("enabled");
                        _print(data, "changePassword: "+remoteHostAddress+"/api/user/change-password")
                    },
                    dataType:"json"
                });
            })
    };
    MainThis.getLoginCmp = function(){
        MainThis.getRemoteJson({
            url:"/api/user/info",
            success:function(data){
                if(data.status=="OK"){
                    if (data.authenticated){
                        if(!data.activated){
                            var form_activate = JSON.parse(phanterwebCacheDataJS.components.component_alert_top_activation)
                            $("#alert-top").html(form_activate)
                            $("#alert-top").slideDown();
                            $("#alert-top").addClass("enabled");
                            $("#alert-top-activation").phanterwebFormValidator()
                            $("#input-code_activation").phanterMask('custom',{'mask':"#####"})
                            M.updateTextFields();
                            $("#input-code_activation").focus()
                            $("#alert-top-activate")
                                .off('click.activate_account')
                                .on('click.activate_account', function(){
                                    $(".main-progress-bar").addClass("enabled");
                                    var code = $("#input-code_activation").val();
                                    if(isACTIVATIONCODE(code)){                                
                                        $.ajax({url:remoteHostAddress+"/api/user/active-code",
                                            type: "POST",
                                            crossOrigin: true,
                                            data: {"code":code},
                                            success: function(data, textStatus){
                                                if(data.status=="OK"){
                                                    $("#alert-top").slideUp();
                                                    M.toast({html: "Conta ativada com sucesso!"});
                                                    phanterpages.principal();
                                                } else if(data.status=="ERROR"){
                                                    M.toast({html: data.message})
                                                }
                                            },
                                            error: function(data){
                                                M.toast({html: "Erro na conexão"})
                                                $(".progressbar-form-modal").removeClass("enabled");
                                                $(".main-progress-bar").removeClass("enabled");
                                                _print(data, "getLoginCmp: "+remoteHostAddress+"/api/user/active-code")
                                            },
                                            headers:{
                                                'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                                                'Authorization': localStorage.getItem("token")
                                                },
                                            dataType:"json"
                                        });
                                    } else {
                                        M.toast({html: "Código Inválido"})
                                    }
                                });
                        }
                        var component_user_login = phanterwebCacheDataJS.components.component_user_login
                        var component_user_login_menu = phanterwebCacheDataJS.components.component_user_login_menu
                        $("#echo-user-cmp-login").html(JSON.parse(component_user_login));
                        $("#options-top-main-bar-left").html(JSON.parse(component_user_login_menu));
                        $("#url_image_user").attr('src', data.info.url_image_user)
                        $("#materialize-component-left-menu-url-imagem-user").attr('src', data.info.url_image_user)
                        $("#form-login-image-user-url").attr('src', data.info.url_image_user)
                        $("#form-lock-image-user-url").attr('src', data.info.url_image_user)
                        $("#user_first_and_last_name_login").html(data.info.name)
                        $("#materialize-component-left-menu-name-user").text(data.info.name)
                        if(data.info.roles.indexOf("root")>-1){
                            $("#user_role_login").text("Usuário")
                        } else if(data.info.roles.indexOf("administrator")>-1){
                            $("#user_role_login").text("Administrador")
                        } else {
                            $("#user_role_login").text("Usuário")
                        }

                        $("#toggle-cmp-bar-user")
                            .off("click.toggle-cmp-bar-user")
                            .on("click.toggle-cmp-bar-user",
                                function(){
                                    enabled_switch($("#toggle-cmp-bar-user").parent())
                                });
                        $(".cmp-bar-usermenu-option")
                            .off("click.cmp-bar-usermenu-option")
                            .on("click.cmp-bar-usermenu-option", 
                                function(){
                                    $("#toggle-cmp-bar-user").parent().removeClass("enabled")
                                });
                        $("#cmp-bar-usermenu-option-logout, #materialize-component-left-menu-submenu-button-logout")
                            .off('click.cmp-bar-usermenu-option-logout')
                            .on('click.cmp-bar-usermenu-option-logout', function(){
                                localStorage.removeItem('token');
                                MainThis.getLoginCmp();
                                M.toast({html: "Volte sempre!"});
                                phanterpages.principal();
                            });
                        links_href();
                        ComponenteMenu.init();
                    } else {
                        var component_user_nologin = phanterwebCacheDataJS.components.component_user_nologin
                        var component_user_nologin_menu = phanterwebCacheDataJS.components.component_user_nologin_menu
                        $("#echo-user-cmp-login").html(JSON.parse(component_user_nologin));
                        $("#options-top-main-bar-left").html(JSON.parse(component_user_nologin_menu));
                        $("#toggle-cmp-bar-user")
                            .off("click.toggle-cmp-bar-user")
                            .on("click.toggle-cmp-bar-user",
                                function(){
                                    enabled_switch($("#toggle-cmp-bar-user").parent())
                                });
                        $(".cmp-bar-usermenu-option")
                            .off("click.cmp-bar-usermenu-option")
                            .on("click.cmp-bar-usermenu-option", 
                                function(){
                                    $("#toggle-cmp-bar-user").parent().removeClass("enabled")
                                });

                        $("#cmp-bar-usermenu-option-login, #materialize-component-left-menu-submenu-button-login")
                            .off('click.cmp-bar-usermenu-option-login')
                            .on('click.cmp-bar-usermenu-option-login', function(){
                                MainThis.openModalLogin();
                            });
                        $("#cmp-bar-usermenu-option-register, #materialize-component-left-menu-submenu-button-register")
                            .off('click.cmp-bar-usermenu-option-register')
                            .on('click.cmp-bar-usermenu-option-register', function(){
                                MainThis.openModalRegister();
                            });
                        $("#cmp-bar-usermenu-option-request-password, #materialize-component-left-menu-submenu-button-request-password")
                            .off('click.cmp-bar-usermenu-option-request-password')
                            .on('click.cmp-bar-usermenu-option-request-password', function(){
                                MainThis.openModalRequestPassword();
                            });
                        links_href();
                        ComponenteMenu.init();
                    }
                } else {

                };
            },
            error: function(data){
                M.toast({html: "Erro na conexão"})
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                _print(data, "getRemoteJson: "+remoteHostAddress+"/api/user/info")
            }
        });  
    };
    MainThis.getAdminButton = function(){
        $("#options-bottom-main-bar-left").html("");
        MainThis.getRemoteJson({
            url:"/api/user/info",
            success:function(data){
                if(data.status=="OK"){
                    if (data.authenticated){
                        if(data.info.roles.indexOf("root")>-1){
                            phanterpages.addButtonPack("button_admin");
                        } else {
                            $("#options-bottom-main-bar-left").html("");
                        };
                    } else {
                        $("#options-bottom-main-bar-left").html("");
                    }
                    ComponenteMenu.init()
                } else {

                };
            },
            error: function(data){
                M.toast({html: "Erro na conexão"})
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                _print(data, "getAdminButton: "+remoteHostAddress+"/api/user/active-code")
            }
        });  
    }
    MainThis.getCsrfCaptcha = function(cmd_option, token_captcha, group){
            var html = JSON.parse(phanterwebCacheDataJS.components.component_preloader_circle_big)
            $("#captcha-"+group+"-container").html(html)
            $.ajax({url:remoteHostAddress+"/api/captcha",
                type: "POST",
                crossOrigin: true,
                data: {"cmd_option":cmd_option,
                       "token_captcha":token_captcha,
                       "group":group
                    },
                success: function(data, textStatus){
                    if(data.status=="OK"){
                        var csrf_token = data.csrf;
                        $("input[name='csrf_token']").val(csrf_token);
                        $(".progressbar-form-modal").removeClass("enabled");
                        $("#captcha-"+group+"-container").html(data.html).fadeIn()
                        $("#captcha-ok-svg-container-"+group).fadeIn();
                    } else if(data.status=="ERROR"){
                        MainThis.getCaptcha(group);
                        M.toast({html: data.message})
                        $(".progressbar-form-modal").removeClass("enabled");
                    }
                },
                headers:{
                    'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                    'Authorization': localStorage.getItem("token")
                    },
                error: function(data){
                    M.toast({html: "Erro na conexão"})
                    $(".progressbar-form-modal").removeClass("enabled");
                    $(".main-progress-bar").removeClass("enabled");
                    _print(data, "getCsrfCaptcha: "+remoteHostAddress+"/api/captcha")
                },
                dataType:"json"
            });
    };
    MainThis.getCaptcha = function(group){
        $.ajax({url:remoteHostAddress+"/api/captcha",
            type: "GET",
            crossOrigin: true,
            data: {"group":group},
            success: function(data, textStatus){
                if(data.status=="OK"){
                    $("#captcha-"+group+"-container").html(data.html)
                    $(".captcha-option")
                        .off("click.captcha-option")
                        .on("click.captcha-option", function(){
                            var cmd_option = $(this).attr("cmd_option");
                            var token_captcha = $(this).attr("token");
                            var group = $(this).attr("id_captcha");
                            MainThis.getCsrfCaptcha(cmd_option, token_captcha, group);
                        });         
                } else if(data.status=="ERROR"){
                    M.toast({html: data.message})
                }
            },
            headers:{
                'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                'Content-Type':'text/html; charset=utf-8',
                'Authorization': localStorage.getItem("token")
                },
            error: function(data){
                M.toast({html: "Erro na conexão"})
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                _print(data, "getCaptcha: "+remoteHostAddress+"/api/captcha")
            },
            dataType:"json"
        });
    };
    MainThis.getLocalHtmlToTarget = function(pagina, target, onsucess){
        $.ajax({url:pagina,
            type: "GET",
            crossOrigin: true,
            success: function(data, textStatus){
                MainThis.currentPage = pagina;
                $(target).html(data);
                onsucess();
            },
            headers:{
                    'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
            },
            error: function(data){
                M.toast({html: "Erro na conexão"})
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                _print(data, "getLocalHtmlToTarget"+remoteHostAddress+"/api/user/active-code")
            },
        });
    };
    MainThis.getCsrfToInput = function(proposito, inputalvo, callback){
        $.ajax({url:remoteHostAddress+"/api/csrf?proposito="+proposito,
            type: "GET",
            crossOrigin: true,
            cache: false,
            data: {},
            success: function(data, textStatus){
                if(data.status=="OK"){
                    $(inputalvo).val(data.csrf);
                }
                if (callback && typeof(callback) === "function"){
                    callback();
                }
            },
            headers:{
                'Cache-Control':'no-store, must-revalidate, no-cache, max-age=0',
                'Authorization': localStorage.getItem("token")
                },
            error: function(data){
                M.toast({html: "Erro na conexão"})
                $(".progressbar-form-modal").removeClass("enabled");
                $(".main-progress-bar").removeClass("enabled");
                _print(data, "getCsrfToInput: "+remoteHostAddress+"/api/csrf?proposito="+proposito);
            },
            dataType:"json",
        });        
    };
    MainThis.addButtonPack = function(buttonpack){
        $("#options-bottom-main-bar-left").html("");
        if(isNotEmpty(buttonpack)){
            if(buttonpack in phanterwebCacheDataJS.buttons){
                $("#options-bottom-main-bar-left").append(JSON.parse(phanterwebCacheDataJS.buttons[buttonpack]));
            } else {
                console.error("'"+buttonpack+"' doesn't in phanterwebCacheDataJS")
            }
        }
        links_href();
        ComponenteMenu.init();
    };
    MainThis.getPamameters = function(){
        var currentpage = JSON.parse(localStorage.getItem("currentPage"));
        if(isNotEmpty(currentpage)){
            return currentpage.parameters
        } else {
            return null
        }
    };
    MainThis.resetParameters = function(){
        var currentpage = JSON.parse(localStorage.getItem("currentPage"));
        currentpage.parameters = {};
        localStorage.setItem("currentPage", JSON.stringify(currentpage));       
    };
    MainThis.setParameters = function(parameters){
        var currentpage = JSON.parse(localStorage.getItem("currentPage"));
        currentpage.parameters = parameters;
        localStorage.setItem("currentPage", JSON.stringify(currentpage));
    };
    MainThis.setParameter = function(parameter, value){
        var currentpage = JSON.parse(localStorage.getItem("currentPage"));
        if(isNotEmpty(currentpage.parameters)){
            currentpage.parameters[parameter] = value;
        } else {
            var parameters = {
            }
            parameters[""+parameter] = value
            currentpage.parameters = parameters
        };
        localStorage.setItem("currentPage", JSON.stringify(currentpage));       
    };
    MainThis.delParameter = function(parameter){
        var currentpage = JSON.parse(localStorage.getItem("currentPage"));
        if(isNotEmpty(currentpage.parameters)){
            delete currentpage.parameters[parameter]
        }
        localStorage.setItem("currentPage", JSON.stringify(currentpage));
    };
};
var phanterpages = new PhanterPages();
var target_page=JSON.parse(localStorage.getItem("currentPage"))
if(isNotEmpty(target_page)){
    phanterpages.getLocalHtml(target_page.page);

}else{
    phanterpages.getLocalHtml("page-layout.html");
};
function links_href(){
    $("[link_href]")
        .off("click.links_href").on("click.links_href", function(){
            var url = $(this).attr("link_href");
            var parameters = $(this).attr("link_href_parameters");
            if (isNotEmpty(parameters)){
                parameters = JSON.parse(parameters);
                phanterpages.getLocalHtml(url, parameters);
            }else{
                phanterpages.getLocalHtml(url);
            }
            $("#left-bar").removeClass("expanded");
        });
}

// _prints
_print({"currentPage":localStorage.getItem("currentPage"), "lastPage": localStorage.getItem("lastPage")});
//touch events


var PHANTERWEB = function(){
    this.init = function(){
        phanterpages.getAdminButton();
        //materializecss
        M.AutoInit();
        var toast = localStorage.getItem("toast");
        if ((toast!==null)&&(toast!==undefined)&&(toast!="")){
            M.toast({html: toast})
            localStorage.removeItem("toast")
        }
        $(".materilize-button-show-hidde-input-new")
            .off("click.materialize_select")
            .on("click.materialize_select", function(){
                var target = $(this).attr("target-switch");
                var target_check = $(this).attr("target-check");
                var el_target = $("#"+target);
                var el_target_check = $("#"+target_check);
                if(el_target.hasClass("actived-select")){
                    el_target.removeClass("actived-select");
                    el_target.addClass("actived-input");
                    el_target_check.removeClass("actived-select");
                    el_target_check.addClass("actived-input");
                } else if(el_target.hasClass("actived-input")){
                    el_target.removeClass("actived-input");
                    el_target.addClass("actived-select");
                    el_target_check.removeClass("actived-input");
                    el_target_check.addClass("actived-select");
                }
            });
        _print("Iniciando PHANTERWEB")
        ajustar_imagem();
        links_href();
        phanterpages.getLoginCmp();
        ComponenteMenu.init()
    }
    return this
}()
$(document).ready(function(){
    PHANTERWEB.init()
    //TouchEmulator();
    $("body").hammer({
  inputClass: Hammer.SUPPORT_POINTER_EVENTS ? Hammer.PointerEventInput : Hammer.TouchInput
    }).on("swiperight.event_menu", function(ev){
            if((ev.gesture.center.x-ev.gesture.deltaX)<10){
                ComponenteMenu.menuExpand();
            }
        }).on("tap.event_menu", function(){
            ComponenteMenu.menuDecrease();
        });
    /*window.onbeforeunload = function() { return "Your work will be lost."; };*/
});