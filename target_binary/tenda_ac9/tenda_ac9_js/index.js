var G = {},
    syncData = null,
    validTimeout = null;;

$(function () {

    //add by xc
    //iframe 内重定向到快速设置页面，则对齐父窗口进行重定向
    if(window.self != window.top){
        parent.window.location.replace(window.location.href);
    }
    //end
    getInitData();
    initEvent();
    G.validate = $.validate({
        custom: function () {
            var netWanType = $("#netWanType").val(),
                vpnWanType = $("[name='vpnWanType']:checked").val(),
                staticIp = $("#staticIp").val(),
                mask = $("#mask").val(),
                gateway = $("#gateway").val(),
                dns1 = $("#dns1").val(),
                dns2 = $("#dns2").val(),
                vpnServer = $("#domain").val(),
                vpnUser = $("#vpn_userName").val(),
                vpnPwd = $("#vpn_password").val(),
                user = $("#adslUser").val(),
                pwd = $("#adslPwd").val(),
                cloneType = $("#cloneType").val(),

                lanIp = $("#lanIp").val(),
                lanMask = $("#lanMask").val(),

                inputMsg = "",
                data = "",
                rel = /[^\x00-\x80]|[\\~;'&"%\s]/,
                mac;

            /*PPTP/L2TP双接入时；若服务器地址为ip，且地址类型为静态。dns可为全空，且dns为空时，向后台传入dnsAuto "1",不为空，传入dnsAuto "0",除此以外的静态IP设置下，dns1不能为空*/
            if ((dns1 === "") && (!($("#dns1").is(":hidden")))) {
                //服务器为域名（不是ip）则首选dns不能为空。
                if ((((!$("#domain").is(":hidden"))) && (!$.validate.valid.ip.all(vpnServer))) || (netWanType === "5")) {} else {
                    return _("Please specify a primary DNS server.");
                }
            }

            if ((netWanType === "3") || (netWanType === "4")) {
                //同网段判断
                if (checkIpInSameSegment(vpnServer, lanMask, lanIp, lanMask)) {
                    inputMsg = _("%s and %s (%s) must not be in the same network segment.", [_("Server IP Address"), _("LAN IP Address"), lanIp]);
                }
            }

            if ((netWanType == 1) || ((netWanType == 3) && (vpnWanType == 0)) || ((netWanType == 4) && (vpnWanType == 0)) || ((netWanType == 5) && (vpnWanType == 0))) { //static IP
                //同网段判断
                if (checkIpInSameSegment(staticIp, mask, lanIp, lanMask)) {
                    return _("%s and %s (%s) must not be in the same network segment.", [_("WAN IP Address"), _("LAN IP Address"), lanIp]);
                }

                if (!checkIpInSameSegment(staticIp, mask, gateway, mask)) {
                    return _("The gateway and the IP address must be in the same network segment.");
                }
                if (staticIp == gateway) {
                    return _("The IP address and gateway cannot be the same.");
                }
                if (staticIp == dns1) {
                    return _("The IP address and primary DNS server cannot be the same.");
                }
                if (staticIp == dns2) {
                    return _("The IP address and secondary DNS server cannot be the same.");
                }
                if ((dns1 === dns2) && (dns1 !== "")) {
                    return _("The primary DNS server and secondary DNS server cannot be the same.");
                }

                var mask_arry = mask.split("."),
                    ip_arry = staticIp.split("."),
                    mask_arry2 = [],
                    maskk,
                    netIndex = 0,
                    netIndexl = 0,
                    bIndex = 0;
                if (ip_arry[0] == 127) {
                    return _("The IP address cannot begin with 127.");
                }
                if (ip_arry[0] == 0 || ip_arry[0] >= 224) {
                    return _("Incorrect IP address.");
                }

                for (var i = 0; i < 4; i++) { // IP & mask
                    if ((ip_arry[i] & mask_arry[i]) == 0) {
                        netIndexl += 0;
                    } else {
                        netIndexl += 1;
                    }
                }

                for (var i = 0; i < mask_arry.length; i++) {
                    maskk = 255 - parseInt(mask_arry[i], 10);
                    mask_arry2.push(maskk);
                }
                for (var k = 0; k < 4; k++) { // ip & 255-mask
                    if ((ip_arry[k] & mask_arry2[k]) == 0) {
                        netIndex += 0;
                    } else {
                        netIndex += 1;
                    }
                }
                if (netIndex == 0 || netIndexl == 0) {
                    return _("The IP address must not indicate a network segment.");
                }
                for (var j = 0; j < 4; j++) { // ip | mask
                    if ((ip_arry[j] | mask_arry[j]) == 255) {
                        bIndex += 0;
                    } else {
                        bIndex += 1;
                    }
                }

                if (bIndex == 0) {
                    return _("The IP address cannot be a broadcast IP address.");
                }
            }

            //add by xc 點擊下一步 清除定時器
            if(!$("#internet").hasClass('none')){
                validTimeout && clearTimeout(validTimeout);
            }
        },

        success: function () {
            var netWanType = $("#netWanType").val(),
                vpnWanType = $("[name='vpnWanType']:checked").val(),
                staticIp = $("#staticIp").val(),
                mask = $("#mask").val(),
                gateway = $("#gateway").val(),
                dns1 = $("#dns1").val(),
                dns2 = $("#dns2").val(),
                vpnServer = $("#domain").val(),
                vpnUser = $("#vpn_userName").val(),
                vpnPwd = $("#vpn_password").val(),
                user = $("#adslUser").val(),
                pwd = $("#adslPwd").val(),
                cloneType = $("#cloneType").val(),

                lanIp = $("#lanIp").val(),
                lanMask = $("#lanMask").val(),
                dnsAuto;

            dnsAuto = vpnWanType;

            if (!($("#dns1").is(":hidden"))) {
                if ((dns1 === dns2) && (dns1 === "")) {
                    dnsAuto = 1;
                } else {
                    dnsAuto = 0;
                }
            }


            if ($("#cloneType").val() == "0") {
                mac = G.data.defMac.toUpperCase();
            } else if ($("#cloneType").val() == "1") {
                mac = G.data.deviceMac.toUpperCase();
            } else {
                mac = $("#mac").val().toUpperCase();
            }

            var internetObj = [{
                "netWanType": netWanType,
                "cloneType": cloneType,
                "mac": mac
            }, {
                "netWanType": netWanType,
                "staticIp": staticIp,
                "mask": mask,
                "gateway": gateway,
                "dns1": dns1,
                "dns2": dns2,
                "cloneType": cloneType,
                "mac": mac
            }, {
                "netWanType": netWanType,
                "adslUser": user,
                "adslPwd": pwd,
                "cloneType": cloneType,
                "mac": mac
            }, {
                "netWanType": netWanType,
                "vpnServer": vpnServer,
                "vpnUser": vpnUser,
                "vpnPwd": vpnPwd,
                "vpnWanType": vpnWanType,
                "staticIp": staticIp,
                "mask": mask,
                "gateway": gateway,
                "dns1": dns1,
                "dns2": dns2,
                "cloneType": cloneType,
                "mac": mac,
                "dnsAuto": dnsAuto
            }, {
                "netWanType": netWanType,
                "vpnServer": vpnServer,
                "vpnUser": vpnUser,
                "vpnPwd": vpnPwd,
                "vpnWanType": vpnWanType,
                "staticIp": staticIp,
                "mask": mask,
                "gateway": gateway,
                "dns1": dns1,
                "dns2": dns2,
                "cloneType": cloneType,
                "mac": mac,
                "dnsAuto": dnsAuto
            }, {
                "netWanType": netWanType,
                "adslUser": user,
                "adslPwd": pwd,
                "vpnWanType": vpnWanType,
                "staticIp": staticIp,
                "mask": mask,
                "gateway": gateway,
                "dns1": dns1,
                "dns2": dns2,
                "cloneType": cloneType,
                "mac": mac,
                "dnsAuto": dnsAuto
            }];

            data = objTostring(internetObj[parseInt(netWanType)]);
            $.post("goform/fast_setting_internet_set", data);

            $("#internet").addClass("none");
            $("#wifi_setting").removeClass("none");
            $("#wrlPassword").focus();
            $("#step-over").addClass("none");
        },

        error: function (msg) {
            if (msg !== "") {
                showErrMsg("message-net", msg);
                setTimeout(function () {
                    showErrMsg("message-net", "&nbsp;");
                }, 3000);
            }
        }
    });
    G.browserLang = getBrowserLang();
    $("#changePwdEn")[0].checked = false;
    clickLoginPwd();
    $('#username').addPlaceholder(_("User Name"));
    $('#password').initPassword(_("Password"), false, false);
    $('#adslUser').addPlaceholder(_("Enter the user name from your ISP."));
    $('#adslPwd').initPassword(_("Enter the password from your ISP."), false, false);
    $('#vpn_password').initPassword(_(""), false, false);

    var langTxt = Butterlate.langArr;
    $("#langToggle span").html(langTxt[B.getLang()]);

    /**
     * add by xc
     * 账号同步功能
     */

    var isAC5 = CONFIG_SYNC_ACCOUNT;

    if(isAC5 === "y"){
        $("#ac5-set").removeClass('none');
        $("#btnSync").removeClass('none');

        getSyncData();
        $("#btnSync").off("click.modaldialog").on("click.modaldialog",function(){
            $(this).modalDialog({
                title:$("#syncwrapTitle").text(),
                content:$("#syncwrap"),
                width:822
            });
        });
    }

    function getSyncData(){
        window.setTimeout(function(){
        //发送请求--getSyncAccount
            $.get("goform/getSyncAccount?" + Math.random(), function (obj) {
                //请求未超时，则清除定时器
                validTimeout && clearTimeout(validTimeout);
                validTimeout = null;
                try{
                    obj && (obj = JSON.parse(obj));
                    syncCallback(obj);
                }
                catch(e) {
                    console.log(e);
                }
            });
        },0);

        // 请求超时后，重新发送请求，超时时间为2s
        validTimeout = window.setTimeout(function(){
            getSyncData();
        }, 2000);
    }

    function syncCallback(data){
        //数据已返回，直接退出
        if(!!syncData) return;

        if(data && data.status == 1){
            syncData = data;
            $("#adslUser").val(syncData.username).click();
            $("#adslPwd,#adslPwd_").val(syncData.password).click();
            $("#btnSync").addClass('none');
            $("#hasSync").removeClass('none');

            $("#btnSync").modalDialog("hide");
        }else{
            //请求之间间隔500秒
            setTimeout(function(){
                getSyncData();
            },500);
        }
    }
    /**
     * AC5 特定功能end
     */
});

function getInitData() {
    /*G.data = {
        "net": "1",   //是否检测网络
        "line": "0",  //是否连接网线
        "wanType":"2"  //2 pppop 0 dhcp
    };*/
    G.checkNet = false;
    G.checkLine = false;
    G.accessType = 1; //1有线，2无线
    //获取数据，产品名称，根据产品名称显示图片
    $.getJSON("goform/getProduct" + "?" + Math.random(), function (obj) {
        /*if (obj.product) {
            $("#product_name").attr("src", "./img/" + obj.product.toLowerCase() + ".png");
        } else {
            $("#product_name").attr("src", "./img/" + "fh1203" + ".png");
        }*/

        G.accessType = obj.accessType;
    });


    $.getJSON("goform/fast_setting_get" + "?" + Math.random(), function (obj) {
        var host = location.host;
        /*路由器不能上网时，访问网站dns解析到192.168.0.2；当路由器可以上网后，域名解析正常了，所以原有的访问失效了，所以不能配置路由器
        解决办法：提取浏览器的输入框域名：如果不是www.tendawifi.com、tendawifi.com和管理ip，页面做一个跳转*/
        if ((obj.lanIp !== host) && ('tendawifi.com' !== host)) {
            location.host = 'tendawifi.com';
        }
    });

    $.validate.valid.ppoe = {
        all: function (str) {
            var ret = this.specific(str);

            if (ret) {
                return ret;
            }
        },
        specific: function (str) {
            var ret = str;
            var rel = /[^\x00-\x80]|[~;'&"%\s]/;
            if (rel.test(str)) {
                return _("Can't contain ~;'&\"% and space and Chinese character.");
            }
        }
    };

    $.validate.valid.wanmask = {
        all: function (str) {
            var rel = /^(255|254|252|248|240|224|192|128)\.0\.0\.0$|^(255\.(254|252|248|240|224|192|128|0)\.0\.0)$|^(255\.255\.(254|252|248|240|224|192|128|0)\.0)$|^(255\.255\.255\.(255|254|252|248|240|224|192|128|0))$/;
            if (!rel.test(str)) {
                return _("Please enter a valid subnet mask.");
            }

        }
    };
}

function initLang() {
    var lis = "";
    var configLang = CONFIG_MULTI_LANGUAGE_SORFWARE;
    var lang = configLang.split(",");
    $.each(lang,function (i,val) {
        var v = eval("Butterlate.langArr."+val)
        lis += "<li><a data-country="+val+">"+v+"</a></li>";
        G.langList = lis;
        $("#langMenu").html(G.langList)
    });
}

function clickLoginPwd() {
    if ($("#changePwdEn")[0].checked) {
        $("#loginPwd").parent().parent().css("display", "none");
        $("#hideLoginPwd").parent().css("display", "none");
    } else {
        $("#loginPwd").parent().parent().css("display", "");
        $("#hideLoginPwd").parent().css("display", "");
    }
}

function clickHideWrlPwd() {
    if ($("[name='hideWrlPwd']")[0].checked === true) {
        $("#wrlPassword").attr("disabled", true);
    } else {
        $("#wrlPassword").attr("disabled", false);
    }
}

function clickHideLoginPwd() {
    if ($("[name='hideLoginPwd']")[0].checked === true) {
        $("#loginPwd").attr("disabled", true);
		if($("#loginPwd_").length > 0) {
			$("#loginPwd_").attr("disabled", true);
		}
    } else {
        $("#loginPwd").attr("disabled", false);
		if($("#loginPwd_").length > 0) {
			$("#loginPwd_").attr("disabled", false);
		}
    }
}

function wanTypeSelect(wan_type) {

    $('#internet-form input:text, #internet-form input:password').val("");
    switch (parseInt(wan_type)) {
    case 0:
        $("#static_ip").addClass("none");
        $("#ppoe_set").addClass("none");
        $("#double_access").addClass("none");
        break;
    case 1:
        $("#static_ip").removeClass("none");
        $("#ppoe_set").addClass("none");
        $("#double_access").addClass("none");
        break;
    case 2:
        $("#static_ip").addClass("none");
        $("#ppoe_set").removeClass("none");
        $("#double_access").addClass("none");
        if(syncData && syncData.status == 1){
            $("#adslUser").val(syncData.username).click();
            $("#adslPwd,#adslPwd_").val(syncData.password).click();
        }
        break;
    case 3:
        $("#static_ip").addClass("none");
        $("#ppoe_set").addClass("none");
        $("#double_access").removeClass("none");
        $("#double_access #serverInfo").removeClass("none");
        $('[name="vpnWanType"]')[0].checked = true;
        break;
    case 4:
        $("#static_ip").addClass("none");
        $("#ppoe_set").addClass("none");
        $("#double_access").removeClass("none");
        $("#double_access #serverInfo").removeClass("none");
        $('[name="vpnWanType"]')[0].checked = true;
        break;
    case 5:
        $("#static_ip").addClass("none");
        $("#ppoe_set").removeClass("none");
        $("#double_access").removeClass("none");
        $("#double_access #serverInfo").addClass("none");
        $('[name="vpnWanType"]')[0].checked = true;
        if(syncData && syncData.status == 1){
            $("#adslUser").val(syncData.username).click();
            $("#adslPwd,#adslPwd_").val(syncData.password).click();
        }
        break;
    default:
        break;
    }
}

function changeMacType() {
    if ($("#cloneType").val() == "0" || $("#cloneType").val() == "1") {
        $("#other-mac").addClass("none");
        $("#macaddress").removeClass("none");
        if ($("#cloneType").val() == "0") {
            $("#mac-address").html(_("Default: ") + G.data.defMac.toUpperCase());
        } else {
            $("#mac-address").html(_("Local: ") + G.data.deviceMac.toUpperCase());
        }
    } else {
        $("#other-mac").removeClass("none");
        $("#macaddress").addClass("none");
    }
    top.initIframeHeight();
}

function initEvent() {
    initLang();
    $("#start-btn").on("click", startSet);
    $("#step-next").on("click", nextSet);
    $("#more_set").on("click", moreSet);
    $("#step-over").on("click", overStep);
    $(".mastbody .input-text").on("focus", addFocus);
    $(".mastbody .input-text").on("blur", delFocus);
    $("#back, .iframe-close").on("click", backSetWifi);
    $("#continue").on("click", continueSet);

    $("#changePwdEn").on("click", clickLoginPwd);
    $("#hideWrlPwd").on("click", clickHideWrlPwd);
    $("#hideLoginPwd").on("click", clickHideLoginPwd);

    $(document).on("keydown", function (event) {
        if (event.keyCode == 13) {
            //startSet, nextSet, moreSet, overStep,continueSetcontinue==
            /*if(!$("#step1").hasClass("none")) {
                //进行开始设置
                startSet();
            } else if(!$("#step2").hasClass("none")){
                if(!$("#confirmNext").hasClass("none")) {
                    backSetWifi();
                } else {
                    nextSet();
                }
            }*/

            if (!$("#first_begin").hasClass("none")) {
                //进行开始设置
                startSet();
            } else {
                if (!$("#confirmNext").hasClass("none")) {
                    backSetWifi();
                } else {
                    nextSet();
                }
            }
        }
    });

    //$("#url_link").on("click",function() {
    //  window.open("http://wifi.yunos.com/aliwifi/down.htm","_blank");
    //});


    //语言选择
    $("#langToggle").on("click", function () {
        if ($("#langMenu").hasClass("none")) {
            $("#langMenu").removeClass("none")
        } else {
            $("#langMenu").addClass("none")
        }
    });
    $("#langMenu a").on("click", function () {
        $("#langToggle span").html($(this).html());
        $("#langMenu").addClass("none")
        B.setLang($(this).attr("data-country"));
        setTimeout("location.reload()", 300);
    })
    $(document).on("click", function (e) {
        if ($(e.target).parents("#lang").length == 0)
            $("#langMenu").addClass("none");
    });

    $("#netWanType").on("change", function () {
        wanTypeSelect($("#netWanType").val());
    });

    $("[name='vpnWanType']").on("click", function () {
        if ($(this).val() === "1") {
            $("#static_ip").addClass("none");
        } else {
            $("#static_ip").removeClass("none");
        }
    });

    $("#cloneType").on("change", changeMacType);

    $("[name='addr-type']").on("click", function () {
        if ($(this).val() === "1") {
            $("#static_ip").addClass("none");
        } else {
            $("#static_ip").removeClass("none");
        }
    });
}

function showMsg(className, str) {
    $("." + className).html(str);
    /*setTimeout(function() {
        $("."+className).html("&nbsp;");
    },2000)*/
}

function delFocus() {
    $(this).parent().parent().removeClass("text-focus");
}

function addFocus() {
    $(this).parent().parent().addClass("text-focus");
}

var outTypeMsg = {
    "0": _("Dynamic IP Address"),
    "1": _("Static IP Address"),
    "2": _("PPPoE"),
    "3": _("Russia PPTP"),
    "4": _("Russia L2TP"),
    "5": _("Russia PPPoE")
};

function initValue(obj) {
    var recommendType = 1; //未检测到联网方式时默认为静态
    G.data = obj;

    $("#ssid").val(G.data.ssid);
    $("#wrlPassword").val(G.data.wrlPassword);
    $('#wrlPassword').initPassword(_("WiFi password of 8-32 characters"), false, false);
    $('#loginPwd').initPassword(_("Login password of 5-32 characters"), false, false);
    $("#power").val(G.data.power);
    $("#lanIp").val(G.data.lanIp);
    $("#lanMask").val(G.data.lanMask);
    $("#staticIp,#mask,#gateway,#dns1,#dns2").inputCorrect("ip");

    if (G.data.power == "high") { //高功率
        $("#power_setting").css("display", "none");
    } else { //低功率
        $("#power_setting").css("display", "");
    }
    $('#ssid').addPlaceholder(_("WiFi Name"));

    if (G.data.line == 1) { //已插网线
        //G.data.net = 0;
        $("#net_setting").addClass("none");
        if (G.data.net == 1) { //是否检测完
            if ($("#step-over").hasClass("none")) {
                //表示已经通过了这个检测，就不需要再进行了
                return;
            }
            G.checkNet = true;
            $("#net_find").addClass("none");
            $("#internet").removeClass("none");
            $("#netWanType").focus();
            if (G.browserLang === "RU" || G.browserLang === "UK") {
                $("#macCloneWrapper").removeClass("none");
                $("#netWanType").append('<option value="3">Russia PPTP</option><option value="4">Russia L2TP</option><option value="5">Russia PPPoE</option>');
            }

            //初始化推荐的联网方式
            if ((G.data.wanType === 0) || (G.data.wanType === 1) || (G.data.wanType === 2)) {
                recommendType = G.data.wanType;
            } else {
                recommendType = G.data.outType
            }
            $("#recommend-mode").html(" " + outTypeMsg[recommendType]);
            if (G.browserLang === "RU" || G.browserLang === "UK") {
                $('.recommend').addClass("none");
            } else if (G.data.timeout !== "1") {
                $('.recommend').removeClass("none");
            } else {
                $('.recommend').html(_("Detection timed out. Please select your connection type manually."));
            }
            $('#netWanType').val(recommendType);
            wanTypeSelect(recommendType);

            $("#step-next").val(_("Next"));
        } else {

            $("#net_find").removeClass("none");
            setTimeout(function () {
                $.getJSON("goform/fast_setting_get" + "?" + Math.random(), initValue);
            }, 5000);
        }
    } else {
        $("#net_find").addClass("none");
        if ($("#step-over").hasClass("none")) {
            //表示已经手动跳过wan口检测了

        } else {
            $("#net_setting").removeClass("none");

            G.time = setTimeout(function () {
                $.getJSON("goform/fast_setting_get" + "?" + Math.random(), initValue);
            }, 2000);
        }
    }

    if (!$("#net_find").hasClass("none")) {
        $("#btn_control").addClass("none");
    } else {
        $("#btn_control").removeClass("none");
    }

    //Mac init
    $("#cloneType").val(G.data.cloneType);
    $("#mac").val(G.data.mac).addPlaceholder(_("Format: XX:XX:XX:XX:XX:XX"));
    changeMacType();
}

function startSet() {
    $("body").removeClass("index-body");
    //$("#step1").addClass("none");
    $("#first_begin").addClass("none");
    //$("#step2").removeClass("none");
    $("#net_find").removeClass("none");
    //隐藏语言选择框
    $("#lang").addClass("none");
    /*$.ajaxSetup({
        error:function(x,e){
            setTimeout(function() {
                top.location.reload(true)}
            ,4000);
            return false;
        }
    });*/

    $.getJSON("goform/fast_setting_get?" + Math.random(), initValue);

}

// function getTimeZone() {
//     var a = [],
//         b = new Date().getTime(),
//         zone = new Date().getTimezoneOffset() / -60,
//         timeZoneStr;
//
//     /*if (a = displayDstSwitchDates()) {
//         if (a[0] < a[1]) {
//             if (b > a[0] && b < a[1]) {
//                 zone--;
//             }
//         } else {
//             if (b > a[0] || b < a[1]) {
//                 zone--;
//             }
//         }
//     }*/
//
//     if (zone > 0) {
//         zone = ((zone * 100) + 0); //变成600
//         if (zone < 1000) {
//             zone = "+0" + zone;
//         } else {
//             zone = "+" + zone;
//         }
//
//     } else if (zone < 0) {
//         zone = zone * (-100); //变成650
//         if (zone < 1000) {
//             zone = "-0" + zone;
//         } else {
//             zone = "-" + zone;
//         }
//     } else {
//         zone = "+0000";
//     }
//
//     timeZoneStr = zone.slice(0, zone.length - 2) + ":" + zone.slice(-2);
//
//     return timeZoneStr;
// }
function getTimeZone() {
    var a = [],
        b = new Date().getTime(),
        zone = new Date().getTimezoneOffset() / -60,
        timeZoneStr;

    /*if (a = displayDstSwitchDates()) {
        if (a[0] < a[1]) {
            if (b > a[0] && b < a[1]) {
                zone--;
            }
        } else {
            if (b > a[0] || b < a[1]) {
                zone--;
            }
        }
    }*/

    var z_split = zone.toString().split(".");
    var decimal;

    if( zone%1 == 0){
        decimal = 0;
    }else{
        decimal = "0."+z_split[1];
    }

    if (zone > 0) {
        zone = ((z_split[0] * 100) + decimal*60); //变成600
        if (zone < 1000) {
            zone = "+0" + zone;
        } else {
            zone = "+" + zone;
        }

    } else if (zone < 0) {
        zone = ((z_split[0] * (-100)) + decimal*60); //变成650
        if (zone < 1000) {
            zone = "-0" + zone;
        } else {
            zone = "-" + zone;
        }
    } else {
        zone = "+0000";
    }

    timeZoneStr = zone.slice(0, zone.length - 2) + ":" + zone.slice(-2);

    return timeZoneStr;
}

function nextSet() {
    var data;
    if (!$("#net_find").hasClass("none")) {
        setTimeout(function () {
            $.getJSON("goform/fast_setting_get" + "?" + Math.random(), initValue);
        }, 5000);
    } else if (!$("#net_setting").hasClass("none")) {
        //未插网线
        $.getJSON("goform/fast_setting_get" + "?" + Math.random(), function (obj) {
            G.data = obj;
            if (G.data.line == 1) {
                /*if (G.data.wanType == 0) {
                    $("#dhcp_setting").removeClass("none");
                    $("#net_setting").addClass("none");
                    $("#step-next").val(_("Next"));
                    $("#step-over").addClass("none");
                } else if (G.data.wanType == -1) {
                    $("#net_setting").addClass("none");
                    $("#net_find").removeClass("none");
                    $("#btn_control").addClass("none");
                    nextSet();
                } else if (G.data.wanType == -2) {
                    $("#static_setting").removeClass("none");
                    $("#net_setting").addClass("none");
                    $("#step-next").val(_("Next"));
                    $("#step-over").addClass("none");
                } else if (G.data.wanType == 2) {
                    $("#ppoe_setting").removeClass("none");
                    //$("#username")[0].focus();
                    $("#net_setting").addClass("none");
                    $("#step-next").val(_("Next"));
                } else {
                    $("#net_setting").addClass("none");
                    $("#net_find").removeClass("none");
                }*/
            } else {
                showMsg("main-text", _("Connect the Ethernet cable with internet connectivity to the Internet port and then proceed with the configuration."));
                //继续按钮
                $(".main-text").css("color", "red");
                //moveL();
                //setTimeout(moveR, 50);
                //setTimeout(moveL, 100);
                //setTimeout(moveR, 150);
                //setTimeout(moveR, 150);
            }
        });

    }
    /*else if (!$("#dhcp_setting").hasClass("none")) {
           $("#dhcp_setting").addClass("none")
           $("#wifi_setting").removeClass("none");
           $("#wrlPassword").focus();
       } else if (!$("#static_setting").hasClass("none")) {
           $("#static_setting").addClass("none")
           $("#wifi_setting").removeClass("none");
           $("#wrlPassword").focus();
       } else if (!$("#ppoe_setting").hasClass("none")) {
           var user = $("#username").val(),
               pwd = $("#password").val(),
               data = "",
               //rel = /[\\"']/g;
               rel = /[^\x00-\x80]|[\\~;'&"%\s]/;
           if (user == "" || pwd == "") {
               showErrMsg("message-error", _("Please specify your ISP user name and password."));
               return;
           }
           if (rel.test(user) || rel.test(pwd)) {
               showErrMsg("message-error", _("An ISP user name or password cannot contain space, backslash (\\), tilde (~), semicolon (;), apostrophe ('), ampersand (&), double-quotation mark (\"), or percentage mark( % )."));
               return;
           }
           data = "username=" + encodeURIComponent(user) + "&password=" + encodeURIComponent(pwd);

           $("#step-next").blur();

           $.post("goform/fast_setting_pppoe_set", data, handPpoe);
       }*/
    else if (!$("#wifi_setting").hasClass("none")) {
        //验证无线
        var ssid = $("#ssid").val(),
            wrlPwd = $("#wrlPassword").val(),
            loginPwd = $("#loginPwd").val();
        rel = /[!@#$%^]/g;
        rel_str = /[^\x00-\x80]/;
        if (ssid == "") {
            showErrMsg("message-ssid", _("Please specify a WiFi name. "));
            return;
        }

        /*if (ssid.charAt(0) == " " || ssid.charAt(ssid.length - 1) == " ") {
            showErrMsg("message-ssid", _("The first and last characters of WiFi Name cannot be spaces."));
            return;
        }*/

        if (getStrByteNum(ssid) > 29) {
            showErrMsg("message-ssid", _("The WiFi name can contain only a maximum of %s bytes.", [29]));
            return;
        }

        if ((wrlPwd !== "") && ($("#hideWrlPwd")[0].checked === false)) {
            if (wrlPwd.charAt(0) == " " || wrlPwd.charAt(wrlPwd.length - 1) == " ") {
                showErrMsg("message-ssid", _("The first and last characters of WiFi Password cannot be spaces."));
                return;
            }

            if (!/^[\x00-\x80]{8,32}$/.test(wrlPwd)) {
                showErrMsg("message-ssid", _("WiFi Password must consist of 8-32 characters."));
                return;
            }

            var login_pwd;
            if (!$("#changePwdEn")[0].checked) {

                //需要密码;
                if (!$("#hideLoginPwd")[0].checked) {
                    if (!/^[\x00-\x80]{5,32}$/.test(loginPwd)) {
                        showErrMsg("message-ssid", _("Login Password must consist of 5-32 characters."));
                        return;
                    }
                    if (loginPwd.charAt(0) == " " || loginPwd.charAt(loginPwd.length - 1) == " ") {
                        showErrMsg("message-ssid", _("The first and last characters of Login Password cannot be spaces."));
                        return;
                    }
                    login_pwd = $("#loginPwd").val();

                    //无需密码;
                } else {
                    login_pwd = "";
                }

            } else {
                login_pwd = wrlPwd;
            }

            //TODO:hack wan connected
            //$("#waiting").removeClass("none");
            //$("#wifi_setting").addClass("none");
            //$("#btn_control").addClass("none");

            var dateArry = /([\+\-]\d{2})(\d{2})/.exec((new Date()).toString());

            var subObj = {
                "ssid": $("#ssid").val(),
                "wrlPassword": ($("#hideWrlPwd").prop("checked")) ? "" : wrlPwd,
                "power": $("#power").val(),
                "timeZone": getTimeZone(),
                "loginPwd": ($("#hideLoginPwd").prop("checked")) ? "" : hex_md5(login_pwd)
            }
            data = objTostring(subObj);
            $.getJSON("goform/getWanConnectStatus?" + Math.random(), function (obj) {
                G.wanStatus = obj.connectStatus;
                $.post("goform/fast_setting_wifi_set", data, handWifi);
            });
        } else {

            if (!$("#changePwdEn")[0].checked && !$("#hideLoginPwd")[0].checked) {
                if (!/^[\x00-\x80]{5,32}$/.test(loginPwd)) {
                    showErrMsg("message-ssid", _("Login Password must consist of 5-32 characters."));
                    return;
                }
                if (loginPwd.charAt(0) == " " || loginPwd.charAt(loginPwd.length - 1) == " ") {
                    showErrMsg("message-ssid", _("The first and last characters of Login Password cannot be spaces."));
                    return;
                }

            }
            /* else if (!$("#hideLoginPwd")[0].checked) {
                showErrMsg("message-ssid", _("Please specify a WiFi password before setting it as the login password."));
                return;
            }*/
            $("#wifi_setting").addClass("none");
            $("#btn_control").addClass("none");
            $("input[type='text'], input[type='password']").blur();
            $("#confirmNext").removeClass("none");
        }
    } else if (!$("#internet").hasClass("none")) {
        G.validate.checkAll();
    }
}

function moveL() {
    $(".main-text").css("color", "red");
    $(".main-text").animate({
        "padding-left": "20px"
    }, "fast");
}

function moveR() {
    $(".main-text").animate({
        "padding-left": "0px"
    }, "fast");
}

function backSetWifi() {
    $("#confirmNext").addClass("none");
    $("#wifi_setting").removeClass("none");
    $("#btn_control").removeClass("none");
    $("#wrlPassword").focus();
}

function continueSet() {
    var data = "";
    //TODO:hack wan connected
    $("#confirmNext").addClass("none");
    //$("#waiting").removeClass("none");
    var dateArry = /([\+\-]\d{2})(\d{2})/.exec((new Date()).toString());

    var subObj = {
        "ssid": $("#ssid").val(),
        "wrlPassword": "",
        "power": $("#power").val(),
        "timeZone": getTimeZone(),
        "loginPwd": ($("#hideLoginPwd").prop("checked") || $("#changePwdEn").prop("checked")) ? "" : hex_md5($("#loginPwd").val())
    }
    data = objTostring(subObj);
    //data = "ssid=" + encodeURIComponent($("#ssid").val()) + "&wrlPassword=" + encodeURIComponent($("#wrlPassword").val());
    $.getJSON("goform/getWanConnectStatus?" + Math.random(), function (obj) {
        G.wanStatus = obj.connectStatus;
        $.post("goform/fast_setting_wifi_set", data, handWifi);
    });
}

function showFinish() {
    $("#btn_control").addClass("none");
    if (G.wanStatus == "7") {
        //已联网，
        $(".loadding-ok img").attr("src", "./img/ok_connected.png")
        $("#waiting").addClass("none");
        $("#set_ok").removeClass("none");
        $("#wifi_setting").addClass("none");

        $("#ssid_2g").html($("#ssid").val());
        $("#ssid_5g").html($("#ssid").val() + "_5G");
        $("#connected").removeClass("none");
        if (G.accessType == 1) {
            $("#connected-tip, .wel-button").removeClass("none");
        } else {
            $("#connected-tip, .wel-button").addClass("none");
        }

    } else {
        //TODO: 跳转到未联网状态,即不显示恭喜您可以上网了
        //倒计时完成后需要再次获取wan口数据，如果G.wanStatus仍然不等于7，则不显示恭喜您可以上网了
        //$.getJSON("goform/getWanConnectStatus?"+Math.random(),function(obj) {
        //G.wanStatus = obj.connectStatus;
        //G.wanStatus = "6";
        $("#waiting").addClass("none");
        $("#set_ok").removeClass("none");
        $("#wifi_setting").addClass("none");

        $("#ssid_2g").html($("#ssid").val());
        $("#ssid_5g").html($("#ssid").val() + "_5G");

        if (G.wanStatus == 7) {
            $(".loadding-ok img").attr("src", "./img/ok_connected.png")
            $("#connected").removeClass("none");

            if (G.accessType == 1) {
                $("#connected-tip, .wel-button").removeClass("none");
            } else {
                $("#connected-tip, .wel-button").addClass("none");
            }
        } else {
            $(".loadding-ok img").attr("src", "./img/ok.png")
            $("#connected, #connected-tip, .wel-button").addClass("none");
            //间隔3秒后未联网时，跳转到主页
            if (G.accessType == 1) {
                setTimeout(function () {
                    window.location = window.location.href.split("/index")[0];
                }, 3000);
            }
        }
    }
    $('#more_set').focus();
}

function handWifi() {
    var index = 0;
    if (G.wanStatus == "7") {
        showFinish();
        return;
    }
    $("#waiting").removeClass("none");
    $("#wifi_setting").addClass("none");
    $("#btn_control").addClass("none");
    setTimeout(function () {
        $.getJSON("goform/getWanConnectStatus?" + Math.random(), function (obj) {
            G.wanStatus = obj.connectStatus;
        });
    }, 5000);
    if (index == 0) {
        var pc = 9;
        var time = setInterval(function () {
            $(".loadding-number").html(pc);
            if (pc == 0) {
                showFinish();
                clearInterval(time);
            }
            pc--;
        }, 1000);
    }
}

/*function handPpoe(str) {
    var index = $.parseJSON(str).errCode;
    if (index == 0) {
        $("#ppoe_setting").addClass("none");
        $("#wifi_setting").removeClass("none");
        $("#wrlPassword").focus();
        $("#step-over").addClass("none");
        $(".save-msg").addClass("none");
        $("#page-message").html("");
    }
}*/

function moreSet() {
    window.location = window.location.href.split("/index.html")[0];
}

function overStep() {
    clearTimeout(G.time);
    $("#step-next").val(_("Next"));
    if (!$("#net_setting").hasClass("none")) {
        $("#net_setting").addClass("none");
        $("#wifi_setting").removeClass("none");
        $("#wrlPassword").focus();
        $("#step-over").addClass("none");
    }
    /*else if (!$("#ppoe_setting").hasClass("none")) {
           $("#ppoe_setting").addClass("none");
           $("#wifi_setting").removeClass("none");
           $("#wrlPassword").focus();
           $("#step-over").addClass("none");
       }*/
    else if (!$("#internet").hasClass("none")) {
        $("#internet").addClass("none");
        $("#wifi_setting").removeClass("none");
        $("#wrlPassword").focus();
        $("#step-over").addClass("none");
    }
    $("#wrlPassword_").focus();
}
