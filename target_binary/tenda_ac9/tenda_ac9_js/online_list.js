var blackNum = 0,
	maxBlackNum = 30,
	initObj = null,
	macFilterType;

var deviceInfo;
var pageview = R.pageView({ //页面初始化
	init: function () {
		top.loginOut();
		top.$(".main-dailog").removeClass("none");
		top.$(".save-msg").addClass("none");

		$("#blackTable").on("click", function () {
			$("#onlineListTable").addClass("none");
			$("#blackListTable").removeClass("none");
			blackView.init();
		});

		$("#onlineDeviceTips").on("click", function () {
			$("#onlineListTable").removeClass("none");
			$("#blackListTable").addClass("none");
			onlineView.init();
		});
	}
});
var pageModel = R.pageModel({});

/********online list****************/
var onlineView = R.moduleView({
	init: function () {
		initEvent();
		getOnlineList();
	}
})
var moduleModel = R.moduleModel({});

//模块注册
R.module("onlineList", onlineView, moduleModel);


function initEvent() {
	$("#onlineList").delegate(".edit-btn", "click", function () {
		showEditNameArea($(this).parents("tr")[0], $(this).parents("tr").find(".dev-name").attr("title"));
	});

	$("#onlineList").delegate(".dev-name-input", "blur", function () {
		var mac = $(this).parents("tr").attr("alt");
		newName = $(this).parents("tr").find("input.dev-name-input").val();
		changeDevName(mac, newName);
	});

	$("#onlineList").delegate(".del", "click", function () {
		var mac = $(this).parents("tr").attr("alt");
		$(this).attr("disabled", true);
		delList(mac);
	});

}

function getOnlineList() {
	$.getJSON("goform/getOnlineList?" + Math.random(), initValue);
}

function createOnlineList(initDataList, localhostMac) {
	var str = "",
		i = 0,
		deviceType,
		connectTypeStr = [_("Wired"), _("2.4 GHz"), _("5 GHz")];
	for (i = 0; i < initDataList.length; i++) {
		deviceType = translateDeviceType(initDataList[i].linkType);
		str += "<tr alt='" + initDataList[i].deviceId + "' class='tr-row'>" +
			"<td class='edit-td'><div class='device-icon'><img src='" + deviceType.src + "'>" + showDeviceLogoString(deviceType, initDataList[i].linkType) + "</div>";
		str += "<div class='online-device-content'><div class='dev-name text-fixed' style='padding-right: 30px;'><span class='dev-name-txt'></span><img class='edit-btn edit-btn-txt-append' src='img/edit_new.png' style='width:14px;height:14px;' /></div><div class='txt-help-tips font-txt-small' data-alt='ip'>" + initDataList[i].ip + "</div></div></td>";

		//wisp、 router显示流量
		if (top.G.workMode == "wisp" || top.G.workMode == "router") {
			str += "<td data-alt='uploadSpeed'>" + translateSpeed(initDataList[i].uploadSpeed) + "</td>" +
				"<td data-alt='downloadSpeed'>" + translateSpeed(initDataList[i].downloadSpeed) + "</td>";
		} else {
			//其他模式显示MAC地址
			str += "<td>" + initDataList[i].deviceId + "</td>";
		}

		str += "<td data-alt='lineType'>" + connectTypeStr[initDataList[i].line] + "</td>";
		if (macFilterType == "black") {
			str += "<td data-alt='action'>" + (function () {

				//如果是访客网络
				if (initDataList[i].isGuestClient == "true") {
					return _("Guest");
				} else {
					if (initDataList[i].deviceId == localhostMac) {
						return _("Local Host");
					} else {
						return "<input type='button' class='btn del btn-action' value='" + _("Add") + "'>";
					}

				}
			})() + "</td>";
		}

		str += "</tr>";
	}
	$("#onlineList").html(str);

	var j = 0;
	$("#onlineList").find(".dev-name").each(function (i) {
		$(this).attr("title", initDataList[j].devName);
		$(this).find(".dev-name-txt").text(initDataList[j].devName);
		j++;
	});
}

function initValue(obj) {
	var i = 0,
		k = 0,
		len = obj.length,
		str = "",
		initDataList = [],
		localhostMac = obj[0].localhostMac,
		localhostObj = {},
		deviceType,
		thStr = "";

	initObj = obj;
	blackNum = obj[0].blackNum;
	macFilterType = obj[0].macFilterType || "white";



	if (macFilterType == "black") {
		$("#blackDeviceTips").removeClass("none");

		if (top.G.workMode == "wisp" || top.G.workMode == "router") {

		} else {
			//黑名单 ap模式
			thStr = '<tr><th width="35%" >' + _("Device Name") + '</th>' +
				'<th width="25%">' + _("MAC Address") + '</th>' +
				'<th width="20%">' + _("Access Type") + '</th>' +
				'<th width="20%">' + _("Add") + '</th></tr>';
			$("#onlineListTable thead").html(thStr);
		}

	} else {
		$("#blackDeviceTips").remove();
		if (top.G.workMode == "wisp" || top.G.workMode == "router") {

			$("#blackDeviceTips").remove(); 
			//白名单 路由模式
			thStr = '<tr><th width="40%" >' + _("Device Name") + '</th>' +
				'<th width="20%">' + _("Upload Speed") + '</th>' +
				'<th width="20%">' + _("Download Speed") + '</th>' +
				'<th width="20%">' + _("Access Type") + '</th>' +
				'</tr>';
			$("#onlineListTable thead").html(thStr);
		} else {
			thStr = '<tr><th width="40%" >' + _("Device Name") + '</th>' +
				'<th width="30%">' + _("MAC Address") + '</th>' +
				'<th width="30%">' + _("Access Type") + '</th>' +
				'</tr>';
			$("#onlineListTable thead").html(thStr);
		}

	}

	for (k = 1; k < len; k++) {
		//访客网络优先显示，不管是否在黑白名单中
		if (obj[k].isGuestClient != "true") {
			if (obj[k].black == 1) {
				continue;
			}
		}

		if (obj[k].deviceId == localhostMac) {
			localhostObj = obj[k];
			continue;
		}
		initDataList.push(obj[k]);
	}

	initDataList.sort((function () {
		var splitter = /^(\d+)([A-Z]*)/;
		return function (a, b) {
			a = a.line.match(splitter);
			b = b.line.match(splitter);
			var anum = parseInt(a[1], 10),
				bnum = parseInt(b[1], 10);
			if (anum === bnum) {
				return a[2] < b[2] ? -1 : a[2] > b[2] ? 1 : 0;
			} else {
				return anum - bnum;
			}
		}
	})());

	//本机未加入黑名单时，将本机加入在线列表中
	if (localhostObj.deviceId && localhostObj.black != 1) {
		initDataList.unshift(localhostObj);
	}

	$("#onlineDeviceTips").html(_("Attached Devices (%s)", [initDataList.length]));
	if (initDataList.length != 0) {
		createOnlineList(initDataList, localhostMac);
	} else {
		str = "<tr><td colspan='" + $("#onlineListTable th").length + "' >" + _("No online client") + "</td></tr>";
		$("#onlineList").html(str);
	}

	if (top.G.workMode == "ap" || top.G.workMode == "client+ap") {
		delOnlineIp();
	}

	top.initIframeHeight();
	initTableHeight();
}

function delOnlineIp() {
	$("#onlineList").find("div[data-alt='ip']").remove();
	$("#onlineList .online-device-content").css("margin-top", "10px");
}

function delList(mac) {
	var isParentCtrled = false;

	for (var i = initObj.length - 1; i >= 1; i--) {
		if (initObj[i].deviceId == mac) {
			if (initObj[i].parentCtrl == 1) {
				isParentCtrled = true;
				break;
			}
		}
	};

	/*if (!isParentCtrled && blackNum >= maxBlackNum) {
		//showErrMsg("msg-err",_("Up to %s device can be added to the blacklist.", [maxBlackNum]));
		showErrMsg("msg-err",_("Only a maximum of %s devices are allowed in the blacklist and parental control list.", [maxBlackNum]));
		return;
	}*/

	var data;

	data = "mac=" + mac;
	$.post("goform/setBlackRule", data, callback);
}

function callback(str) {
	if (!top.isTimeout(str)) {
		return;
	}
	var num = $.parseJSON(str).errCode;
	clearInterval(onlineTimer);
	onlineTimer = setInterval(function () {
		updateOnlineList();
	}, 5000);
	if (num == 0) {
		updateOnlineList();
		top.showSaveMsg(num, _("Adding to the blacklist..."), 2);
	} else if (num == 1) {
		$("#onlineList .del").removeAttr("disabled");
		showErrMsg("msg-err", _("Only a maximum of %s rules are allowed.", [maxBlackNum]));
		return;
	}

}

function showEditNameArea(rowEle, name) {
	var inputWidth = $(rowEle).find(".dev-name").width() - 50 + "px";

	var htmlStr = '<div class="table-btn-group"><input type="text" class="dev-name-input" maxlength="20" style="width:' + inputWidth + '"/></div>';
	$(rowEle).find(".dev-name").html(htmlStr);
	$(rowEle).find(".dev-name .dev-name-input").val(name);
	//edit by xc 
	//设备名称支持全字符，注释以下代码
	//clearDevNameForbidCode($(rowEle).find(".dev-name .dev-name-input")[0]);
}

function hideEditNameArea(rowEle, devName) {
	$(rowEle).find(".dev-name").text(devName).append('<img class="edit-btn edit-btn-txt-append" src="img/edit_new.png" style="width:14px;height:14px;"/>');
}

function changeDevName(macAddress, newName) {
	var submitStr = "mac=" + macAddress + "&devName=" + encodeURIComponent(newName);

	$("#msg-err").addClass("red").removeClass("text-success");

	//统一验证设备名称合法性
	var msg = checkDevNameValidity(newName);

	if (msg) {
		showErrMsg("msg-err", msg);
		return false;
	}

	$.post("goform/SetOnlineDevName", submitStr, function (str) {
		if ($.parseJSON(str).errCode == "0") {
			$("#msg-err").removeClass("red").addClass("text-success");
			showErrMsg("msg-err", _("Modification success"));
			$("#onlineList tr").each(function () {
				if ($(this).attr("alt") == macAddress) {
					$(this).find(".dev-name").attr("title", newName).find(".dev-name-txt").text(newName);
					hideEditNameArea(this, newName);
					return false;
				}
			});
			top.staInfo.initValue();
		} else {
			showErrMsg("msg-err", _("Modification failure"));
		}

	});
}

//更新数据
function updateOnlineList() {
	$.getJSON("goform/getOnlineList?" + Math.random(), updateSpeed);
}

var onlineTimer = setInterval(function () {
	updateOnlineList();
}, 5000);

function updateSpeed(obj) {
	var i = 1,
		len = obj.length,
		connectTypeStr = [_("Wired"), _("2.4G"), _("5G")],
		randomStr = Math.random(),
		localhostMac = obj[0].localhostMac,
		devMac,
		devname,
		deviceType,
		connectType,
		actionStr,
		$trDom,
		str;

	for (i = 1; i < len; i++) {
		if (obj[i].isGuestClient != "true") {
			//过滤黑名单
			if (obj[i].black == 1) {
				continue;
			}
		}

		devMac = obj[i].deviceId;
		devname = (obj[i].devName == "" ? top.G.deviceNameSpace : obj[i].devName);
		$trDom = $("#onlineList tr[alt='" + devMac + "']");
		connectType = connectTypeStr[obj[i].line];
		actionStr = (function () {
			if (obj[i].isGuestClient == "true") {
				return _("Guest");
			} else if (devMac == localhostMac) {
				return _("Local Host");
			} else {
				return "<input type='button' class='btn del btn-action' value='" + _("Add") + "'>";
			}
		})();
		//存在在线列表中时
		if ($trDom.length === 1) {
			//更新速度
			if (top.G.workMode == "wisp" || top.G.workMode == "router") {
				$trDom.find("td[data-alt='uploadSpeed']").html(translateSpeed(obj[i].uploadSpeed));
				$trDom.find("td[data-alt='downloadSpeed']").html(translateSpeed(obj[i].downloadSpeed));
			}

			//更新连接类型
			$trDom.find("td[data-alt='lineType']").html(connectType);
			//更新访客、加入黑名单
			$trDom.find("td[data-alt='action']").html(actionStr);
			//更新IP
			$trDom.find("div[data-alt='ip']").html(obj[i].ip);

			$trDom.data("online.flag", randomStr);
		} else { //不存在时，说明是新增的
			deviceType = translateDeviceType(obj[i].linkType);
			str = "<tr alt='" + obj[i].deviceId + "' class='tr-row device-target'>" +
				"<td class='edit-td'><div class='device-icon'><img src='" + deviceType.src + "'>" + showDeviceLogoString(deviceType, obj[i].linkType) + "</div><div class='online-device-content'><div class='dev-name text-fixed' style='padding-right: 30px;'><span class='dev-name-txt'></span><img class='edit-btn edit-btn-txt-append' src='img/edit_new.png' style='width:14px;height:14px;' /></div>" +
				"<div class='txt-help-tips font-txt-small' data-alt='ip'>" + obj[i].ip + "</div></div></td>";
			if (top.G.workMode == "wisp" || top.G.workMode == "router") {
				str += "<td data-alt='uploadSpeed'>" + translateSpeed(obj[i].uploadSpeed) + "</td>" +
					"<td data-alt='downloadSpeed'>" + translateSpeed(obj[i].downloadSpeed) + "</td>";
			} else {
				str += "<td>" + obj[i].deviceId + "</td>";
			}

			str += "<td data-alt='lineType'>" + connectType + "</td>";
			if (macFilterType == "black") {
				str += "<td data-alt='action'>" + actionStr + "</td>";
			}
			str += "</tr>"

			$("#onlineList").append(str);
			$("#onlineList").find(".device-target .dev-name").each(function (k) {
				$(this).attr("title", devname);
				$(this).find(".dev-name-txt").text(devname);
			});
			$("#onlineList").find(".device-target").data("online.flag", randomStr);
			$("#onlineList").find(".device-target").removeClass("device-target");
		}
	}

	//删除下线的设备
	$("#onlineList").children().map(function () {
		if ($(this).data("online.flag") != randomStr) { //本次数据不在线的设备
			if ($(this).find("input[type='text'].dev-name-input").length === 0) {
				//如果此设备不在编辑状态
				$(this).remove()
			}
		}
	});

	$("#onlineDeviceTips").html(_("Attached Devices (%s)", [$("#onlineList").children().length]));

	top.initIframeHeight();
	if (top.G.workMode == "ap" || top.G.workMode == "client+ap") {
		delOnlineIp();
	}

}

/*************end online list************************/

var pageModel = R.pageModel({});

/********online list****************/
var blackView = R.moduleView({
	init: function () {
		getBlackList();
	}
})
var moduleModel = R.moduleModel({});

//模块注册
R.module("blackList", blackView, moduleModel);

function getBlackList() {
	//$.getJSON("list.txt",initValue);
	//$.getJSON("goform/initWifiMacFilter?"+Math.random(),initValue);
	$.getJSON("goform/getBlackRuleList?" + Math.random(), initBlackList);
}

function initBlackList(obj) {
	var i = 0,
		len = obj.length,
		devname,
		str = "";
	if (len != 0) {
		for (i = 0; i < len; i++) {

			str += "<tr class='tr-row'><td class='dev-name fixed' title=''></td>" +
				"<td title='" + obj[i].deviceId + "'>" + obj[i].deviceId.toUpperCase() + "</td>" +
				"<td><input type='button' class='btn del btn-action' value='" + _("Remove") + "'></td></tr>";
		}
	} else {
		str = "<tr><td colspan=3 >" + _("The blacklist is empty.") + "</td></tr>";
	}
	if (str == "") {
		str = "<tr><td colspan=3 >" + _("The blacklist is empty.") + "</td></tr>";
	}

	$("#blackList").html(str).find(".dev-name").each(function (i) {
		devname = (obj[i].devName == "" ? top.G.deviceNameSpace : obj[i].devName);
		$(this).attr("title", devname);
		$(this).text(devname);
	});
	$("#blackList .del").on("click", delBlackList);
	top.initIframeHeight();
}

function delBlackList() {
	var mac = $(this).parents("tr").find("td").eq(1).attr("title"),
		data;

	data = "mac=" + mac;
	$.post("goform/delBlackRule", data, blackCallback);
}

function blackCallback(str) {
	if (!top.isTimeout(str)) {
		return;
	}
	var num = $.parseJSON(str).errCode;
	//clearInterval(onlineTimer);
	top.showSaveMsg(num, _("Removing from the blacklist..."), 2);
	if (num == 0) {
		getBlackList();
		//top.staInfo.initValue();
	}
}

window.onload = function () {
	deviceInfo = R.page(pageview, pageModel);
};

window.onunload = function () {
	clearInterval(onlineTimer);
};