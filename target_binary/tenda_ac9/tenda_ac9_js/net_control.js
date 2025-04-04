var G = {},
	initDataList = [],
	addMacList = [],
	editing = false,
	ajaxInterval = {};

var selectObjDown = {
	"initVal": "",
	"editable": "1",
	"seeAsTrans": true,
	"size": "small",
	"options": [{
		//"0": _("Denied"),
		"0": _("Unlimited "),
		"1": _("1.0Mbps (For Browsing)"),
		"2": _("2.0Mbps (For SD Video)"),
		"4": _("4.0Mbps (For HD Video)"),
		".divider": ".divider",
		".hand-set": _("Manual (unit:Mbps)")
	}]
};

var selectObjUp = {
	"initVal": "",
	"editable": "1",
	"seeAsTrans": true,
	"size": "small",
	"options": [{
		//"0": _("Denied"),
		"0": _("Unlimited "),
	}, {
		"0.5": "0.5 "+_("Mbps")
	}, {
		"1": "1.0 "+_("Mbps"),
		"2": "2.0 "+_("Mbps"),
		".divider": ".divider",
		".hand-set": _("Manual")
	}]
};

/***********************************************/
var netCtrlInfo;
var pageview = R.pageView({ //页面初始化
	init: function () {
		top.loginOut();
		top.$(".main-dailog").removeClass("none");
		top.$(".save-msg").addClass("none");

		$("#submit").on("click", function () {
			netCtrlInfo.submit();
		});
	}
});
var pageModel = R.pageModel({
	getUrl: "goform/GetNetControlList",
	setUrl: "goform/SetNetControlList",
	translateData: function (data) {
		var newData = {};
		newData.netControl = data;
		return newData;
	},
	afterSubmit: callback
});

/************************/
var view = R.moduleView({
	initEvent: initEvent,
	checkData: function () {
		var data = "",
			ip = "",
			i = 0,
			str = "",
			$row = $("#netBody tr"),
			len = $("#netBody").children().length,
			limitUp = 0,
			limitDown = 0,
			devName;
		//if ($("#netControlEn").val() == "1") {
		for (i = 0; i < len; i++) {

			if ($row.eq(i).find(".dev-name-input").length > 0) {
				devName = $row.find(".dev-name-input").val();
				//编辑状态下不能为空
				str = checkDevNameValidity(devName);
			}

			//统一验证设备名称合法性
			if (str) {
				return str;
			}
		}
		//}

		/*if (len > 30) {
			return _("Only a maximum of %s bandwidth control rules are allowed.", [30]);
		}*/
	}
});

var moduleModel = R.moduleModel({
	initData: initList,
	getSubmitData: function () {
		var data = "",
			ip = "",
			i = 0,
			str = "",
			$row = $("#netBody tr"),
			len = $("#netBody").children().length,
			limitUp = 0,
			limitDown = 0,
			devName;

		//data += "netControlEn=" + $("#netControlEn").val();
		str = "list=";
		//if ($("#netControlEn").val() == "1") {
		for (i = 0; i < len; i++) {

			limitUp = parseFloat($row.eq(i).find("[alt=limitUp]")[0].val().replace(/[^\d\.]/g, ""));
			limitDown = parseFloat($row.eq(i).find("[alt=limitDown]")[0].val().replace(/[^\d\.]/g, ""));
			//en = ($row.eq(i).find('.operate span').hasClass("enable")) ? "0" : "1";

			if ($row.eq(i).find(".dev-name-input").length > 0) {
				devName = $row.eq(i).find(".dev-name-input").val();
			} else {
				devName = $row.eq(i).find(".dev-name").attr("title");
			}

			//str += ($.inArray($row.eq(i).attr('alt'), addMacList) > -1) ? $row.eq(i).find('td:eq(0)').attr('title') : "";
			str += encodeURIComponent(devName);
			str += "\r";
			str += $row.eq(i).attr("alt") + "\r";
			str += limitUp * 128 + "\r";
			str += limitDown * 128 + "\n";
		}
		//}
		str = str.replace(/(\n)$/, "");
		data = str;
		return data;
	}
});

//模块注册
R.module("netControl", view, moduleModel);

function initEvent() {
	$('#deviceInfo').inputCorrect('mac').addPlaceholder(_("MAC Address"));
	$('#deviceName').addPlaceholder(_("Optional"));

	//$("#netControlEn").on("click", changeControlEn);


	$("#netBody").delegate(".edit-btn", "click", function () {
		showEditNameArea($(this).parents("tr")[0], $(this).parents("tr").find(".dev-name").attr("title"));
	});

	$("#netBody").delegate(".dev-name-input", "blur", function () {
		var mac = $(this).parents("tr").attr("alt"),
			newName = $(this).parents("tr").find("input.dev-name-input").val(),
			parentElem = $(this).parents("tr")[0];

		var msg = checkDevNameValidity(newName);

		if (msg) {
			$("#msg-err").addClass("red").removeClass("text-success");
			showErrMsg("msg-err", msg);
			return true;
		}
		var submitStr = "mac=" + mac + "&devName=" + encodeURIComponent(newName);
		$.post("goform/SetOnlineDevName", submitStr, function (str) {
			if ($.parseJSON(str).errCode == "0") {
				$("#msg-err").removeClass("red").addClass("text-success");
				showErrMsg("msg-err", _("Modification success"));
				hideEditNameArea(parentElem, newName);
				//top.staInfo.initValue();
			} else {
				$("#msg-err").addClass("red").removeClass("text-success");
				showErrMsg("msg-err", _("Modification failure"));
			}
		});

	});

	//checkData();
	top.initIframeHeight();
}

function setIptValue() {
	var val = this.value.replace(/[^\d\.]/g, "");

	val = (val === "" ? 0 : val);
	val = parseFloat(val > 2000 ? 2000 : parseFloat(val).toFixed(2));
	$(this).parent(".input-append").find("[type=hidden]").val(val);
	/*if (parseFloat(val, 10) >= 2000) {
		this.value = _("Unlimited");
	} else */
	if (parseFloat(val, 10) === 0) {
		this.value = _("Unlimited ");
	} else {
		this.value = val + _("Mbps");
	}
}

/*function addNetControl() {
	G.validate.checkAll();
}*/

var delMacList = [];

/*function delNetControl() {
	var delMac = $(this).parents("tr").find("td:eq(1)").attr("title");
	delMacList.push(delMac);
	$(this).parents("tr").remove();
	ajaxInterval.startUpdate();
}*/

function initList(list) {
	var initEn = list[0];
	updateData(list);

	ajaxInterval = new AjaxInterval({
		url: "goform/GetNetControlList",
		successFun: updateData,
		failFun: failUpdate,
		gapTime: 5000
	});

	//$("#netControlEn").attr("class", (initEn.netControlEn == "1" ? "btn-off" : "btn-on"));
	changeControlEn();

	initTableHeight();
}

function changeControlEn() {
	var className = $("#netControlEn").attr("class");
	if (className == "btn-off") {
		$("#netControlEn").attr("class", "btn-on");
		$("#netControlEn").val(1);
		//$("#netList").removeClass("none");
		ajaxInterval.startUpdate();
	} else {
		$("#netControlEn").attr("class", "btn-off");
		$("#netControlEn").val(0);
		//$("#netList").addClass("none");
		ajaxInterval.stopUpdate();

	}
	top.initIframeHeight();
}

function showEditNameArea(rowEle, name) {
	var htmlStr = '<div class="table-btn-group"><input type="text" class="input-small dev-name-input" maxlength="20"/></div>';
	$(rowEle).find(".dev-name").html(htmlStr);
	$(rowEle).find(".dev-name .dev-name-input").val(name);
	clearDevNameForbidCode($(rowEle).find(".dev-name .dev-name-input")[0]);
}


function hideEditNameArea(rowEle, devName) {
	$(rowEle).find(".dev-name").text(devName).attr("title", devName).append('<img class="edit-btn edit-btn-txt-append" src="img/edit_new.png" style="width:14px;height:14px;"/>');
}

//更新数据
function updateData(dataList) {
	for (var i = 0; i < initDataList.length; i++) {
		for (var j = dataList.length - 1; j >= 1; j--) {
			if (dataList[j].mac == initDataList[i].mac) {
				initDataList[i] = dataList[j];
				dataList.splice(j, 1);
				break;
			}
		}
	}
	dataList.shift();

	initDataList = initDataList.concat(dataList);

	//排序：优先按是否在线排序(在线在前离线在后)，其次按照是否配置排序，未配置在前已配置在后
	initDataList.sort((function () {
		var splitter = /^(\d)$/;
		return function (item1, item2) {
			a = item1.offline.match(splitter);
			b = item2.offline.match(splitter);
			c = item1.isSet.match(splitter);
			d = item2.isSet.match(splitter);
			e = item1.mac;
			f = item2.mac;
			var anum = parseInt(a[1], 10),
				bnum = parseInt(b[1], 10);
			var cnum = parseInt(c[1], 10),
				dnum = parseInt(d[1], 10);
			if (anum === bnum) {
				if (cnum === dnum) {
					return e < f ? -1 : e > f ? 1 : 0;
				} else {
					return cnum < dnum ? -1 : cnum > dnum ? 1 : 0;
				}
			} else {
				return anum - bnum;
			}
		};
	})());


	//不显示删除项
	/*for (var k = 0; k < delMacList.length; k++) {
		for (var len = initDataList.length - 1; len >= 1; len--) {
			if (delMacList[k] === initDataList[len].mac) {
				initDataList.splice(len, 1);
			}
		}
	}*/

	drawList(initDataList);
}

//更新数据失败
function failUpdate() {
	updateData([""]);
}

//用数据创建（更新）列表：table 
function drawList(dataList) {
	var rowData = {},
		addData = {},
		limitUp,
		limitDown,
		upSpeed,
		downSpeed;

	$("#netBody tr").each(function () {
		var mac = $(this).attr('alt');
		for (var i = dataList.length - 1; i >= 0; i--) {
			rowData = dataList[i];
			if (mac == rowData.mac) {
				//通过mac匹配对应行 更新该行数据
				//速度统一转换成Mbps
				upSpeed = Number(rowData.upSpeed);
				downSpeed = Number(rowData.downSpeed);
				limitUp = Number(rowData.limitUp);
				limitDown = Number(rowData.limitDown);

				upSpeed = (((limitUp > upSpeed) || (limitUp === 0)) ? upSpeed : limitUp);

				downSpeed = (((limitDown > downSpeed) || (limitDown === 0)) ? downSpeed : limitDown);

				$(this).find('[alt=hostName]').text(rowData.hostName || top.G.deviceNameSpace);
				$(this).find('[alt=netIp]').html(rowData.mac + "<br>" + rowData.ip);

				//更新IP地址
				$(this).find(".online-device-content .txt-help-tips").html(rowData.ip || "---");
				if (!rowData.upSpeed || rowData.offline == "1") {
					$(this).find('[alt=upSpeed]').html("---");
				} else {
					$(this).find('[alt=upSpeed]').html(translateSpeed(upSpeed));
				}

				if (!rowData.downSpeed || rowData.offline == "1") {
					$(this).find('[alt=downSpeed]').html("---");
				} else {
					$(this).find('[alt=downSpeed]').html(translateSpeed(downSpeed));
				}
				dataList[i].exist = true;
				return;
			}
		}
	});

	//新记录添加到表尾
	for (var i = 0; i < dataList.length; i++) {
		addData = dataList[i];
		if (!addData.exist) {
			addRow(addData);
		}
	}
}

//添加一条记录
function addRow(obj) {
	var limitUp = (!obj.upSpeed && !obj.downSpeed) ? obj.limitUp : ((parseFloat(obj.limitUp) / 128).toFixed(2));
	var limitDown = (!obj.upSpeed && !obj.downSpeed) ? obj.limitDown : ((parseFloat(obj.limitDown) / 128).toFixed(2)),
		upSpeed, downSpeed,
		deviceType;

	deviceType = translateDeviceType(obj.devType);
	str = "";
	str += "<tr alt='" + obj.mac + "'>";

	str += "<td class='edit-td'><div class='device-icon'><img src='" + deviceType.src + "'>" + showDeviceLogoString(deviceType, obj.devType) + "</div><div class='online-device-content'><div class='dev-name text-fixed' style='padding-right: 30px;'><span class='dev-name-txt'></span><img class='edit-btn edit-btn-txt-append' src='img/edit_new.png' style='width:14px;height:14px;' /></div><div class='txt-help-tips'>" + (obj.ip || "---") + "</div></div></td>";


	if (!obj.upSpeed || obj.offline == "1") {
		str += "<td alt='upSpeed'>---</td>";
	} else {
		upSpeed = (((Number(obj.limitUp) > Number(obj.upSpeed)) || (limitUp == 0.00))) ? obj.upSpeed : obj.limitUp;
		str += "<td alt='upSpeed'>" + translateSpeed(upSpeed) + "</td>";
	}

	if (!obj.downSpeed || obj.offline == "1") {
		str += "<td alt='downSpeed'>---</td>";
	} else {
		//当限制下载速率大于下载速率或者下载无限制时 下载数据取真实的下载数据
		//其他情况下载速度取限制下载速率
		downSpeed = ((Number(obj.limitDown) > Number(obj.downSpeed)) || (limitDown == 0.00)) ? obj.downSpeed : obj.limitDown;
		str += "<td alt='downSpeed'>" + translateSpeed(downSpeed) + "</td>"
	}

	str += "<td><span alt='limitUp' class='validatebox'> </span></td>";
	str += "<td><span alt='limitDown' class='validatebox'> </span></td>";
	str += "</tr>";
	$("#netBody").append(str);

	$("#netBody tr:last").find(".dev-name-txt").text(obj.hostName || top.G.deviceNameSpace);
	$("#netBody tr:last").find(".dev-name").attr("title", obj.hostName || top.G.deviceNameSpace);
	$("#netBody tr:last").find("span[alt=limitUp]").toSelect(selectObjUp)[0].val(limitUp);
	$("#netBody tr:last").find("span[alt=limitDown]").toSelect(selectObjDown)[0].val(limitDown);
	//下拉选择右对齐
	$("#netBody tr:last").find("[alt=limitDown] .dropdown-menu").css("left", $("#netBody tr:last").find("span[alt=limitDown]").width() - $("#netBody tr:last").find("[alt=limitDown] .dropdown-menu").width() + "px");

	$("#netBody tr:last input[type=text]").inputCorrect("float").on("focus", function () {
		this.value = this.value.replace(/[^\d\.]/g, "");
	}).on("blur", function () {
		setIptValue.call(this);
	}).each(function () {
		setIptValue.call(this);
	});

	top.initIframeHeight();
}

function callback(str) {
	if (!top.isTimeout(str)) {
		return;
	}
	var num = $.parseJSON(str).errCode;
	top.showSaveMsg(num);


	if (num == "0") {
		ajaxInterval.stopUpdate();
		//getValue();
		top.advInfo.initValue();
	}
}

window.onload = function () {
	netCtrlInfo = R.page(pageview, pageModel);
};