Object.assign(window.ui.AdServiceConfig, {
	configurations: {
		sizes: {
			'top': {
				'sizes': window.ui.viewportSize == "tablet" ? [[728,90],[468,60],[320,75],[320,50],[300,50],[300,75]] : [[970,250],[800,250],[970,90],[728,90],[468,60]]
			},
			'right': {
				'sizes': location.href.indexOf("mail.com") !== -1 && (window.innerWidth - document.getElementById("content").offsetWidth - 50)/2 < 300 ? ((window.innerWidth - document.getElementById("content").offsetWidth - 50)/2 >= 200 ? [[200,600],[160,600],[120,600]] : ((window.innerWidth - document.getElementById("content").offsetWidth - 50)/2 >= 160 ? [[160,600],[120,600]] : ((window.innerWidth - document.getElementById("content").offsetWidth - 50)/2 >= 120 ? [[120,600]] : []))) : [[300,600],[200,600],[160,600],[120,600]]
			},
			'contentad_1': {
				'sizes': [[300,250]]
			},
			'contentad_2': {
				'sizes': [[300,250]]
			},
			'box_1': {
				'sizes': window.ui.viewportSize == "tablet" ? [[300,250]] : [[300,600],[300,250]]
			},
			'box_2': {
				'sizes': [[300,250]]
			},
			'box_3': {
				'sizes': [[300,250]]
			},
			'box_4': {
				'sizes': [[300,250]]
			},
			'box_5': {
				'sizes': [[300,250]]
			},
			'bottom': {
				'sizes': window.ui.viewportSize == "tablet" ? [[728,90],[468,60],[320,75],[320,50],[300,50],[300,75]] : [[970,250],[800,250],[970,90],[728,90],[468,60]]
			},
			'rectangle_exit': {
				'sizes': [[300,600],[300,250]]
			},
			'rectangle_exit_2': {
				'sizes': [[300,250]]
			},
			'rectangle_layer': {
				'sizes': [[300,600],[300,250]]
			},
			'rectangle_layer_2': {
				'sizes': [[300,250]]
			},
			'slider': {
				'sizes': [[728,90]]
			},
			'teaserline': {
				'sizes': [['fluid']]
			},
			'nativebox': {
				'sizes': [[300,257],[300,250]]
			}
		}
	},
	exclusionRules: {},
	prebidRules: function() {
		AdService.AdSlot('right').setConfig('enable-filter-sizes',false);
		AdService.AdSlot('box_1').setConfig('secure',false);
		AdService.setParam("layoutclass","b");
		AdService.setParam("deviceclass","b");
		AdService.setParam("deviceclient","browser");
		AdService.setParam("pagev","230314");
		if(typeof (document.cookie.match(/(?:^|; )gdna=([^;]*)/i) || [0, false])[1] === 'string') {
			AdService.setParam("GDNA","1");
		} else {
			AdService.setParam("GDNA","0");
		}
		/* targeting */
		var pbTargeting = {};
		/* xandr id */
		function getCookieValue(cookie) {
			var val = document.cookie.match('(^|;)\\s*' + cookie + '\\s*=\\s*([^;]+)');
			return val ? val.pop() : '';
		}
		var pbXandr = undefined;
		/* params */
		var getPlacementName = function(tagid,adtype,short){
			var separator = short == 2 ? '-' : (short == 3 ? '/' : '|');
			return (short == 3 ? separator + AdService.getParam('network') + separator : '')+ AdService.getParam('portal') + separator + AdService.getParam('category') + (short == undefined || short == 3 ? separator + AdService.getParam('section') : '') + separator + tagid + (short == undefined || short == 2 ? separator + AdService.getParam('layoutclass') : '') + (short == undefined ? separator + AdService.getParam('deviceclass') + separator + AdService.getParam('deviceclient') : '') + (adtype !== undefined && adtype !== null ? separator + adtype : '');
		};
		/* prebid config */
		var domain = {'mailcom':'mail.com','gmxcom':'gmx.com','gmxes':'gmx.es','gmxfr':'gmx.fr','gmxcouk':'gmx.co.uk'}[AdService.getParam('portal')] || 'mail.com';
		var isDev = location.host.indexOf(".server.lan") !== -1 || location.host.indexOf("dev.") !== -1 || location.host.indexOf("qa.") !== -1 || location.href.indexOf("prebiddebug=1") !== -1 || location.host.indexOf(".cad.") !== -1;
		var runIt_simple = AdService.getParam('category') != 'advertorial' && AdService.info.abd().isBlocked != true && AdService.getParam('deviceclient') != 'browser_clean';
		var runIt = runIt_simple && (getCookieValue("uiconsent").indexOf("fullConsent") !== -1 || (AdService.getParam('tcf_pur').indexOf(',1,') != -1 && AdService.getParam('tcf_pur').indexOf(',2,') != -1 && AdService.getParam('tcf_pur').indexOf(',3,') != -1 && AdService.getParam('tcf_pur').indexOf(',4,') != -1 && AdService.getParam('tcf_pur').indexOf(',7,') != -1 && AdService.getParam('tcf_pub').indexOf(',1,') != -1 && AdService.getParam('tcf_pub').indexOf(',2,') != -1 && AdService.getParam('tcf_pub').indexOf(',3,') != -1 && AdService.getParam('tcf_pub').indexOf(',4,') != -1 && AdService.getParam('tcf_pub').indexOf(',7,') != -1));
		var pbConfig = {
			enabled: runIt && location.href.indexOf("disable_prebid=1") == -1 ? true : false,
			iframeUrl: '//dl.'+domain+'/uim/'+(isDev ? 'dev' : 'live')+'/logic_pbjs.html'+(isDev && document.cookie.indexOf("pbjsdebug=1") !== -1 ? '?pbjs_debug=true&apn_test=true' : ''),
			initial: ['top','right','contentad_1','contentad_2','box_1','box_2','box_3','bottom','slider'],
			//slotSets: [['top','right','contentad_1','contentad_2','box_1','box_2','box_3','bottom','slider'],['top','right','contentad_1','contentad_2','box_1','box_2','box_3','bottom','slider']/*,'top','right','contentad_1','contentad_2','box_1','box_2','box_3','bottom','slider'*/,'rectangle_layer','rectangle_exit'],
			slotSets: [['top','right','contentad_1','contentad_2','box_1','box_2','box_3','bottom','slider'],'rectangle_layer','rectangle_exit'],
			timeout: !isDev ? { initial: AdService.getParam('portal') == 'gmxcom' ? 1700 : 1700, slots: [900, 1000, 1200, 1500, 1800, 2100, 2400, 2700, 3000, 3300], auctionIframe: 3000 } : { initial: 10000, slots: [10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000], auctionIframe: 10000 },
			passover: {
				timeout: !isDev ? { initial: { bidder: AdService.getParam('portal') == 'gmxcom' ? 1500 : 1500, total: 1900 }, slots: [{ bidder: 900, total: 900 }, { bidder: 1000, total: 1000 }, { bidder: 1200, total: 1200 }, { bidder: 1500, total: 1500 }, { bidder: 1800, total: 1800 }, { bidder: 2100, total: 2100 }, { bidder: 2400, total: 2400 }, { bidder: 2700, total: 2700 }, { bidder: 3000, total: 3000 }, { bidder: 3300, total: 3300 }], cmp: 7000 } : { initial: { bidder: 10000, total: 12000 }, slots: [{ bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }, { bidder: 10000, total: 12000 }], cmp: 7000 },
				slots: {},
				initial: ['top','right','contentad_1','contentad_2','box_1','box_2','box_3','bottom','slider'],
				params: {portal:AdService.getParam('portal'),category:AdService.getParam('category'),section:AdService.getParam('section'),layoutclass:AdService.getParam('layoutclass'),deviceclass:AdService.getParam('deviceclass'),deviceclient:AdService.getParam('deviceclient'),customdebug:AdService.getParam('customdebug'),amzn_debug_mode:AdService.getParam('amzn_debug_mode'),external_uid:AdService.getParam('external_uid'),forcetimeout:location.href.indexOf("forcetimeout=1") !== -1,int:1,targeting:{prebidtest:location.href.indexOf("prebidtest=1") !== -1 ? "1" : undefined},cl:AdService.getParam("cl")}
			}
		};
		AdService.AdServer('google').setConfig({'enable-refresh-tagid':true});
			if(AdService.getParam('portal') == 'mailcom'){
				AdService.setRefreshInterval(AdService.version.minor >= 17 ? {60:{slots:['box_1','box_2','box_3','right','top','bottom','slider','nativebox']}} : {box_1:60,box_2:60,box_3:60,right:60,top:60,bottom:60,slider:60,nativebox:60});
			} else {
				AdService.setRefreshInterval(AdService.version.minor >= 17 ? {60:{slots:['box_1','contentad_1','contentad_2','right','top','bottom','slider','nativebox']}} : {box_1:60,contentad_1:60,contentad_2:60,right:60,top:60,bottom:60,slider:60});
			}
		AdService.setConfig('refreshOnlyIfVisible',true);
		AdService.setConfig('visibility-precheck',function(){return document.hasFocus();});
		if(AdService.getParam('portal') == 'mailcom'){
			pbConfig.initial = ['top','right','box_1','box_2','box_3','box_4','box_5','bottom','slider','nativebox'];
			pbConfig.slotSets = [['top','right','box_1','box_2','box_3','box_4','box_5','bottom','slider','nativebox'],'rectangle_layer','rectangle_exit'];
			pbConfig.passover.initial = ['top','right','box_1','box_2','box_3','box_4','box_5','bottom','slider','nativebox'];
			pbConfig.passover.slots = {
				'box_4': [{
					code: "box_4|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_4.sizes}}, pubstack:{adUnitName:"box_4",adUnitPath:getPlacementName("box_4",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_4")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340126",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662636",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613933"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375113",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039583",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491918",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037512",position:"btf"}},
						{bidder:"adform",params:{mid:"1038034"}},
						// {bidder:"emx_digital",params:{tagid:"146714"}},
						{bidder:"sovrn",params:{tagid:"890909"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_4","medium_rectangle",2)}}
					]
				},{
					code: "box_4|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_4",adUnitPath:getPlacementName("box_4",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22942439",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_4")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_4","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_4.sizes}
				}],
				'box_5': [{
					code: "box_5|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_5.sizes}}, pubstack:{adUnitName:"box_5",adUnitPath:getPlacementName("box_5",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_5")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340127",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662637",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613934"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375114",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039586",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491919",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037920",position:"btf"}},
						{bidder:"adform",params:{mid:"1038035"}},
						// {bidder:"emx_digital",params:{tagid:"146715"}},
						{bidder:"sovrn",params:{tagid:"890911"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_5","medium_rectangle",2)}}
					]
				},{
					code: "box_5|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_5",adUnitPath:getPlacementName("box_5",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22942439",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_5")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_5","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_5.sizes}
				}],
				'top': [{
					code: "top|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("top")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340122",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662641",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613964"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375115",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039590",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491876",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037922",position:"atf"}},
						{bidder:"adform",params:{mid:"1038048"}}
					]
				},{
					code: "top|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146716"}},
						{bidder:"sovrn",params:{tagid:"890913"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("top","billboard",1)}}
					]
				},{
					code: "top|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146718"}},
						{bidder:"sovrn",params:{tagid:"890914"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("top","leaderboard",1)}}
					]
				},{
					code: "top|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146719"}},
						{bidder:"sovrn",params:{tagid:"890915"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("top","superbanner",1)}}
					]
				},{
					code: "top|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146720"}},
						{bidder:"sovrn",params:{tagid:"890917"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("top","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("top","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}
				}],
				'box_1': [{
					code: "box_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340123",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662643",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613960"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375116",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039594",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491877",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037924",position:"atf"}},
						{bidder:"adform",params:{mid:"1038041"}}
					]
				},{
					code: "box_1|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146721"}},
						{bidder:"sovrn",params:{tagid:"890919"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("box_1","halfpagead",1)}}
					]
				},{
					code: "box_1|mediumrectangle", mediaTypes: {banner:{sizes: [[300,250]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146722"}},
						{bidder:"sovrn",params:{tagid:"890922"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("box_1","medium_rectangle",1)}}
					]
				},{
					code: "box_1|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22942439",allowSmallerSizes:true,position:"above",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}
				}],
				'box_2': [{
					code: "box_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340128",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662645",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613935"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375117",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039595",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491920",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037926",position:"btf"}},
						{bidder:"adform",params:{mid:"1038036"}},
						// {bidder:"emx_digital",params:{tagid:"146723"}},
						{bidder:"sovrn",params:{tagid:"890924"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_2","medium_rectangle",2)}}
					]
				},{
					code: "box_2|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22942439",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}
				}],
				'box_3': [{
					code: "box_3|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340129",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662646",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613936"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375118",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039600",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491921",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037928",position:"btf"}},
						{bidder:"adform",params:{mid:"1038037"}},
						// {bidder:"emx_digital",params:{tagid:"146724"}},
						{bidder:"sovrn",params:{tagid:"890926"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_3","medium_rectangle",2)}}
					]
				},{
					code: "box_3|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22942439",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_3","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}
				}],
				'right': [{
					code: "right|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("right")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340124",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662648",size:[160,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613930"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375119",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039603",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491878",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037930",position:"atf"}},
						{bidder:"adform",params:{mid:"1038044"}}
					]
				},{
					code: "right|skyscraper", mediaTypes: {banner:{sizes: [[160,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146726"}},
						{bidder:"sovrn",params:{tagid:"890930"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","wide_skyscraper",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("right","wide_skyscraper",1)}}
					]
				},{
					code: "right|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146725"}},
						{bidder:"sovrn",params:{tagid:"890928"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("right","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("right","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}
				}],
				'bottom': [{
					code: "bottom|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("bottom")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340125",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662653",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613965"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375120",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039606",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491879",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037932",position:"atf"}},
						{bidder:"adform",params:{mid:"1038045"}}
					]
				},{
					code: "bottom|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146716"}},
						{bidder:"sovrn",params:{tagid:"890913"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("bottom","billboard",1)}}
					]
				},{
					code: "bottom|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146718"}},
						{bidder:"sovrn",params:{tagid:"890914"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("bottom","leaderboard",1)}}
					]
				},{
					code: "bottom|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146719"}},
						{bidder:"sovrn",params:{tagid:"890915"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("bottom","superbanner",1)}}
					]
				},{
					code: "bottom|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146720"}},
						{bidder:"sovrn",params:{tagid:"890917"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("bottom","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("bottom","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}
				}],
				'slider': [{
					code: "slider|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}}, pubstack:{adUnitName:"slider",adUnitPath:getPlacementName("slider",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("slider")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340130",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662655",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613966"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1375121",formatId:"75982"}},
						{bidder:"openx",params:{unit:"544039609",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491922",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372886",zoneId:"2037934",position:"btf"}},
						{bidder:"adform",params:{mid:"1038042"}},
						// {bidder:"emx_digital",params:{tagid:"146733"}},
						{bidder:"sovrn",params:{tagid:"890942"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("slider","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("slider","superbanner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("slider","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}
				}],
				'rectangle_layer': [{
					code: "rectangle_layer|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}}, pubstack:{adUnitName:"rectangle_layer",adUnitPath:getPlacementName("rectangle_layer",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_layer")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482032",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689409",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3908101"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1406393",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113827",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537588",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2104618",position:"atf"}},
						{bidder:"adform",params:{mid:"1071586"}},
						// {bidder:"emx_digital",params:{tagid:"150111"}},
						{bidder:"sovrn",params:{tagid:"926702"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_layer","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("rectangle_layer","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_layer","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}
				}],
				'rectangle_exit': [{
					code: "rectangle_exit|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}}, pubstack:{adUnitName:"rectangle_exit",adUnitPath:getPlacementName("rectangle_exit",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_exit")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482033",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689410",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3908102"}},
						{bidder:"smart",params:{siteId:"407339",pageId:"1406394",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113830",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537589",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2104620",position:"atf"}},
						{bidder:"adform",params:{mid:"1071587"}},
						// {bidder:"emx_digital",params:{tagid:"150112"}},
						{bidder:"sovrn",params:{tagid:"926703"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_exit","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1554711",tagId:getPlacementName("rectangle_exit","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_exit","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}
				}],
				'nativebox': [{
					code: "nativebox|native", sizes: [1,1], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"nativebox",adUnitPath:getPlacementName("nativebox",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22942439",allowSmallerSizes:true,position:"above",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("nativebox")}}
					]
				},{
					code: "nativebox|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.nativebox.sizes}}, pubstack:{adUnitName:"nativebox",adUnitPath:getPlacementName("nativebox",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("nativebox")}},
						{bidder:"appnexus",params:{placementId:"21485669",position:"above",keywords:pbTargeting}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("nativebox","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.nativebox.sizes}
				}]
			};
		} else if(AdService.getParam('portal') == 'gmxcom'){
			pbConfig.passover.slots = {
				'contentad_1': [{
					code: "contentad_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_1.sizes}}, pubstack:{adUnitName:"contentad_1",adUnitPath:getPlacementName("contentad_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("contentad_1")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340090",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662755",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613442"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375097",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039569",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491909",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037510",position:"atf"}},
						{bidder:"adform",params:{mid:"1038019"}},
						// {bidder:"emx_digital",params:{tagid:"146682"}},
						{bidder:"sovrn",params:{tagid:"890865"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("contentad_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("contentad_1","medium_rectangle",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("contentad_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_1.sizes}
				}],
				'contentad_2': [{
					code: "contentad_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_2.sizes}}, pubstack:{adUnitName:"contentad_2",adUnitPath:getPlacementName("contentad_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("contentad_2")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340091",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662756",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613443"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375098",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039571",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491910",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037820",position:"btf"}},
						{bidder:"adform",params:{mid:"1038020"}},
						// {bidder:"emx_digital",params:{tagid:"146683"}},
						{bidder:"sovrn",params:{tagid:"890866"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("contentad_2","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("contentad_2","medium_rectangle",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("contentad_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_2.sizes}
				}],
				'top': [{
					code: "top|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("top")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340086",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662760",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613436"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375099",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039574",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491870",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037822",position:"atf"}},
						{bidder:"adform",params:{mid:"1038033"}}
					]
				},{
					code: "top|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146684"}},
						{bidder:"sovrn",params:{tagid:"890868"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("top","billboard",1)}}
					]
				},{
					code: "top|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146686"}},
						{bidder:"sovrn",params:{tagid:"890869"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("top","leaderboard",1)}}
					]
				},{
					code: "top|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146687"}},
						{bidder:"sovrn",params:{tagid:"890870"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("top","superbanner",1)}}
					]
				},{
					code: "top|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146688"}},
						{bidder:"sovrn",params:{tagid:"890872"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("top","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("top","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}
				}],
				'box_1': [{
					code: "box_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340087",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662762",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613437"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375100",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039579",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491871",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037824",position:"atf"}},
						{bidder:"adform",params:{mid:"1038026"}}
					]
				},{
					code: "box_1|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146689"}},
						{bidder:"sovrn",params:{tagid:"890874"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("box_1","halfpagead",1)}}
					]
				},{
					code: "box_1|mediumrectangle", mediaTypes: {banner:{sizes: [[300,250]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146690"}},
						{bidder:"sovrn",params:{tagid:"890875"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("box_1","medium_rectangle",1)}}
					]
				},{
					code: "box_1|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22940932",allowSmallerSizes:true,position:"above",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}
				}],
				'box_2': [{
					code: "box_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340092",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662764",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613444"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375101",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039582",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491911",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037826",position:"btf"}},
						{bidder:"adform",params:{mid:"1038021"}},
						// {bidder:"emx_digital",params:{tagid:"146691"}},
						{bidder:"sovrn",params:{tagid:"890876"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_2","medium_rectangle",2)}}
					]
				},{
					code: "box_2|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22940932",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}
				}],
				'box_3': [{
					code: "box_3|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340093",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662765",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613445"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375102",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039585",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491912",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037828",position:"btf"}},
						{bidder:"adform",params:{mid:"1038022"}},
						// {bidder:"emx_digital",params:{tagid:"146692"}},
						{bidder:"sovrn",params:{tagid:"891509"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_3","medium_rectangle",2)}}
					]
				},{
					code: "box_3|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22940932",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_3","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}
				}],
				'right': [{
					code: "right|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("right")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340088",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662767",size:[160,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613438"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375103",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039558",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491872",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037830",position:"atf"}},
						{bidder:"adform",params:{mid:"1038029"}}
					]
				},{
					code: "right|skyscraper", mediaTypes: {banner:{sizes: [[160,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146694"}},
						{bidder:"sovrn",params:{tagid:"890885"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","wide_skyscraper",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("right","wide_skyscraper",1)}}
					]
				},{
					code: "right|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146693"}},
						{bidder:"sovrn",params:{tagid:"890883"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("right","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("right","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}
				}],
				'bottom': [{
					code: "bottom|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("bottom")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340089",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662772",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613439"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375104",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039561",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491873",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037832",position:"atf"}},
						{bidder:"adform",params:{mid:"1038030"}}
					]
				},{
					code: "bottom|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146696"}},
						{bidder:"sovrn",params:{tagid:"890887"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("bottom","billboard",1)}}
					]
				},{
					code: "bottom|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146698"}},
						{bidder:"sovrn",params:{tagid:"890889"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("bottom","leaderboard",1)}}
					]
				},{
					code: "bottom|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146699"}},
						{bidder:"sovrn",params:{tagid:"890894"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("bottom","superbanner",1)}}
					]
				},{
					code: "bottom|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146700"}},
						{bidder:"sovrn",params:{tagid:"890896"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("bottom","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("bottom","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}
				}],
				'slider': [{
					code: "slider|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}}, pubstack:{adUnitName:"slider",adUnitPath:getPlacementName("slider",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("slider")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340094",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"662774",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613446"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1375105",formatId:"75982"}},
						{bidder:"openx",params:{unit:"544039564",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491913",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2037834",position:"btf"}},
						{bidder:"adform",params:{mid:"1038027"}},
						// {bidder:"emx_digital",params:{tagid:"146701"}},
						{bidder:"sovrn",params:{tagid:"890897"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("slider","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("slider","superbanner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("slider","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}
				}],
				'rectangle_layer': [{
					code: "rectangle_layer|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}}, pubstack:{adUnitName:"rectangle_layer",adUnitPath:getPlacementName("rectangle_layer",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_layer")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482023",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689394",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3908069"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1406383",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113828",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537579",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2104612",position:"atf"}},
						{bidder:"adform",params:{mid:"1071578"}},
						// {bidder:"emx_digital",params:{tagid:"150102"}},
						{bidder:"sovrn",params:{tagid:"926693"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_layer","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("rectangle_layer","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_layer","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}
				}],
				'rectangle_exit': [{
					code: "rectangle_exit|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}}, pubstack:{adUnitName:"rectangle_exit",adUnitPath:getPlacementName("rectangle_exit",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_exit")}},
						{bidder:"appnexus",params:{placementId:"21485661",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482024",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689395",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3908070"}},
						{bidder:"smart",params:{siteId:"407335",pageId:"1406384",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113831",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537580",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372884",zoneId:"2104614",position:"atf"}},
						{bidder:"adform",params:{mid:"1071579"}},
						// {bidder:"emx_digital",params:{tagid:"150103"}},
						{bidder:"sovrn",params:{tagid:"926694"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_exit","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1554714",tagId:getPlacementName("rectangle_exit","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_exit","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}
				}]
			};
		} else if(AdService.getParam('portal') == 'gmxes'){
			pbConfig.passover.slots = {
				'contentad_1': [{
					code: "contentad_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_1.sizes}}, pubstack:{adUnitName:"contentad_1",adUnitPath:getPlacementName("contentad_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("contentad_1")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340108",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663493",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613594"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375056",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039555",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491900",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037500",position:"atf"}},
						{bidder:"adform",params:{mid:"1037996"}},
						// {bidder:"emx_digital",params:{tagid:"146650"}},
						{bidder:"sovrn",params:{tagid:"890824"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("contentad_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("contentad_1","medium_rectangle",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("contentad_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_1.sizes}
				}],
				'contentad_2': [{
					code: "contentad_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_2.sizes}}, pubstack:{adUnitName:"contentad_2",adUnitPath:getPlacementName("contentad_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("contentad_2")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340109",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663494",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613595"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375057",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039557",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491901",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037720",position:"btf"}},
						{bidder:"adform",params:{mid:"1037997"}},
						// {bidder:"emx_digital",params:{tagid:"146651"}},
						{bidder:"sovrn",params:{tagid:"890825"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("contentad_2","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("contentad_2","medium_rectangle",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("contentad_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_2.sizes}
				}],
				'top': [{
					code: "top|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("top")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340104",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663498",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613626"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375059",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039559",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491864",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037722",position:"atf"}},
						{bidder:"adform",params:{mid:"1038010"}}
					]
				},{
					code: "top|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146652"}},
						{bidder:"sovrn",params:{tagid:"890826"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("top","billboard",1)}}
					]
				},{
					code: "top|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146654"}},
						{bidder:"sovrn",params:{tagid:"890827"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("top","leaderboard",1)}}
					]
				},{
					code: "top|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146655"}},
						{bidder:"sovrn",params:{tagid:"890829"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("top","superbanner",1)}}
					]
				},{
					code: "top|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146656"}},
						{bidder:"sovrn",params:{tagid:"890830"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("top","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("top","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}
				}],
				'box_1': [{
					code: "box_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340105",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663500",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613623"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375060",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039562",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491865",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037724",position:"atf"}},
						{bidder:"adform",params:{mid:"1038003"}}
					]
				},{
					code: "box_1|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146657"}},
						{bidder:"sovrn",params:{tagid:"890832"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("box_1","halfpagead",1)}}
					]
				},{
					code: "box_1|mediumrectangle", mediaTypes: {banner:{sizes: [[300,250]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146658"}},
						{bidder:"sovrn",params:{tagid:"890833"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("box_1","medium_rectangle",1)}}
					]
				},{
					code: "box_1|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22940966",allowSmallerSizes:true,position:"above",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}
				}],
				'box_2': [{
					code: "box_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340110",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663502",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613596"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375061",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039566",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491902",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037726",position:"btf"}},
						{bidder:"adform",params:{mid:"1037998"}},
						// {bidder:"emx_digital",params:{tagid:"146659"}},
						{bidder:"sovrn",params:{tagid:"890835"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_2","medium_rectangle",2)}}
					]
				},{
					code: "box_2|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22940966",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}
				}],
				'box_3': [{
					code: "box_3|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340111",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663503",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613597"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375062",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039568",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491903",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037728",position:"btf"}},
						{bidder:"adform",params:{mid:"1037999"}},
						// {bidder:"emx_digital",params:{tagid:"146660"}},
						{bidder:"sovrn",params:{tagid:"890837"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_3","medium_rectangle",2)}}
					]
				},{
					code: "box_3|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22940966",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_3","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}
				}],
				'right': [{
					code: "right|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("right")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340106",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663505",size:[160,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613591"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375063",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039572",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491866",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037730",position:"atf"}},
						{bidder:"adform",params:{mid:"1038006"}}
					]
				},{
					code: "right|skyscraper", mediaTypes: {banner:{sizes: [[160,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146662"}},
						{bidder:"sovrn",params:{tagid:"890842"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","wide_skyscraper",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("right","wide_skyscraper",1)}}
					]
				},{
					code: "right|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146661"}},
						{bidder:"sovrn",params:{tagid:"890840"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("right","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("right","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}
				}],
				'bottom': [{
					code: "bottom|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("bottom")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340107",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663510",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613627"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375064",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039576",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491867",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037732",position:"atf"}},
						{bidder:"adform",params:{mid:"1038007"}}
					]
				},{
					code: "bottom|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146664"}},
						{bidder:"sovrn",params:{tagid:"890844"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("bottom","billboard",1)}}
					]
				},{
					code: "bottom|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146666"}},
						{bidder:"sovrn",params:{tagid:"890845"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("bottom","leaderboard",1)}}
					]
				},{
					code: "bottom|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146667"}},
						{bidder:"sovrn",params:{tagid:"891508"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("bottom","superbanner",1)}}
					]
				},{
					code: "bottom|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146668"}},
						{bidder:"sovrn",params:{tagid:"890849"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("bottom","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("bottom","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}
				}],
				'slider': [{
					code: "slider|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}}, pubstack:{adUnitName:"slider",adUnitPath:getPlacementName("slider",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("slider")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340112",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663512",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613628"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1375065",formatId:"75982"}},
						{bidder:"openx",params:{unit:"544039578",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491904",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2037734",position:"btf"}},
						{bidder:"adform",params:{mid:"1038004"}},
						// {bidder:"emx_digital",params:{tagid:"146669"}},
						{bidder:"sovrn",params:{tagid:"890851"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("slider","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("slider","superbanner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("slider","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}
				}],
				'rectangle_layer': [{
					code: "rectangle_layer|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}}, pubstack:{adUnitName:"rectangle_layer",adUnitPath:getPlacementName("rectangle_layer",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_layer")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482029",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689401",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3908083"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1406390",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113846",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537585",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2104594",position:"atf"}},
						{bidder:"adform",params:{mid:"1071660"}},
						// {bidder:"emx_digital",params:{tagid:"150108"}},
						{bidder:"sovrn",params:{tagid:"926699"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_layer","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("rectangle_layer","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_layer","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}
				}],
				'rectangle_exit': [{
					code: "rectangle_exit|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}}, pubstack:{adUnitName:"rectangle_exit",adUnitPath:getPlacementName("rectangle_exit",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_exit")}},
						{bidder:"appnexus",params:{placementId:"21485665",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482030",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689402",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3908084"}},
						{bidder:"smart",params:{siteId:"407329",pageId:"1406391",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113820",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537586",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372876",zoneId:"2104596",position:"atf"}},
						{bidder:"adform",params:{mid:"1071661"}},
						// {bidder:"emx_digital",params:{tagid:"150109"}},
						{bidder:"sovrn",params:{tagid:"926700"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_exit","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555392",tagId:getPlacementName("rectangle_exit","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_exit","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}
				}]
			};
		} else if(AdService.getParam('portal') == 'gmxfr'){
			pbConfig.passover.slots = {
				'contentad_1': [{
					code: "contentad_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_1.sizes}}, pubstack:{adUnitName:"contentad_1",adUnitPath:getPlacementName("contentad_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("contentad_1")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340117",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664695",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613703"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375031",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039539",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491891",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037472",position:"atf"}},
						{bidder:"adform",params:{mid:"1037974"}},
						// {bidder:"emx_digital",params:{tagid:"146618"}},
						{bidder:"sovrn",params:{tagid:"890782"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("contentad_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("contentad_1","medium_rectangle",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("contentad_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_1.sizes}
				}],
				'contentad_2': [{
					code: "contentad_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_2.sizes}}, pubstack:{adUnitName:"contentad_2",adUnitPath:getPlacementName("contentad_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("contentad_2")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340118",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664696",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613704"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375032",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039542",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491892",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037614",position:"btf"}},
						{bidder:"adform",params:{mid:"1037975"}},
						// {bidder:"emx_digital",params:{tagid:"146619"}},
						{bidder:"sovrn",params:{tagid:"890783"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("contentad_2","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("contentad_2","medium_rectangle",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("contentad_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_2.sizes}
				}],
				'top': [{
					code: "top|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("top")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340113",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664700",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613734"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375033",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039545",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491858",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037616",position:"atf"}},
						{bidder:"adform",params:{mid:"1037988"}}
					]
				},{
					code: "top|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146620"}},
						{bidder:"sovrn",params:{tagid:"890784"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("top","billboard",1)}}
					]
				},{
					code: "top|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146622"}},
						{bidder:"sovrn",params:{tagid:"890786"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("top","leaderboard",1)}}
					]
				},{
					code: "top|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146623"}},
						{bidder:"sovrn",params:{tagid:"891506"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("top","superbanner",1)}}
					]
				},{
					code: "top|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146624"}},
						{bidder:"sovrn",params:{tagid:"890790"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("top","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("top","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}
				}],
				'box_1': [{
					code: "box_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340114",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664702",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613731"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375034",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039548",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491859",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037618",position:"atf"}},
						{bidder:"adform",params:{mid:"1037981"}}
					]
				},{
					code: "box_1|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146625"}},
						{bidder:"sovrn",params:{tagid:"890791"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("box_1","halfpagead",1)}}
					]
				},{
					code: "box_1|mediumrectangle", mediaTypes: {banner:{sizes: [[300,250]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146626"}},
						{bidder:"sovrn",params:{tagid:"890793"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("box_1","medium_rectangle",1)}}
					]
				},{
					code: "box_1|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22941335",allowSmallerSizes:true,position:"above",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}
				}],
				'box_2': [{
					code: "box_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340119",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664705",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613705"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375035",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039551",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491893",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037620",position:"btf"}},
						{bidder:"adform",params:{mid:"1037976"}},
						// {bidder:"emx_digital",params:{tagid:"146627"}},
						{bidder:"sovrn",params:{tagid:"890795"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_2","medium_rectangle",2)}}
					]
				},{
					code: "box_2|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22941335",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}
				}],
				'box_3': [{
					code: "box_3|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340120",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664706",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613706"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375036",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039554",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491894",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037622",position:"btf"}},
						{bidder:"adform",params:{mid:"1037977"}},
						// {bidder:"emx_digital",params:{tagid:"146628"}},
						{bidder:"sovrn",params:{tagid:"890798"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_3","medium_rectangle",2)}}
					]
				},{
					code: "box_3|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22941335",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_3","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}
				}],
				'right': [{
					code: "right|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("right")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340115",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664708",size:[160,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613700"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375037",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039528",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491860",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037624",position:"atf"}},
						{bidder:"adform",params:{mid:"1037984"}}
					]
				},{
					code: "right|skyscraper", mediaTypes: {banner:{sizes: [[160,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146630"}},
						{bidder:"sovrn",params:{tagid:"890801"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","wide_skyscraper",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("right","wide_skyscraper",1)}}
					]
				},{
					code: "right|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146629"}},
						{bidder:"sovrn",params:{tagid:"890800"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("right","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("right","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}
				}],
				'bottom': [{
					code: "bottom|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("bottom")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340116",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664713",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613735"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375038",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039531",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491861",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037626",position:"atf"}},
						{bidder:"adform",params:{mid:"1037985"}}
					]
				},{
					code: "bottom|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146632"}},
						{bidder:"sovrn",params:{tagid:"890806"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("bottom","billboard",1)}}
					]
				},{
					code: "bottom|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146634"}},
						{bidder:"sovrn",params:{tagid:"890808"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("bottom","leaderboard",1)}}
					]
				},{
					code: "bottom|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146635"}},
						{bidder:"sovrn",params:{tagid:"890809"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("bottom","superbanner",1)}}
					]
				},{
					code: "bottom|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146636"}},
						{bidder:"sovrn",params:{tagid:"890810"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("bottom","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("bottom","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}
				}],
				'slider': [{
					code: "slider|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}}, pubstack:{adUnitName:"slider",adUnitPath:getPlacementName("slider",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("slider")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340121",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"664715",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613736"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1375039",formatId:"75982"}},
						{bidder:"openx",params:{unit:"544039534",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491895",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2037628",position:"btf"}},
						{bidder:"adform",params:{mid:"1037982"}},
						// {bidder:"emx_digital",params:{tagid:"146637"}},
						{bidder:"sovrn",params:{tagid:"890811"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("slider","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("slider","superbanner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("slider","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}
				}],
				'rectangle_layer': [{
					code: "rectangle_layer|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}}, pubstack:{adUnitName:"rectangle_layer",adUnitPath:getPlacementName("rectangle_layer",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_layer")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482026",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689374",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3908092"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1406386",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113837",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537582",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2115566",position:"atf"}},
						{bidder:"adform",params:{mid:"1071672"}},
						// {bidder:"emx_digital",params:{tagid:"150105"}},
						{bidder:"sovrn",params:{tagid:"926696"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_layer","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("rectangle_layer","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_layer","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}
				}],
				'rectangle_exit': [{
					code: "rectangle_exit|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}}, pubstack:{adUnitName:"rectangle_exit",adUnitPath:getPlacementName("rectangle_exit",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_exit")}},
						{bidder:"appnexus",params:{placementId:"21485667",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482027",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689375",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3908093"}},
						{bidder:"smart",params:{siteId:"407323",pageId:"1406387",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113840",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537583",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372872",zoneId:"2115568",position:"atf"}}, 
						{bidder:"adform",params:{mid:"1071673"}},
						// {bidder:"emx_digital",params:{tagid:"150106"}},
						{bidder:"sovrn",params:{tagid:"926697"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_exit","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555391",tagId:getPlacementName("rectangle_exit","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_exit","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}
				}]
			};
		} else if(AdService.getParam('portal') == 'gmxcouk'){
			pbConfig.passover.slots = {
				'contentad_1': [{
					code: "contentad_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_1.sizes}}, pubstack:{adUnitName:"contentad_1",adUnitPath:getPlacementName("contentad_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("contentad_1")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340099",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663043",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613498"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375013",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544046313",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491882",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037436",position:"atf"}},
						{bidder:"adform",params:{mid:"1037857"}},
						// {bidder:"emx_digital",params:{tagid:"146585"}},
						{bidder:"sovrn",params:{tagid:"890736"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("contentad_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("contentad_1","medium_rectangle",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("contentad_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_1.sizes}
				}],
				'contentad_2': [{
					code: "contentad_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_2.sizes}}, pubstack:{adUnitName:"contentad_2",adUnitPath:getPlacementName("contentad_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("contentad_2")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340100",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663044",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613499"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375014",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039527",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491883",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037514",position:"btf"}},
						{bidder:"adform",params:{mid:"1037859"}},
						// {bidder:"emx_digital",params:{tagid:"146586"}},
						{bidder:"sovrn",params:{tagid:"890738"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("contentad_2","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("contentad_2","medium_rectangle",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("contentad_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.contentad_2.sizes}
				}],
				'top': [{
					code: "top|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("top")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340095",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663048",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613540"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375015",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039529",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491852",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037516",position:"atf"}},
						{bidder:"adform",params:{mid:"1037970"}}
					]
				},{
					code: "top|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146587"}},
						{bidder:"sovrn",params:{tagid:"890739"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("top","billboard",1)}}
					]
				},{
					code: "top|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146589"}},
						{bidder:"sovrn",params:{tagid:"890740"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("top","leaderboard",1)}}
					]
				},{
					code: "top|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146590"}},
						{bidder:"sovrn",params:{tagid:"890741"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("top","superbanner",1)}}
					]
				},{
					code: "top|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"top",adUnitPath:getPlacementName("top",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146591"}},
						{bidder:"sovrn",params:{tagid:"890742"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("top","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("top","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("top","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.top.sizes}
				}],
				'box_1': [{
					code: "box_1|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340096",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663050",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3616799"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375016",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039532",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491853",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037518",position:"atf"}},
						{bidder:"adform",params:{mid:"1037886"}}
					]
				},{
					code: "box_1|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146592"}},
						{bidder:"sovrn",params:{tagid:"890744"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("box_1","halfpagead",1)}}
					]
				},{
					code: "box_1|mediumrectangle", mediaTypes: {banner:{sizes: [[300,250]]}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146593"}},
						{bidder:"sovrn",params:{tagid:"890745"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_1","medium_rectangle",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("box_1","medium_rectangle",1)}}
					]
				},{
					code: "box_1|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_1",adUnitPath:getPlacementName("box_1",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22941265",allowSmallerSizes:true,position:"above",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_1")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_1","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_1.sizes}
				}],
				'box_2': [{
					code: "box_2|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340101",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663052",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613500"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375017",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039535",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491884",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037520",position:"btf"}},
						{bidder:"adform",params:{mid:"1037863"}},
						// {bidder:"emx_digital",params:{tagid:"146594"}},
						{bidder:"sovrn",params:{tagid:"890748"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_2","medium_rectangle",2)}}
					]
				},{
					code: "box_2|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_2",adUnitPath:getPlacementName("box_2",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22941265",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_2")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_2","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_2.sizes}
				}],
				'box_3': [{
					code: "box_3|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340102",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663053",size:[300,250]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613501"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375018",formatId:"75978"}},
						{bidder:"openx",params:{unit:"544039538",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491885",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037522",position:"btf"}},
						{bidder:"adform",params:{mid:"1037868"}},
						// {bidder:"emx_digital",params:{tagid:"146595"}},
						{bidder:"sovrn",params:{tagid:"890751"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("box_3","medium_rectangle",2)}}
					]
				},{
					code: "box_3|native", sizes: [[1,1]], mediaTypes: {native:{image:{required:true},title:{required:true},icon:{required:false},body:{required:false}}}, pubstack:{adUnitName:"box_3",adUnitPath:getPlacementName("box_3",null,3)},
					bids: [
						{bidder:"appnexus",params:{placementId:"22941265",allowSmallerSizes:true,position:"below",keywords:pbTargeting}},
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("box_3")}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("box_3","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.box_3.sizes}
				}],
				'right': [{
					code: "right|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("right")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340097",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663055",size:[160,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613495"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375019",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039541",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491854",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037524",position:"atf"}},
						{bidder:"adform",params:{mid:"1037911"}}
					]
				},{
					code: "right|skyscraper", mediaTypes: {banner:{sizes: [[160,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146597"}},
						{bidder:"sovrn",params:{tagid:"890753"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","wide_skyscraper",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("right","wide_skyscraper",1)}}
					]
				},{
					code: "right|halfpagead", mediaTypes: {banner:{sizes: [[300,600]]}}, pubstack:{adUnitName:"right",adUnitPath:getPlacementName("right",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146596"}},
						{bidder:"sovrn",params:{tagid:"890752"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("right","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("right","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("right","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.right.sizes}
				}],
				'bottom': [{
					code: "bottom|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("bottom")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340098",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663060",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613527"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375020",formatId:"88173"}},
						{bidder:"openx",params:{unit:"544039544",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491855",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037526",position:"atf"}},
						{bidder:"adform",params:{mid:"1037966"}}
					]
				},{
					code: "bottom|billboard", mediaTypes: {banner:{sizes: [[970,250]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146599"}},
						{bidder:"sovrn",params:{tagid:"890756"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","billboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("bottom","billboard",1)}}
					]
				},{
					code: "bottom|leaderboard", mediaTypes: {banner:{sizes: [[970,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146601"}},
						{bidder:"sovrn",params:{tagid:"890758"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","leaderboard",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("bottom","leaderboard",1)}}
					]
				},{
					code: "bottom|superbanner", mediaTypes: {banner:{sizes: [[728,90]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146602"}},
						{bidder:"sovrn",params:{tagid:"890760"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("bottom","superbanner",1)}}
					]
				},{
					code: "bottom|fullsize", mediaTypes: {banner:{sizes: [[468,60]]}}, pubstack:{adUnitName:"bottom",adUnitPath:getPlacementName("bottom",null,3)},
					bids: [
						// {bidder:"emx_digital",params:{tagid:"146603"}},
						{bidder:"sovrn",params:{tagid:"890762"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("bottom","fullsize_banner",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("bottom","fullsize_banner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("bottom","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.bottom.sizes}
				}],
				'slider': [{
					code: "slider|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}}, pubstack:{adUnitName:"slider",adUnitPath:getPlacementName("slider",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("slider")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"below",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12340103",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"663062",size:[728,90]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3613528"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1375021",formatId:"75982"}},
						{bidder:"openx",params:{unit:"544039547",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22491886",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2037528",position:"btf"}},
						{bidder:"adform",params:{mid:"1037902"}},
						// {bidder:"emx_digital",params:{tagid:"146604"}},
						{bidder:"sovrn",params:{tagid:"890768"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("slider","superbanner",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("slider","superbanner",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("slider","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.slider.sizes}
				}],
				'rectangle_layer': [{
					code: "rectangle_layer|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}}, pubstack:{adUnitName:"rectangle_layer",adUnitPath:getPlacementName("rectangle_layer",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_layer")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482020",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689386",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3907964"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1406380",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113819",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537576",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2104534",position:"atf"}}, 
						{bidder:"adform",params:{mid:"1071653"}},
						// {bidder:"emx_digital",params:{tagid:"150099"}},
						{bidder:"sovrn",params:{tagid:"926690"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_layer","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("rectangle_layer","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_layer","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_layer.sizes}
				}],
				'rectangle_exit': [{
					code: "rectangle_exit|all", mediaTypes: {banner:{sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}}, pubstack:{adUnitName:"rectangle_exit",adUnitPath:getPlacementName("rectangle_exit",null,3)},
					bids: [
						{bidder:"criteo",params:{networkId:"2558",publisherSubId:getPlacementName("rectangle_exit")}},
						{bidder:"appnexus",params:{placementId:"21485663",position:"above",keywords:pbTargeting}},
						{bidder:"yieldlab",params:{adslotId:"12482021",supplyId:"13216",targeting:pbTargeting}},
						{bidder:"ix",params:{siteId:"689387",size:[300,600]}},
						{bidder:"pubmatic",params:{publisherId:"157878",adSlot:"3907966"}},
						{bidder:"smart",params:{siteId:"407319",pageId:"1406381",formatId:"75979"}},
						{bidder:"openx",params:{unit:"544113823",delDomain:"united-internet-d.openx.net"}},
						{bidder:"improvedigital",params:{placementId:"22537577",publisherId:1258}},
						{bidder:"rubicon",params:{accountId:"21240",siteId:"372868",zoneId:"2104536",position:"atf"}}, 
						{bidder:"adform",params:{mid:"1071654"}},
						// {bidder:"emx_digital",params:{tagid:"150100"}},
						{bidder:"sovrn",params:{tagid:"926691"}},
						{bidder:"triplelift",params:{inventoryCode:getPlacementName("rectangle_exit","halfpagead",2)}},
						{bidder:"taboola",params:{publisherId:"1555390",tagId:getPlacementName("rectangle_exit","halfpagead",1)}}
					]
				},{
					amazon: true, params: {slotID: getPlacementName("rectangle_exit","sizeless"), sizes: window.ui.AdServiceConfig.configurations.sizes.rectangle_exit.sizes}
				}]
			};
		}
		return pbConfig;
	}
});