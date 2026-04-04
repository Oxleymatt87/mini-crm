var fs = require("fs");
var j = fs.readFileSync("public/main.js", "utf8");

// Remove old voiceGemini function
j = j.replace(/async function voiceGemini[\s\S]*?(?=\n(?:async )?function |window\.|$)/, "");

// Add local parser
j += '\n' + 'function parseVoiceTranscript(text) {' +
'\n  var t = text.toLowerCase();' +
'\n  var words = {"zero":0,"one":1,"two":2,"three":3,"four":4,"five":5,"six":6,"seven":7,"eight":8,"nine":9,"ten":10,"eleven":11,"twelve":12,"thirteen":13,"fourteen":14,"fifteen":15,"sixteen":16,"seventeen":17,"eighteen":18,"nineteen":19,"twenty":20,"thirty":30,"forty":40,"fifty":50,"sixty":60,"seventy":70,"eighty":80,"ninety":90,"hundred":100};' +
'\n  Object.keys(words).forEach(function(w){t=t.replace(new RegExp("\\\\b"+w+"\\\\b","g"),words[w]);});' +
'\n  t=t.replace(/(\\d+)\\s+(\\d{1,2})(?!\\d)/g,function(_,a,b){return parseInt(a)<10?a+b:parseInt(a)*10+parseInt(b);});' +
'\n  t=t.replace(/\\b(or|are|our)\\b/gi,"R").replace(/\\b(by|buy)\\b/gi,"/").replace(/\\bpoint\\b/gi,".");' +
'\n  var sizes=["11R22.5","11R24.5","12R22.5","215/75R17.5","225/70R19.5","235/75R17.5","245/70R19.5","255/70R22.5","265/70R19.5","275/70R22.5","275/80R22.5","285/75R24.5","295/60R22.5","295/75R22.5","295/80R22.5","305/70R19.5","315/70R22.5","315/80R22.5","365/65R22.5","385/65R22.5","425/65R22.5","445/50R22.5","445/65R22.5","ST235/80R16","ST235/85R16"];' +
'\n  var foundSize=null;sizes.forEach(function(s){if(t.toUpperCase().indexOf(s)!==-1)foundSize=s;});' +
'\n  if(!foundSize){sizes.forEach(function(s){var p=s.replace(/\\//g,"[/ ]?").replace(/R/,"[R ]?").replace(/\\./,"[. ]?");var re=new RegExp(p,"i");var m=t.match(re);if(m)foundSize=s;});}' +
'\n  var brands={"amulet":"Amulet","royal black":"Royal Black","royalblack":"Royal Black","jinyu":"Jinyu","atlas":"Atlas","lancaster":"Lancaster","giti":"Giti","sailun":"Sailun"};' +
'\n  var foundBrand=null;Object.keys(brands).forEach(function(b){if(t.indexOf(b)!==-1)foundBrand=brands[b];});' +
'\n  var models=["AT505","AD507","AA610","AA612","AD515","SL101","SL102","DL301","AM201","AV211","WDV01","DV302","DM325","TL001"];' +
'\n  var foundModel=null;models.forEach(function(m){if(t.toUpperCase().indexOf(m)!==-1)foundModel=m;});' +
'\n  var qtyMatch=t.match(/^\\s*(\\d+)\\b/);var qty=qtyMatch?parseInt(qtyMatch[1]):null;' +
'\n  var pos="All Position";if(/\\b(steer|front)\\b/i.test(t))pos="Steer";if(/\\bdrive\\b/i.test(t))pos="Drive";if(/\\btrailer\\b/i.test(t))pos="Trailer";' +
'\n  return {brand:foundBrand||"",model:foundModel||"",size:foundSize||"",quantity:qty,position:pos,condition:"New"};' +
'\n}';

// Replace voiceGemini call with parseVoiceTranscript
j = j.replace(/await voiceGemini\(text\)/g, "parseVoiceTranscript(text)");
j = j.replace(/var r=await parseVoiceTranscript/g, "var r=parseVoiceTranscript");

fs.writeFileSync("public/main.js", j);
console.log("DONE");
