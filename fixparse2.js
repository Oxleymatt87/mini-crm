var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");

// Switch back to local parser
j=j.replace('var r;try{r=await voiceGemini(text);}catch(err){document.getElementById("voiceStatus").textContent="ERR: "+err.message;document.getElementById("voiceMicBtn").className="";if(voiceOn)setTimeout(voiceListen,2000);return;}','var r=parseVoiceTranscript(text);');

// Replace onresult back to non-async since no await needed
j=j.replace('rec.onresult=async function(e){','rec.onresult=function(e){');

// Replace the parseVoiceTranscript function
var start=j.indexOf("function parseVoiceTranscript(text)");
var end=j.indexOf("\n}", start)+2;
var before=j.substring(0,start);
var after=j.substring(end);

var p='function parseVoiceTranscript(text) {\n';
p+='  var t=text.toLowerCase().trim();\n';
p+='  var sizes=["11R22.5","11R24.5","12R22.5","215/75R17.5","225/70R19.5","235/75R17.5","245/70R19.5","255/70R22.5","265/70R19.5","275/70R22.5","275/80R22.5","285/75R24.5","295/60R22.5","295/75R22.5","295/80R22.5","305/70R19.5","315/70R22.5","315/80R22.5","365/65R22.5","385/65R22.5","425/65R22.5","445/50R22.5","445/65R22.5","ST235/80R16","ST235/85R16"];\n';
p+='  var brands={"amulet":"Amulet","royal black":"Royal Black","jinyu":"Jinyu","atlas":"Atlas","lancaster":"Lancaster","giti":"Giti","sailun":"Sailun","inlet":"Amulet","hamlet":"Amulet"};\n';
p+='  var models={"at505":"AT505","ad507":"AD507","aa610":"AA610","aa612":"AA612","ad515":"AD515","sl101":"SL101","sl102":"SL102","dl301":"DL301","am201":"AM201","av211":"AV211","wdv01":"WDV01","dv302":"DV302","dm325":"DM325","tl001":"TL001","8505":"AT505","8505s":"AT505","a505":"AT505","80505":"AT505"};\n';
p+='  var foundBrand=null,foundModel=null,foundSize=null,foundQty=null;\n';
p+='  // Find brand\n';
p+='  Object.keys(brands).forEach(function(b){if(t.indexOf(b)!==-1)foundBrand=brands[b];});\n';
p+='  // Find model from text tokens\n';
p+='  t.split(/[\\s,]+/).forEach(function(w){\n';
p+='    var wu=w.replace(/[^a-z0-9]/g,"");\n';
p+='    if(models[wu])foundModel=models[wu];\n';
p+='    if(!foundModel){Object.keys(models).forEach(function(k){if(wu.indexOf(k)!==-1)foundModel=models[k];});}\n';
p+='  });\n';
p+='  // Find size - check for pattern like "511r22.5" -> qty 5 + 11R22.5\n';
p+='  sizes.forEach(function(s){\n';
p+='    var sl=s.toLowerCase();\n';
p+='    // Direct match\n';
p+='    if(t.indexOf(sl)!==-1){foundSize=s;return;}\n';
p+='    // Match with qty prefix: "511r22.5" -> 5 + 11r22.5, "1011r22.5" -> 10 + 11r22.5\n';
p+='    for(var q=1;q<=99;q++){\n';
p+='      if(t.indexOf(q+sl)!==-1||t.indexOf(q+" "+sl)!==-1){foundSize=s;foundQty=q;return;}\n';
p+='    }\n';
p+='    // Match in tokens\n';
p+='    t.split(/[\\s,]+/).forEach(function(w){\n';
p+='      if(w===sl){foundSize=s;return;}\n';
p+='      for(var q=1;q<=99;q++){if(w===q+sl){foundSize=s;foundQty=q;}}\n';
p+='    });\n';
p+='  });\n';
p+='  // Find qty if not found from size prefix\n';
p+='  if(!foundQty){\n';
p+='    var qm=t.match(/^(\\d{1,2})\\s/);\n';
p+='    if(qm)foundQty=parseInt(qm[1]);\n';
p+='    if(!foundQty){qm=t.match(/\\b(\\d{1,2})\\b/);if(qm&&parseInt(qm[1])<=50)foundQty=parseInt(qm[1]);}\n';
p+='  }\n';
p+='  var pos="All Position";\n';
p+='  if(/\\b(steer|front)\\b/i.test(t))pos="Steer";\n';
p+='  if(/\\bdrive\\b/i.test(t))pos="Drive";\n';
p+='  if(/\\btrailer\\b/i.test(t))pos="Trailer";\n';
p+='  return {brand:foundBrand||"",model:foundModel||"",size:foundSize||"",quantity:foundQty,position:pos,condition:"New"};\n';
p+='}';

j=before+p+after;
fs.writeFileSync("public/main.js",j);
console.log("DONE");
