var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");
j=j.replace(
  'document.getElementById("voiceStatus").textContent="Mic tapped...";if(!voiceRecog&&!voiceInit()){document.getElementById("voiceStatus").textContent="ERROR: No speech support in this browser";return;}',
  'document.getElementById("voiceStatus").textContent="Initializing...";try{if(!voiceRecog&&!voiceInit()){document.getElementById("voiceStatus").textContent="ERROR: No speech API";return;}}catch(err){document.getElementById("voiceStatus").textContent="INIT ERROR: "+err.message;return;}'
);
j=j.replace(
  'voiceRecog.onend=function(){if(voiceOn){clearTimeout(voiceRT);voiceRT=setTimeout(function(){try{voiceRecog.start();}catch(e){}},200);}};return true;}',
  'voiceRecog.onend=function(){document.getElementById("voiceStatus").textContent="Mic ended, restarting...";if(voiceOn){clearTimeout(voiceRT);voiceRT=setTimeout(function(){try{voiceRecog.start();}catch(e){document.getElementById("voiceStatus").textContent="RESTART ERROR: "+e.message;}},200);}};voiceRecog.onerror=function(e){document.getElementById("voiceStatus").textContent="MIC ERROR: "+e.error;};return true;}'
);
fs.writeFileSync("public/main.js",j);
console.log("DONE");
