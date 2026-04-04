var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");
j=j.replace(
  'window.voiceToggle=function(){if(!voiceRecog&&!voiceInit())return;',
  'window.voiceToggle=function(){document.getElementById("voiceStatus").textContent="Mic tapped...";if(!voiceRecog&&!voiceInit()){document.getElementById("voiceStatus").textContent="ERROR: No speech support in this browser";return;}'
);
fs.writeFileSync("public/main.js",j);
console.log("DONE");
