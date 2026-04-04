var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");

// Add or->R conversion at the start of parseVoiceTranscript
j=j.replace(
  "var t=text.toLowerCase().trim();",
  "var t=text.toLowerCase().trim();\n  t=t.replace(/\\bor\\b/gi,'r').replace(/\\bare\\b/gi,'r').replace(/\\bour\\b/gi,'r').replace(/\\bby\\b/gi,'/').replace(/\\bpoint\\b/gi,'.');\n  t=t.replace(/(\\d)\\s+r\\s*(\\d)/gi,'$1r$2').replace(/(\\d)\\s+\\/\\s*(\\d)/g,'$1/$2').replace(/(\\d)\\s+\\.\\s*(\\d)/g,'$1.$2');"
);

// Wrap voiceSaveEntry call in try/catch
j=j.replace(
  "voiceSaveEntry(r).then(function(){",
  "voiceSaveEntry(r).then(function(){"
);

// Add status display before save attempt
j=j.replace(
  "voiceSaveEntry(r).then(function(){",
  'document.getElementById("voiceStatus").textContent="Saving: "+r.brand+" "+r.size+" x"+r.quantity;voiceSaveEntry(r).then(function(){'
);

fs.writeFileSync("public/main.js",j);
console.log("DONE");
