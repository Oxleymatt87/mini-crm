var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");
j=j.replace(
  'voiceRecog.continuous=true;voiceRecog.interimResults=true;',
  'voiceRecog.continuous=false;voiceRecog.interimResults=false;'
);
fs.writeFileSync("public/main.js",j);
console.log("DONE");
