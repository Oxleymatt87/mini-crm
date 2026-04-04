var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");
j=j.replace(
  'var key="AIzaSyC5ERlQSJC_ZTQvCL7Z5HdqG_qG0G8YrQw"',
  'var key="AIzaSyDGeGbcMQrcMNeZzNutbbb4oUsTXEimnSo"'
);
j=j.replace(
  'await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent?key="+key,{method:"POST",headers:{"Content-Type":"application/json"}',
  'await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent",{method:"POST",headers:{"Content-Type":"application/json","X-goog-api-key":key}'
);
fs.writeFileSync("public/main.js",j);
console.log("DONE");
