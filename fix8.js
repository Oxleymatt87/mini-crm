var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");
j=j.replace(
  'if(!resp.ok)throw new Error("API "+resp.status);var data=await resp.json();var t=data.candidates[0].content.parts[0].text;var m=t.match(/\\{[\\s\\S]*\\}/);if(m)return JSON.parse(m[0]);return JSON.parse(t);',
  'var data=await resp.json();if(!resp.ok)throw new Error("API "+resp.status+": "+JSON.stringify(data).substring(0,100));if(!data.candidates||!data.candidates[0])throw new Error("No candidates: "+JSON.stringify(data).substring(0,100));var t=data.candidates[0].content.parts[0].text;var m=t.match(/\\{[\\s\\S]*\\}/);if(m)return JSON.parse(m[0]);return JSON.parse(t);'
);
fs.writeFileSync("public/main.js",j);
console.log("DONE");
