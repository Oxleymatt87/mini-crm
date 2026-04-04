var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");
var lines=j.split("\n");
var last=lines[lines.length-1];
if(last.includes("loadGeminiKey")){
  lines.pop();
  lines.push("");
  lines.push('async function loadGeminiKey(){try{var doc=await db.collection("config").doc("gemini").get();if(doc.exists&&doc.data().key){window._gemKey=doc.data().key;}}catch(e){}}');
  lines.push("");
}
j=lines.join("\n");
fs.writeFileSync("public/main.js",j);
console.log("FIXED");
