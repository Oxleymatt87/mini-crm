var fs=require("fs");
var j=fs.readFileSync("public/main.js","utf8");

// Replace parseVoiceTranscript call with async Gemini call
j=j.replace(
  'var r=parseVoiceTranscript(text);',
  'var r=await voiceGemini(text);'
);

// Make voiceListen's onresult async
j=j.replace(
  'rec.onresult=function(e){',
  'rec.onresult=async function(e){'
);

// Add voiceGemini function before the closing voiceRenderLog
j+='\nasync function voiceGemini(text){\n';
j+='  var prompt="You are a TBR tire inventory parser. The input is garbled speech-to-text. Figure out what tire is being described. Return ONLY JSON: {brand,model,size,quantity,position,condition}. Voice mangles: or/are/our=R, by/buy=/, point=., amulet/inlet/hamlet=Amulet, royal black/royalblack=Royal Black. Brands: Amulet(AT505,AD507,AA610,AA612,AD515), Royal Black(SL101,SL102,DL301,AM201,AV211,WDV01,DV302,DM325,TL001), Jinyu, Atlas, Lancaster. Sizes: 11R22.5,11R24.5,225/70R19.5,235/75R17.5,255/70R22.5,275/70R22.5,285/75R24.5,295/75R22.5,315/80R22.5,385/65R22.5,425/65R22.5,ST235/80R16,ST235/85R16. Input: "+text;\n';
j+='  var resp=await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=AIzaSyDGeGbcMQrcMNeZzNutbbb4oUsTXEimnSo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({contents:[{parts:[{text:prompt}]}]})});\n';
j+='  if(!resp.ok){var e=await resp.text();throw new Error("API "+resp.status);}\n';
j+='  var data=await resp.json();\n';
j+='  var t=data.candidates[0].content.parts[0].text;\n';
j+='  var m=t.match(/\\{[\\s\\S]*\\}/);\n';
j+='  if(m)return JSON.parse(m[0]);\n';
j+='  return JSON.parse(t);\n';
j+='}\n';

fs.writeFileSync("public/main.js",j);
console.log("DONE");
