export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const key = url.searchParams.get("key") || env.TILES_KEY || "AIzaSyD-R3irWMKrC1y7xkHWccXmkjODYweMyFg";
    const html = PAGE.replaceAll("__TILES_KEY__", key);
    return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
  }
};

const PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
<title>Oxley Globe — Immersive</title>
<script src="https://cesium.com/downloads/cesiumjs/releases/1.124/Build/Cesium/Cesium.js"></script>
<link href="https://cesium.com/downloads/cesiumjs/releases/1.124/Build/Cesium/Widgets/widgets.css" rel="stylesheet" />
<style>
  html, body, #cesiumContainer { width:100%; height:100%; margin:0; padding:0; overflow:hidden; background:#000; }
  #bar {
    position:absolute; top:0; left:0; right:0; z-index:10;
    display:flex; gap:8px; align-items:center; padding:8px 10px;
    background:linear-gradient(#000c,#0000); color:#e8e8e8;
    font:13px/1.2 -apple-system,Segoe UI,Roboto,sans-serif;
  }
  #bar button, #bar label {
    background:#161616; color:#eee; border:1px solid #333; border-radius:6px;
    padding:7px 11px; cursor:pointer; white-space:nowrap;
  }
  #bar button:hover, #bar label:hover { background:#222; }
  #status { margin-left:auto; opacity:.7; }
  #drop { position:absolute; inset:0; z-index:5; display:none;
    background:#0af3; border:3px dashed #0af; align-items:center; justify-content:center;
    color:#fff; font:600 20px sans-serif; }
  #drop.on { display:flex; }
  input[type=file]{ display:none; }
  .cesium-viewer-bottom{ display:none; }
</style>
</head>
<body>
<div id="bar">
  <label for="kmlFile">Load KML</label>
  <input id="kmlFile" type="file" accept=".kml,.kmz" />
  <button id="fly">Fly to pins</button>
  <button id="top">Top-down</button>
  <button id="reset">Reset view</button>
  <span id="status">booting…</span>
</div>
<div id="drop">drop KML here</div>
<div id="cesiumContainer"></div>

<script>
const $ = s => document.querySelector(s);
const setStatus = t => $("#status").textContent = t;

const params = new URLSearchParams(location.search);
let GKEY = params.get("key") || "__TILES_KEY__";
if (!GKEY || GKEY.indexOf("__TILES") === 0) GKEY = prompt("Google Map Tiles API key:") || "";

Cesium.Ion.defaultAccessToken = undefined;
Cesium.GoogleMaps.defaultApiKey = GKEY;

const viewer = new Cesium.Viewer("cesiumContainer", {
  globe: false,
  baseLayerPicker: false,
  geocoder: false,
  homeButton: false,
  sceneModePicker: false,
  navigationHelpButton: false,
  timeline: false,
  animation: false,
  fullscreenButton: true,
  vrButton: true,
  infoBox: true,
  selectionIndicator: true,
});

const cc = viewer.scene.screenSpaceCameraController;
cc.enableCollisionDetection = true;
cc.minimumZoomDistance = 1;
viewer.scene.skyAtmosphere.show = true;

const HOME = Cesium.Cartesian3.fromDegrees(-94.14, 30.10, 9000);
function reset(){
  viewer.camera.flyTo({ destination: HOME,
    orientation:{ heading:0, pitch:Cesium.Math.toRadians(-35), roll:0 }, duration:1.5 });
}

(async () => {
  try {
    setStatus("loading 3D tiles…");
    const ts = await Cesium.createGooglePhotorealistic3DTileset();
    viewer.scene.primitives.add(ts);
    setStatus("ready — orbit: L-drag · tilt: R-drag / 2-finger · zoom: scroll/pinch");
    reset();
  } catch (e) {
    setStatus("3D tiles failed — check key / Map Tiles API. " + (e.message||e));
  }
  const kmlUrl = params.get("kml");
  if (kmlUrl) loadKml(kmlUrl);
})();

let currentDS = null;
async function loadKml(source){
  try {
    setStatus("loading pins…");
    if (currentDS) viewer.dataSources.remove(currentDS, true);
    const ds = await Cesium.KmlDataSource.load(source, {
      camera: viewer.camera, canvas: viewer.canvas, clampToGround: true
    });
    currentDS = await viewer.dataSources.add(ds);
    await viewer.flyTo(ds);
    setStatus(ds.entities.values.length + " pins loaded — tap a pin for details");
  } catch(e){ setStatus("KML failed: " + (e.message||e)); }
}

$("#kmlFile").addEventListener("change", e => { if(e.target.files[0]) loadKml(e.target.files[0]); });
$("#fly").addEventListener("click", () => currentDS && viewer.flyTo(currentDS));
$("#reset").addEventListener("click", reset);
$("#top").addEventListener("click", () => {
  const c = viewer.camera.positionCartographic;
  viewer.camera.flyTo({
    destination: Cesium.Cartesian3.fromRadians(c.longitude, c.latitude, Math.max(c.height,4000)),
    orientation:{ heading:0, pitch:Cesium.Math.toRadians(-90), roll:0 }, duration:1 });
});

const drop = $("#drop"), body = document.body;
["dragenter","dragover"].forEach(ev => body.addEventListener(ev, e=>{e.preventDefault(); drop.classList.add("on");}));
["dragleave","drop"].forEach(ev => body.addEventListener(ev, e=>{e.preventDefault(); if(ev==="drop"||e.target===drop) drop.classList.remove("on");}));
body.addEventListener("drop", e => { const f=e.dataTransfer.files[0]; if(f) loadKml(f); });
</script>
</body>
</html>`;
