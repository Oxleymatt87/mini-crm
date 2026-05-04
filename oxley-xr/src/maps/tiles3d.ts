import { TilesRenderer } from '3d-tiles-renderer';
import type { Camera, WebGLRenderer } from 'three';

const GOOGLE_3D_TILES_ROOT =
  'https://tile.googleapis.com/v1/3dtiles/root.json';

export type Google3dTilesOptions = {
  apiKey: string;
  camera: Camera;
  renderer: WebGLRenderer;
};

// Returns a configured TilesRenderer pointed at Google's photorealistic 3D Tiles.
// The caller owns the three.js scene and must call `tiles.update()` per frame
// and `tiles.dispose()` on teardown. A WebGL surface is required — on RN this
// means hosting inside a WebView or expo-gl context.
export function createGoogle3dTiles({
  apiKey,
  camera,
  renderer,
}: Google3dTilesOptions): TilesRenderer {
  const tiles = new TilesRenderer(`${GOOGLE_3D_TILES_ROOT}?key=${apiKey}`);
  tiles.setCamera(camera);
  tiles.setResolutionFromRenderer(camera, renderer);
  return tiles;
}
