import { NativeModules } from 'react-native';

type OpenXrNative = {
  isXrDevice(): Promise<boolean>;
  getRuntimeInfo(): Promise<{ platform: string; immersiveSupported: boolean }>;
};

const { OpenXr } = NativeModules as { OpenXr: OpenXrNative };

export const isXrDevice = () => OpenXr.isXrDevice();
export const getRuntimeInfo = () => OpenXr.getRuntimeInfo();
