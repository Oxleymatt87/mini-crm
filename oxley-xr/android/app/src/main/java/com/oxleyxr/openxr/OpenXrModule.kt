package com.oxleyxr.openxr

import android.content.pm.PackageManager
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableNativeMap

class OpenXrModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String = NAME

  @ReactMethod
  fun isXrDevice(promise: Promise) {
    val pm = reactApplicationContext.packageManager
    val supportsImmersive = pm.hasSystemFeature(FEATURE_XR_IMMERSIVE)
    val supportsHeadTracking = pm.hasSystemFeature(PackageManager.FEATURE_VR_MODE_HIGH_PERFORMANCE) ||
      pm.hasSystemFeature("android.hardware.vr.headtracking")
    promise.resolve(supportsImmersive || supportsHeadTracking)
  }

  @ReactMethod
  fun getRuntimeInfo(promise: Promise) {
    val map = WritableNativeMap()
    map.putString("platform", "android-xr")
    // Real OpenXR runtime name comes from xrEnumerateInstanceExtensionProperties via NDK.
    // From Kotlin we surface what the Android XR system advertises.
    map.putBoolean("immersiveSupported", reactApplicationContext.packageManager.hasSystemFeature(FEATURE_XR_IMMERSIVE))
    promise.resolve(map)
  }

  companion object {
    const val NAME = "OpenXr"
    private const val FEATURE_XR_IMMERSIVE = "android.software.xr.immersive"
  }
}
