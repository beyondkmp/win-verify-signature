type NativeModule = {
  is24hoursTimeFormat: () => boolean
}

// The native binary will be loaded lazily to avoid any possible crash at start
// time, which are harder to trace.
let _nativeModule: NativeModule | undefined = undefined

function getNativeModule() {
  _nativeModule = require('bindings')('check-24-hours-time.node')
  return _nativeModule
}

export function is24hoursTimeFormat(): boolean {
  const result = getNativeModule()?.is24hoursTimeFormat()
  return !!result
}
