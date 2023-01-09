'use strict'
Object.defineProperty(exports, '__esModule', { value: true })
exports.is24hoursTimeFormat = void 0
// The native binary will be loaded lazily to avoid any possible crash at start
// time, which are harder to trace.
let _nativeModule = undefined
function getNativeModule() {
  _nativeModule = require('bindings')('check-24-hours-time.node')
  // _nativeModule = require('../build/Release/win32-user-locale.node')
  return _nativeModule
}
function is24hoursTimeFormat() {
  var _a
  const result =
    (_a = getNativeModule()) === null || _a === void 0
      ? void 0
      : _a.is24hoursTimeFormat()
  return !!result
}
exports.is24hoursTimeFormat = is24hoursTimeFormat
//# sourceMappingURL=index.js.map
