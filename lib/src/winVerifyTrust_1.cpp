/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

#include <napi.h>

Napi::Object InitAll(Napi::Env env, Napi::Object exports){
  return exports;
}

NODE_API_MODULE(winVerifyTrust,InitAll);