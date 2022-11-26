/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

const  path = require('path');
const fs = require('fs');
const verify = require('../build/Release/winVerifyTrust.node');

function verifySignatureByPublishName(filePath,publishName) {

  const allowed = [ '.exe', '.cab', '.dll', '.ocx', '.msi', '.msix', '.xpi' ];
  const ext = path.extname(filePath);
  if (!allowed.includes(ext)) throw Error(`Accepted file types are: ${allowed.join(",")}`);
  
  if (!fs.existsSync(filePath)) throw Error("Unable to locate target file");
  return verify.verifySignature(filePath, publishName);
}

module.exports =  { verifySignatureByPublishName };