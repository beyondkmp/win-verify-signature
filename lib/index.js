/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

import { parse } from "node:path";
import { existsSync } from "node:fs";
import { verifySignature } from '../build/Release/winVerifyTrust.node';

function verifySignature(filePath,publishName) {

  const allowed = [ '.exe', '.cab', '.dll', '.ocx', '.msi', '.msix', '.xpi' ];
  const ext = parse(filePath).ext;
  if (!allowed.includes(ext)) throw new Error(`Accepted file types are: ${allowed.join(",")}`, "ERR_UNEXPECTED_FILE_TYPE");
  
  if (!existsSync(filePath)) throw new Error("Unable to locate target file", "ERR_NO_SUCH_FILE");

  return verifySignature(filePath);
}


export { verifySignature };