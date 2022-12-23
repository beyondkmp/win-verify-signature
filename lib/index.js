/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

const path = require("path");
const fs = require("fs");
const verify = require("../build/Release/winVerifyTrust.node");

function parseDn(seq) {
  let quoted = false;
  let key = null;
  let token = "";
  let nextNonSpace = 0;

  seq = seq.trim();
  const result = new Map();
  for (let i = 0; i <= seq.length; i++) {
    if (i === seq.length) {
      if (key !== null) {
        result.set(key, token);
      }
      break;
    }

    const ch = seq[i];
    if (quoted) {
      if (ch === '"') {
        quoted = false;
        continue;
      }
    } else {
      if (ch === '"') {
        quoted = true;
        continue;
      }

      if (ch === "\\") {
        i++;
        const ord = parseInt(seq.slice(i, i + 2), 16);
        if (Number.isNaN(ord)) {
          token += seq[i];
        } else {
          i++;
          token += String.fromCharCode(ord);
        }
        continue;
      }

      if (key === null && ch === "=") {
        key = token;
        token = "";
        continue;
      }

      if (ch === "," || ch === ";" || ch === "+") {
        if (key !== null) {
          result.set(key, token);
        }
        key = null;
        token = "";
        continue;
      }
    }

    if (ch === " " && !quoted) {
      if (token.length === 0) {
        continue;
      }

      if (i > nextNonSpace) {
        let j = i;
        while (seq[j] === " ") {
          j++;
        }
        nextNonSpace = j;
      }

      if (
        nextNonSpace >= seq.length ||
        seq[nextNonSpace] === "," ||
        seq[nextNonSpace] === ";" ||
        (key === null && seq[nextNonSpace] === "=") ||
        (key !== null && seq[nextNonSpace] === "+")
      ) {
        i = nextNonSpace - 1;
        continue;
      }
    }

    token += ch;
  }

  return result;
}

function checkDn(signResult, publisherNames) {
  const subject = parseDn(signResult.subject);
  let match = false;
  for (const name of publisherNames) {
    const dn = parseDn(name);
    if (dn.size) {
      // if we have a full DN, compare all values
      const allKeys = Array.from(dn.keys());
      match = allKeys.every((key) => {
        return dn.get(key) === subject.get(key);
      });
    } else if (name === subject.get("CN")) {
      signResult.message = `Signature validated using only CN ${name}. Please add your full Distinguished Name (DN) to publisherNames configuration`;
      match = true;
    }
  }
  return match;
}

function verifySignatureByPublishName(filePath, publishNames) {
  const allowed = [".exe", ".cab", ".dll", ".ocx", ".msi", ".msix", ".xpi"];
  const ext = path.extname(filePath);
  if (!allowed.includes(ext))
    throw Error(`Accepted file types are: ${allowed.join(",")}`);

  if (!fs.existsSync(filePath)) throw Error("Unable to locate target file");
  const result = verify.verifySignature(filePath);
  if (result.signed === false) return result;
  if (checkDn(result, publishNames)) {
    return result;
  }
  return {
    signed: false,
    message: `Publisher name does not match ${publishNames} and ${result.subject}`,
  };
}

module.exports = { verifySignatureByPublishName };
