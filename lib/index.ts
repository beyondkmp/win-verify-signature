const path = require("path");
const fs = require("fs");
declare interface ISignStatus {
  signed: boolean;
  message: string;
  subject: string;
}

type NativeModule = {
  verifySignature: (filePath: string) => ISignStatus;
};

// The native binary will be loaded lazily to avoid any possible crash at start
// time, which are harder to trace.
let _nativeModule: NativeModule;

function getNativeModule() {
  _nativeModule = require("bindings")("win-verify-signature.node");
  return _nativeModule;
}

function parseDn(seq: string): Map<string, string> {
  let quoted = false;
  let key: string | null = null;
  let token = "";
  let nextNonSpace = 0;

  seq = seq.trim();
  const result = new Map<string, string>();
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

export function verifySignatureByPublishName(
  filePath: string,
  publishNames: string[]
): ISignStatus {
  const allowed = [".exe", ".cab", ".dll", ".ocx", ".msi", ".msix", ".xpi"];
  const ext = path.extname(filePath);
  if (!allowed.includes(ext))
    throw Error(`Accepted file types are: ${allowed.join(",")}`);
  if (!fs.existsSync(filePath)) throw Error("Unable to locate target file");
  const result = getNativeModule().verifySignature(filePath);

  if (result.signed === false) return result;

  const subject = parseDn(result.subject);
  let match = false;
  for (const name of publishNames) {
    const dn = parseDn(name);
    if (dn.size) {
      // if we have a full DN, compare all values
      const allKeys = Array.from(dn.keys());
      match = allKeys.every((key) => {
        return dn.get(key) === subject.get(key);
      });
    } else if (name === subject.get("CN")) {
      match = true;
    }

    if (match) {
      return result;
    }
  }

  return {
    signed: false,
    message: `Publisher name does not match ${publishNames} and ${result.subject}`,
    subject: result.subject,
  };
}
