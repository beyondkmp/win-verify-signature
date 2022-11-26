import { isSigned, trustStatus } from "@xan105/win-verify-trust";

console.log( await isSigned("path/to/file") ); //True (Signed) or False

console.log( await trustStatus("path/to/file") ); //Verbose
/* Example:
  "The signature is present but not trusted"
*/