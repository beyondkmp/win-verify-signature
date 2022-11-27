About
=====

Check the signature of an _executable_ file using the WinVerifyTrust API.

Example
=======

```js

const verify = require("@beyondkmp/node-win-verify-trust");

console.log( verify.verifySignature("path/to/file", "publisherName") ); 

/* Example: 
{
  signed: true,
  message: "The file is signed and the signature was verified"
}
*/
```

### types

```
declare interface IStatus {
  signed: boolean,
  message: string
}

export function verifySignatureByPublishName(filePath: string, publisherName: string): IStatus;
```
