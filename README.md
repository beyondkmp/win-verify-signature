About
=====

Check the signature of an _executable_ file using the WinVerifyTrust API.

Example
=======

```js

const verify = require("win-verify-signature");

console.log( verify.verifySignature("path/to/file", ["CN=Microsoft Corporation;O=Microsoft Corporation;L=Redmond;S=Washington;C=US;"]) ); 

/* Example: 
{
  signed: true,
  message: "The file is signed and the signature was verified"
  signObject: "CN=Microsoft Corporation;O=Microsoft Corporation;L=Redmond;S=Washington;C=US;"
}
*/
```

### types

```
declare interface IStatus {
  signed: boolean,
  message: string,
  signObject?: string
}
export function verifySignatureByPublishName(filePath: string, publisherName: string): IStatus;
```
