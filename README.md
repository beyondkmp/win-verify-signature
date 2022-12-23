About
=====

Check the signature of an _executable_ file using the WinVerifyTrust API

Example
=======

```js

const verify = require("win-verify-signature");

console.log( verify.verifySignatureByPublishName("path/to/file", ["CN=Microsoft Corporation;O=Microsoft Corporation;L=Redmond;S=Washington;C=US;"]) ); 

/* Example: 
{
  signed: true,
  message: "The file is signed and the signature was verified"
  subject: "CN=Microsoft Corporation;O=Microsoft Corporation;L=Redmond;S=Washington;C=US;"
}
*/
```

### types

```
declare interface IStatus {
  signed: boolean,
  message: string,
  subject?: string
}
export function verifySignatureByPublishName(filePath: string, publisherName: string): IStatus;
```

# Refer
https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/security/cryptoapi/VerifyNameTrust/VerifyNameTrust/VerifyNameTrust.cpp
