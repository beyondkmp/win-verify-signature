About
=====

This module is a wrapper for the WinVerifyTrust API. It is a native module and requires a C++ compiler to build. It is tested on Windows 10 and Windows 11.

The module will get all keys refers to following table and compare them with the publisher info you provide. If they matches it will return signed=true. If not, it will return the failed reason(type is string). You don't need to provide the whole publisher info, you can just provide the keys you want to compare.

```js
//  Key         Object Identifier               RDN Value Type(s)
//  ---         -----------------               -----------------
//  CN          szOID_COMMON_NAME               Printable, Unicode
//  L           szOID_LOCALITY_NAME             Printable, Unicode
//  O           szOID_ORGANIZATION_NAME         Printable, Unicode
//  OU          szOID_ORGANIZATIONAL_UNIT_NAME  Printable, Unicode
//  E           szOID_RSA_emailAddr             Only IA5
//  C           szOID_COUNTRY_NAME              Only Printable
//  S           szOID_STATE_OR_PROVINCE_NAME    Printable, Unicode
//  STREET      szOID_STREET_ADDRESS            Printable, Unicode
//  T           szOID_TITLE                     Printable, Unicode
//  G           szOID_GIVEN_NAME                Printable, Unicode
//  I           szOID_INITIALS                  Printable, Unicode
//  SN          szOID_SUR_NAME                  Printable, Unicode
//  DC          szOID_DOMAIN_COMPONENT          IA5, UTF8
//  SERIALNUMBER szOID_DEVICE_SERIAL_NUMBER     Only Printable
```


Example
=======

### Synchronous Usage (Blocks main thread)

```js
import { verifySignatureByPublishName } from 'win-verify-signature';

console.log( verifySignatureByPublishName("path/to/file", ['CN="Microsoft Corporation",O="Microsoft Corporation",L=Redmond,S=Washington,C=US"'])); 

/* Example: 
{
  signed: true,
  message: "The file is signed and the signature was verified"
  subject: "CN=\"Microsoft Corporation\";O=\"Microsoft Corporation\";L=\"Redmond\";S=\"Washington\";C=\"US\";"
}
*/
```

### Asynchronous Usage (Non-blocking, recommended for large files)

```js
import { verifySignatureByPublishNameAsync } from 'win-verify-signature';

// Using async/await
async function verifyFile() {
  try {
    const result = await verifySignatureByPublishNameAsync(
      "path/to/large-file.exe", 
      ['Microsoft Corporation']
    );
    console.log(result);
  } catch (error) {
    console.error('Verification failed:', error);
  }
}

verifyFile();

// Using Promise
verifySignatureByPublishNameAsync("path/to/file", ['Microsoft Corporation'])
  .then(result => console.log(result))
  .catch(error => console.error(error));
```

### Performance Comparison

For large files, the async version prevents blocking the main thread:

```js
// Synchronous - blocks main thread for large files
console.time('sync');
const syncResult = verifySignatureByPublishName("large-file.exe", ['Publisher']);
console.timeEnd('sync'); // May block for several seconds

// Asynchronous - non-blocking
console.time('async');
const asyncResult = await verifySignatureByPublishNameAsync("large-file.exe", ['Publisher']);
console.timeEnd('async'); // Main thread remains responsive
```

### types

```js
declare interface ISignStatus {
  signed: boolean;
  message: string;
  subject?: string;
}

export function verifySignatureByPublishName(filePath:string, publishNames:string[]):ISignStatus
export function verifySignatureByPublishNameAsync(filePath:string, publishNames:string[]):Promise<ISignStatus>
```

## When to use Async vs Sync

**Use Async (`verifySignatureByPublishNameAsync`) when:**
- Verifying large files (> 50MB)
- Batch processing multiple files
- In web servers or GUI applications where responsiveness matters
- You want to avoid blocking the event loop

**Use Sync (`verifySignatureByPublishName`) when:**
- Verifying small files (< 10MB)
- Simple command-line tools
- Blocking is acceptable for your use case

# Refer
https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/security/cryptoapi/VerifyNameTrust/VerifyNameTrust/VerifyNameTrust.cpp
