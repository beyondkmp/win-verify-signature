About
=====

This module is a wrapper for the WinVerifyTrust API. It is a native module and requires a C++ compiler to build. It is tested on Windows 10 and Windows 11.

The module will get all keys refers to following table and compare them with the publisher info you provide. If they matches it will return null. If not, it will return the failed reason(type is string). You don't need to provide the whole publisher info, you can just provide the keys you want to compare.

```js
//  Key         Object Identifier               RDN Value Type(s)
//  ---         -----------------               -----------------
//  CN          szOID_COMMON_NAME               Printable, Unicode
//  L           szOID_LOCALITY_NAME             Printable, Unicode
//  O           szOID_ORGANIZATION_NAME         Printable, Unicode
//  OU          szOID_ORGANIZATIONAL_UNIT_NAME  Printable, Unicode
//  E           szOID_RSA_emailAddr             Only IA5
//  Email       szOID_RSA_emailAddr             Only IA5
//  C           szOID_COUNTRY_NAME              Only Printable
//  S           szOID_STATE_OR_PROVINCE_NAME    Printable, Unicode
//  ST          szOID_STATE_OR_PROVINCE_NAME    Printable, Unicode
//  STREET      szOID_STREET_ADDRESS            Printable, Unicode
//  T           szOID_TITLE                     Printable, Unicode
//  Title       szOID_TITLE                     Printable, Unicode
//  G           szOID_GIVEN_NAME                Printable, Unicode
//  GN          szOID_GIVEN_NAME                Printable, Unicode
//  GivenName   szOID_GIVEN_NAME                Printable, Unicode
//  I           szOID_INITIALS                  Printable, Unicode
//  Initials    szOID_INITIALS                  Printable, Unicode
//  SN          szOID_SUR_NAME                  Printable, Unicode
//  DC          szOID_DOMAIN_COMPONENT          IA5, UTF8
//  SERIALNUMBER szOID_DEVICE_SERIAL_NUMBER     Only Printable
```


Example
=======

```js

const verify = require("win-verify-signature");

console.log( verify.verifySignatureByPublishName("path/to/file", ["CN=\"Microsoft Corporation\",O=\"Microsoft Corporation\",L=Redmond,S=Washington,C=US"]) ); 

/* Example: 
{
  signed: true,
  message: "The file is signed and the signature was verified"
  subject: "CN=\"Microsoft Corporation\";O=\"Microsoft Corporation\";L=\"Redmond\";S=\"Washington\";C=\"US\";"
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
export function verifySignatureByPublishName(filePath: string, publisherName: string[]): IStatus;
```

# Refer
https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/security/cryptoapi/VerifyNameTrust/VerifyNameTrust/VerifyNameTrust.cpp
