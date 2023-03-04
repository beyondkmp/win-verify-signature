const path = require("path");
import { verifySignatureByPublishName } from "../lib";

const sample = {
  signed: path.resolve("./test/sample/signed.exe"),
  unsigned: path.resolve("./test/sample/unsigned.dll"),
  ext: path.resolve("./test/sample/empty.txt"),
};

describe("getUserLocale", () => {
  it("verify signed exe", () => {
    let result = verifySignatureByPublishName(sample.signed, [
      'CN="Microsoft Corporation",L="Redmond",O="Microsoft Corporation",OU="Microsoft Corporation",C="US",S="Washington"',
    ]);
    expect(result).toEqual({
      signed: true,
      message: "The file is signed and the signature was verified",
      subject:
        'CN="Microsoft Corporation",L="Redmond",O="Microsoft Corporation",OU="Microsoft Corporation",C="US",S="Washington",SERIALNUMBER="230865+470561",',
    });

    result = verifySignatureByPublishName(sample.signed, ["test is here"]);

    expect(result).toEqual({
      signed: false,
      message:
        'Publisher name does not match test is here and CN="Microsoft Corporation",L="Redmond",O="Microsoft Corporation",OU="Microsoft Corporation",C="US",S="Washington",SERIALNUMBER="230865+470561",',
      subject:
        'CN="Microsoft Corporation",L="Redmond",O="Microsoft Corporation",OU="Microsoft Corporation",C="US",S="Washington",SERIALNUMBER="230865+470561",',
    });

    result = verifySignatureByPublishName(sample.signed, [
      "Microsoft Corporation",
    ]);

    expect(result).toEqual({
      signed: true,
      message: "The file is signed and the signature was verified",
      subject:
        'CN="Microsoft Corporation",L="Redmond",O="Microsoft Corporation",OU="Microsoft Corporation",C="US",S="Washington",SERIALNUMBER="230865+470561",',
    });
  });

  it("verify unsigned exe", () => {
    let result = verifySignatureByPublishName(sample.unsigned, [
      'CN="Microsoft Corporation",L="Redmond",O="Microsoft Corporation",OU="Microsoft Corporation",C="US",S="Washington"',
    ]);
    expect(result).toEqual({
      message: "The file is not signed",
      signed: false,
      subject: "",
    });
  });

  it("verify not accepted file", () => {
    try {
      verifySignatureByPublishName(sample.ext, ["test is here"]);
    } catch (e: any) {
      expect(e.message).toEqual(
        "Accepted file types are: .exe,.cab,.dll,.ocx,.msi,.msix,.xpi"
      );
    }
  });
});
