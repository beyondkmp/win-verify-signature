const verify = require("../lib/index.js");
const path = require("path");
const t = require("tap");

const sample = {
  signed: path.resolve("./test/sample/signed.exe"),
  unsigned: path.resolve("./test/sample/unsigned.dll"),
  ext: path.resolve("./test/sample/empty.txt"),
};

t.test("isSigned()", async (t) => {
  await t.test("test file is signed: full Distinguished Name", async (t) =>
    t.strictSame(
      await verify.verifySignatureByPublishName(sample.signed, [
        "CN=Microsoft Corporation;O=Microsoft Corporation;L=Redmond;S=Washington;C=US",
      ]),
      {
        signed: true,
        message: "The file is signed and the signature was verified",
        signObject:
          "CN=Microsoft Corporation;O=Microsoft Corporation;L=Redmond;S=Washington;C=US;",
      }
    )
  );
  await t.test("test file is signed: Common Name", async (t) =>
    t.strictSame(
      await verify.verifySignatureByPublishName(sample.signed, [
        "Microsoft Corporation",
      ]),
      {
        signed: true,
        message: "Signature validated using only CN Microsoft Corporation. Please add your full Distinguished Name (DN) to publisherNames configuration",
        signObject:
          "CN=Microsoft Corporation;O=Microsoft Corporation;L=Redmond;S=Washington;C=US;",
      }
    )
  );
  await t.test("test file is not signed", async (t) =>
    t.strictSame(
      await verify.verifySignatureByPublishName(sample.unsigned, ["test"]),
      { signed: false, message: "pProvSigner is null" }
    )
  );
  await t.test("test file is not match: Common Name", async (t) =>
    t.strictSame(
      await verify.verifySignatureByPublishName(sample.signed, ["test"]),
      {
        signed: false,
        message:
          "Publisher name does not match test and CN=Microsoft Corporation;O=Microsoft Corporation;L=Redmond;S=Washington;C=US;",
      }
    )
  );
  t.end();
});
