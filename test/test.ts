const verify = require("../lib/index.js");
const path = require("path");
const t = require("tap");

const sample = {
  signed: path.resolve("./test/sample/signed.exe"),
  unsigned: path.resolve("./test/sample/unsigned.dll"),
  ext: path.resolve("./test/sample/empty.txt"),
};


import { is24hoursTimeFormat } from '../lib'

describe('getUserLocale', () => {
  it('works', () => {
    if (process.platform === 'win32') {
      const locale = is24hoursTimeFormat()
      expect(locale).not.toBeUndefined()
      console.log(locale)
      expect(typeof locale).toBe('boolean')
    }
    if (process.platform === 'darwin') {
      const locale = is24hoursTimeFormat()
      expect(locale).not.toBeUndefined()
      console.log(locale)
      expect(typeof locale).toBe('boolean')
    }
  })
})
