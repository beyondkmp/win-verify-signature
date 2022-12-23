const os = require("os");
const { spawnSync } = require("child_process");

if (os.platform() === "win32") {
  spawnSync("npm", ["run", "native_build"], {
    input: "win32 detected. Build native module.",
    stdio: "inherit",
  });
}
