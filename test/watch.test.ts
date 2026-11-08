import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { watchConfigPath } from "../src/util/watch.js";

function changed(path: string, write: () => void): Promise<boolean> {
  return new Promise((resolve) => {
    const handle = watchConfigPath({
      path,
      debounceMs: 20,
      onChange: () => {
        handle.stop();
        resolve(true);
      },
    });
    setTimeout(() => {
      handle.stop();
      resolve(false);
    }, 4000).unref();
    // Past the watcher arming, so the event is not lost to a race.
    setTimeout(write, 100);
  });
}

test("watchConfigPath fires when the config file appears", async () => {
  const dir = mkdtempSync(join(tmpdir(), "approver-watch-"));
  try {
    const p = join(dir, "approver.config.js");
    assert.equal(await changed(p, () => writeFileSync(p, "export default () => null;\n")), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// fs.watch reports the name as it is on disk. A path written with different
// casing names the same file on Windows, so it has to match there.
test(
  "watchConfigPath matches the file name case-insensitively on Windows",
  { skip: process.platform !== "win32" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "approver-watch-"));
    try {
      const watched = join(dir, "Approver.Config.js");
      const onDisk = join(dir, "approver.config.js");
      assert.equal(
        await changed(watched, () => writeFileSync(onDisk, "export default () => null;\n")),
        true,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
