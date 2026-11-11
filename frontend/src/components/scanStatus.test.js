import assert from "node:assert/strict";
import test from "node:test";
import { scannerStatusClass } from "./scanStatus.js";

test("scanner status classes distinguish failed scans without changing other states", () => {
  assert.equal(scannerStatusClass("completed"), "success");
  assert.equal(scannerStatusClass("failed"), "failed");
  assert.equal(scannerStatusClass("running"), "pending");
  assert.equal(scannerStatusClass("pending"), "pending");
  assert.equal(scannerStatusClass("unknown"), "pending");
});
