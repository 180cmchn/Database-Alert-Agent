import assert from "node:assert/strict";
import test from "node:test";

import { flashDutyProgressLabel } from "../src/lib/format.ts";

test("FlashDuty progress uses handling labels instead of analysis labels", () => {
  assert.deepEqual(flashDutyProgressLabel, {
    Triggered: "待处理",
    Processing: "处理中",
    Closed: "已关闭",
  });
});
