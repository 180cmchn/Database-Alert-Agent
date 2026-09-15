import assert from "node:assert/strict";
import test from "node:test";

import { flashDutyProgressLabel, unacknowledgedAssigneeLabel } from "../src/lib/format.ts";

test("FlashDuty progress uses handling labels instead of analysis labels", () => {
  assert.deepEqual(flashDutyProgressLabel, {
    Triggered: "待处理",
    Processing: "处理中",
    Closed: "已关闭",
  });
});

test("unacknowledged assignee label prefers the resolved member name", () => {
  assert.equal(
    unacknowledgedAssigneeLabel({ person_id: 12, person_name: "assigned.only" }),
    "assigned.only未认领",
  );
});

test("unacknowledged assignee label falls back to the numeric person id", () => {
  assert.equal(
    unacknowledgedAssigneeLabel({ person_id: 12, person_name: null }),
    "成员 #12未认领",
  );
});
