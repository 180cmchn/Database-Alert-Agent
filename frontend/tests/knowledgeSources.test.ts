import assert from "node:assert/strict";
import test from "node:test";
import { knowledgeSourcesForSave } from "../src/lib/knowledgeSources.ts";

test("saving external knowledge selection preserves extension sources and order", () => {
  assert.deepEqual(
    knowledgeSourcesForSave(
      ["incident_library", "external_knowledge", "team_wiki"],
      true,
    ),
    ["incident_library", "external_knowledge", "team_wiki"],
  );
});

test("turning off external knowledge removes only that provider", () => {
  assert.deepEqual(
    knowledgeSourcesForSave(
      ["incident_library", "external_knowledge", "team_wiki"],
      false,
    ),
    ["incident_library", "team_wiki"],
  );
});

test("turning on external knowledge appends it without replacing extensions", () => {
  assert.deepEqual(
    knowledgeSourcesForSave(["incident_library"], true),
    ["incident_library", "external_knowledge"],
  );
});
