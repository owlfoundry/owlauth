import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "../dist/index.js";

test("Client stores its base URL", () => {
  const client = new Client("https://auth.example.com");
  assert.equal(client.baseUrl, "https://auth.example.com");
});
