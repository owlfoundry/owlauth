import { describe, expect, it, vi } from "vitest";

import {
  ControlAuthenticationError,
  ControlRequestError,
  IdempotencyAttempt,
  verifyControlKey,
} from "./client";

describe("Control capability verification", () => {
  it("unlocks for provisioning readiness without claiming federated Project Auth", async () => {
    const client = await verifyControlKey(
      "/v1/",
      "operator-key",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          Response.json({
            product: "owlauth-server",
            provisioning: true,
            login_readiness: true,
            federated_project_auth: false,
          }),
        ),
      ),
    );

    client.dispose();
  });

  it("rejects a deployment that lacks provisioning capability", async () => {
    await expect(
      verifyControlKey(
        "/v1/",
        "operator-key",
        vi.fn<typeof fetch>(() =>
          Promise.resolve(
            Response.json({
              product: "owlauth-server",
              provisioning: false,
              login_readiness: true,
              federated_project_auth: false,
            }),
          ),
        ),
      ),
    ).rejects.toBeInstanceOf(ControlAuthenticationError);
  });
});

describe("IdempotencyAttempt", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("reuses one key after ambiguous failure and blocks concurrent dispatch", () => {
    vi.spyOn(crypto, "randomUUID").mockReturnValue("11111111-1111-4111-8111-111111111111");
    const attempt = new IdempotencyAttempt();

    const first = attempt.begin();
    expect(first).toBe("console_11111111111141118111111111111111");
    expect(attempt.begin()).toBeNull();

    attempt.settle(new TypeError("network response was lost"));
    expect(attempt.begin()).toBe(first);
  });

  it("rotates after success or a definitive client response", () => {
    const attempt = new IdempotencyAttempt();
    const first = attempt.begin();
    attempt.settle();
    expect(attempt.begin()).not.toBe(first);

    attempt.settle(new ControlRequestError(undefined, 409));
    const afterConflict = attempt.begin();
    expect(afterConflict).not.toBe(first);
  });

  it("retains retry identity for ambiguous timeout, in-progress, and server responses", () => {
    const attempt = new IdempotencyAttempt();
    const first = attempt.begin();
    attempt.settle(new ControlRequestError(undefined, 408));
    expect(attempt.begin()).toBe(first);

    attempt.settle(
      new ControlRequestError(
        {
          code: "operation_in_progress",
          detail: "The durable operation has not completed yet.",
          request_id: "request-1",
          status: 409,
          title: "Operation in progress",
          type: "about:blank",
        },
        409,
      ),
    );
    expect(attempt.begin()).toBe(first);

    attempt.settle(new ControlRequestError(undefined, 503));
    expect(attempt.begin()).toBe(first);
    attempt.abandon();
    expect(attempt.retainsKey).toBe(false);
  });
});
