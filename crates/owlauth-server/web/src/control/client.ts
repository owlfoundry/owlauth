import createClient from "openapi-fetch";

import type { paths } from "../generated/control-openapi";
import { assertSameOriginPlaneUrl } from "../shared/configured-base";

export interface DisposableControlClient {
  readonly client: ReturnType<typeof createClient<paths>>;
  dispose(): void;
}

export class ControlAuthenticationError extends Error {
  constructor() {
    super("Control authentication failed");
    this.name = "ControlAuthenticationError";
  }
}

function createControlClient(
  controlBase: string,
  operatorKey: string,
  fetchImplementation: typeof fetch,
): DisposableControlClient {
  let activeKey = operatorKey;
  let disposed = false;

  const baseUrl = assertSameOriginPlaneUrl(controlBase, controlBase).href;
  const client = createClient<paths>({
    baseUrl,
    fetch: async (input) => {
      if (disposed) {
        throw new Error("Control client is locked");
      }

      const request = input instanceof Request ? input : new Request(input);
      assertSameOriginPlaneUrl(request.url, controlBase);
      const headers = new Headers(request.headers);
      headers.delete("authorization");
      headers.set("authorization", `Bearer ${activeKey}`);
      return fetchImplementation(new Request(request, { headers }));
    },
  });

  return {
    client,
    dispose() {
      disposed = true;
      activeKey = "";
    },
  };
}

/**
 * Verifies one page-memory key through the ordinary Control API and returns its
 * disposable same-base client. A failed or malformed response always disposes the key.
 */
export async function verifyControlKey(
  controlBase: string,
  operatorKey: string,
  fetchImplementation: typeof fetch = fetch,
): Promise<DisposableControlClient> {
  const disposable = createControlClient(controlBase, operatorKey, fetchImplementation);
  try {
    const { data, response } = await disposable.client.GET("/v1/system");
    if (
      !response.ok ||
      data?.product !== "owlauth-server" ||
      typeof data.project_auth !== "boolean"
    ) {
      throw new ControlAuthenticationError();
    }
    return disposable;
  } catch (error) {
    disposable.dispose();
    if (error instanceof ControlAuthenticationError) throw error;
    throw new ControlAuthenticationError();
  }
}
