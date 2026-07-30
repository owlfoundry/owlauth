import createClient from "openapi-fetch";

import type { paths } from "../generated/runtime-openapi";
import { assertSameOriginPlaneUrl } from "../shared/configured-base";

export function createRuntimeClient(
  runtimeBase: string,
  fetchImplementation: typeof fetch = fetch,
) {
  const baseUrl = assertSameOriginPlaneUrl(runtimeBase, runtimeBase).href;
  return createClient<paths>({
    baseUrl,
    fetch: async (input) => {
      const request = input instanceof Request ? input : new Request(input);
      assertSameOriginPlaneUrl(request.url, runtimeBase);
      return fetchImplementation(request);
    },
  });
}
