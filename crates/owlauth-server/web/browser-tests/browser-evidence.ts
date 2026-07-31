import type { BrowserContext, Page } from "@playwright/test";

export interface HeaderEntry {
  readonly name: string;
  readonly value: string;
}

export interface NetworkRecord {
  body: string;
  headers: readonly HeaderEntry[];
  readonly method?: string;
  readonly status?: number;
  readonly url: string;
}

export interface LifecycleSample {
  readonly body: string;
  readonly cookies: string;
  readonly history: string;
  readonly html: string;
  readonly local: readonly (readonly [string, string])[];
  readonly pageId: number;
  readonly reason: string;
  readonly session: readonly (readonly [string, string])[];
  readonly url: string;
}

export interface BrowserEvidenceSnapshot {
  readonly consoleMessages: readonly string[];
  readonly lifecycle: readonly LifecycleSample[];
  readonly pageCount: number;
  readonly requests: readonly NetworkRecord[];
  readonly responses: readonly NetworkRecord[];
  readonly storageState: string;
}

interface BrowserLifecycleSample {
  readonly body: string;
  readonly cookies: string;
  readonly history: string;
  readonly html: string;
  readonly local: readonly (readonly [string, string])[];
  readonly reason: string;
  readonly session: readonly (readonly [string, string])[];
  readonly url: string;
}

let nextBindingId = 0;

/**
 * Losslessly records the network and ephemeral browser surfaces for one context.
 * Call create before the first navigation so the lifecycle observer is installed in
 * every document, including popups and pages created later.
 */
export class BrowserEvidence {
  readonly consoleMessages: string[] = [];
  readonly context: BrowserContext;
  readonly lifecycle: LifecycleSample[] = [];
  readonly requests: NetworkRecord[] = [];
  readonly responses: NetworkRecord[] = [];
  readonly #pageIds = new Map<Page, number>();
  readonly #pages = new Set<Page>();
  readonly #pending: Promise<void>[] = [];

  private constructor(context: BrowserContext) {
    this.context = context;
  }

  static async create(context: BrowserContext): Promise<BrowserEvidence> {
    const evidence = new BrowserEvidence(context);
    const bindingName = `__owlauthEvidence${String(nextBindingId++)}`;

    context.on("page", (page) => {
      evidence.#observePage(page);
    });
    context.on("request", (request) => {
      const record: NetworkRecord = {
        body: request.postData() ?? "",
        headers: [],
        method: request.method(),
        url: request.url(),
      };
      evidence.requests.push(record);
      evidence.#pending.push(
        request.headersArray().then((headers) => {
          record.headers = headers.map(({ name, value }) => ({ name, value }));
        }),
      );
    });
    context.on("response", (response) => {
      const record: NetworkRecord = {
        body: "",
        headers: [],
        method: response.request().method(),
        status: response.status(),
        url: response.url(),
      };
      evidence.responses.push(record);
      evidence.#pending.push(
        Promise.all([response.headersArray(), response.text().catch(() => "")]).then(
          ([headers, responseBody]) => {
            record.headers = headers.map(({ name, value }) => ({ name, value }));
            record.body = responseBody;
          },
        ),
      );
    });

    await context.exposeBinding(bindingName, (source, payload: unknown) => {
      const pageId = evidence.#pageId(source.page);
      const sample = browserSample(payload);
      if (sample !== null) evidence.lifecycle.push({ ...sample, pageId });
    });
    await context.addInitScript(installLifecycleObserver, bindingName);
    for (const page of context.pages()) evidence.#observePage(page);
    return evidence;
  }

  pages(): readonly Page[] {
    return [...this.#pages];
  }

  async settle(): Promise<void> {
    let completed = 0;
    while (completed < this.#pending.length) {
      const current = this.#pending.slice(completed);
      completed += current.length;
      await Promise.all(current);
    }
  }

  async snapshot(): Promise<BrowserEvidenceSnapshot> {
    await this.settle();
    for (const page of this.#pages) {
      if (page.isClosed()) continue;
      try {
        const sample = await page.evaluate(readCurrentLifecycleState, "final");
        this.lifecycle.push({ ...sample, pageId: this.#pageId(page) });
      } catch {
        // Navigation may replace the execution context while taking the final sample.
        // The init-script observer and synchronous frame URL event remain authoritative.
      }
    }
    return {
      consoleMessages: [...this.consoleMessages],
      lifecycle: [...this.lifecycle],
      pageCount: this.#pages.size,
      requests: this.requests.map(copyNetworkRecord),
      responses: this.responses.map(copyNetworkRecord),
      storageState: JSON.stringify(await this.context.storageState()),
    };
  }

  #observePage(page: Page): void {
    if (this.#pages.has(page)) return;
    this.#pages.add(page);
    const pageId = this.#pageId(page);
    page.on("console", (message) => this.consoleMessages.push(message.text()));
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) {
        this.lifecycle.push(emptyLifecycleSample(pageId, "navigation", frame.url()));
      }
    });
  }

  #pageId(page: Page): number {
    const existing = this.#pageIds.get(page);
    if (existing !== undefined) return existing;
    const created = this.#pageIds.size + 1;
    this.#pageIds.set(page, created);
    return created;
  }
}

function copyNetworkRecord(record: NetworkRecord): NetworkRecord {
  return {
    body: record.body,
    headers: record.headers.map(({ name, value }) => ({ name, value })),
    ...(record.method === undefined ? {} : { method: record.method }),
    ...(record.status === undefined ? {} : { status: record.status }),
    url: record.url,
  };
}

function emptyLifecycleSample(pageId: number, reason: string, url: string): LifecycleSample {
  return {
    body: "",
    cookies: "",
    history: "",
    html: "",
    local: [],
    pageId,
    reason,
    session: [],
    url,
  };
}

function browserSample(value: unknown): BrowserLifecycleSample | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const candidate = value as Partial<BrowserLifecycleSample>;
  if (
    typeof candidate.body !== "string" ||
    typeof candidate.cookies !== "string" ||
    typeof candidate.history !== "string" ||
    typeof candidate.html !== "string" ||
    !storageEntries(candidate.local) ||
    typeof candidate.reason !== "string" ||
    !storageEntries(candidate.session) ||
    typeof candidate.url !== "string"
  ) {
    return null;
  }
  return candidate as BrowserLifecycleSample;
}

function storageEntries(value: unknown): value is readonly (readonly [string, string])[] {
  return (
    Array.isArray(value) &&
    value.every(
      (entry) =>
        Array.isArray(entry) &&
        entry.length === 2 &&
        typeof entry[0] === "string" &&
        typeof entry[1] === "string",
    )
  );
}

function readCurrentLifecycleState(reason: string): BrowserLifecycleSample {
  const entries = (storage: Storage): [string, string][] => {
    const result: [string, string][] = [];
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      if (key !== null) result.push([key, storage.getItem(key) ?? ""]);
    }
    return result;
  };
  const stringifyHistory = (): string => {
    try {
      return JSON.stringify(history.state);
    } catch {
      return "[unserializable]";
    }
  };
  return {
    body: document.body.textContent,
    cookies: document.cookie,
    history: stringifyHistory(),
    html: document.documentElement.outerHTML,
    local: entries(localStorage),
    reason,
    session: entries(sessionStorage),
    url: location.href,
  };
}

function installLifecycleObserver(bindingName: string): void {
  const exposed = (window as unknown as Record<string, unknown>)[bindingName];
  if (typeof exposed !== "function") return;
  const deliver = exposed as (sample: BrowserLifecycleSample) => Promise<void>;

  const entries = (storage: Storage): [string, string][] => {
    const result: [string, string][] = [];
    try {
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        if (key !== null) result.push([key, storage.getItem(key) ?? ""]);
      }
    } catch {
      // Opaque documents may deny storage access.
    }
    return result;
  };
  let previousState = "";
  const capture = (reason: string, transientBody = "", transientHtml = ""): void => {
    let historyState = "";
    try {
      historyState = JSON.stringify(history.state);
    } catch {
      historyState = "[unserializable]";
    }
    let cookies = "";
    try {
      cookies = document.cookie;
    } catch {
      // Opaque documents may deny cookie access.
    }
    const body = `${document.querySelector("body")?.textContent ?? ""}${transientBody}`;
    const html = `${document.querySelector("html")?.outerHTML ?? ""}${transientHtml}`;
    const local = entries(localStorage);
    const session = entries(sessionStorage);
    const url = location.href;
    const state = JSON.stringify([body, cookies, historyState, html, local, session, url]);
    if (state === previousState) return;
    previousState = state;
    const sample: BrowserLifecycleSample = {
      body,
      cookies,
      history: historyState,
      html,
      local,
      reason,
      session,
      url,
    };
    void deliver(sample).catch(() => {
      // Evidence must never alter the browser journey.
    });
  };

  const originalPushState = history.pushState.bind(history);
  history.pushState = (...arguments_: Parameters<History["pushState"]>) => {
    originalPushState(...arguments_);
    capture("history.pushState");
  };
  const originalReplaceState = history.replaceState.bind(history);
  history.replaceState = (...arguments_: Parameters<History["replaceState"]>) => {
    originalReplaceState(...arguments_);
    capture("history.replaceState");
  };

  // eslint-disable-next-line @typescript-eslint/unbound-method
  const originalSetItem = Storage.prototype.setItem;
  Storage.prototype.setItem = function (key: string, value: string): void {
    originalSetItem.call(this, key, value);
    capture("storage.setItem");
  };
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const originalRemoveItem = Storage.prototype.removeItem;
  Storage.prototype.removeItem = function (key: string): void {
    originalRemoveItem.call(this, key);
    capture("storage.removeItem");
  };
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const originalClear = Storage.prototype.clear;
  Storage.prototype.clear = function (): void {
    originalClear.call(this);
    capture("storage.clear");
  };

  const cookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
  if (cookieDescriptor?.get !== undefined && cookieDescriptor.set !== undefined) {
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const getCookie = cookieDescriptor.get;
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const setCookie = cookieDescriptor.set;
    try {
      Object.defineProperty(document, "cookie", {
        configurable: true,
        get: () => getCookie.call(document) as string,
        set: (value: string) => {
          setCookie.call(document, value);
          capture("cookie");
        },
      });
    } catch {
      // Initial and event-driven document samples still observe cookie state.
    }
  }

  const snapshotNode = (node: Node): readonly [string, string] => {
    const text = node.textContent ?? "";
    if (node instanceof Element) return [text, node.outerHTML];
    if (node instanceof Attr) return [node.value, `${node.name}=${node.value}`];
    return [text, text];
  };
  const mutationFragments = (records: readonly MutationRecord[]): readonly [string, string] => {
    const text: string[] = [];
    const html: string[] = [];
    for (const record of records) {
      if (record.oldValue !== null) {
        text.push(record.oldValue);
        html.push(record.oldValue);
      }
      for (const node of [...record.addedNodes, ...record.removedNodes]) {
        const [nodeText, nodeHtml] = snapshotNode(node);
        text.push(nodeText);
        html.push(nodeHtml);
      }
    }
    return [text.join(""), html.join("")];
  };

  // MutationObserver delivery is a microtask: an insert followed by a removal in the
  // same task is absent from the live DOM by callback time. Preserve both the records'
  // detached nodes/old values and synchronous post-mutation states for the core DOM APIs.
  const instrumentMutation = (owner: object, key: string, reason: string): void => {
    const original = (owner as Record<string, unknown>)[key];
    if (typeof original !== "function") return;
    try {
      Object.defineProperty(owner, key, {
        configurable: true,
        value: function (this: unknown, ...arguments_: unknown[]) {
          const result = (original as (...values: unknown[]) => unknown).apply(this, arguments_);
          capture(reason);
          return result;
        },
        writable: true,
      });
    } catch {
      // Mutation records still retain detached nodes and old values.
    }
  };
  instrumentMutation(Node.prototype, "appendChild", "dom.appendChild");
  instrumentMutation(Node.prototype, "insertBefore", "dom.insertBefore");
  instrumentMutation(Node.prototype, "replaceChild", "dom.replaceChild");
  instrumentMutation(Element.prototype, "append", "dom.append");
  instrumentMutation(Element.prototype, "prepend", "dom.prepend");
  instrumentMutation(Element.prototype, "replaceChildren", "dom.replaceChildren");
  instrumentMutation(Element.prototype, "insertAdjacentElement", "dom.insertAdjacentElement");
  instrumentMutation(Element.prototype, "insertAdjacentHTML", "dom.insertAdjacentHTML");
  instrumentMutation(Element.prototype, "insertAdjacentText", "dom.insertAdjacentText");
  instrumentMutation(Element.prototype, "setAttribute", "dom.setAttribute");
  instrumentMutation(Element.prototype, "setAttributeNS", "dom.setAttributeNS");

  new MutationObserver((records) => {
    const [transientBody, transientHtml] = mutationFragments(records);
    capture("dom.records", transientBody, transientHtml);
  }).observe(document, {
    attributeOldValue: true,
    attributes: true,
    characterData: true,
    characterDataOldValue: true,
    childList: true,
    subtree: true,
  });
  for (const event of ["beforeunload", "hashchange", "pagehide", "popstate"] as const) {
    addEventListener(
      event,
      () => {
        capture(event);
      },
      { capture: true },
    );
  }
  // The initial sample observes cookies delivered with each document response; the setter
  // hook observes script mutations without polling or writing instrumentation state.
  capture("init");
}
