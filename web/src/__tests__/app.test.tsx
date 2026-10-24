// Screen tests (task K11: criteria S1-01, S1-05, S1-06, S1-08).
// The whole flow runs in a simulated browser against a fake API that returns
// the same shapes as the real server.
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { PROJECT_PATTERN } from "../components/StartForm";
import { Api, isSafeLink, type DiscoveryReply, type QuestionView, type Spec } from "../api";

const CSRF = "csrf-test-token";

const choice = (id: string, text: string, options: string[], dflt: string): QuestionView => ({
  id,
  text,
  why: `Why ${id}`,
  answer: "choice",
  options: options.map((o) => ({ value: o, label: o })),
  default: dflt,
});
const field = (id: string, text: string, answer: QuestionView["answer"], dflt: string | null): QuestionView => ({
  id,
  text,
  why: `Why ${id}`,
  answer,
  options: [],
  default: dflt,
});

const ROUNDS: QuestionView[][] = [
  [
    choice("tenant", "Do you already have a tenant?", ["existing", "new"], "existing"),
    choice("subscription", "Existing or new subscription?", ["existing", "new"], "existing"),
    field("region", "Which Azure region?", "region", null),
  ],
  [choice("os", "Which operating system?", ["linux", "windows"], "linux")],
  [field("address_space", "Which private address range?", "cidr", "10.20.0.0/16")],
  [field("operators", "Which groups need access?", "principal_list", null)],
];

const SPEC: Spec = {
  project_id: "web-shop",
  region: "westeurope",
  blueprint: "vm_behind_app_gateway",
  scope: {
    tenant: { placeholder: "TENANT_1", mode: "existing" },
    subscription: { placeholder: "SUBSCRIPTION_1", mode: "existing" },
  },
  resources: [
    { id: "vm", kind: "virtual_machine", name: "vm-web-shop", settings: { os: "linux" } },
    { id: "agw", kind: "application_gateway", name: "agw-web-shop", settings: { sku: "WAF_v2" } },
  ],
  network: {
    address_space: ["10.20.0.0/16"],
    subnets: [{ resource_id: "snet_app", cidr: "10.20.2.0/24", nsg_id: "nsg_app" }],
    nsg_rules: [
      {
        nsg_id: "nsg_app",
        name: "allow-https-from-gateway",
        priority: 100,
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        source: "10.20.1.0/24",
        destination: "10.20.2.0/24",
        destination_ports: "443",
      },
    ],
  },
  access: [{ principal: "GROUP_1", role: "Reader", scope_resource: "rg" }],
  approval: { approved: false, version: null },
};

function reply(overrides: Partial<DiscoveryReply>): DiscoveryReply {
  return {
    session_id: "sess-1",
    status: "asking",
    message: "",
    round: null,
    questions: [],
    still_unknown: [],
    understood: [],
    problems: [],
    resources: [],
    spec: null,
    known_gaps: [],
    ...overrides,
  };
}

interface Call {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
}

function fakeServer() {
  const calls: Call[] = [];
  let round = 0;
  const handler = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const body: unknown = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ method, url, headers, body });
    const json = (data: unknown, status = 200) =>
      new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });

    if (method !== "GET" && headers["X-CSRF-Token"] !== CSRF) return json({ detail: "csrf" }, 403);

    if (url === "/api/session") {
      return json({ csrf_token: CSRF, csrf_header: "X-CSRF-Token", product_name: "Test Brand", tagline: "Test tagline" });
    }
    if (url === "/api/discovery") {
      round = 0;
      return json(
        reply({
          message: "This needs a private server. Round 1 of 4.",
          round: 1,
          questions: ROUNDS[0],
          still_unknown: ["a", "b", "c", "d", "e", "f"],
          resources: [
            { id: "vm", kind: "virtual_machine", what: "A virtual server.", why: "Runs your app.", sources: ["https://learn.microsoft.com/x"] },
            { id: "bad", kind: "subnet", what: "Bad link test.", why: "Unsafe link.", sources: ["javascript:alert(1)"] },
          ],
          known_gaps: ["Logging is not modelled yet."],
        }),
      );
    }
    if (url === "/api/discovery/sess-1/answers") {
      round += 1;
      if (round < ROUNDS.length) {
        return json(
          reply({
            message: `Round ${round + 1} of 4.`,
            round: round + 1,
            questions: ROUNDS[round],
            still_unknown: ["x"],
            understood: [{ question: "Which Azure region?", value: "westeurope", via: "ai" }],
          }),
        );
      }
      return json(reply({ status: "review", message: "Here is the draft design.", spec: SPEC }));
    }
    if (url === "/api/discovery/sess-1/approve") {
      return json({ project_id: "web-shop", version: "v1", commit: "7c565fcaac646a0d6ccb96c3b8c49bda5ccba078" });
    }
    if (url.startsWith("/api/audit/verify")) return json({ ok: true, checked: 1, first_bad_id: null });
    if (url.startsWith("/api/audit")) {
      return json({
        entries: [
          {
            id: 1,
            at: "2026-10-24T10:00:00Z",
            purpose: "discovery: read answers",
            provider: "anthropic",
            model: "m",
            host: "api.anthropic.com",
            outcome: "sent",
            reason: null,
            request: [{ role: "user", content: "tenant ID_1 in CIDR_1" }],
            response: "{}",
            redactions: { ID: 1, CIDR: 1 },
          },
        ],
        next_before_id: null,
        total: 1,
      });
    }
    return json({ detail: "not found" }, 404);
  });
  vi.stubGlobal("fetch", handler);
  return { calls };
}

beforeEach(() => {
  document.title = "Loading";
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function startDesign(user: ReturnType<typeof userEvent.setup>) {
  render(<App api={new Api()} />);
  await screen.findByRole("heading", { name: "Test Brand" });
  await user.type(screen.getByLabelText(/your requirement/i), "Deploy my app on Azure on a server");
  await user.click(screen.getByRole("button", { name: "Start" }));
  await screen.findByRole("heading", { name: "Round 1" });
}

describe("screen", () => {
  it("shows the product name from the branding config, not a hardcoded one", async () => {
    fakeServer();
    render(<App api={new Api()} />);
    await screen.findByRole("heading", { name: "Test Brand" });
    expect(document.title).toBe("Test Brand");
    expect(screen.getByText("Test tagline")).toBeTruthy();
  });

  it("uses a project name pattern that browsers accept", () => {
    // Browsers compile the pattern attribute with the "v" flag.
    const re = new RegExp(`^(?:${PROJECT_PATTERN})$`, "v");
    expect(re.test("web-shop")).toBe(true);
    expect(re.test("My App!")).toBe(false);
    expect(re.test("ab")).toBe(false);
  });

  it("offers Azure now and marks AWS and GCP as coming later", async () => {
    fakeServer();
    render(<App api={new Api()} />);
    const select = (await screen.findByLabelText("Cloud")) as HTMLSelectElement;
    const options = Array.from(select.options);
    expect(options.find((o) => o.value === "azure")?.disabled).toBe(false);
    expect(options.find((o) => o.value === "aws")?.disabled).toBe(true);
    expect(options.find((o) => o.value === "gcp")?.disabled).toBe(true);
  });

  it("runs the full flow: start, four rounds, review, confirm, saved as v1", async () => {
    const { calls } = fakeServer();
    const user = userEvent.setup();
    await startDesign(user);

    // Explanations with official sources sit beside the questions.
    expect(screen.getByText("A virtual server.")).toBeTruthy();
    expect(screen.getByText("Still to decide (6)")).toBeTruthy();

    await user.type(screen.getByLabelText("Which Azure region?"), "westeurope");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByRole("heading", { name: "Round 2" });
    expect(screen.getByText("read by AI, please check")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByRole("heading", { name: "Round 3" });
    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByRole("heading", { name: "Round 4" });
    expect(screen.getByText(/never sent to the AI/)).toBeTruthy();
    expect(screen.queryByLabelText(/answer in your own words/i)).toBeNull();
    const groups = screen.getByLabelText("Which groups need access?") as HTMLTextAreaElement;
    expect(groups.value).toBe("");
    await user.type(groups, "Platform Team");
    await user.click(screen.getByRole("button", { name: "Next" }));

    const review = await screen.findByRole("region", { name: "Review the design" });
    expect(within(review).getByText("westeurope")).toBeTruthy();
    expect(within(review).getByText("allow-https-from-gateway")).toBeTruthy();
    expect(within(review).getByText("GROUP_1: Reader")).toBeTruthy();

    // Approval needs a second, explicit confirmation.
    await user.click(within(review).getByRole("button", { name: "Approve" }));
    expect(calls.some((c) => c.url.endsWith("/approve"))).toBe(false);
    await user.click(within(review).getByRole("button", { name: "Yes, approve and save" }));
    await screen.findByText(/Approved and saved as v1 \(commit 7c565fc\)/);

    const approve = calls.find((c) => c.url.endsWith("/approve"));
    expect(approve?.body).toEqual({ confirm: true });
    const firstAnswer = calls.find((c) => c.url.endsWith("/answers"));
    expect(firstAnswer?.body).toEqual({
      answers: { tenant: "existing", subscription: "existing", region: "westeurope" },
    });
  });

  it("sends the CSRF token on every change and never on reads", async () => {
    const { calls } = fakeServer();
    const user = userEvent.setup();
    await startDesign(user);
    const posts = calls.filter((c) => c.method === "POST");
    expect(posts.length).toBeGreaterThan(0);
    for (const post of posts) expect(post.headers["X-CSRF-Token"]).toBe(CSRF);
    for (const get of calls.filter((c) => c.method === "GET")) {
      expect(get.headers["X-CSRF-Token"]).toBeUndefined();
    }
  });

  it("only links to https sources, opened safely", async () => {
    fakeServer();
    const user = userEvent.setup();
    await startDesign(user);
    const links = screen.getAllByRole("link", { name: "Official documentation" });
    expect(links).toHaveLength(1);
    expect(links[0]?.getAttribute("href")).toBe("https://learn.microsoft.com/x");
    expect(links[0]?.getAttribute("rel")).toBe("noopener noreferrer");
    expect(isSafeLink("javascript:alert(1)")).toBe(false);
    expect(isSafeLink("http://example.com")).toBe(false);
  });

  it("shows text from the server as text, never as HTML", async () => {
    fakeServer();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const body =
          url === "/api/session"
            ? { csrf_token: CSRF, csrf_header: "X-CSRF-Token", product_name: "<img src=x onerror=alert(1)>", tagline: "" }
            : {};
        return new Response(JSON.stringify(body), { status: 200 });
      }),
    );
    render(<App api={new Api()} />);
    await screen.findByRole("heading", { name: "<img src=x onerror=alert(1)>" });
    expect(document.querySelector("img")).toBeNull();
  });

  it("shows the audit log with what was sent after redaction", async () => {
    fakeServer();
    const user = userEvent.setup();
    render(<App api={new Api()} />);
    await screen.findByRole("heading", { name: "Test Brand" });
    await user.click(screen.getByRole("button", { name: "Audit log" }));
    await screen.findByText("Log intact: 1 records checked.");
    expect(screen.getByText("Hidden before sending: 1 ID, 1 CIDR")).toBeTruthy();
    expect(screen.getByText("user: tenant ID_1 in CIDR_1")).toBeTruthy();
  });

  it("shows server errors in plain words", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input) === "/api/session") {
          return new Response(JSON.stringify({ csrf_token: CSRF, csrf_header: "X-CSRF-Token", product_name: "B", tagline: "" }));
        }
        return new Response(JSON.stringify({ detail: "a project called 'web-shop' already exists" }), { status: 409 });
      }),
    );
    const user = userEvent.setup();
    render(<App api={new Api()} />);
    await screen.findByRole("heading", { name: "B" });
    await user.type(screen.getByLabelText(/your requirement/i), "x");
    await user.click(screen.getByRole("button", { name: "Start" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/already exists/));
  });
});
