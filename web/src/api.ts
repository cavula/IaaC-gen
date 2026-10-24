// Typed client for the local API. Every request goes to the same origin.
// State changing requests carry the CSRF token from /api/session.

export interface Session {
  csrf_token: string;
  csrf_header: string;
  product_name: string;
  tagline: string;
}

export interface QuestionView {
  id: string;
  text: string;
  why: string;
  answer: "choice" | "text" | "region" | "cidr" | "port" | "principal_list";
  options: { value: string; label: string }[];
  default: string | null;
}

export interface ResourceView {
  id: string;
  kind: string;
  what: string;
  why: string;
  sources: string[];
}

export interface Understood {
  question: string;
  value: string;
  via: "exact" | "ai";
}

export interface NsgRule {
  nsg_id: string;
  name: string;
  priority: number;
  direction: string;
  access: string;
  protocol: string;
  source: string;
  destination: string;
  destination_ports: string;
}

export interface Spec {
  project_id: string;
  region: string;
  blueprint: string;
  scope: { tenant: { placeholder: string; mode: string }; subscription: { placeholder: string; mode: string } };
  resources: { id: string; kind: string; name: string; settings: Record<string, string | number | boolean> }[];
  network: {
    address_space: string[];
    subnets: { resource_id: string; cidr: string; nsg_id: string | null }[];
    nsg_rules: NsgRule[];
  } | null;
  access: { principal: string; role: string; scope_resource: string }[];
  approval: { approved: boolean; version: string | null };
}

export interface DiscoveryReply {
  session_id: string | null;
  status: "asking" | "review" | "unsupported";
  message: string;
  round: number | null;
  questions: QuestionView[];
  still_unknown: string[];
  understood: Understood[];
  problems: string[];
  resources: ResourceView[];
  spec: Spec | null;
  known_gaps: string[];
}

export interface Approved {
  project_id: string;
  version: string;
  commit: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  purpose: string;
  provider: string;
  model: string;
  host: string;
  outcome: "sent" | "blocked" | "error";
  reason: string | null;
  request: { role: string; content: string }[];
  response: string | null;
  redactions: Record<string, number>;
}

export interface AuditPage {
  entries: AuditEntry[];
  next_before_id: number | null;
  total: number;
}

export interface AuditVerify {
  ok: boolean;
  checked: number;
  first_bad_id: number | null;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function parse<T>(response: Response): Promise<T> {
  const body: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail =
      typeof body === "object" && body !== null && "detail" in body && typeof body.detail === "string"
        ? body.detail
        : `Request failed (${response.status})`;
    throw new ApiError(detail, response.status);
  }
  return body as T;
}

export class Api {
  private session: Session | null = null;

  async getSession(): Promise<Session> {
    if (!this.session) {
      this.session = await parse<Session>(await fetch("/api/session", { credentials: "same-origin" }));
    }
    return this.session;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const session = await this.getSession();
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", [session.csrf_header]: session.csrf_token },
      body: JSON.stringify(body),
    });
    return parse<T>(response);
  }

  private async get<T>(path: string): Promise<T> {
    return parse<T>(await fetch(path, { credentials: "same-origin" }));
  }

  startDiscovery(cloud: string, requirement: string, projectId: string): Promise<DiscoveryReply> {
    return this.post("/api/discovery", { cloud, requirement, project_id: projectId });
  }

  answer(sessionId: string, answers: Record<string, string> | null, text: string | null): Promise<DiscoveryReply> {
    return this.post(`/api/discovery/${encodeURIComponent(sessionId)}/answers`, {
      ...(answers ? { answers } : {}),
      ...(text ? { text } : {}),
    });
  }

  approve(sessionId: string): Promise<Approved> {
    return this.post(`/api/discovery/${encodeURIComponent(sessionId)}/approve`, { confirm: true });
  }

  auditPage(beforeId: number | null): Promise<AuditPage> {
    const query = beforeId === null ? "" : `?before_id=${beforeId}`;
    return this.get(`/api/audit${query}`);
  }

  auditVerify(): Promise<AuditVerify> {
    return this.get("/api/audit/verify");
  }
}

/** Only https links from the blueprint are shown as links. */
export function isSafeLink(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}
