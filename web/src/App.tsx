import { useEffect, useMemo, useState } from "react";
import { Api, ApiError, type Approved, type DiscoveryReply, type Session } from "./api";
import { AuditLog } from "./components/AuditLog";
import { Questions } from "./components/Questions";
import { Resources } from "./components/Resources";
import { Review } from "./components/Review";
import { StartForm } from "./components/StartForm";

type Tab = "design" | "audit";

export function App({ api: given }: { api?: Api }) {
  const api = useMemo(() => given ?? new Api(), [given]);
  const [session, setSession] = useState<Session | null>(null);
  const [tab, setTab] = useState<Tab>("design");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [reply, setReply] = useState<DiscoveryReply | null>(null);
  const [resources, setResources] = useState<DiscoveryReply["resources"]>([]);
  const [knownGaps, setKnownGaps] = useState<string[]>([]);
  const [approved, setApproved] = useState<Approved | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getSession()
      .then((s) => {
        setSession(s);
        document.title = s.product_name;
      })
      .catch(() => setError("Could not reach the local server."));
  }, [api]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  function accept(next: DiscoveryReply) {
    setReply(next);
    if (next.resources.length) setResources(next.resources);
    if (next.known_gaps.length) setKnownGaps(next.known_gaps);
  }

  const start = (cloud: string, requirement: string, projectId: string) =>
    run(async () => {
      const next = await api.startDiscovery(cloud, requirement, projectId);
      setSessionId(next.session_id);
      setApproved(null);
      accept(next);
    });

  const answer = (answers: Record<string, string> | null, text: string | null) =>
    run(async () => {
      if (sessionId) accept(await api.answer(sessionId, answers, text));
    });

  const approve = () =>
    run(async () => {
      if (sessionId) setApproved(await api.approve(sessionId));
    });

  function reset() {
    setSessionId(null);
    setReply(null);
    setResources([]);
    setKnownGaps([]);
    setApproved(null);
    setError(null);
  }

  return (
    <div className="app">
      <header>
        <div>
          <h1>{session?.product_name ?? ""}</h1>
          <p className="tagline">{session?.tagline ?? ""}</p>
        </div>
        <nav aria-label="Sections">
          <button
            type="button"
            className={tab === "design" ? "tab active" : "tab"}
            aria-pressed={tab === "design"}
            onClick={() => setTab("design")}
          >
            Design
          </button>
          <button
            type="button"
            className={tab === "audit" ? "tab active" : "tab"}
            aria-pressed={tab === "audit"}
            onClick={() => setTab("audit")}
          >
            Audit log
          </button>
        </nav>
      </header>

      {error && (
        <p className="danger" role="alert">
          {error}
        </p>
      )}

      {tab === "audit" ? (
        <AuditLog api={api} />
      ) : !reply || reply.status === "unsupported" ? (
        <main>
          {reply?.status === "unsupported" && (
            <p className="card notice" role="status">
              {reply.message}
            </p>
          )}
          <StartForm busy={busy} onStart={start} />
        </main>
      ) : (
        <main className="workspace">
          <div className="main-column">
            <p className="card message" role="status">
              {reply.message}
            </p>
            {reply.understood.length > 0 && (
              <section className="card" aria-label="How your answers were understood">
                <h2>How I understood your answers</h2>
                <ul className="plain">
                  {reply.understood.map((u) => (
                    <li key={u.question}>
                      {u.question} <strong>{u.value}</strong>
                      {u.via === "ai" && <span className="badge">read by AI, please check</span>}
                    </li>
                  ))}
                </ul>
              </section>
            )}
            {reply.problems.length > 0 && (
              <ul className="card danger" aria-label="Problems">
                {reply.problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            )}
            {reply.status === "asking" && (
              <Questions
                round={reply.round}
                questions={reply.questions}
                busy={busy}
                onAnswers={(a) => answer(a, null)}
                onText={(t) => answer(null, t)}
              />
            )}
            {reply.status === "review" && reply.spec && (
              <Review spec={reply.spec} busy={busy} approved={approved} onApprove={approve} />
            )}
            <button type="button" className="secondary" onClick={reset}>
              Start over
            </button>
          </div>
          <Resources
            resources={resources}
            stillUnknown={reply.status === "asking" ? reply.still_unknown : []}
            knownGaps={knownGaps}
          />
        </main>
      )}
    </div>
  );
}
