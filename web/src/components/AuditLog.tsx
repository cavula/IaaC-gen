import { useCallback, useEffect, useState } from "react";
import { ApiError, type Api, type AuditEntry, type AuditVerify } from "../api";

interface Props {
  api: Api;
}

export function AuditLog({ api }: Props) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [total, setTotal] = useState(0);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (beforeId: number | null) => {
      try {
        const page = await api.auditPage(beforeId);
        setEntries((current) => (beforeId === null ? page.entries : [...current, ...page.entries]));
        setNext(page.next_before_id);
        setTotal(page.total);
        if (beforeId === null) setVerify(await api.auditVerify());
        setError(null);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "Could not load the audit log.");
      }
    },
    [api],
  );

  useEffect(() => {
    void load(null);
  }, [load]);

  return (
    <section className="card" aria-label="Audit log">
      <h2>What was sent to the AI</h2>
      <p>
        Every call is listed here exactly as it left this computer, after redaction. Blocked calls are
        listed too.
      </p>
      {verify && (
        <p className={verify.ok ? "success" : "danger"} role="status">
          {verify.ok
            ? `Log intact: ${verify.checked} records checked.`
            : `Warning: the log was changed outside the app, starting at record ${verify.first_bad_id}.`}
        </p>
      )}
      {error && <p className="danger">{error}</p>}
      {entries.length === 0 && !error && <p>No calls yet.</p>}
      <ol className="audit">
        {entries.map((e) => (
          <li key={e.id} className={`outcome-${e.outcome}`}>
            <div className="audit-head">
              <span className="badge">{e.outcome}</span>
              <span>{new Date(e.at).toLocaleString()}</span>
              <span>{e.purpose}</span>
              <span>{e.host}</span>
            </div>
            {e.reason && <p>Reason: {e.reason}</p>}
            {Object.keys(e.redactions).length > 0 && (
              <p>
                Hidden before sending:{" "}
                {Object.entries(e.redactions)
                  .map(([kind, count]) => `${count} ${kind}`)
                  .join(", ")}
              </p>
            )}
            {e.request.length > 0 && (
              <details>
                <summary>Show what was sent</summary>
                {e.request.map((m, i) => (
                  <pre key={i}>
                    {m.role}: {m.content}
                  </pre>
                ))}
                {e.response !== null && <pre>reply: {e.response}</pre>}
              </details>
            )}
          </li>
        ))}
      </ol>
      {next !== null && entries.length < total && (
        <button type="button" className="secondary" onClick={() => void load(next)}>
          Load older
        </button>
      )}
    </section>
  );
}
