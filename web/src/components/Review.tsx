import { useState } from "react";
import type { Approved, Spec } from "../api";

interface Props {
  spec: Spec;
  busy: boolean;
  approved: Approved | null;
  onApprove: () => void;
}

const any = (value: string) => (value === "*" ? "Any" : value);

function setting(spec: Spec, id: string, key: string): string {
  const value = spec.resources.find((r) => r.id === id)?.settings[key];
  return value === undefined ? "not set" : String(value);
}

export function Review({ spec, busy, approved, onApprove }: Props) {
  const [confirming, setConfirming] = useState(false);
  const network = spec.network;

  return (
    <section className="card review" aria-label="Review the design">
      <h2>Review the design</h2>
      <p>Nothing is saved until you approve it.</p>

      <dl className="summary">
        <dt>Project</dt>
        <dd>{spec.project_id}</dd>
        <dt>Region</dt>
        <dd>{spec.region}</dd>
        <dt>Tenant</dt>
        <dd>
          {spec.scope.tenant.placeholder} ({spec.scope.tenant.mode})
        </dd>
        <dt>Subscription</dt>
        <dd>
          {spec.scope.subscription.placeholder} ({spec.scope.subscription.mode})
        </dd>
        <dt>Server</dt>
        <dd>{setting(spec, "vm", "os")}, private address only</dd>
        <dt>Gateway</dt>
        <dd>{setting(spec, "agw", "sku")}</dd>
        {network && (
          <>
            <dt>Network</dt>
            <dd>{network.address_space.join(", ")}</dd>
            <dt>Subnets</dt>
            <dd>{network.subnets.map((s) => `${s.resource_id} ${s.cidr}`).join(", ")}</dd>
          </>
        )}
        <dt>Access</dt>
        <dd>{spec.access.map((a) => `${a.principal}: ${a.role}`).join(", ") || "none"}</dd>
      </dl>

      {network && (
        <div className="table-scroll">
        <table className="rules">
          <caption>Firewall rules</caption>
          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">Priority</th>
              <th scope="col">Access</th>
              <th scope="col">From</th>
              <th scope="col">To</th>
              <th scope="col">Ports</th>
            </tr>
          </thead>
          <tbody>
            {network.nsg_rules.map((r) => (
              <tr key={`${r.nsg_id}-${r.name}`}>
                <td>{r.name}</td>
                <td>{r.priority}</td>
                <td>{r.access}</td>
                <td>{any(r.source)}</td>
                <td>{any(r.destination)}</td>
                <td>
                  {r.protocol === "*" && r.destination_ports === "*"
                    ? "Any"
                    : `${any(r.protocol)} ${any(r.destination_ports)}`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}

      <details>
        <summary>Full spec (JSON)</summary>
        <pre>{JSON.stringify(spec, null, 2)}</pre>
      </details>

      {approved ? (
        <p className="success" role="status">
          Approved and saved as {approved.version} (commit {approved.commit.slice(0, 7)}).
        </p>
      ) : confirming ? (
        <div className="confirm" role="alertdialog" aria-label="Confirm approval">
          <p>Approve this design and save it as version 1?</p>
          <button type="button" onClick={onApprove} disabled={busy}>
            Yes, approve and save
          </button>
          <button type="button" className="secondary" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </div>
      ) : (
        <button type="button" onClick={() => setConfirming(true)} disabled={busy}>
          Approve
        </button>
      )}
    </section>
  );
}
