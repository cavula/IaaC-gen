import { useState, type FormEvent } from "react";

// Browsers compile this with the "v" flag, where a literal dash in a
// character class must be escaped.
export const PROJECT_PATTERN = "[a-z0-9][a-z0-9\\-]{2,30}";

const CLOUDS = [
  { value: "azure", label: "Microsoft Azure", available: true },
  { value: "aws", label: "Amazon Web Services (coming later)", available: false },
  { value: "gcp", label: "Google Cloud (coming later)", available: false },
];

interface Props {
  busy: boolean;
  onStart: (cloud: string, requirement: string, projectId: string) => void;
}

export function StartForm({ busy, onStart }: Props) {
  const [cloud, setCloud] = useState("azure");
  const [projectId, setProjectId] = useState("my-app");
  const [requirement, setRequirement] = useState("");

  function submit(event: FormEvent) {
    event.preventDefault();
    if (requirement.trim()) onStart(cloud, requirement.trim(), projectId.trim());
  }

  return (
    <form className="card start" onSubmit={submit} aria-label="Describe what you need">
      <h2>What do you want to build?</h2>
      <div className="row">
        <label>
          Cloud
          <select value={cloud} onChange={(e) => setCloud(e.target.value)}>
            {CLOUDS.map((c) => (
              <option key={c.value} value={c.value} disabled={!c.available}>
                {c.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Project name
          <input
            value={projectId}
            onChange={(e) => setProjectId(e.target.value.toLowerCase())}
            pattern={PROJECT_PATTERN}
            title="3 to 31 lowercase letters, digits or dashes"
            required
          />
        </label>
      </div>
      <label>
        Your requirement, in plain words
        <textarea
          value={requirement}
          onChange={(e) => setRequirement(e.target.value)}
          placeholder="For example: deploy my app on Azure on a server"
          maxLength={4000}
          rows={3}
          required
        />
      </label>
      <button type="submit" disabled={busy || !requirement.trim()}>
        {busy ? "Working..." : "Start"}
      </button>
    </form>
  );
}
