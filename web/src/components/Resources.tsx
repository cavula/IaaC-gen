import { isSafeLink, type ResourceView } from "../api";

interface Props {
  resources: ResourceView[];
  stillUnknown: string[];
  knownGaps: string[];
}

export function Resources({ resources, stillUnknown, knownGaps }: Props) {
  return (
    <aside className="side">
      {stillUnknown.length > 0 && (
        <section className="card" aria-label="Still to decide">
          <h2>Still to decide ({stillUnknown.length})</h2>
          <ul className="plain">
            {stillUnknown.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="card" aria-label="What will be built">
        <h2>What will be built</h2>
        <ol className="resources">
          {resources.map((r) => (
            <li key={r.id}>
              <strong>{r.what}</strong>
              <p>{r.why}</p>
              <p className="sources">
                {r.sources.filter(isSafeLink).map((url) => (
                  <a key={url} href={url} target="_blank" rel="noopener noreferrer">
                    Official documentation
                  </a>
                ))}
              </p>
            </li>
          ))}
        </ol>
      </section>

      {knownGaps.length > 0 && (
        <details className="card gaps">
          <summary>Not covered yet ({knownGaps.length})</summary>
          <ul className="plain">
            {knownGaps.map((gap) => (
              <li key={gap}>{gap}</li>
            ))}
          </ul>
        </details>
      )}
    </aside>
  );
}
