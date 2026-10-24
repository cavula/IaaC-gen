import { useEffect, useState, type FormEvent } from "react";
import type { QuestionView } from "../api";

interface Props {
  round: number | null;
  questions: QuestionView[];
  busy: boolean;
  onAnswers: (answers: Record<string, string>) => void;
  onText: (text: string) => void;
}

function initial(questions: QuestionView[]): Record<string, string> {
  return Object.fromEntries(questions.map((q) => [q.id, q.default ?? ""]));
}

export function Questions({ round, questions, busy, onAnswers, onText }: Props) {
  const [values, setValues] = useState<Record<string, string>>(() => initial(questions));
  const [text, setText] = useState("");
  const onlyGroups = questions.length > 0 && questions.every((q) => q.answer === "principal_list");

  useEffect(() => setValues(initial(questions)), [questions]);

  function set(id: string, value: string) {
    setValues((current) => ({ ...current, [id]: value }));
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    const filled = Object.fromEntries(Object.entries(values).filter(([, v]) => v.trim() !== ""));
    onAnswers(filled);
  }

  function submitText(event: FormEvent) {
    event.preventDefault();
    if (text.trim()) {
      onText(text.trim());
      setText("");
    }
  }

  return (
    <section className="card" aria-label="Questions">
      <h2>{round ? `Round ${round}` : "Questions"}</h2>
      <form onSubmit={submit}>
        {questions.map((q) => (
          <fieldset key={q.id} className="question">
            <legend>{q.text}</legend>
            <p className="why">{q.why}</p>
            {q.answer === "choice" ? (
              <div className="choices" role="radiogroup" aria-label={q.text}>
                {q.options.map((o) => (
                  <label key={o.value} className="choice">
                    <input
                      type="radio"
                      name={q.id}
                      value={o.value}
                      checked={values[q.id] === o.value}
                      onChange={() => set(q.id, o.value)}
                    />
                    {o.label}
                  </label>
                ))}
              </div>
            ) : q.answer === "principal_list" ? (
              <>
                <textarea
                  aria-label={q.text}
                  value={values[q.id] ?? ""}
                  onChange={(e) => set(q.id, e.target.value)}
                  placeholder="One group per line, or separated by commas"
                  rows={3}
                />
                <p className="note">
                  Group names stay on this computer. They are saved as placeholders such as GROUP_1
                  and are never sent to the AI.
                </p>
              </>
            ) : (
              <input
                aria-label={q.text}
                value={values[q.id] ?? ""}
                onChange={(e) => set(q.id, e.target.value)}
                placeholder={q.answer === "region" ? "for example westeurope" : ""}
              />
            )}
          </fieldset>
        ))}
        <button type="submit" disabled={busy}>
          Next
        </button>
      </form>

      {!onlyGroups && (
        <form className="free-text" onSubmit={submitText}>
          <label>
            Or answer in your own words
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="For example: we have a tenant already, new subscription, West Europe"
              maxLength={4000}
              rows={2}
            />
          </label>
          <p className="note">
            Sensitive values such as IDs, IP ranges and emails are replaced with placeholders before
            anything reaches the AI.
          </p>
          <button type="submit" className="secondary" disabled={busy || !text.trim()}>
            Send
          </button>
        </form>
      )}
    </section>
  );
}
