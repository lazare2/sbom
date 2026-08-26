import { useEnvironment } from "./EnvironmentProvider.tsx";

/**
 * The header control naming which estate every figure on the page describes.
 *
 * Always visible, including when there is only one environment. A control that appears
 * the day a second estate is created is a control nobody has ever seen before at the
 * moment they most need to understand it, and its absence would make the platform look
 * as though it had no concept of estates at all -- which is how somebody reads a
 * production number as if it covered everything.
 */
export function EnvironmentSwitcher() {
  const { environments, current, select } = useEnvironment();
  const only = environments.length === 1;

  return (
    <label className="flex items-center gap-1.5">
      <span className="text-xs uppercase tracking-wide text-text-faint">Environment</span>
      <select
        value={current.id}
        aria-label="Environment"
        onChange={(e) => select(e.target.value)}
        // Not disabled when there is one option: a greyed control reads as broken, and the
        // single option still tells the reader which estate they are looking at.
        className={`rounded-md border px-2 py-1 text-sm font-medium ${
          only
            ? "border-border-base bg-bg-subtle text-text-muted"
            : "border-accent/40 bg-accent-subtle text-accent"
        }`}
      >
        {environments.map((environment) => (
          <option key={environment.id} value={environment.id}>
            {environment.name}
          </option>
        ))}
      </select>
    </label>
  );
}
