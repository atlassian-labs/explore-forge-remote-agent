import { createForgeLogger } from "@forge-ahead/logging";

// Human-readable console output for local development: a header line with the
// scalar fields, then nested objects (for example the JSON-RPC request body)
// as indented JSON. This is the default; set LOG_FORMAT=json for the library's
// compact JSON lines (for example when shipping logs to a collector).

const levelColors: Record<string, string> = {
  trace: "90",
  debug: "36",
  info: "32",
  warn: "33",
  error: "31",
  fatal: "1;31",
};

// Same mapping the library uses to pick a console method per level.
const consoleMethods = {
  fatal: "error",
  error: "error",
  warn: "warn",
  info: "info",
  debug: "debug",
  trace: "debug",
} as const;

function isNested(value: unknown): value is object {
  return value !== null && typeof value === "object";
}

export function formatPrettyRecord(line: string, color: boolean): string {
  let record: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(line);
    if (!isNested(parsed) || Array.isArray(parsed)) return line;
    record = parsed as Record<string, unknown>;
  } catch {
    return line;
  }
  const paint = (code: string, text: string) =>
    color ? `\u001b[${code}m${text}\u001b[0m` : text;
  const dim = (text: string) => paint("2", text);

  const { time, level, msg, ...fields } = record;
  const levelName = String(level ?? "").toLowerCase();
  const timestamp =
    typeof time === "string" || typeof time === "number"
      ? new Date(time).toISOString().slice(11, 23)
      : "";

  const scalars: string[] = [];
  const nested: [string, object][] = [];
  for (const [key, value] of Object.entries(fields)) {
    if (isNested(value)) nested.push([key, value]);
    else scalars.push(`${dim(`${key}=`)}${String(value)}`);
  }

  const header = [
    dim(timestamp),
    paint(levelColors[levelName] ?? "0", levelName.toUpperCase().padEnd(5)),
    typeof msg === "string" ? msg : "",
    ...scalars,
  ]
    .filter((part) => part !== "")
    .join(" ");
  const body = nested.map(
    ([key, value]) =>
      `  ${dim(`${key}:`)} ${JSON.stringify(value, null, 2).replaceAll("\n", "\n  ")}`,
  );
  return [header, ...body].join("\n");
}

function usePretty(): boolean {
  return process.env.LOG_FORMAT !== "json";
}

function createPrettyDestination() {
  const color = process.stdout.isTTY === true && !process.env.NO_COLOR;
  return {
    write(chunk: string) {
      const line = chunk.endsWith("\n") ? chunk.slice(0, -1) : chunk;
      const level = (() => {
        try {
          return String((JSON.parse(line) as { level?: unknown }).level);
        } catch {
          return "info";
        }
      })();
      const method = consoleMethods[level as keyof typeof consoleMethods];
      console[method ?? "info"](formatPrettyRecord(line, color));
    },
  };
}

export const log = usePretty()
  ? createForgeLogger({}, createPrettyDestination())
  : createForgeLogger();
