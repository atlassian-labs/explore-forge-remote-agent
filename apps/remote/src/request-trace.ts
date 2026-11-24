import { AsyncLocalStorage } from "node:async_hooks";

// The trace ID Atlassian sends with each request (the B3 `x-b3-traceid`
// header). Kept per request so log lines emitted later, while a scenario plays,
// can carry it without threading it through every function.
const traceStorage = new AsyncLocalStorage<string | undefined>();

export function traceIdFromHeaders(
  headers: Record<string, string | string[] | undefined>,
): string | undefined {
  const value = headers["x-b3-traceid"];
  const first = Array.isArray(value) ? value[0] : value;
  return first && first.length > 0 ? first : undefined;
}

export function runWithTraceId<Result>(
  traceId: string | undefined,
  callback: () => Result,
): Result {
  return traceStorage.run(traceId, callback);
}

export function currentTraceId(): string | undefined {
  return traceStorage.getStore();
}
