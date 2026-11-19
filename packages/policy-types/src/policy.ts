/* Generated from agentforge.schema.json by scripts/generate.mjs. Do not edit. */
/* Regenerate: pnpm --filter @agentforge/policy-types generate */

export type Agent = "claude-code" | "codex";
/**
 * The policy API version that this build understands.
 */
export type ApiVersion = "agentforge.dev/v1alpha1";
export type SimpleFallback = "deny" | "require-approval";
/**
 * The execution backends.
 */
export type BackendKind = "local" | "container" | "cloudflare";
export type Kind = "AgentPolicy";
/**
 * The effect a rule has when it matches.
 */
export type Effect = "allow" | "route" | "require-approval" | "deny";

/**
 * The top-level policy document.
 */
export interface Policy {
  agents?: Agent[];
  apiVersion: ApiVersion;
  audit?: Audit;
  execution?: Execution;
  kind: Kind;
  project: Project;
  /**
   * Extra protected paths. These are added to the built-in list and can
   * never remove entries from it. Entries are directories or files
   * (`~` is expanded), or basename globs such as `*.secret`.
   */
  protectedPaths?: string[];
  rules?: Rule[];
}
export interface Audit {
  dir?: string;
  format?: "json";
  redactSecrets?: boolean;
}
export interface Execution {
  backends?: Backends;
  /**
   * The backend used by `allow` and `require-approval` rules that do not
   * name one.
   */
  default?: "local" | "container" | "cloudflare";
  /**
   * What to do with a command that no rule matched, or an opaque command that
   * only `allow` rules matched.
   */
  fallback?: SimpleFallback | RouteFallback;
}
export interface Backends {
  cloudflare?: CloudflareBackend;
  container?: ContainerBackend;
  local?: LocalBackend;
}
export interface CloudflareBackend {
  enabled?: boolean;
}
export interface ContainerBackend {
  cpus?: number;
  enabled?: boolean;
  /**
   * Variables passed into the container. Values come from the host, and
   * none are passed by default.
   */
  env?: string[];
  image?: string;
  memoryMB?: number;
  network?: "none" | "bridge";
  pidsLimit?: number;
  readOnlyRootfs?: boolean;
  timeoutSeconds?: number;
}
export interface LocalBackend {
  enabled?: boolean;
  /**
   * Environment variables passed through from the host. Everything else is
   * cleared.
   */
  env?: string[];
  timeoutSeconds?: number;
}
export interface RouteFallback {
  route: BackendKind;
}
export interface Project {
  name: string;
  root?: string;
}
export interface Rule {
  /**
   * Only for `allow` and `route` rules. When this is set, every flag after
   * the prefix must match an entry, or the rule does not apply.
   */
  allowFlags?: string[] | null;
  /**
   * Required for `route`. Optional for `allow` and `require-approval`,
   * which default to `execution.default`.
   */
  backend?: BackendKind | null;
  /**
   * Each entry is an argv prefix: the executable name, then leading
   * arguments. The element `*` matches any single argument.
   */
  commands: string[][];
  /**
   * Only for `allow` and `route` rules. If any argument after the prefix
   * matches, the rule does not apply. A pattern `--flag` also matches
   * `--flag=value`, and a trailing `*` makes the pattern a prefix match.
   */
  denyArgs?: string[];
  description?: string | null;
  effect: Effect;
  id: string;
}
