export type Defaults = {
  config: Config;
};

export type Config = {
  port: number;
  target_timeout: string;
  connection_timeout: string;
  concurrency: number;
  per_host_connections: number;
  rate_limit: number;
  maximum_targets: number;
  ip_preference: "any" | "ipv4" | "ipv6";
  auth_probe_enabled: boolean;
  audit_user: string;
  failure_threshold: "critical" | "high" | "medium" | "never";
};

export type ScanInput = {
  targets: string;
  port: number;
  ip_preference: string;
  target_timeout: string;
  connection_timeout: string;
  concurrency: number;
  per_host_connections: number;
  rate_limit: number;
  maximum_targets: number;
  audit_user: string;
  auth_probe_enabled: boolean;
  known_hosts_path: string;
  policy_path: string;
  failure_threshold: string;
  scope_reference: string;
  operator_confirmed: boolean;
};

export type ScanOutput = {
  report: Report;
};

export type Report = {
  schema_version: string;
  tool_version: string;
  started_at: string;
  finished_at: string;
  configuration: Config;
  authorization: {
    scope_reference: string;
    operator_confirmed: boolean;
  };
  targets: TargetResult[];
  errors: ProbeError[];
  status: Status;
};

export type TargetResult = {
  target: {
    original: string;
    hostname: string;
    resolved_ip: string;
    port: number;
    ip_version: string;
  };
  observations: Observation[];
  findings: Finding[];
  errors: ProbeError[];
  status: Status;
};

export type Observation = {
  id: string;
  probe: string;
  observed_at: string;
  confidence: string;
  value: {
    kind: string;
    boolean?: boolean;
    string?: string;
    number?: number;
    unit?: string;
    strings?: string[];
    host_keys?: HostKey[];
    kex_proposal?: unknown;
  };
};

export type HostKey = {
  algorithm: string;
  fingerprint_sha256: string;
  public_key_type: string;
  bits?: number;
  certificate: boolean;
  ca_fingerprint_sha256?: string;
  known_hosts_status: string;
};

export type Finding = {
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: string;
  description: string;
  recommendation: string;
  affected_values?: string[];
};

export type ProbeError = {
  kind: string;
  probe: string;
  message: string;
  retryable: boolean;
};

export type Status = "complete" | "partial" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
