-- PR context for webhook-initiated scans, so findings can be posted back to the PR.
CREATE TABLE pr_jobs (
  scan_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  repo TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  head_sha TEXT NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(id)
);
