-- Persist a short, sanitized failure reason on the scan so GET /api/scans/:id can
-- surface WHY a scan failed (instead of the UI always showing a generic fallback).
ALTER TABLE scans ADD COLUMN error TEXT;
