/**
 * OSV API Types
 * Based on https://google.github.io/osv.dev/api/
 */

export interface OsvSeverity {
  type: 'CVSS_V3' | 'CVSS_V2';
  score: string;
}

export interface OsvAffectedRange {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  events: Array<{
    introduced?: string;
    fixed?: string;
    last_affected?: string;
    limit?: string;
  }>;
}

export interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  severity?: OsvSeverity[];
  affected: Array<{
    package: { name: string; ecosystem: string };
    ranges?: OsvAffectedRange[];
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
}

export interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

/**
 * Simplified severity level for user-friendly output
 */
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

/**
 * Parse CVSS score to severity level
 */
export function cvssToSeverity(score: string): SeverityLevel {
  const numScore = parseFloat(score);
  if (isNaN(numScore)) return 'UNKNOWN';
  if (numScore >= 9.0) return 'CRITICAL';
  if (numScore >= 7.0) return 'HIGH';
  if (numScore >= 4.0) return 'MEDIUM';
  return 'LOW';
}

/**
 * Get the highest severity from a vulnerability
 */
export function getHighestSeverity(vuln: OsvVulnerability): SeverityLevel {
  if (!vuln.severity || vuln.severity.length === 0) return 'UNKNOWN';

  let highest: SeverityLevel = 'UNKNOWN';
  const order: SeverityLevel[] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

  for (const sev of vuln.severity) {
    const level = cvssToSeverity(sev.score);
    if (order.indexOf(level) > order.indexOf(highest)) {
      highest = level;
    }
  }

  return highest;
}

/**
 * Find the fixed version from vulnerability ranges
 */
export function findFixedVersion(vuln: OsvVulnerability): string | undefined {
  for (const affected of vuln.affected) {
    if (affected.ranges) {
      for (const range of affected.ranges) {
        for (const event of range.events) {
          if (event.fixed) {
            return event.fixed;
          }
        }
      }
    }
  }
  return undefined;
}
