#!/usr/bin/env node
/**
 * PatchPilot MCP Server
 * Security scanner for vibe coders - checks npm packages for vulnerabilities
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import * as z from 'zod';
import {
  OsvQueryResponse,
  OsvVulnerability,
  SeverityLevel,
  getHighestSeverity,
  findFixedVersion,
} from './types/osv.js';

const OSV_API_URL = 'https://api.osv.dev/v1/query';
const REQUEST_TIMEOUT_MS = 10000;

/**
 * Query OSV API for vulnerabilities
 */
async function queryOsv(
  packageName: string,
  version: string
): Promise<OsvQueryResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(OSV_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        version,
        package: {
          name: packageName,
          ecosystem: 'npm',
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`OSV API error: ${response.status} ${response.statusText}`);
    }

    const data: unknown = await response.json();
    return validateOsvResponse(data);
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Validate OSV API response structure
 */
function validateOsvResponse(data: unknown): OsvQueryResponse {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Invalid API response: expected object');
  }
  const obj = data as Record<string, unknown>;
  if (obj.vulns !== undefined && !Array.isArray(obj.vulns)) {
    throw new Error('Invalid API response: vulns must be an array');
  }
  return data as OsvQueryResponse;
}

/**
 * Format vulnerability for user-friendly output
 */
function formatVulnerability(vuln: OsvVulnerability): string {
  const severity = getHighestSeverity(vuln);
  const fixedVersion = findFixedVersion(vuln);

  let output = `[${severity}] ${vuln.summary || vuln.id}`;
  if (fixedVersion) {
    output += `\n   Fix: Update to version ${fixedVersion}`;
  }
  return output;
}

/**
 * Get severity emoji for visual feedback
 */
function getSeverityEmoji(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return '🚨';
    case 'HIGH':
      return '⚠️';
    case 'MEDIUM':
      return '⚡';
    case 'LOW':
      return 'ℹ️';
    default:
      return '❓';
  }
}

// Create MCP Server
const server = new McpServer({
  name: 'patchpilot',
  version: '0.1.0',
});

// Register the check_package tool
server.registerTool(
  'check_package',
  {
    title: 'Check Package Security',
    description:
      'Check if an npm package has known security vulnerabilities. Use this before installing any package to ensure it is safe.',
    inputSchema: {
      name: z
        .string()
        .min(1)
        .max(214)
        .regex(/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/, 'Invalid npm package name')
        .describe('Package name (e.g., "lodash", "next", "express")'),
      version: z
        .string()
        .min(1)
        .max(256)
        .regex(/^[0-9a-zA-Z.-]+$/, 'Invalid version format')
        .describe('Package version (e.g., "4.17.0", "14.1.0")'),
    },
  },
  async ({ name, version }) => {
    try {
      const result = await queryOsv(name, version);
      const vulns = result.vulns || [];

      if (vulns.length === 0) {
        const output = `✅ ${name}@${version} looks safe!\n\nNo known vulnerabilities found in the OSV database.`;
        return {
          content: [{ type: 'text', text: output }],
        };
      }

      // Count by severity
      const counts: Record<SeverityLevel, number> = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        UNKNOWN: 0,
      };

      for (const vuln of vulns) {
        counts[getHighestSeverity(vuln)]++;
      }

      // Determine overall severity from counts
      const overallSeverity: SeverityLevel =
        counts.CRITICAL > 0 ? 'CRITICAL' :
        counts.HIGH > 0 ? 'HIGH' :
        counts.MEDIUM > 0 ? 'MEDIUM' :
        counts.LOW > 0 ? 'LOW' : 'UNKNOWN';

      // Build output
      let output = `${getSeverityEmoji(overallSeverity)} ${name}@${version} has ${vulns.length} known vulnerabilit${vulns.length === 1 ? 'y' : 'ies'}!\n\n`;

      // Summary line
      const summaryParts: string[] = [];
      if (counts.CRITICAL > 0) summaryParts.push(`🚨 ${counts.CRITICAL} Critical`);
      if (counts.HIGH > 0) summaryParts.push(`⚠️ ${counts.HIGH} High`);
      if (counts.MEDIUM > 0) summaryParts.push(`⚡ ${counts.MEDIUM} Medium`);
      if (counts.LOW > 0) summaryParts.push(`ℹ️ ${counts.LOW} Low`);
      output += summaryParts.join(' | ') + '\n\n';

      // Details (max 5 to avoid too much output)
      output += '--- Details ---\n';
      for (const vuln of vulns.slice(0, 5)) {
        output += formatVulnerability(vuln) + '\n\n';
      }

      if (vulns.length > 5) {
        output += `... and ${vulns.length - 5} more.\n\n`;
      }

      // Action recommendation
      const fixedVersions = vulns.map(findFixedVersion).filter(Boolean);
      if (fixedVersions.length > 0) {
        const latestFix = fixedVersions[fixedVersions.length - 1];
        output += `💡 Recommendation: Update to ${name}@${latestFix} or later\n`;
        output += `   Run: npm install ${name}@${latestFix}`;
      } else {
        output += `💡 Recommendation: Check for a newer version of ${name} or consider alternatives.`;
      }

      return {
        content: [{ type: 'text', text: output }],
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      return {
        content: [
          {
            type: 'text',
            text: `❌ Error checking ${name}@${version}: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Connect via stdio transport
const transport = new StdioServerTransport();
await server.connect(transport);
