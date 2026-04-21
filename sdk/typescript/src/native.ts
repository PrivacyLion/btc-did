/**
 * Native binding loader for SignedByMe core.
 *
 * This module loads the appropriate native binary for the current platform.
 * The native code is built from Rust using napi-rs.
 */

/* eslint-disable @typescript-eslint/no-var-requires */

import { platform, arch } from 'os';
import { join } from 'path';

interface NativeBindings {
  SignedByClient: {
    fromDelegationJson(json: string): Promise<unknown>;
  };
  SignedByAgent: {
    init(storagePath: string): Promise<unknown>;
  };
  getNpub(client: unknown): string;
  getAgentNpub(agent: unknown): string;
  generateLoginProof(client: unknown, clientId: string, nonce: string): Promise<unknown>;
  publishProofEvent(client: unknown, relayUrl: string, proof: unknown): Promise<void>;
  verifyAndGetToken(
    client: unknown,
    apiUrl: string,
    proof: unknown,
    clientId: string,
    nonce: string
  ): Promise<{
    id_token: string;
    token_type?: string;
    expires_in?: number;
    sub: string;
  }>;
  setEmailMapping(agent: unknown, mapping: Record<string, string>): void;
  connectRelay(agent: unknown, relayUrl: string): Promise<void>;
  subscribeAuthorizations(agent: unknown): AsyncIterable<string>;
  getActivityLog(agent: unknown, limit: number): Array<Record<string, unknown>>;
}

function loadNativeBinding(): NativeBindings {
  const platformName = platform();
  const archName = arch();

  let nativeBinding: NativeBindings;

  // Map platform/arch to package name
  const platformMap: Record<string, Record<string, string>> = {
    darwin: {
      x64: '@signedby/core-darwin-x64',
      arm64: '@signedby/core-darwin-arm64',
    },
    linux: {
      x64: '@signedby/core-linux-x64-gnu',
      arm64: '@signedby/core-linux-arm64-gnu',
    },
    win32: {
      x64: '@signedby/core-win32-x64-msvc',
    },
  };

  const packageName = platformMap[platformName]?.[archName];

  if (!packageName) {
    throw new Error(
      `Unsupported platform: ${platformName}-${archName}. ` +
        'SignedByMe SDK supports: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64'
    );
  }

  try {
    // Try to load the platform-specific package
    nativeBinding = require(packageName);
  } catch (loadError) {
    // Fall back to local development binary
    try {
      nativeBinding = require(join(__dirname, '..', 'native', `signedby_core.${platformName}.node`));
    } catch {
      throw new Error(
        `Failed to load native module for ${platformName}-${archName}. ` +
          `Install with: npm install ${packageName}\n` +
          `Original error: ${loadError}`
      );
    }
  }

  return nativeBinding;
}

export = loadNativeBinding();
