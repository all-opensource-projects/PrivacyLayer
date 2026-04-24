import { stableHash32 } from './stable';

type CryptoLike = {
  getRandomValues<T extends ArrayBufferView | null>(array: T): T;
};

export interface RandomnessSource {
  randomBytes(length: number): Uint8Array;
}

export interface RuntimeRandomnessSourceOptions {
  runtime?: { crypto?: CryptoLike };
  enableNodeFallback?: boolean;
}

function resolveRuntimeCrypto(options: RuntimeRandomnessSourceOptions = {}): CryptoLike {
  const runtime = options.runtime ?? (globalThis as RuntimeRandomnessSourceOptions['runtime']);
  if (runtime?.crypto && typeof runtime.crypto.getRandomValues === 'function') {
    return runtime.crypto;
  }

  if (options.enableNodeFallback !== false) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require('crypto') as { webcrypto?: CryptoLike };
      if (nodeCrypto.webcrypto && typeof nodeCrypto.webcrypto.getRandomValues === 'function') {
        return nodeCrypto.webcrypto;
      }
    } catch {
      // Runtime does not support require('crypto')
    }
  }

  throw new Error(
    'Secure randomness unavailable: no crypto.getRandomValues implementation found in this runtime.'
  );
}

/**
 * RuntimeRandomnessSource uses secure randomness in browser and Node runtimes.
 */
export class RuntimeRandomnessSource implements RandomnessSource {
  private options: RuntimeRandomnessSourceOptions;

  constructor(options: RuntimeRandomnessSourceOptions = {}) {
    this.options = options;
  }

  randomBytes(length: number): Uint8Array {
    if (!Number.isInteger(length) || length <= 0) {
      throw new Error(`Random byte length must be a positive integer, received: ${length}`);
    }
    const out = new Uint8Array(length);
    resolveRuntimeCrypto(this.options).getRandomValues(out);
    return out;
  }
}

let defaultRandomnessSource: RandomnessSource = new RuntimeRandomnessSource();

export function setDefaultRandomnessSource(source: RandomnessSource): void {
  defaultRandomnessSource = source;
}

export function resetDefaultRandomnessSource(): void {
  defaultRandomnessSource = new RuntimeRandomnessSource();
}

/**
 * PrivacyLayer Note
 * 
 * Represents a private "IOU" in the shielded pool.
 * A note consists of a nullifier (revealed on withdrawal) and a secret (never revealed).
 * The commitment = Hash(nullifier, secret) is what's stored in the Merkle tree.
 */
export class Note {
  constructor(
    public readonly nullifier: Buffer,
    public readonly secret: Buffer,
    public readonly poolId: string,
    public readonly amount: bigint
  ) {
    if (nullifier.length !== 31 || secret.length !== 31) {
      throw new Error('Nullifier and secret must be 31 bytes to fit BN254 field');
    }
  }

  /**
   * Create a new random note for a specific pool.
   */
  static generate(poolId: string, amount: bigint, randomnessSource: RandomnessSource = defaultRandomnessSource): Note {
    return new Note(
      Buffer.from(randomnessSource.randomBytes(31)),
      Buffer.from(randomnessSource.randomBytes(31)),
      poolId,
      amount
    );
  }

  /**
   * Deterministic derivation for fixtures/testing only.
   * Keep this separate from production randomness.
   */
  static deriveDeterministic(seed: Uint8Array | Buffer | string, poolId: string, amount: bigint): Note {
    const seedBytes = typeof seed === 'string' ? Buffer.from(seed, 'utf8') : Buffer.from(seed);
    const nullifier = stableHash32('note-nullifier', seedBytes, poolId, amount).subarray(0, 31);
    const secret = stableHash32('note-secret', seedBytes, poolId, amount).subarray(0, 31);
    return new Note(Buffer.from(nullifier), Buffer.from(secret), poolId, amount);
  }

  /**
   * In a real implementation, this would use a WASM-based Poseidon hash
   * compatible with the Noir circuit and Soroban host function.
   */
  getCommitment(): Buffer {
    // Placeholder commitment derivation for SDK plumbing tests.
    // Production should replace this with Poseidon(nullifier, secret).
    return stableHash32('commitment', this.nullifier, this.secret);
  }

  /**
   * Serialize note to a secure string (e.g., for backup).
   */
  serialize(): string {
    const data = Buffer.concat([
      this.nullifier,
      this.secret,
      Buffer.from(this.poolId, 'hex'),
      Buffer.alloc(16) // amount padding
    ]);
    // writeBigUInt64BE for amount
    data.writeBigUInt64BE(this.amount, 31 + 31 + 32);
    return `privacylayer-note-${data.toString('hex')}`;
  }

  /**
   * Deserialize note from a string.
   */
  static deserialize(noteStr: string): Note {
    if (!noteStr.startsWith('privacylayer-note-')) {
      throw new Error('Invalid note format');
    }
    const hex = noteStr.replace('privacylayer-note-', '');
    const data = Buffer.from(hex, 'hex');
    
    const nullifier = data.subarray(0, 31);
    const secret = data.subarray(31, 62);
    const poolId = data.subarray(62, 94).toString('hex');
    const amount = data.readBigUInt64BE(94);
    
    return new Note(nullifier, secret, poolId, amount);
  }
}
