import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

// ZK-041: Accept version parameter for versioned artifact layout
const zkVersion = process.argv[2] || '1';
const artifactsDir = path.join(repoRoot, 'artifacts', 'zk', `v${zkVersion}`);
const manifestPath = path.join(artifactsDir, 'manifests', 'manifest.json');
const PRODUCTION_MERKLE_ROOT_DEPTH = 20;

/**
 * Computes a deterministic SHA-256 checksum for a JSON object.
 */
function computeChecksum(obj) {
  const str = JSON.stringify(obj, Object.keys(obj).sort());
  return '0x' + createHash('sha256').update(str).digest('hex');
}

function main() {
  console.log(`Refreshing ZK manifest for version ${zkVersion}...`);

  // ZK-041: Create manifests directory if it doesn't exist
  if (!fs.existsSync(path.dirname(manifestPath))) {
    fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  }

  // ZK-041: Initialize manifest structure if it doesn't exist
  let manifest;
  if (fs.existsSync(manifestPath)) {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } else {
    manifest = {
      version: zkVersion,
      backend: 'barretenberg',
      circuits: {},
    };
  }

  // ZK-041: Update circuits list to include merkle
  const circuits = ['withdraw', 'commitment', 'merkle'];

  for (const name of circuits) {
    // ZK-041: Look for circuits in versioned directory structure
    const filePath = path.join(artifactsDir, 'circuits', name, `${name}.json`);
    if (!fs.existsSync(filePath)) {
      console.warn(`Warning: Missing artifact for ${name} at ${filePath}`);
      continue;
    }

    const artifact = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const checksum = computeChecksum(artifact);

    if (!manifest.circuits[name]) {
      manifest.circuits[name] = {};
    }
    // ZK-041: Update path to reflect new directory structure
    manifest.circuits[name].path = `circuits/${name}/${name}.json`;
    manifest.circuits[name].checksum = checksum;
    
    // Production artifact depth is fixed for this protocol version.
    if (name === 'withdraw') {
      manifest.circuits[name].root_depth = PRODUCTION_MERKLE_ROOT_DEPTH;
    }
  }

  // Idempotent write
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  console.log(`Manifest updated at ${manifestPath}`);
}

main();
