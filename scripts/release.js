/* global console */
import fs from 'node:fs';
import { execSync } from 'node:child_process';
import process from 'node:process';

/**
 * Runs a command and returns its output.
 * Exits the process if the command fails.
 */
const run = (command, options = {}) => {
  const { silent = false, stdio = 'inherit' } = options;
  if (!silent) console.log(`> ${command}`);
  try {
    return execSync(command, {
      stdio,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024, // 1MB
      ...options,
    });
  } catch (error) {
    if (!silent) {
      console.error(`\nError: Command failed: ${command}`);
      if (error.stdout && stdio === 'pipe') console.error(error.stdout);
      if (error.stderr && stdio === 'pipe') console.error(error.stderr);
    }
    process.exit(1);
  }
};

const main = () => {
  console.log('--- Starting Release Process ---');

  // Read the current version from package.json
  console.log('Reading version from package.json...');
  if (!fs.existsSync('package.json')) {
    console.error('Error: package.json not found.');
    process.exit(1);
  }

  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const version = pkg.version;
  if (!version) {
    console.error('Error: version not found in package.json.');
    process.exit(1);
  }

  const tagName = `v${version}`;
  console.log(`Current version: ${version}`);

  // Confirm a git tag for that version doesn't already exist
  console.log(`Checking if tag ${tagName} already exists...`);
  const tagExists = run(`git tag -l ${tagName}`, { stdio: 'pipe' }).trim() !== '';
  if (tagExists) {
    console.error(`Error: Git tag ${tagName} already exists.`);
    process.exit(1);
  }

  // Confirm the working tree is clean and on main
  console.log('Verifying git state...');
  const currentBranch = run('git rev-parse --abbrev-ref HEAD', { stdio: 'pipe' }).trim();
  if (currentBranch !== 'main') {
    console.error(`Error: Not on branch 'main' (currently on '${currentBranch}').`);
    process.exit(1);
  }

  const gitStatus = run('git status --porcelain', { stdio: 'pipe' }).trim();
  if (gitStatus !== '') {
    console.error('Error: Working tree is not clean. Commit or stash changes first.');
    console.error(gitStatus);
    process.exit(1);
  }

  // Run npm run build && npm test && npm run lint
  console.log('Running build, test, and lint...');
  run('npm run build');
  run('npm test');
  run('npm run lint');

  // Create and push the git tag
  console.log(`Creating tag ${tagName}...`);
  run(`git tag ${tagName}`);
  
  console.log(`Pushing tag ${tagName} to origin...`);
  run(`git push origin ${tagName}`);

  // Create the GitHub release using gh CLI
  console.log(`Creating GitHub release ${tagName}...`);
  run(`gh release create ${tagName} --title "${tagName}" --generate-notes`);

  console.log('\n--- Release completed successfully! ---');
};

main();
