# Signed update pipeline

This repository includes a simple signed-release verification scaffold.

## What is included
- manifest builder script
- release verifier
- public key config file

## What is not included
- private keys
- automatic remote updater
- full TUF repository server

## Basic flow
1. Build the bundle.
2. Generate a signed manifest using a private Ed25519 key.
3. Commit only the public verification key.
4. Verify the bundle before promoting it.
