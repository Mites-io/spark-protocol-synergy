# Test-only keypair

These files are a throwaway RSA-2048 server keypair generated solely for the unit tests in this directory. They are **not** a secret: they have never been deployed to any server or flashed to any device, and they protect nothing. They are committed so `npm test` runs with no setup step. Do not reuse them for anything real.
