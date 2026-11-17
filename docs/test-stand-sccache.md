# Optional sccache runner for test laptops

**Experimental; not yet accepted for routine use.** A Windows test-laptop run with sccache 0.13.0 completed a Cargo build and reported 14 cache hits and 21 misses. Earlier tests with a simulated server checked exit codes and a simulated low-disk condition. The Linux runner has not been run on the test laptop. A matched cold/warm comparison, interrupted runs, long-running disk monitoring and incremental-artifact cleanup still need end-to-end validation. Do not treat this runner as a substitute for the existing gate until those checks pass.

The runners in `scripts/test-stand-cargo.sh` and `scripts/test-stand-cargo.ps1` are opt-in and intended for designated test laptops. Ordinary Cargo and the development incremental cache are unchanged. Install Cargo and sccache separately; the scripts do not install tools or change the user's permanent Cargo configuration.

Create a dedicated private directory for each stand and keep its path stable. On Windows it must be on a non-system local drive, for example `D:\nrr-stand-cache`. On Linux choose a short absolute path without symbolic links, owned by the current user, on a volume with enough space. The path uses ASCII letters, digits, slash, dot, underscore and hyphen only; the runner rejects longer paths that cannot safely hold its private Unix socket. The directory contains `target`, `cache`, and an empty sccache configuration file. Do not point it at a shared target, another user's directory, or a directory in use by another run. The Linux runner needs `flock` and `setsid`.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-stand-cargo.ps1 -Root D:\nrr-stand-cache build --offline -p nrr-domain -j2
```

```bash
bash scripts/test-stand-cargo.sh --root /data/nrr-stand-cache build --offline -p nrr-domain -j2
```

The runner sets `CARGO_INCREMENTAL=0`, wraps Rust compilation with sccache, limits the local cache to 10 GB and starts a separate local server. This does not cache C++ builds automatically. The cache limit does not cap the Cargo target, dependencies, or temporary files. Paths and compiler flags influence cache hits; use the same target path for repeated builds. The runner rejects inherited Rust wrappers or `SCCACHE_*` settings so that it cannot silently use a remote or differently configured cache. It stops the server it started and returns Cargo's exit status.

The Windows runner checks that C: has at least 8 GiB free and the stand volume at least 15 GiB before starting, then monitors both and stops its own Cargo process tree below 7 GiB. The Linux runner requires at least 15 GiB free on the stand volume and monitors it during the run, stopping its own Cargo process group below 7 GiB. The 2 GiB margin protects the 5 GiB reserve but cannot prevent an exceptionally large burst between checks. These thresholds are minimums, not a bound on build growth: budget additional expected space and keep required evidence outside C:.

The stand target does not generate incremental artifacts while the runner is active. Existing incremental directories from ordinary development or earlier runs are not automatically deleted: they may be shared or in use. After a run, inspect the exact resolved target and its ownership, confirm that no build or process uses it and that no path component is a link or reparse point, then remove only obsolete artifacts belonging to the completed run. Keep evidence and never delete an active or shared target. Report free disk before and after cleanup. An automated cleanup command is not provided until exclusive ownership and absence of active users can be verified safely.
