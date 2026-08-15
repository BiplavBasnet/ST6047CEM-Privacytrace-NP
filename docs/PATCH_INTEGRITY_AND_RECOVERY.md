# Patch Integrity and Recovery

Controlled patches record `patch_hash`, safe diffs, sandbox workspace references, and rollback status. Apply is sandbox/workspace-only (Option B gold fixture). Production apply is out of scope. Rollback restores the sandbox snapshot when available.

See `docs/CONTROLLED_PATCH_IMPLEMENTATION.md`.
