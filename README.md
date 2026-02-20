# xva_sync — XCP-ng XAPI Plugin

Remote XVA template synchronization plugin for **XCP-ng**.

This plugin syncs VM templates stored as `.xva` files on a **read-only SMB share** into a local Storage Repository (SR).  
It is designed for minimal, unattended XCP-ng hosts managed by an external orchestrator.

The intended use is centralizing the management of templates safely with multiple **non-clustered** hypervisors.

This plugin was developed for [Hoxey](https://github.com/orgs/Hoxey-security) and is released under MIT License

---

## Features

- Mounts a remote SMB share (can be read-only)
- Imports new `.xva` templates into a target SR
- Replaces templates when the source XVA changes
- Deletes templates removed from the share (if safe)
- Preserves templates that have local clones/snapshots
- Uses file size + mtime for fast change detection
- Optional `.sha256` sidecar support
- Fire-and-forget background execution (double-fork)
- Dry-run mode with full diff output
- Locking to prevent concurrent runs
- Persistent state file for last run status

---

## Requirements

- XCP-ng host
- `xe` CLI available
- CIFS/SMB client support
- Plugin installed on the host

Tested on:
- XCP-ng 8.x

---

## Installation

Copy the plugin to the XAPI plugins directory:

```bash
cp xva_sync.py /etc/xapi.d/plugins/
chmod +x /etc/xapi.d/plugins/xva_sync.py
```

---

## Usage

### Fire-and-Forget Sync

Returns immediately and performs sync in background.

```bash
xe host-call-plugin host-uuid=<HOST_UUID> plugin=xva_sync.py fn=sync_templates \
  args:smb_host=192.168.1.10 \
  args:smb_share=templates \
  args:smb_user=svc \
  args:smb_password=secret \
  args:sr_uuid=<SR_UUID> \
  args:network_uuid=<NET_UUID>
```

Example response:

```json
{ "status": "started", "worker_pid": 12345 }
```

---

### Dry Run (Diff / Status)

Does not modify anything. Returns pending actions and last run state.

```bash
xe host-call-plugin host-uuid=<HOST_UUID> plugin=xva_sync.py fn=sync_templates \
  args:smb_host=192.168.1.10 \
  args:smb_share=templates \
  args:smb_user=svc \
  args:smb_password=secret \
  args:sr_uuid=<SR_UUID> \
  args:dry_run=true
```

---

## Arguments

### Required

| Argument        | Description |
|---------------|------------|
| `smb_host`     | SMB server hostname or IP |
| `smb_share`    | Share name |
| `smb_user`     | SMB username |
| `smb_password` | SMB password |
| `sr_uuid`      | Target Storage Repository UUID |

### Optional

| Argument        | Default | Description |
|----------------|---------|------------|
| `network_uuid` | —       | Replaces all template VIFs with this network |
| `smb_version`  | `3.0`   | SMB protocol version |
| `smb_subdir`   | —       | Subdirectory inside the share |
| `dry_run`      | `false` | Enable dry-run mode |

---

## How It Works

1. Acquire lock
2. Mount SMB share (read-only)
3. Scan `.xva` files
4. Compare with managed templates on SR
5. Compute diff:
   - Import
   - Replace
   - Delete
   - Skip
6. Execute safely:
   - Never deletes templates with children
   - Uses atomic `vm-import`
7. Write state file
8. Unmount share and release lock

---

## Metadata

Templates managed by this plugin are tagged in `other-config`:

- `xva_sync_managed=true`
- `xva_sync_source=<filename>`
- `xva_sync_sha256=<hash>`
- `xva_sync_size=<bytes>`
- `xva_sync_mtime=<mtime>`

Only tagged templates are managed or removed.

---

## State & Logs

- Lock file: `/tmp/xva_sync.lock`
- State file: `/tmp/xva_sync_state.json`
- Log file: `/var/log/xva_sync.log`

---

## Safety

- Will NOT delete templates with local clones or snapshots
- Will NOT overwrite templates with children
- Mounts SMB share read-only
- Prevents concurrent sync runs
- Credentials stored in temporary 0600 file and removed immediately

---

## Optional: SHA256 Sidecar

To avoid hashing large files over SMB, place a sidecar file:

```bash
sha256sum template.xva | awk '{print $1}' > template.xva.sha256
```

The plugin will use it automatically if valid.

---

## Design Philosophy

- Minimal
- Deterministic
- Safe-by-default
- No external dependencies
- Suitable for infrastructure automation

---

## License

MIT License.  
Use at your own risk.
