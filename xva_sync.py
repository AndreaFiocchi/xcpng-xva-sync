#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xva_sync.py -- XCP-ng XAPI Plugin: Remote XVA Template Sync

Syncs VM templates from a read-only SMB share to a local SR.
Designed to run on uncluttered XCP-ng hosts managed by an external orchestrator.
Fully autonomous: cleans up orphaned templates and VDIs automatically.

Install:
    cp xva_sync.py /etc/xapi.d/plugins/
    chmod +x /etc/xapi.d/plugins/xva_sync.py

Usage:
    # Fire-and-forget sync (returns immediately):
    xe host-call-plugin host-uuid=<UUID> plugin=xva_sync.py fn=sync_templates \
        args:smb_host=192.168.1.10 args:smb_share=templates \
        args:smb_user=svc args:smb_password=secret \
        args:sr_uuid=<SR_UUID> args:network_uuid=<NET_UUID>

    # Dry-run / status check (returns full diff + last run info):
    xe host-call-plugin host-uuid=<UUID> plugin=xva_sync.py fn=sync_templates \
        args:smb_host=192.168.1.10 args:smb_share=templates \
        args:smb_user=svc args:smb_password=secret \
        args:sr_uuid=<SR_UUID> args:dry_run=true
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# XenAPIPlugin shim -- allows syntax/logic testing outside XCP-ng
# ---------------------------------------------------------------------------
try:
    import XenAPIPlugin
except ImportError:
    class _XenAPIPlugin:
        class Failure(Exception):
            def __init__(self, code, args=None):
                self.code = code
                self.args_ = args or []
                super().__init__("%s: %s" % (code, args))
        @staticmethod
        def dispatch(table):
            pass
    XenAPIPlugin = _XenAPIPlugin()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOCK_FILE       = "/tmp/xva_sync.lock"
STATE_FILE      = "/tmp/xva_sync_state.json"
MOUNT_BASE      = "/tmp/xva_sync_mnt"
CRED_FILE_BASE  = "/tmp/xva_sync_cred"
LOG_FILE        = "/var/log/xva_sync.log"

# Metadata keys stored in XAPI other-config
META_MANAGED    = "xva_sync_managed"   # sentinel: we own this template
META_SOURCE     = "xva_sync_source"    # original filename
META_SHA256     = "xva_sync_sha256"    # hash of the XVA at import time
META_SIZE       = "xva_sync_size"      # file size at import time
META_MTIME      = "xva_sync_mtime"     # file mtime at import time

DEFAULT_SMB_VER = "3.0"

# ---------------------------------------------------------------------------
# Logging -- single initialization, dedup-safe across fork
# ---------------------------------------------------------------------------

_logging_initialized = False

def _setup_logging():
    global _logging_initialized
    if _logging_initialized:
        return
    _logging_initialized = True

    root = logging.getLogger()
    # Clear any inherited handlers (e.g. from parent process before fork)
    root.handlers = []
    root.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(LOG_FILE)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Only add stderr handler if stderr is a real TTY/pipe, not if it has
    # been redirected to the log file (which causes duplicate lines).
    try:
        if os.isatty(sys.stderr.fileno()):
            sh = logging.StreamHandler(sys.stderr)
            sh.setFormatter(fmt)
            root.addHandler(sh)
    except Exception:
        pass

log = logging.getLogger("xva_sync")

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SyncError(Exception):
    """Non-fatal per-item error during sync."""

class FatalError(Exception):
    """Fatal error that aborts the entire run."""

# ---------------------------------------------------------------------------
# Helpers: shell / xe
# ---------------------------------------------------------------------------

def _run(cmd, check=True, timeout=None):
    """Run a command, return (stdout, stderr, returncode)."""
    log.debug("RUN: %s", " ".join(str(c) for c in cmd))
    result = subprocess.run(
        [str(c) for c in cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise SyncError(
            "Command failed (rc=%d): %s\nstderr: %s"
            % (result.returncode,
               " ".join(str(c) for c in cmd),
               result.stderr.strip())
        )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def _xe(*args, check=True, timeout=None):
    return _run(["xe"] + list(args), check=check, timeout=timeout)


def _xe_list(object_type, **filters):
    """
    Return list of UUIDs from 'xe <type>-list --minimal' with optional filters.
    Python underscores in keyword args are converted to hyphens for xe CLI.
    """
    cmd = ["%s-list" % object_type, "--minimal"]
    for k, v in filters.items():
        cmd.append("%s=%s" % (k.replace("_", "-"), v))
    out, _, _ = _xe(*cmd, check=False)
    if not out.strip():
        return []
    return [u.strip() for u in out.split(",") if u.strip()]


def _xe_get(object_type, uuid, param):
    """Get a single param value."""
    out, _, _ = _xe("%s-param-get" % object_type, "uuid=%s" % uuid, "param-name=%s" % param)
    return out.strip()


def _xe_other_config_get(object_type, uuid, key):
    """Safely read a single key from other-config map."""
    out, _, rc = _xe(
        "%s-param-get" % object_type,
        "uuid=%s" % uuid,
        "param-name=other-config",
        "param-key=%s" % key,
        check=False,
    )
    if rc != 0:
        return None
    return out.strip() or None


def _xe_other_config_set(object_type, uuid, key, value):
    """Set a single key in other-config map."""
    _xe(
        "%s-param-set" % object_type,
        "uuid=%s" % uuid,
        "other-config:%s=%s" % (key, value),
    )

# ---------------------------------------------------------------------------
# Helpers: locking
# ---------------------------------------------------------------------------

def _acquire_lock():
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            log.info("Lock held by PID %d -- already running.", pid)
            return False
        except (ValueError, ProcessLookupError, OSError):
            log.warning("Stale lock file found (PID gone), removing.")
            os.unlink(LOCK_FILE)
    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))
    return True


def _rewrite_lock_with_current_pid():
    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))


def _release_lock():
    try:
        os.unlink(LOCK_FILE)
    except FileNotFoundError:
        pass


def _is_locked():
    if not os.path.exists(LOCK_FILE):
        return False
    try:
        with open(LOCK_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, ProcessLookupError, OSError):
        return False

# ---------------------------------------------------------------------------
# Helpers: state file
# ---------------------------------------------------------------------------

def _write_state(state):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log.warning("Could not write state file: %s", e)


def _read_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

# ---------------------------------------------------------------------------
# Helpers: SHA256
# ---------------------------------------------------------------------------

def _sha256(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _sha256_for_xva(xva_path):
    """
    Return SHA256 for an XVA, using a sidecar .sha256 file when available.
    Sidecar: <xva>.sha256 containing the 64-char hex digest.
    """
    sidecar = xva_path + ".sha256"
    if os.path.isfile(sidecar):
        try:
            with open(sidecar) as f:
                digest = f.read().strip().lower()
            if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
                log.debug("Using sidecar SHA256 for %s: %s", xva_path, digest)
                return digest
            log.warning("Sidecar %s has invalid content, falling back to full hash", sidecar)
        except OSError as e:
            log.warning("Could not read sidecar %s: %s -- falling back to full hash", sidecar, e)
    return _sha256(xva_path)

# ---------------------------------------------------------------------------
# Helpers: file identity (size + mtime)
# ---------------------------------------------------------------------------

def _file_identity(xva_path):
    st = os.stat(xva_path)
    return str(st.st_size), str(int(st.st_mtime))

# ---------------------------------------------------------------------------
# Helpers: SMB mount / unmount
# ---------------------------------------------------------------------------

def _write_cred_file(user, password):
    fd, path = tempfile.mkstemp(prefix=CRED_FILE_BASE)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("username=%s\npassword=%s\n" % (user, password))
        os.chmod(path, 0o600)
    except Exception:
        os.unlink(path)
        raise
    return path


def _mount_smb(host, share, user, password, smb_ver, mount_point):
    os.makedirs(mount_point, exist_ok=True)
    out, _, _ = _run(["findmnt", "-n", "-o", "TARGET", mount_point], check=False)
    if out.strip() == mount_point:
        log.warning("Mount point already in use, unmounting first: %s", mount_point)
        _unmount_smb(mount_point)
    cred_file = _write_cred_file(user, password)
    try:
        unc = "//%s/%s" % (host, share)
        cmd = [
            "mount", "-t", "cifs", unc, mount_point,
            "-o", "credentials=%s,ro,vers=%s" % (cred_file, smb_ver),
        ]
        _, stderr, rc = _run(cmd, check=False)
        if rc != 0:
            raise FatalError("SMB mount failed (rc=%d): %s" % (rc, stderr))
        log.info("Mounted %s at %s", unc, mount_point)
    finally:
        try:
            os.unlink(cred_file)
        except Exception:
            pass


def _unmount_smb(mount_point):
    try:
        _run(["umount", "-l", mount_point], check=False)
        log.info("Unmounted %s", mount_point)
    except Exception as e:
        log.warning("Unmount failed for %s: %s", mount_point, e)
    try:
        shutil.rmtree(mount_point, ignore_errors=True)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Helpers: XAPI template inspection
# ---------------------------------------------------------------------------

def _get_managed_templates(sr_uuid=None):
    """
    Return dict of { source_filename: { uuid, sha256, size, mtime, name_label, source_file } }
    for all templates tagged with META_MANAGED=true.

    Uses 'xe template-list' because templates are hidden from 'xe vm-list'
    on XCP-ng.
    """
    vm_uuids = _xe_list("template")
    managed = {}
    for uuid in vm_uuids:
        if _xe_other_config_get("template", uuid, META_MANAGED) != "true":
            continue

        if sr_uuid:
            vbd_uuids = _xe_list("vbd", vm_uuid=uuid)
            on_target_sr = False
            for vbd_uuid in vbd_uuids:
                vdi_uuid = _xe_get("vbd", vbd_uuid, "vdi-uuid")
                if not vdi_uuid or vdi_uuid == "<not in database>":
                    continue
                if _xe_get("vdi", vdi_uuid, "sr-uuid") == sr_uuid:
                    on_target_sr = True
                    break
            if not on_target_sr:
                log.debug("Template %s skipped -- not on SR %s", uuid, sr_uuid)
                continue

        source     = _xe_other_config_get("template", uuid, META_SOURCE) or ""
        sha256     = _xe_other_config_get("template", uuid, META_SHA256) or ""
        size       = _xe_other_config_get("template", uuid, META_SIZE) or ""
        mtime      = _xe_other_config_get("template", uuid, META_MTIME) or ""
        name_label = _xe_get("template", uuid, "name-label")
        managed[source] = {
            "uuid": uuid,
            "sha256": sha256,
            "size": size,
            "mtime": mtime,
            "name_label": name_label,
            "source_file": source,
        }
    return managed


def _has_children(template_uuid):
    """
    Return True if any VDI belonging to this template has clones or snapshots.
    """
    vbd_uuids = _xe_list("vbd", vm_uuid=template_uuid)
    for vbd_uuid in vbd_uuids:
        vdi_uuid = _xe_get("vbd", vbd_uuid, "vdi-uuid")
        if not vdi_uuid or vdi_uuid == "<not in database>":
            continue
        child_vdis = _xe_list("vdi", snapshot_of=vdi_uuid)
        if child_vdis:
            log.debug(
                "Template %s VDI %s has child VDIs: %s",
                template_uuid, vdi_uuid, child_vdis,
            )
            return True
    return False

# ---------------------------------------------------------------------------
# Helpers: VIF management
# ---------------------------------------------------------------------------

def _replace_vifs(template_uuid, network_uuid):
    existing_vifs = _xe_list("vif", vm_uuid=template_uuid)
    for vif_uuid in existing_vifs:
        _xe("vif-destroy", "uuid=%s" % vif_uuid)
        log.info("Destroyed existing VIF %s on template %s", vif_uuid, template_uuid)
    out, _, _ = _xe(
        "vif-create",
        "vm-uuid=%s" % template_uuid,
        "network-uuid=%s" % network_uuid,
        "device=0",
    )
    vif_uuid = out.strip()
    log.info("Created VIF %s on network %s for template %s", vif_uuid, network_uuid, template_uuid)
    return vif_uuid

# ---------------------------------------------------------------------------
# Helpers: import / delete
# ---------------------------------------------------------------------------

def _import_xva(xva_path, sr_uuid):
    log.info("Importing %s into SR %s ...", xva_path, sr_uuid)
    out, _, _ = _xe(
        "vm-import",
        "filename=%s" % xva_path,
        "sr-uuid=%s" % sr_uuid,
        "preserve=false",
        timeout=1800,
    )
    uuids = [u.strip() for u in out.split(",") if u.strip()]
    if not uuids:
        raise SyncError("vm-import returned no UUID for %s" % xva_path)
    if len(uuids) > 1:
        log.warning("XVA %s produced multiple VMs: %s -- using first", xva_path, uuids)
    return uuids[0]


def _set_as_template(vm_uuid):
    _xe("vm-param-set", "uuid=%s" % vm_uuid, "is-a-template=true")


def _rename_template_and_vdis(vm_uuid, name_label):
    """Set name-label on the template record and all its attached VDIs."""
    _xe("vm-param-set", "uuid=%s" % vm_uuid, "name-label=%s" % name_label)
    vbd_uuids = _xe_list("vbd", vm_uuid=vm_uuid)
    for vbd_uuid in vbd_uuids:
        vdi_uuid = _xe_get("vbd", vbd_uuid, "vdi-uuid")
        if vdi_uuid and vdi_uuid != "<not in database>":
            _xe("vdi-param-set", "uuid=%s" % vdi_uuid, "name-label=%s" % name_label)
            log.info("Renamed VDI %s to '%s'", vdi_uuid, name_label)


def _tag_template(vm_uuid, source_file, sha256, size="", mtime=""):
    _xe_other_config_set("vm", vm_uuid, META_MANAGED, "true")
    _xe_other_config_set("vm", vm_uuid, META_SOURCE, source_file)
    _xe_other_config_set("vm", vm_uuid, META_SHA256, sha256)
    _xe_other_config_set("vm", vm_uuid, META_SIZE, size)
    _xe_other_config_set("vm", vm_uuid, META_MTIME, mtime)


def _delete_template(vm_uuid):
    log.info("Deleting template %s and its disks ...", vm_uuid)
    # Destroy each VDI attached to the template
    vbd_uuids = _xe_list("vbd", vm_uuid=vm_uuid)
    for vbd_uuid in vbd_uuids:
        vdi_uuid = _xe_get("vbd", vbd_uuid, "vdi-uuid")
        if vdi_uuid and vdi_uuid != "<not in database>":
            _xe("vdi-destroy", "uuid=%s" % vdi_uuid)
            log.info("Destroyed VDI %s for template %s", vdi_uuid, vm_uuid)
    # Destroy the template record
    _xe("vm-destroy", "uuid=%s" % vm_uuid)
    log.info("Deleted template %s", vm_uuid)


def _rollback_vm(vm_uuid, context=""):
    """
    Best-effort destroy of a partially-imported template and its disks.
    Used to clean up after failed imports where vm-import succeeded
    but subsequent steps (tagging, VIF) failed.
    """
    try:
        vbd_uuids = _xe_list("vbd", vm_uuid=vm_uuid)
        for vbd_uuid in vbd_uuids:
            try:
                vdi_uuid = _xe_get("vbd", vbd_uuid, "vdi-uuid")
                if vdi_uuid and vdi_uuid != "<not in database>":
                    _xe("vdi-destroy", "uuid=%s" % vdi_uuid, check=False)
            except Exception:
                pass
        _xe("vm-destroy", "uuid=%s" % vm_uuid, check=False)
        log.info("Rolled back orphaned template %s (%s)", vm_uuid, context)
    except Exception as e:
        log.warning("Failed to roll back template %s: %s", vm_uuid, e)

# ---------------------------------------------------------------------------
# Cleanup: orphaned templates and VDIs
# ---------------------------------------------------------------------------

def _cleanup_orphaned_templates(sr_uuid, state):
    """
    Find and remove templates on sr_uuid that:
    - Have an import_task in other-config (created by vm-import)
    - Do NOT have xva_sync_managed=true (never tagged, or tag failed)
    - Have no children (safe to delete)

    These are leftovers from interrupted/failed sync runs or manual
    operations in XO where the template was deleted but disks remained.
    """
    log.info("Scanning for orphaned templates on SR %s ...", sr_uuid)
    all_templates = _xe_list("template")
    orphans_found = 0
    orphans_deleted = 0

    for uuid in all_templates:
        # Skip managed templates -- they are ours and intentional
        if _xe_other_config_get("template", uuid, META_MANAGED) == "true":
            continue

        # Only consider templates that have VDIs on our target SR
        vbd_uuids = _xe_list("vbd", vm_uuid=uuid)
        on_target_sr = False
        for vbd_uuid in vbd_uuids:
            vdi_uuid = _xe_get("vbd", vbd_uuid, "vdi-uuid")
            if not vdi_uuid or vdi_uuid == "<not in database>":
                continue
            if _xe_get("vdi", vdi_uuid, "sr-uuid") == sr_uuid:
                on_target_sr = True
                break

        if not on_target_sr:
            continue

        # Only consider templates that look like they came from vm-import
        # (have import_task in other-config) to avoid touching built-in
        # XCP-ng templates or manually created ones
        import_task = _xe_other_config_get("template", uuid, "import_task")
        if not import_task:
            continue

        orphans_found += 1
        name_label = _xe_get("template", uuid, "name-label")

        # Safety: don't delete if it has children
        if _has_children(uuid):
            log.warning(
                "Orphaned template %s (%s) has children -- skipping",
                uuid, name_label,
            )
            continue

        log.info("Deleting orphaned template %s (%s)", uuid, name_label)
        try:
            _xe("vm-uninstall", "uuid=%s" % uuid, "force=true")
            orphans_deleted += 1
            state.setdefault("orphans_cleaned", []).append({
                "type": "template",
                "uuid": uuid,
                "name_label": name_label,
            })
        except Exception as e:
            log.warning("Failed to delete orphaned template %s: %s", uuid, e)

    log.info(
        "Orphaned template scan: %d found, %d deleted",
        orphans_found, orphans_deleted,
    )


def _cleanup_orphaned_vdis(sr_uuid, state):
    """
    Find and remove VDIs on sr_uuid that are not attached to any VBD.

    These are leftover disks from templates that were partially deleted
    (e.g. template record removed in XO but VDIs left behind).

    Only targets VDIs that are:
    - On the target SR
    - type=user (not system/metadata VDIs)
    - Not attached to any VBD
    - managed=true in XAPI (i.e. not an ISO or special VDI)
    """
    log.info("Scanning for orphaned VDIs on SR %s ...", sr_uuid)
    all_vdis = _xe_list("vdi", sr_uuid=sr_uuid)
    orphans_found = 0
    orphans_deleted = 0

    for vdi_uuid in all_vdis:
        # Only user VDIs (skip metadata, redo-log, etc.)
        vdi_type = _xe_get("vdi", vdi_uuid, "type")
        if vdi_type != "user":
            continue

        # Only managed VDIs (XAPI-managed, not raw/external)
        vdi_managed = _xe_get("vdi", vdi_uuid, "managed")
        if vdi_managed != "true":
            continue

        # Check if any VBD references this VDI
        vbd_uuids = _xe_list("vbd", vdi_uuid=vdi_uuid)
        if vbd_uuids:
            continue

        # This VDI is an orphan
        orphans_found += 1
        name_label = _xe_get("vdi", vdi_uuid, "name-label")
        log.info("Deleting orphaned VDI %s (%s)", vdi_uuid, name_label)

        try:
            _xe("vdi-destroy", "uuid=%s" % vdi_uuid)
            orphans_deleted += 1
            state.setdefault("orphans_cleaned", []).append({
                "type": "vdi",
                "uuid": vdi_uuid,
                "name_label": name_label,
            })
        except Exception as e:
            log.warning("Failed to delete orphaned VDI %s: %s", vdi_uuid, e)

    log.info(
        "Orphaned VDI scan: %d found, %d deleted",
        orphans_found, orphans_deleted,
    )

# ---------------------------------------------------------------------------
# Core sync logic
# ---------------------------------------------------------------------------

def _file_changed(xva_path, tpl):
    """
    Determine whether the XVA on the share differs from the managed template.
    Uses fast size+mtime comparison when available, falls back to SHA256.
    Returns (changed: bool, sha256: str, size: str, mtime: str)
    """
    current_size, current_mtime = _file_identity(xva_path)

    if tpl["size"] and tpl["mtime"]:
        if current_size == tpl["size"] and current_mtime == tpl["mtime"]:
            log.info("File %s unchanged (size+mtime match)", os.path.basename(xva_path))
            return False, tpl["sha256"], current_size, current_mtime
        else:
            log.info(
                "File %s changed: size %s->%s, mtime %s->%s",
                os.path.basename(xva_path),
                tpl["size"], current_size,
                tpl["mtime"], current_mtime,
            )
            sha256 = _sha256_for_xva(xva_path)
            return True, sha256, current_size, current_mtime

    log.info("No size/mtime metadata for %s -- falling back to SHA256", os.path.basename(xva_path))
    sha256 = _sha256_for_xva(xva_path)
    changed = sha256 != tpl["sha256"]
    return changed, sha256, current_size, current_mtime


def _compute_diff(mount_point, managed_templates):
    diff = {
        "to_import":  [],
        "to_delete":  [],
        "to_replace": [],
        "to_skip":    [],
        "warnings":   [],
    }

    try:
        xva_files = {
            f for f in os.listdir(mount_point)
            if f.lower().endswith(".xva") and os.path.isfile(os.path.join(mount_point, f))
        }
    except OSError as e:
        raise FatalError("Cannot list mount point %s: %s" % (mount_point, e))

    log.info("Found %d XVA(s) on share: %s", len(xva_files), sorted(xva_files))

    share_files = set(xva_files)
    managed_files = set(managed_templates.keys())

    # New files -> import
    for fname in sorted(share_files - managed_files):
        xva_path = os.path.join(mount_point, fname)
        log.info("New file %s -- computing identity ...", fname)
        size, mtime = _file_identity(xva_path)
        sha256 = _sha256_for_xva(xva_path)
        diff["to_import"].append({
            "source_file": fname,
            "xva_path": xva_path,
            "sha256": sha256,
            "size": size,
            "mtime": mtime,
        })

    # Existing files -> check for changes
    for fname in sorted(share_files & managed_files):
        tpl = managed_templates[fname]
        xva_path = os.path.join(mount_point, fname)
        changed, sha256, size, mtime = _file_changed(xva_path, tpl)

        if not changed:
            diff["to_skip"].append({
                "uuid": tpl["uuid"],
                "name_label": tpl["name_label"],
                "source_file": fname,
                "reason": "unchanged",
            })
        else:
            has_children = _has_children(tpl["uuid"])
            if has_children:
                msg = (
                    "Template %s (%s) has changed on share "
                    "but has local children -- keeping old version."
                    % (tpl["uuid"], fname)
                )
                log.warning(msg)
                diff["warnings"].append({
                    "uuid": tpl["uuid"],
                    "source_file": fname,
                    "reason": "changed_has_children",
                    "message": msg,
                })
                diff["to_skip"].append({
                    "uuid": tpl["uuid"],
                    "name_label": tpl["name_label"],
                    "source_file": fname,
                    "reason": "changed_has_children",
                })
            else:
                diff["to_replace"].append({
                    "uuid": tpl["uuid"],
                    "name_label": tpl["name_label"],
                    "source_file": fname,
                    "xva_path": xva_path,
                    "sha256": sha256,
                    "size": size,
                    "mtime": mtime,
                    "has_children": False,
                })

    # Removed from share -> delete
    for fname in sorted(managed_files - share_files):
        tpl = managed_templates[fname]
        has_children = _has_children(tpl["uuid"])
        if has_children:
            msg = (
                "Template %s (%s) was removed from share "
                "but has local children -- skipping deletion."
                % (tpl["uuid"], fname)
            )
            log.warning(msg)
            diff["warnings"].append({
                "uuid": tpl["uuid"],
                "source_file": fname,
                "reason": "removed_from_share_has_children",
                "message": msg,
            })
        else:
            diff["to_delete"].append({
                "uuid": tpl["uuid"],
                "name_label": tpl["name_label"],
                "source_file": fname,
            })

    return diff


def _execute_diff(diff, sr_uuid, network_uuid, state):
    """
    Execute the diff: import, replace, delete.
    Rolls back partially-created VMs on failure.
    """

    # --- DELETIONS ---
    for item in diff["to_delete"]:
        try:
            _delete_template(item["uuid"])
            state["deleted"].append({
                "uuid": item["uuid"],
                "name_label": item["name_label"],
                "source_file": item["source_file"],
            })
        except Exception as e:
            err = "Failed to delete %s (%s): %s" % (item["uuid"], item["source_file"], e)
            log.error(err)
            state["errors"].append({"source_file": item["source_file"], "message": err})

    # --- REPLACEMENTS ---
    for item in diff["to_replace"]:
        new_uuid = None
        try:
            log.info("Replacing template %s (%s)", item["uuid"], item["source_file"])
            _delete_template(item["uuid"])
            new_uuid = _import_xva(item["xva_path"], sr_uuid)
            _set_as_template(new_uuid)
            _rename_template_and_vdis(new_uuid, os.path.splitext(item["source_file"])[0])
            _tag_template(new_uuid, item["source_file"], item["sha256"],
                          item.get("size", ""), item.get("mtime", ""))
            vif_uuid = None
            if network_uuid:
                vif_uuid = _replace_vifs(new_uuid, network_uuid)
            entry = {
                "uuid": new_uuid,
                "replaced_uuid": item["uuid"],
                "name_label": item["name_label"],
                "source_file": item["source_file"],
            }
            if vif_uuid:
                entry["vif_uuid"] = vif_uuid
            state["imported"].append(entry)
        except Exception as e:
            err = "Failed to replace %s: %s" % (item["source_file"], e)
            log.error(err)
            state["errors"].append({"source_file": item["source_file"], "message": str(e)})
            if new_uuid:
                _rollback_vm(new_uuid, "failed replace of %s" % item["source_file"])

    # --- IMPORTS ---
    for item in diff["to_import"]:
        new_uuid = None
        try:
            new_uuid = _import_xva(item["xva_path"], sr_uuid)
            _set_as_template(new_uuid)
            _rename_template_and_vdis(new_uuid, os.path.splitext(item["source_file"])[0])
            _tag_template(new_uuid, item["source_file"], item["sha256"],
                          item.get("size", ""), item.get("mtime", ""))
            vif_uuid = None
            if network_uuid:
                vif_uuid = _replace_vifs(new_uuid, network_uuid)
            entry = {
                "uuid": new_uuid,
                "source_file": item["source_file"],
            }
            if vif_uuid:
                entry["vif_uuid"] = vif_uuid
            state["imported"].append(entry)
            log.info("Imported %s -> %s", item["source_file"], new_uuid)
        except Exception as e:
            err = "Failed to import %s: %s" % (item["source_file"], e)
            log.error(err)
            state["errors"].append({"source_file": item["source_file"], "message": str(e)})
            if new_uuid:
                _rollback_vm(new_uuid, "failed import of %s" % item["source_file"])

# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def _sync_worker(smb_host, smb_share, smb_user, smb_password,
                 smb_ver, sr_uuid, network_uuid, smb_subdir=None):
    _setup_logging()
    log.info("=== xva_sync worker started (PID %d) ===", os.getpid())

    state = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "imported": [],
        "deleted": [],
        "skipped": [],
        "warnings": [],
        "errors": [],
        "orphans_cleaned": [],
    }
    _write_state(state)

    mount_point = "%s_%d" % (MOUNT_BASE, os.getpid())

    try:
        # 1. Mount
        _mount_smb(smb_host, smb_share, smb_user, smb_password, smb_ver, mount_point)

        # 2. Gather managed templates
        log.info("Scanning managed templates on host ...")
        managed_templates = _get_managed_templates(sr_uuid=sr_uuid)
        log.info("Found %d managed template(s)", len(managed_templates))

        # 3. Compute diff
        log.info("Computing diff ...")
        scan_root = os.path.join(mount_point, smb_subdir.strip('/')) if smb_subdir else mount_point
        log.info("Scanning XVAs in: %s", scan_root)
        diff = _compute_diff(scan_root, managed_templates)

        log.info(
            "Diff: %d to import, %d to delete, %d to replace, %d warnings",
            len(diff["to_import"]), len(diff["to_delete"]),
            len(diff["to_replace"]), len(diff["warnings"]),
        )

        state["skipped"] = [
            {"uuid": s["uuid"], "source_file": s["source_file"], "reason": s["reason"]}
            for s in diff["to_skip"]
        ]
        state["warnings"] = diff["warnings"]
        _write_state(state)

        # 4. Execute sync
        _execute_diff(diff, sr_uuid, network_uuid, state)

        # 5. Cleanup orphans (always runs, even if sync had no work)
        _cleanup_orphaned_templates(sr_uuid, state)
        _cleanup_orphaned_vdis(sr_uuid, state)

    except FatalError as e:
        log.error("Fatal error: %s", e)
        state["errors"].append({"source_file": None, "message": str(e)})
    except Exception as e:
        log.error("Unexpected error: %s\n%s", e, traceback.format_exc())
        state["errors"].append({"source_file": None, "message": str(e)})
    finally:
        _unmount_smb(mount_point)
        _release_lock()
        state["status"] = "completed"
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _write_state(state)
        log.info(
            "=== xva_sync worker finished: %d imported, %d deleted, %d errors, %d orphans cleaned ===",
            len(state["imported"]), len(state["deleted"]),
            len(state["errors"]), len(state.get("orphans_cleaned", [])),
        )

# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------

def _do_dry_run(smb_host, smb_share, smb_user, smb_password, smb_ver, sr_uuid, smb_subdir=None):
    mount_point = "%s_dryrun_%d" % (MOUNT_BASE, os.getpid())
    result = {
        "dry_run": True,
        "sync_running": _is_locked(),
        "converged": False,
        "pending": {
            "imports": [],
            "deletions": [],
            "replacements": [],
            "warnings": [],
        },
        "last_run": _read_state(),
        "error": None,
    }

    try:
        _mount_smb(smb_host, smb_share, smb_user, smb_password, smb_ver, mount_point)
        managed_templates = _get_managed_templates(sr_uuid=sr_uuid)
        scan_root = os.path.join(mount_point, smb_subdir.strip('/')) if smb_subdir else mount_point
        log.info("Scanning XVAs in: %s", scan_root)
        diff = _compute_diff(scan_root, managed_templates)

        result["pending"]["imports"] = [
            {"source_file": i["source_file"], "sha256": i["sha256"]}
            for i in diff["to_import"]
        ]
        result["pending"]["deletions"] = [
            {"uuid": d["uuid"], "name_label": d["name_label"], "source_file": d["source_file"]}
            for d in diff["to_delete"]
        ]
        result["pending"]["replacements"] = [
            {
                "old_uuid": r["uuid"],
                "name_label": r["name_label"],
                "source_file": r["source_file"],
            }
            for r in diff["to_replace"]
        ]
        result["pending"]["warnings"] = diff["warnings"]

        last_errors = result["last_run"].get("errors", [])
        nothing_pending = (
            not diff["to_import"]
            and not diff["to_delete"]
            and not diff["to_replace"]
        )
        result["converged"] = nothing_pending and not last_errors

    except Exception as e:
        result["error"] = str(e)
        log.error("Dry-run error: %s\n%s", e, traceback.format_exc())
    finally:
        _unmount_smb(mount_point)

    return result

# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

def sync_templates(session, args):
    _setup_logging()

    def _req(key):
        val = args.get(key, "").strip()
        if not val:
            raise XenAPIPlugin.Failure("MISSING_ARG", ["Missing required argument: %s" % key])
        return val

    smb_host    = _req("smb_host")
    smb_share   = _req("smb_share")
    smb_user    = _req("smb_user")
    smb_password= _req("smb_password")
    sr_uuid     = _req("sr_uuid")
    network_uuid= args.get("network_uuid", "").strip() or None
    smb_ver     = args.get("smb_version", DEFAULT_SMB_VER).strip()
    smb_subdir  = args.get("smb_subdir", "").strip().strip("/") or None
    dry_run     = args.get("dry_run", "false").strip().lower() == "true"

    if dry_run:
        log.info("Dry-run requested.")
        result = _do_dry_run(smb_host, smb_share, smb_user, smb_password, smb_ver, sr_uuid, smb_subdir)
        return json.dumps(result, indent=2)

    if not _acquire_lock():
        log.info("Sync already running -- returning immediately.")
        return json.dumps({"status": "already_running"})

    try:
        pid = os.fork()
    except OSError as e:
        _release_lock()
        raise XenAPIPlugin.Failure("FORK_ERROR", [str(e)])

    if pid > 0:
        log.info("Forked sync worker PID %d -- returning to caller.", pid)
        return json.dumps({"status": "started", "worker_pid": pid})

    try:
        os.setsid()
        try:
            pid2 = os.fork()
            if pid2 > 0:
                os._exit(0)
        except OSError:
            pass

        _rewrite_lock_with_current_pid()

        # Redirect stdio -- this must happen BEFORE _setup_logging in worker
        # so the logging module sees the redirected stderr
        with open("/dev/null", "r") as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
        with open(LOG_FILE, "a") as logf:
            os.dup2(logf.fileno(), sys.stdout.fileno())
            os.dup2(logf.fileno(), sys.stderr.fileno())

        # Reset logging so worker gets a clean setup with redirected stderr
        global _logging_initialized
        _logging_initialized = False

        _sync_worker(
            smb_host, smb_share, smb_user, smb_password,
            smb_ver, sr_uuid, network_uuid, smb_subdir,
        )
    except Exception as e:
        try:
            log.error("Worker crash: %s\n%s", e, traceback.format_exc())
            _release_lock()
        except Exception:
            pass
    finally:
        os._exit(0)

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

DISPATCH = {
    "sync_templates": sync_templates,
}

if __name__ == "__main__":
    if XenAPIPlugin is None or not hasattr(XenAPIPlugin, "dispatch"):
        print("Run this as an XCP-ng XAPI plugin.", file=sys.stderr)
        sys.exit(1)
    XenAPIPlugin.dispatch(DISPATCH)
