#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
# Orchestrates F-Droid repo signing via a YubiHSM 2.
# Ensures the repo signing key is present on the HSM, then runs `fdroid update`.
#

import base64
import getpass
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Dependency check: report all missing packages in one go before doing
# anything else, so the user can fix everything with a single apt command.
# ---------------------------------------------------------------------------

# Maps import_name -> Debian package name
_THIRD_PARTY_DEPS: list[tuple[str, str]] = [
    ("yubihsm", "python3-yubihsm"),
    ("yaml", "python3-yaml"),
    ("cryptography", "python3-cryptography"),
]

_missing: list[str] = []
for _mod, _pkg in _THIRD_PARTY_DEPS:
    try:
        __import__(_mod)
    except ImportError:
        _missing.append(_pkg)

if _missing:
    pkgs = " ".join(_missing)
    print("ERROR: The following required Python libraries are not installed:", file=sys.stderr)
    for pkg in _missing:
        print(f"  - {pkg}", file=sys.stderr)
    print(f"\nInstall them with:\n  sudo apt install {pkgs}", file=sys.stderr)
    sys.exit(1)

# Safe to import now
import cryptography.x509
import yubihsm
import yubihsm.exceptions
from yubihsm import YubiHsm
from yubihsm.defs import CAPABILITY, OBJECT
from yubihsm.objects import Opaque, WrapKey
import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_FILE = SCRIPT_DIR / "config.yml"
PKCS11_CFG = SCRIPT_DIR / "pkcs11_yubihsm2.cfg"

WRAP_KEY_ID = 0x0010

AUDIT_SCRIPT_REL = Path("vendor/calyx/scripts/pkcs11/vendor.yubihsm.audit.logs.py")


def main() -> None:
    # 1. Pre-flight checks: establishes key_dir and log_dir from CALYX_OTA_TOOLS_DIR
    ota_tools_dir = check_ota_tools_dir()
    key_dir = ota_tools_dir / "keys"
    log_dir = ota_tools_dir / "logs"
    check_fdroid_installed()

    # 2. Read repo signing key alias from config.yml
    repo_key_id = read_repo_key_id()

    # 3. Configure environment (PKCS11 config path, credentials, keystore pass)
    configure_environment()

    # 4. Connect to HSM, ensure the signing key is present, then close the session
    print("\nConnecting to YubiHSM 2...")
    try:
        hsm, session = open_hsm_session()
    except yubihsm.exceptions.YubiHsmAuthenticationError:
        sys.exit(
            "ERROR: HSM authentication failed.\n"
            "Check that YUBIHSM_AUTHKEY and YUBIHSM_PASSWORD are correct."
        )
    except Exception as e:
        sys.exit(f"ERROR: Could not connect to HSM: {e}")

    try:
        hsm_name = get_hsm_name(hsm)
        ensure_key_on_hsm(session, repo_key_id, key_dir)
    finally:
        session.close()

    # 5. Run fdroid update
    print("\nRunning: fdroid update ...")
    subprocess.run(["fdroid", "update"], env=os.environ, check=True, text=True, cwd=SCRIPT_DIR)

    # 6. Save HSM audit log
    run_audit_log_script(ota_tools_dir, log_dir, hsm_name)

    # 7. Remove unneeded files from repo
    remove_repo_files()

    print("\nDone. F-Droid repo updated and signed successfully.")


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def check_ota_tools_dir() -> Path:
    """Verify CALYX_OTA_TOOLS_DIR is set and contains the expected subdirectories."""
    ota_tools_env = os.environ.get("CALYX_OTA_TOOLS_DIR", "").strip()
    if not ota_tools_env:
        sys.exit(
            "ERROR: $CALYX_OTA_TOOLS_DIR is not set.\n"
            "Set it to the root of your ota-tools checkout, e.g.:\n"
            "  export CALYX_OTA_TOOLS_DIR=/path/to/ota-tools"
        )

    ota_tools_dir = Path(ota_tools_env)
    if not ota_tools_dir.is_dir():
        sys.exit(f"ERROR: CALYX_OTA_TOOLS_DIR does not exist or is not a directory: {ota_tools_dir}")

    for subdir in ("keys", "logs"):
        if not (ota_tools_dir / subdir).is_dir():
            sys.exit(
                f"ERROR: Expected subdirectory not found: {ota_tools_dir / subdir}\n"
                "Ensure CALYX_OTA_TOOLS_DIR points to a valid ota-tools directory."
            )

    return ota_tools_dir


def check_fdroid_installed() -> None:
    if shutil.which("fdroid") is None:
        sys.exit(
            "ERROR: 'fdroid' executable not found in PATH.\n"
            "Install it with:  sudo apt install fdroidserver"
        )


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

def read_repo_key_id() -> int:
    """Return the value of repo_keyalias from config.yml."""
    config = yaml.safe_load(CONFIG_FILE.read_text())

    alias = config.get("repo_keyalias", "").strip()
    if not alias:
        sys.exit("ERROR: 'repo_keyalias' not set (or empty) in config.yml.")

    try:
        repo_key_id = int(alias, 16)
    except ValueError:
        sys.exit(
            f"ERROR: repo_keyalias '{alias}' is not a valid hex key ID.\n"
            "Expected a value like '0x1100'."
        )
    print(f"Using repo key ID from config.yml: {alias}")
    return repo_key_id


# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------

def configure_environment() -> None:
    """Set required env vars, prompting for credentials when absent."""
    os.environ["YUBIHSM_PKCS11_CONF"] = str(PKCS11_CFG)

    authkey = os.environ.get("YUBIHSM_AUTHKEY") or input("Enter YUBIHSM_AUTHKEY [default: 0x0001]: ") or "0x0001"
    try:
        authkey_id = int(authkey, 16)
    except ValueError:
        sys.exit(
            f"ERROR: YUBIHSM_AUTHKEY '{authkey}' is not a valid hex key ID.\n"
            "Expected a value like '0x0001'."
        )
    os.environ["YUBIHSM_AUTHKEY"] = authkey

    password = os.environ.get("YUBIHSM_PASSWORD", "").strip()

    if not password:
        password = getpass.getpass("Enter YUBIHSM_PASSWORD: ").strip()
        os.environ["YUBIHSM_PASSWORD"] = password

    # F-Droid expects the keystore password in the form <authkey><password>
    os.environ["FDROID_KEYSTOREPASS"] = f"{authkey_id:04x}{password}"


# ---------------------------------------------------------------------------
# HSM session
# ---------------------------------------------------------------------------

def open_hsm_session():
    """Connect to the HSM and return (hsm, session).
    """
    connector_url = os.environ.get("YUBIHSM_CONNECTOR", "http://127.0.0.1:12345")
    hsm = YubiHsm.connect(connector_url)
    session = hsm.create_session_derived(int(os.environ["YUBIHSM_AUTHKEY"], 16), os.environ["YUBIHSM_PASSWORD"])
    return hsm, session


def get_hsm_name(hsm) -> str:
    """Return a stable identifier for this HSM: '<part_number>-<serial>'."""
    info = hsm.get_device_info()
    return f"{info.part_number}-{info.serial}"


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def ensure_key_on_hsm(session, repo_key_id: int, key_dir: Path) -> None:
    """
    Verify that repo_key_id is present on the HSM.
    If not, locate its .yhw backup file in key_dir and import it, freeing a
    slot first if the HSM is full.
    """
    repo_key_alias = f"0x{repo_key_id:04x}"
    keys = session.list_objects(object_type=OBJECT.ASYMMETRIC_KEY)
    if key_exists_on_hsm(keys, repo_key_id):
        print(f"Signing key {repo_key_alias} is present on the HSM.")
        return

    print(f"Signing key {repo_key_alias} not found on HSM. Attempting import...")

    # Attempt the import; if the HSM is full, evict a key first and retry.
    while True:
        try:
            import_wrapped_key(session, key_dir, repo_key_alias)
            print(f"  Successfully imported signing key 0x{repo_key_id:04x}.")
            break
        except yubihsm.exceptions.YubiHsmDeviceError as e:
            if e.code == 0x07:  # STORAGE_FAILED
                print(f"  HSM returned error: {e} — attempting to free a slot...")
                keys = evict_key(session, keys)
            else:
                raise

    while True:
        try:
            import_attestation_cert(session, key_dir, repo_key_id)
            print(f"  Successfully imported key certificate 0x{repo_key_id:04x}.")
            break
        except yubihsm.exceptions.YubiHsmDeviceError as e:
            if e.code == 0x07:  # STORAGE_FAILED
                print(f"  HSM returned error: {e} — attempting to free a slot...")
                keys = evict_key(session, keys)
            else:
                raise


def key_exists_on_hsm(keys, key_id: int) -> bool:
    """Return True if an asymmetric key with the given ID is present on the HSM."""
    return any(k.id == key_id for k in keys)


def evict_key(session, keys) -> list:
    evict_id = pick_key_to_evict(keys)
    if evict_id is None:
        sys.exit("ERROR: HSM is full but no keys found to evict. Cannot continue.")
    print(
        "\n"
        f"  WARNING: About to delete key 0x{evict_id:04x} from the HSM to free required space.\n"
        "  Press Ctrl-C now to abort if this is not what you want."
    )
    input("  Press Enter to confirm deletion and continue...")

    session.get_object(evict_id, OBJECT.ASYMMETRIC_KEY).delete()
    session.get_object(evict_id, OBJECT.OPAQUE).delete()
    print(f"  Deleted key 0x{evict_id:04x} from HSM.")
    return [k for k in keys if k.id != evict_id]


def pick_key_to_evict(keys) -> int | None:
    """
    Choose a key to remove to free up a slot.

    Priority:
      1. Keys in the 0x2xxx or 0x3xxx range (utility / non-signing objects).
      2. Any other asymmetric key as a last resort.
    """
    if not keys:
        return None

    for key in keys:
        if key.id & 0xF000 in (0x2000, 0x3000):
            return key.id

    return keys[0].id  # last resort


def import_wrapped_key(session, key_dir, repo_key_alias) -> None:
    """Decode a base64-encoded .yhw file and import it into the HSM."""
    # Wrapped key files follow the naming convention: 0x1100-asymmetric-key.yhw
    filename = f"{repo_key_alias}-asymmetric-key.yhw"
    matches = list(key_dir.glob(filename))
    if not matches:
        sys.exit(
            f"ERROR: No wrapped key file found matching: {key_dir / filename}\n"
            "Ensure $CALYX_OTA_TOOLS_DIR/keys contains the correct backup file."
        )
    key_file = matches[0]
    print(f"  Found wrapped key file: {key_file}")

    wrapped_key_bytes = base64.b64decode(key_file.read_text())
    WrapKey(session, WRAP_KEY_ID).import_wrapped(wrapped_key_bytes)


def import_attestation_cert(session, key_dir, key_id: int) -> None:
    """Import a PEM attestation certificate as an Opaque object on the HSM."""
    # Locate attestation certificate, e.g. 0x1600.attestation.pem
    cert_file_name = f"0x{key_id:04x}.attestation.pem"
    cert_matches = list(key_dir.glob(cert_file_name))
    if not cert_matches:
        sys.exit(
            f"ERROR: No attestation certificate found matching: {key_dir / cert_file_name}\n"
            "Ensure $CALYX_OTA_TOOLS_DIR/keys contains the correct backup file."
        )
    cert_file = cert_matches[0]
    print(f"  Found attestation certificate: {cert_file}")

    pem = cryptography.x509.load_pem_x509_certificate(cert_file.read_bytes())
    try:
        Opaque.put_certificate(
            session=session,
            object_id=key_id,
            label="",
            domains=0b1100,  # 3 and 4
            capabilities=CAPABILITY.NONE,
            certificate=pem,
            compress=True,
        )
        print(f"  Successfully imported attestation certificate for 0x{key_id:04x}.")
    except yubihsm.exceptions.YubiHsmDeviceError as e:
        if e.code == 0x11:  # OBJECT_EXISTS
            print("  Attestation certificate already present, skipping.")
        else:
            raise


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def run_audit_log_script(ota_tools_dir: Path, log_dir: Path, hsm_name: str) -> None:
    """Invoke the Calyx audit log script, writing output to a timestamped file."""
    audit_script = ota_tools_dir / AUDIT_SCRIPT_REL
    if not audit_script.is_file():
        sys.exit(f"ERROR: Audit log script not found: {audit_script}")

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d_%H-%M-%S") + f"-{now.strftime('%f')[:3]}"
    log_file = log_dir / hsm_name / f"{date_str}-fdroid-repo.log"

    log_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"\nSaving HSM audit log to {log_file}")
    result = subprocess.run(
        [sys.executable, str(audit_script), "--log-file", str(log_file)],
        env=os.environ,
    )
    if result.returncode != 0:
        sys.exit(f"ERROR: Audit log script exited with code {result.returncode}.")


def remove_repo_files() -> None:
    """Remove unneeded files from the F-Droid repo after signing."""
    for filename in ("diff", "icons-120", "icons-160", "icons-240", "icons-320", "icons-480", "icons-640",
                     "index-v1.jar", "index-v1.json", "index.css", "index.html", "index.jar", "index.png",
                     "index.xml", "status"):
        file_path = SCRIPT_DIR / "repo" / filename
        if file_path.is_file():
            file_path.unlink()
        elif file_path.is_dir():
            shutil.rmtree(file_path)

    # remove old indexes to not create diffs which we don't need
    tmp_dir = SCRIPT_DIR / "tmp"
    for item in tmp_dir.iterdir():
        if item.name.startswith("repo_") and item.name.endswith(".json"):
            item.unlink()


if __name__ == "__main__":
    main()
