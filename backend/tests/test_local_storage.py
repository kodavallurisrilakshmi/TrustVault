
from app.storage.local_storage import LocalStorageService


def test_save_read_and_delete_file(tmp_path):
    storage = LocalStorageService(root=tmp_path)
    content = b"TrustVault private document test"

    # Save the document
    storage_key = storage.save_file(content)

    # The storage key should not reveal the original filename
    assert storage_key
    assert "/" not in storage_key
    assert "\\" not in storage_key

    # Read the saved document
    assert storage.read_file(storage_key) == content

    # Delete the document
    storage.delete_file(storage_key)

    # Confirm the document no longer exists
    try:
        storage.read_file(storage_key)
        assert False, "Deleted file should not exist"
    except FileNotFoundError:
        pass


def test_invalid_storage_key_is_rejected(tmp_path):
    storage = LocalStorageService(root=tmp_path)

    try:
        storage.read_file("../../secret.txt")
        assert False, "Invalid storage key should be rejected"
    except ValueError:
        pass


import os
import uuid

import pytest


def test_storage_rejects_symlink_escape(tmp_path):
    vault = tmp_path / "vault"
    outside = tmp_path / "outside"
    vault.mkdir()
    outside.mkdir()

    storage = LocalStorageService(root=vault)

    # Create a valid UUID storage key and its expected vault folder.
    storage_key = str(uuid.uuid4())
    shard = vault / storage_key[:2]
    shard.mkdir()

    # Make the shard a symlink to a folder outside the vault.
    shard.rmdir()
    try:
        os.symlink(outside, shard, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation is unavailable: {exc}")

    # The storage service must reject the resolved path.
    with pytest.raises(ValueError, match="escapes the vault"):
        storage.read_file(storage_key)

def test_storage_rejects_resolved_path_outside_vault(tmp_path, monkeypatch):
    vault = tmp_path / "vault"
    vault.mkdir()

    storage = LocalStorageService(root=vault)
    storage_key = str(uuid.uuid4())
    outside_file = tmp_path / "outside.txt"

    original_resolve = type(vault).resolve

    def fake_resolve(path, *args, **kwargs):
        if path == vault / storage_key[:2] / storage_key:
            return outside_file
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(type(vault), "resolve", fake_resolve)

    with pytest.raises(ValueError, match="escapes the vault"):
        storage.read_file(storage_key)