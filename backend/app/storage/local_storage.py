
import uuid
from pathlib import Path

from app.core.config import settings


def get_vault_root() -> Path:
    """Return the configured private storage directory."""
    configured_path = (
        settings.TEST_STORAGE_VAULT_PATH
        if settings.APP_ENV == "testing"
        else settings.STORAGE_VAULT_PATH
    )

    path = Path(configured_path)

    if not path.is_absolute():
        project_root = Path(__file__).resolve().parents[3]
        path = project_root / path

    return path.resolve()


class LocalStorageService:
    """Store files privately under random UUID-based keys."""

    def __init__(self, root: Path | None = None):
        self.root = (root if root is not None else get_vault_root()).resolve()
        self.root.mkdir(parents=True, exist_ok=True)


    def _get_path(self, storage_key: str) -> Path:
        """Validate UUID keys and prevent paths from escaping the vault."""
        try:
            safe_key = str(uuid.UUID(storage_key))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("Invalid storage key") from exc

        candidate = self.root / safe_key[:2] / safe_key
        resolved_path = candidate.resolve()

        try:
            resolved_path.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Storage path escapes the vault") from exc

        return resolved_path


    def create_file(self) -> tuple[str, Path]:
        """Create an empty file with a random, exclusive storage key."""
        for _ in range(5):
            storage_key = str(uuid.uuid4())
            path = self._get_path(storage_key)
            path.parent.mkdir(parents=True, exist_ok=True)

            try:
                with path.open("xb"):
                    pass
                return storage_key, path
            except FileExistsError:
                continue

        raise OSError("Could not allocate a unique storage key")

    def save_file(self, content: bytes) -> str:
        """Save bytes under a random key without overwriting files."""
        storage_key, path = self.create_file()

        try:
            with path.open("wb") as file:
                file.write(content)
        except Exception:
            path.unlink(missing_ok=True)
            raise

        return storage_key

    def read_file(self, storage_key: str) -> bytes:
        """Read a stored file using its generated key."""
        return self._get_path(storage_key).read_bytes()

    def delete_file(self, storage_key: str) -> None:
        """Delete a stored file using its generated key."""
        self._get_path(storage_key).unlink(missing_ok=True)
