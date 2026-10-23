import pytest

@pytest.mark.asyncio
async def test_unauthenticated_upload_is_rejected(client):
    response = await client.post(
        "/api/v1/documents",
        files={"file": ("notes.txt", b"Private test document", "text/plain")},
        data={"title": "Unauthenticated upload", "category": "general"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_valid_text_upload_succeeds(client, user_a_headers):
    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={"file": ("notes.txt", b"TrustVault test document", "text/plain")},
        data={"title": "Test notes", "category": "general"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["title"] == "Test notes"
    assert body["original_filename"] == "notes.txt"
    assert body["file_size_bytes"] == len(b"TrustVault test document")


@pytest.mark.asyncio
async def test_empty_upload_is_rejected(client, user_a_headers):
    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={"file": ("empty.txt", b"", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Empty files are not allowed"


@pytest.mark.asyncio
async def test_oversized_upload_is_rejected(
    client, user_a_headers, monkeypatch
):
    from app.api.v1.endpoints import documents

    monkeypatch.setattr(documents.settings, "MAX_UPLOAD_SIZE_BYTES", 8)

    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={"file": ("large.txt", b"0123456789", "text/plain")},
    )

    assert response.status_code == 413


@pytest.mark.asyncio
async def test_disallowed_file_extension_is_rejected(client, user_a_headers):
    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={"file": ("malware.exe", b"not an executable", "application/octet-stream")},
    )

    assert response.status_code == 415
    assert response.json()["detail"] == "File extension is not allowed"


@pytest.mark.asyncio
async def test_path_components_are_removed_from_uploaded_filename(
    client, user_a_headers
):
    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={"file": ("../../private.txt", b"safe text", "text/plain")},
    )

    assert response.status_code == 201
    assert response.json()["original_filename"] == "private.txt"


@pytest.mark.asyncio
async def test_pdf_with_non_pdf_contents_is_rejected(
    client, user_a_headers
):
    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={
            "file": (
                "fake.pdf",
                b"This is not a PDF document",
                "application/pdf",
            )
        },
    )

    assert response.status_code == 415
    assert response.json()["detail"] == (
        "File contents do not match the allowed file type"
    )


import io
import zipfile

import pytest


def make_minimal_office_file(extension: str) -> bytes:
    """Build a minimal ZIP fixture with the required Office document parts."""
    output = io.BytesIO()

    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")

        if extension == "docx":
            archive.writestr("word/document.xml", "<document></document>")
        else:
            archive.writestr("xl/workbook.xml", "<workbook></workbook>")

    return output.getvalue()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("filename", "content", "content_type"),
    [
        ("image.png", b"\x89PNG\r\n\x1a\n" + b"test-image-data", "image/png"),
        ("image.jpg", b"\xff\xd8\xff" + b"test-image-data", "image/jpeg"),
        ("notes.txt", b"Valid UTF-8 text", "text/plain"),
        ("data.csv", b"name,score\nAlice,90\n", "text/csv"),
    ],
)
async def test_supported_signature_and_text_uploads_are_accepted(
    client, user_a_headers, filename, content, content_type
):
    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={"file": (filename, content, content_type)},
        data={"title": "Format validation test", "category": "general"},
    )

    assert response.status_code == 201, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("filename", "content", "content_type"),
    [
        ("image.png", b"not a PNG", "image/png"),
        ("image.jpg", b"not a JPEG", "image/jpeg"),
        ("notes.txt", b"\xff\xfe\xfa", "text/plain"),
        ("data.csv", b"name,score\n\xff\xfe", "text/csv"),
    ],
)
async def test_invalid_signature_or_text_encoding_is_rejected(
    client, user_a_headers, filename, content, content_type
):
    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={"file": (filename, content, content_type)},
        data={"title": "Invalid format test", "category": "general"},
    )

    assert response.status_code == 415, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("extension", ["docx", "xlsx"])
async def test_minimal_office_zip_structure_is_accepted(
    client, user_a_headers, extension
):
    content = make_minimal_office_file(extension)

    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={
            "file": (
                f"sample.{extension}",
                content,
                "application/octet-stream",
            )
        },
        data={"title": "Office format test", "category": "general"},
    )

    assert response.status_code == 201, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("extension", ["docx", "xlsx"])
async def test_invalid_office_zip_structure_is_rejected(
    client, user_a_headers, extension
):
    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={
            "file": (
                f"fake.{extension}",
                b"This is not a ZIP Office document",
                "application/octet-stream",
            )
        },
        data={"title": "Invalid Office format test", "category": "general"},
    )

    assert response.status_code == 415, response.text

@pytest.mark.asyncio
async def test_upload_database_failure_cleans_up_stored_file(
    client, user_a_headers, monkeypatch, tmp_path
):
    from app.api.v1.endpoints import documents
    from sqlalchemy.ext.asyncio import AsyncSession

    storage = documents.LocalStorageService(root=tmp_path)
    monkeypatch.setattr(
        documents,
        "LocalStorageService",
        lambda: storage,
    )

    async def fail_commit(self):
        raise RuntimeError("Simulated database commit failure")

    monkeypatch.setattr(AsyncSession, "commit", fail_commit)

    with pytest.raises(RuntimeError, match="Simulated database commit failure"):
        await client.post(
            "/api/v1/documents",
            headers=user_a_headers,
            files={
                "file": (
                    "cleanup.txt",
                    b"Test upload cleanup",
                    "text/plain",
                )
            },
            data={"title": "Cleanup test", "category": "general"},
        )

    remaining_files = [
        path for path in tmp_path.rglob("*") if path.is_file()
    ]
    assert remaining_files == [], (
        f"Upload files were not cleaned up: {remaining_files}"
    )

    
@pytest.mark.asyncio
async def test_upload_at_exact_size_limit_succeeds(
    client, user_a_headers, monkeypatch
):
    from app.api.v1.endpoints import documents

    content = b"12345678"
    monkeypatch.setattr(
        documents.settings,
        "MAX_UPLOAD_SIZE_BYTES",
        len(content),
    )

    response = await client.post(
        "/api/v1/documents",
        headers=user_a_headers,
        files={"file": ("exact-limit.txt", content, "text/plain")},
        data={"title": "Exact size limit test", "category": "general"},
    )

    assert response.status_code == 201, response.text
    assert response.json()["file_size_bytes"] == len(content)
