import pytest


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
