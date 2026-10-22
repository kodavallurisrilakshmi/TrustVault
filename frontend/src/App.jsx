
import { useEffect, useState } from "react";
import {
  getAccessToken,
  login,
  logout,
  register,
} from "./services/auth.js";
import { API_BASE_URL, api } from "./services/api.js";
import "./index.css";

export default function App() {
  const [mode, setMode] = useState("login");
  const [user, setUser] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [file, setFile] = useState(null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("general");

  const [shareUsers, setShareUsers] = useState({});
  const [shareLevels, setShareLevels] = useState({});
  const [revokeUsers, setRevokeUsers] = useState({});

  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [noticeType, setNoticeType] = useState("success");

  function showMessage(message, type = "success") {
    setNotice(message);
    setNoticeType(type);
  }

  async function loadDocuments() {
    const result = await api.get("/api/v1/documents", {
      headers: { Authorization: `Bearer ${getAccessToken()}` },
    });
    setDocuments(result);
  }

  useEffect(() => {
    if (user) {
      loadDocuments().catch((error) => {
        showMessage(error.message, "error");
      });
    }
  }, [user]);

  async function handleAuth(event) {
    event.preventDefault();
    setBusy(true);
    setNotice("");

    try {
      if (mode === "register") {
        await register({
          email: email.trim(),
          full_name: fullName.trim(),
          password,
        });

        showMessage("Account created. Please log in.");
        setMode("login");
        setPassword("");
      } else {
        const currentUser = await login({
          email: email.trim(),
          password,
        });

        setUser(currentUser);
        setPassword("");
        showMessage(`Welcome, ${currentUser.full_name}!`);
      }
    } catch (error) {
      showMessage(error.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    setBusy(true);

    try {
      await logout();
      setUser(null);
      setDocuments([]);
      setFile(null);
      setTitle("");
      setDescription("");
      setCategory("general");
      setShareUsers({});
      setShareLevels({});
      setRevokeUsers({});
      showMessage("You have logged out.");
    } catch (error) {
      showMessage(error.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleUpload(event) {
    event.preventDefault();

    if (!file) {
      showMessage("Please choose a file to upload.", "error");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    if (title.trim()) formData.append("title", title.trim());
    if (description.trim()) {
      formData.append("description", description.trim());
    }
    formData.append("category", category.trim() || "general");

    setBusy(true);
    setNotice("");

    try {
      await api.post("/api/v1/documents", formData, {
        headers: { Authorization: `Bearer ${getAccessToken()}` },
      });

      setFile(null);
      setTitle("");
      setDescription("");
      setCategory("general");

      const fileInput = document.getElementById("document-file");
      if (fileInput) fileInput.value = "";

      await loadDocuments();
      showMessage("Document uploaded successfully.");
    } catch (error) {
      showMessage(error.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleDownload(document) {
    setBusy(true);
    setNotice("");

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/documents/${document.id}/download`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${getAccessToken()}`,
          },
          credentials: "omit",
        }
      );

      if (!response.ok) {
        let message = "Download failed.";
        try {
          const data = await response.json();
          message = data.detail || message;
        } catch {
          // Keep the fallback message for non-JSON errors.
        }
        throw new Error(message);
      }

      const blob = await response.blob();
      const downloadUrl = URL.createObjectURL(blob);
      const link = documentCreateLink(downloadUrl, document.original_filename);

      link.click();
      link.remove();
      URL.revokeObjectURL(downloadUrl);

      showMessage("Download started.");
    } catch (error) {
      showMessage(error.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleShare(event, documentId) {
    event.preventDefault();

    const recipientId = (shareUsers[documentId] || "").trim();
    const permissionLevel = shareLevels[documentId] || "view";

    if (!recipientId) {
      showMessage("Enter the recipient's user ID.", "error");
      return;
    }

    setBusy(true);
    setNotice("");

    try {
      await api.post(
        `/api/v1/documents/${documentId}/permissions`,
        {
          user_id: recipientId,
          permission_level: permissionLevel,
        },
        {
          headers: { Authorization: `Bearer ${getAccessToken()}` },
        }
      );

      setShareUsers((previous) => ({
        ...previous,
        [documentId]: "",
      }));

      showMessage(`Document shared with ${permissionLevel} access.`);
    } catch (error) {
      showMessage(error.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke(event, documentId) {
    event.preventDefault();

    const recipientId = (revokeUsers[documentId] || "").trim();

    if (!recipientId) {
      showMessage("Enter the user ID whose access you want to revoke.", "error");
      return;
    }

    if (!window.confirm("Revoke this user's access to the document?")) {
      return;
    }

    setBusy(true);
    setNotice("");

    try {
      await api.delete(
        `/api/v1/documents/${documentId}/permissions/${recipientId}`,
        {
          headers: { Authorization: `Bearer ${getAccessToken()}` },
        }
      );

      setRevokeUsers((previous) => ({
        ...previous,
        [documentId]: "",
      }));

      await loadDocuments();
      showMessage("Access revoked successfully.");
    } catch (error) {
      showMessage(error.message, "error");
    } finally {
      setBusy(false);
    }
  }

  if (!user) {
    return (
      <main className="page-shell">
        <section className="panel">
          <div className="brand-mark">TV</div>
          <p className="eyebrow">SECURE DOCUMENT VAULT</p>
          <h1>TrustVault</h1>
          <p className="subtitle">
            Secure document sharing with a real audit trail.
          </p>

          {notice && (
            <div className={`notice ${noticeType}`} role="status">
              {notice}
            </div>
          )}

          <div className="mode-switch">
            <button
              type="button"
              className={`mode ${mode === "login" ? "active" : ""}`}
              onClick={() => {
                setMode("login");
                setNotice("");
              }}
            >
              Log in
            </button>
            <button
              type="button"
              className={`mode ${mode === "register" ? "active" : ""}`}
              onClick={() => {
                setMode("register");
                setNotice("");
              }}
            >
              Create account
            </button>
          </div>

          <form onSubmit={handleAuth}>
            {mode === "register" && (
              <label>
                Full name
                <input
                  type="text"
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                  placeholder="Your full name"
                  autoComplete="name"
                  maxLength={255}
                  required
                />
              </label>
            )}

            <label>
              Email address
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                autoComplete="email"
                required
              />
            </label>

            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                autoComplete={
                  mode === "login" ? "current-password" : "new-password"
                }
                required
              />
            </label>

            <button className="primary-button" type="submit" disabled={busy}>
              {busy
                ? "Please wait..."
                : mode === "login"
                  ? "Log in securely"
                  : "Create account"}
            </button>
          </form>

          <p className="security-note">
            Your session tokens are kept in memory, not browser storage.
          </p>
        </section>
      </main>
    );
  }

  return (
    <main className="page-shell dashboard-shell">
      <section className="panel dashboard">
        <header className="dashboard-header">
          <div>
            <div className="brand-mark">TV</div>
            <p className="eyebrow">YOUR SECURE WORKSPACE</p>
            <h1>TrustVault</h1>
            <p className="subtitle">
              Welcome back, {user.full_name}.
            </p>
          </div>
          <button
            className="secondary-button"
            type="button"
            onClick={handleLogout}
            disabled={busy}
          >
            Log out
          </button>
        </header>

        {notice && (
          <div className={`notice ${noticeType}`} role="status">
            {notice}
          </div>
        )}

        <section className="user-details">
          <p>
            Account <span>{user.full_name}</span>
          </p>
          <p>
            Email <span>{user.email}</span>
          </p>
          <p>
            Role <span>{user.role}</span>
          </p>
        </section>

        <section className="feature-section">
          <h2>Upload a document</h2>
          <p className="section-description">
            Files are stored privately and protected by server-side access
            checks.
          </p>

          <form onSubmit={handleUpload}>
            <label>
              Choose file
              <input
                id="document-file"
                type="file"
                onChange={(event) =>
                  setFile(event.target.files?.[0] || null)
                }
                required
              />
            </label>

            <label>
              Document title (optional)
              <input
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                placeholder="e.g. Project report"
                maxLength={255}
              />
            </label>

            <label>
              Description (optional)
              <textarea
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="What is this document about?"
                maxLength={10000}
                rows={3}
              />
            </label>

            <label>
              Category
              <input
                value={category}
                onChange={(event) => setCategory(event.target.value)}
                placeholder="general"
                maxLength={64}
                required
              />
            </label>

            <button className="primary-button" type="submit" disabled={busy}>
              {busy ? "Please wait..." : "Upload document"}
            </button>
          </form>
        </section>

        <section className="feature-section">
          <div className="section-heading-row">
            <div>
              <h2>Your documents</h2>
              <p className="section-description">
                Documents you own or that have been shared with you.
              </p>
            </div>
            <button
              className="secondary-button"
              type="button"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await loadDocuments();
                  showMessage("Document list refreshed.");
                } catch (error) {
                  showMessage(error.message, "error");
                } finally {
                  setBusy(false);
                }
              }}
            >
              Refresh
            </button>
          </div>

          {documents.length === 0 ? (
            <p className="empty-state">
              No documents available yet. Upload one to get started.
            </p>
          ) : (
            <div className="document-list">
              {documents.map((document) => {
                const isOwner = document.owner_id === user.id;

                return (
                  <article className="document-card" key={document.id}>
                    <div className="document-card-header">
                      <div className="document-icon">DOC</div>
                      <div className="document-title-block">
                        <h3>{document.title}</h3>
                        <p>{document.original_filename}</p>
                      </div>
                    </div>

                    {document.description && (
                      <p className="document-description">
                        {document.description}
                      </p>
                    )}

                    <div className="document-metadata">
                      <span>{document.category}</span>
                      <span>{formatFileSize(document.file_size_bytes)}</span>
                    </div>

                    <p className="document-hash">
                      SHA-256: {document.content_sha256}
                    </p>

                    <button
                      className="primary-button"
                      type="button"
                      disabled={busy}
                      onClick={() => handleDownload(document)}
                    >
                      Download
                    </button>

                    {isOwner && (
                      <div className="sharing-tools">
                        <h3>Share document</h3>
                        <form onSubmit={(event) => handleShare(event, document.id)}>
                          <label>
                            Recipient user ID
                            <input
                              value={shareUsers[document.id] || ""}
                              onChange={(event) =>
                                setShareUsers((previous) => ({
                                  ...previous,
                                  [document.id]: event.target.value,
                                }))
                              }
                              placeholder="Recipient UUID"
                              required
                            />
                          </label>

                          <label>
                            Access level
                            <select
                              value={shareLevels[document.id] || "view"}
                              onChange={(event) =>
                                setShareLevels((previous) => ({
                                  ...previous,
                                  [document.id]: event.target.value,
                                }))
                              }
                            >
                              <option value="view">View</option>
                              <option value="edit">Edit</option>
                            </select>
                          </label>

                          <button
                            className="secondary-button"
                            type="submit"
                            disabled={busy}
                          >
                            Grant access
                          </button>
                        </form>

                        <h3>Revoke access</h3>
                        <form
                          onSubmit={(event) =>
                            handleRevoke(event, document.id)
                          }
                        >
                          <label>
                            User ID to revoke
                            <input
                              value={revokeUsers[document.id] || ""}
                              onChange={(event) =>
                                setRevokeUsers((previous) => ({
                                  ...previous,
                                  [document.id]: event.target.value,
                                }))
                              }
                              placeholder="Recipient UUID"
                              required
                            />
                          </label>

                          <button
                            className="danger-button"
                            type="submit"
                            disabled={busy}
                          >
                            Revoke access
                          </button>
                        </form>
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          )}
        </section>

        <p className="security-note">
          TrustVault checks document permissions on the server for every
          download. Hiding controls in this interface is not a security
          boundary.
        </p>
      </section>
    </main>
  );
}

function formatFileSize(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown size";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function documentCreateLink(url, filename) {
  const link = window.document.createElement("a");
  link.href = url;
  link.download = filename || "document";
  link.style.display = "none";
  window.document.body.appendChild(link);
  return link;
}
