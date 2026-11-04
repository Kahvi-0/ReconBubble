"""SMB share browsing on top of the synchronous ``smbprotocol`` client.

Every operation opens a fresh ``Connection -> Session -> TreeConnect`` stack
and tears it down when done (a :class:`SmbFileHandle` keeps its stack alive
until ``close()`` is called).  All errors are normalised into
:class:`SmbBrowseError` with a stable ``code`` the frontend can key off of:

    unreachable  host unreachable / TCP connect failed / DNS failure / timeout
    auth         bad credentials (logon failure)
    no_share     share name does not exist on the server
    no_access    authenticated but not allowed to do the operation
    no_file      folder/file does not exist (or the path is the wrong type)
    bad_host     host input failed validation
    bad_share    share name failed validation
    bad_path     path segment failed validation
    bad_port     port input failed validation
    bad_domain   domain input failed validation
    no_creds     the selected user has no stored password or NTLM hash
    timeout      the operation did not complete within its wall-clock deadline
    smb_error    anything else the server reported

All functions are synchronous on purpose: ``smbprotocol`` is a blocking
library (plain sockets + one reader thread per connection) and FastAPI runs
plain ``def`` endpoints in its thread pool, so blocking here is correct.

``smbprotocol`` puts its socket into fully blocking mode after negotiation
and waits for responses with no per-operation timeout, so a target that goes
silent mid-operation would otherwise block the calling thread forever.  Every
operation therefore runs its blocking I/O in a bounded module-level thread
pool (:data:`SMB_EXECUTOR`) and the caller applies a wall-clock deadline
(:func:`_with_deadline`).  A worker abandoned by an expired deadline cannot
be cancelled (the blocking call is already running); TCP keepalives plus a
socket-level read timeout (set in :func:`_harden_socket`) kill its socket
within about a minute, the library's reader-thread teardown fires every
pending response event, which unblocks the worker in ``receive()``, and the
worker returns to the pool.
"""
from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import re
import socket
import struct
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterator, List, Optional, Tuple, Union

import spnego
from smbprotocol.connection import Connection
from smbprotocol.exceptions import (
    EndOfFile,
    NoMoreFiles,
    SMBAuthenticationError,
    SMBConnectionClosed,
    SMBException,
    SMBResponseException,
)
from smbprotocol.file_info import FileAttributes, FileInformationClass
from smbprotocol.header import NtStatus
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    QueryDirectoryFlags,
    ShareAccess,
)
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

SMB_PORT = 445
DEFAULT_TIMEOUT = 10.0
CHUNK_SIZE = 64 * 1024

#: Hard cap on concurrent in-flight SMB operations.  Workers abandoned by an
#: expired deadline are reaped by keepalives/socket timeout (see
#: :func:`_harden_socket`), so a run of silent targets can hold at most this
#: many slots before new requests start reporting ``timeout`` themselves.
SMB_MAX_WORKERS = 8
SMB_EXECUTOR = ThreadPoolExecutor(
    max_workers=SMB_MAX_WORKERS, thread_name_prefix="smb-browse"
)

_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$"
)


class SmbBrowseError(Exception):
    """Browse failure carrying a stable machine-readable ``code``."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_host(raw: str) -> str:
    host = (raw or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    if not host:
        raise SmbBrowseError("bad_host", "Host is required.")
    if host.endswith("."):
        host = host[:-1]
    if len(host) > 253:
        raise SmbBrowseError("bad_host", "Host name is too long.")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(host):
        raise SmbBrowseError("bad_host", f"Invalid host name: {raw!r}")
    return host.lower()


def validate_share(raw: str) -> str:
    share = (raw or "").strip()
    if not share:
        raise SmbBrowseError("bad_share", "Share name is required.")
    if len(share) > 100:
        raise SmbBrowseError("bad_share", "Share name is too long.")
    if "\\" in share or "/" in share or "\x00" in share:
        raise SmbBrowseError("bad_share", "Share name cannot contain path separators.")
    if share in (".", ".."):
        raise SmbBrowseError("bad_share", "Invalid share name.")
    return share


def _validate_segment(seg: str, what: str) -> str:
    seg = seg.strip()
    if not seg:
        raise SmbBrowseError("bad_path", f"Empty {what} name in path.")
    if len(seg) > 255:
        raise SmbBrowseError("bad_path", f"{what.capitalize()} name is too long.")
    if seg in (".", ".."):
        raise SmbBrowseError("bad_path", f"Invalid path component: {seg!r}")
    if "\\" in seg or "/" in seg or "\x00" in seg:
        raise SmbBrowseError("bad_path", f"Invalid characters in path component: {seg!r}")
    return seg


def validate_path(raw: str) -> List[str]:
    """Normalise a slash-separated relative path into validated segments."""
    raw = (raw or "").strip().strip("/")
    if not raw:
        return []
    return [_validate_segment(part, "folder") for part in raw.split("/")]


def validate_port(raw: Union[int, str]) -> int:
    """Validate a TCP port and return it as an ``int`` (1-65535)."""
    try:
        port = int(str(raw).strip())
    except (TypeError, ValueError):
        raise SmbBrowseError("bad_port", f"Invalid port: {raw!r}")
    if not 1 <= port <= 65535:
        raise SmbBrowseError("bad_port", "Port must be between 1 and 65535.")
    return port


def _apply_domain(username: str, domain: str) -> str:
    """Qualify a plain username with an optional domain as ``DOMAIN\\user``.

    Anonymous access (empty username) and already-qualified usernames
    (``DOMAIN\\user`` or ``user@domain``) are returned unchanged; an invalid
    domain raises :class:`SmbBrowseError` with code ``bad_domain``.
    """
    user = (username or "").strip()
    dom = (domain or "").strip()
    if not user or not dom:
        return user
    if "\\" in user or "@" in user:
        return user
    if "\\" in dom or "/" in dom or "\x00" in dom or len(dom) > 100:
        raise SmbBrowseError("bad_domain", f"Invalid domain: {domain!r}")
    return f"{dom}\\{user}"


# ---------------------------------------------------------------------------
# Connection plumbing
# ---------------------------------------------------------------------------


#: Null LM hash, paired with a bare NT hash so spnego sees ``<lm>:<nt>``.
_NTLM_NULL_LM = "AAD3B435B51404EEAAD3B435B51404EE"
_NTLM_PAIR_RE = re.compile(r"^([0-9a-fA-F]{32}):([0-9a-fA-F]{32})$")
_NTLM_BARE_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_NTLM_PREFIX_RE = re.compile(r"^\$NTLM\$")


def normalize_ntlm_hash(raw: str) -> str:
    """Normalise a stored NTLM hash to the ``<lm>:<nt>`` form spnego accepts.

    spnego (``spnego._ntlm_raw.crypto.is_ntlm_hash``) only recognises a
    32-hex LM hash, a colon, and a 32-hex NT hash.  The common variants are
    accepted and upper-cased; anything else yields ``""`` (unusable):

    * ``<lm>:<nt>`` pair in any case -> upper-cased pair;
    * bare 32-hex NT hash -> paired with the null LM hash;
    * an optional ``$NTLM$`` prefix is stripped.

    When the value spans several lines (e.g. pasted from a crack output)
    the first line that normalises is used.
    """
    for line in (raw or "").splitlines():
        s = _NTLM_PREFIX_RE.sub("", line.strip()).strip()
        if not s:
            continue
        m = _NTLM_PAIR_RE.match(s)
        if m:
            return f"{m.group(1).upper()}:{m.group(2).upper()}"
        if _NTLM_BARE_RE.match(s):
            return f"{_NTLM_NULL_LM}:{s.upper()}"
    return ""


def _session_credentials(
    username: str, password: str, ntlm_hash: str = ""
) -> Tuple[Union[str, list], Optional[str]]:
    """Return ``(username, password)`` args for :class:`~smbprotocol.session.Session`.

    Anonymous access needs an explicit empty :class:`spnego.Password`:
    pypyspnego turns a falsy username into a ``CredentialCache`` lookup,
    which fails on headless systems with no credential store.

    A named user authenticates with the stored password when one exists;
    otherwise a stored NTLM hash is normalised and used in the password
    slot (pass-the-hash — spnego recognises ``<lm>:<nt>`` hex and builds
    an NTLMv2 response directly from it).  A named user with neither a
    password nor a usable hash raises :class:`SmbBrowseError` with code
    ``no_creds`` before any network I/O happens.
    """
    user = (username or "").strip()
    pwd = password or ""
    if not user and not pwd:
        return [spnego.Password(username="", password="")], None
    if pwd:
        return user, pwd
    normalized = normalize_ntlm_hash(ntlm_hash)
    if not normalized:
        raise SmbBrowseError(
            "no_creds", "The selected user has no stored password or NTLM hash."
        )
    return user, normalized


def _safe_str(exc: Exception) -> str:
    try:
        return str(exc)
    except Exception:
        return exc.__class__.__name__


def _map_error(exc: Exception) -> SmbBrowseError:
    if isinstance(exc, SmbBrowseError):
        return exc
    if isinstance(exc, SMBResponseException):
        status = exc.status
        if status == NtStatus.STATUS_LOGON_FAILURE:
            return SmbBrowseError("auth", "Invalid username or password.")
        if status == NtStatus.STATUS_BAD_NETWORK_NAME:
            return SmbBrowseError("no_share", "The share was not found on the server.")
        if status == NtStatus.STATUS_ACCESS_DENIED:
            return SmbBrowseError("no_access", "Access denied. Check the credentials or share permissions.")
        if status in (
            NtStatus.STATUS_OBJECT_NAME_NOT_FOUND,
            NtStatus.STATUS_OBJECT_PATH_NOT_FOUND,
            NtStatus.STATUS_NO_SUCH_FILE,
        ):
            return SmbBrowseError("no_file", "The folder or file was not found.")
        if status == NtStatus.STATUS_INVALID_DEVICE_REQUEST:
            return SmbBrowseError("no_file", "That path is not a folder.")
        return SmbBrowseError("smb_error", _safe_str(exc) or "SMB server error.")
    if isinstance(exc, SMBAuthenticationError):
        return SmbBrowseError("auth", _safe_str(exc) or "Authentication failed.")
    if isinstance(exc, SMBConnectionClosed):
        return SmbBrowseError("unreachable", "The SMB connection was closed.")
    if isinstance(exc, SMBException):
        return SmbBrowseError("smb_error", _safe_str(exc) or exc.__class__.__name__)
    if isinstance(exc, (ValueError, OSError, ConnectionError)):
        # smbprotocol's Tcp transport wraps every connect failure (refused,
        # DNS, timeout) in a ValueError before it reaches us.
        return SmbBrowseError("unreachable", f"Connection failed: {_safe_str(exc)}")
    return SmbBrowseError("smb_error", f"Unexpected error: {_safe_str(exc)}")


def _safe_disconnect(conn: Connection) -> None:
    try:
        if conn.transport is not None:
            conn.disconnect()
    except Exception:
        pass


def _harden_socket(conn: Connection, timeout: float) -> None:
    """Bound every post-negotiation wait on ``conn``.

    The smbprotocol TCP transport switches the socket to fully blocking mode
    (``settimeout(None)``) once the connection is up, and every operation
    after negotiation (session setup, tree connect, open, query, read) waits
    for its response with no timeout of its own.  Two backstops:

    * a socket-level read timeout, in case ``select`` reports the socket
      ready and ``recv`` still blocks;
    * TCP keepalives (first probe after 30 s idle, then every 5 s, 3 probes)
      so a dead peer kills the socket within ~45 s.  When the library's
      reader thread then exits, its teardown fires every pending response
      event, which unblocks any (possibly abandoned) worker in ``receive()``.
    """
    sock = getattr(getattr(conn, "transport", None), "_sock", None)
    if sock is None:
        return
    try:
        sock.settimeout(max(float(timeout), 1.0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except OSError:
        pass


def _with_deadline(work: Callable[[], Any], timeout: float) -> Any:
    """Run blocking SMB work in the pool and bound it by wall-clock time.

    Raises the builtin :class:`TimeoutError` when the deadline expires; the
    worker is then abandoned and reaped as described in
    :func:`_harden_socket`.
    """
    return SMB_EXECUTOR.submit(work).result(timeout=timeout)


def _establish(host: str, username: str, password: str, timeout: float,
               port: int = SMB_PORT) -> Connection:
    """Connect (TCP + protocol negotiation) and return a live connection."""
    conn = Connection(uuid.uuid4(), host, port, require_signing=True)
    try:
        conn.connect(timeout=timeout)
    except Exception as exc:
        # The smbprotocol TCP transport wraps every connect failure
        # (refused, DNS, timeout) in a ValueError; map whatever it is.
        raise _map_error(exc) from exc
    _harden_socket(conn, timeout)
    return conn


@contextlib.contextmanager
def _smb_session(host: str, username: str, password: str, timeout: float,
                 port: int = SMB_PORT, ntlm_hash: str = "") -> Iterator[Session]:
    """Yield an authenticated session; the connection is always released."""
    user, pwd = _session_credentials(username, password, ntlm_hash)
    conn = _establish(host, username, password, timeout, port)
    try:
        try:
            session = Session(conn, user, pwd, require_encryption=True)
            session.connect()
        except Exception as exc:
            raise _map_error(exc) from exc
        yield session
    finally:
        _safe_disconnect(conn)


def _tree_connect(session: Session, host: str, share: str) -> TreeConnect:
    tree = TreeConnect(session, f"\\\\{host}\\{share}")
    try:
        tree.connect()
    except Exception as exc:
        raise _map_error(exc) from exc
    return tree


# ---------------------------------------------------------------------------
# Directory listing
# ---------------------------------------------------------------------------


@dataclass
class SmbEntry:
    name: str
    is_dir: bool
    size: int
    mtime: Optional[datetime]


def _query_all(dir_open: Open) -> list:
    """Run ``query_directory`` to completion, paging past 64 KiB responses.

    Some servers fill FILE_DIRECTORY_INFORMATION's FileIndex with 0 or
    ignore SMB2_INDEX_SPECIFIED entirely (observed on a live Windows
    target), so a resume query returns the same entries forever.  Stop as
    soon as a page fails to advance past the index we asked for -- the
    entries we already have are all the listing that server will give.
    """
    results: list = []
    next_index = 0
    flags = None
    while True:
        try:
            batch = dir_open.query_directory(
                "*",
                FileInformationClass.FILE_DIRECTORY_INFORMATION,
                flags=flags,
                file_index=next_index,
            )
        except NoMoreFiles:
            break
        if not batch:
            break
        last_index = int(batch[-1]["file_index"].get_value())
        if last_index < next_index:
            break
        results.extend(batch)
        next_index = last_index + 1
        flags = QueryDirectoryFlags.SMB2_RESTART_SCANS | QueryDirectoryFlags.SMB2_INDEX_SPECIFIED
    return results


def _list_folder_blocking(
    host: str, share: str, rel: str, username: str, password: str, timeout: float,
    port: int = SMB_PORT, ntlm_hash: str = "",
) -> list:
    """Blocking SMB I/O for :func:`list_share`; runs in the SMB pool."""
    with _smb_session(host, username, password, timeout, port, ntlm_hash) as session:
        tree = _tree_connect(session, host, share)
        try:
            dir_open = Open(tree, rel)
            # Explicit mask instead of GENERIC_READ: some Windows shares
            # reject the 0x80000000 generic bit on a directory open.
            # (For directories the read bit is FILE_LIST_DIRECTORY, 0x1.)
            dir_open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.FILE_LIST_DIRECTORY
                | DirectoryAccessMask.READ_CONTROL
                | DirectoryAccessMask.SYNCHRONIZE,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
        except Exception as exc:
            raise _map_error(exc) from exc
        try:
            return _query_all(dir_open)
        except Exception as exc:
            raise _map_error(exc) from exc
        finally:
            try:
                dir_open.close(False)
            except Exception:
                pass


def _parse_entries(raw: list) -> List[SmbEntry]:
    entries: List[SmbEntry] = []
    for info in raw:
        name = info["file_name"].get_value().decode("utf-16-le", errors="replace")
        if name in (".", ".."):
            continue
        attrs = info["file_attributes"].get_value()
        is_dir = bool(attrs & FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
        entries.append(
            SmbEntry(
                name=name,
                is_dir=is_dir,
                size=0 if is_dir else int(info["end_of_file"].get_value()),
                mtime=info["last_write_time"].get_value(),
            )
        )
    entries.sort(key=lambda e: (not e.is_dir, e.name.casefold()))
    return entries


def list_share(
    host: str,
    share: str,
    path: str,
    username: str,
    password: str,
    timeout: float = DEFAULT_TIMEOUT,
    domain: str = "",
    port: Union[int, str] = SMB_PORT,
    ntlm_hash: str = "",
) -> List[SmbEntry]:
    """List one folder. ``path`` is the slash-separated path below the share.

    ``domain`` optionally qualifies a plain username as ``DOMAIN\\user``;
    ``port`` selects the TCP port (default 445); ``ntlm_hash`` is used for
    pass-the-hash authentication when no password is given.  The whole
    operation is bounded by a wall-clock ``timeout``; expiry raises
    :class:`SmbBrowseError` with code ``timeout``.
    """
    host = validate_host(host)
    share = validate_share(share)
    segments = validate_path(path)
    port = validate_port(port)
    username = _apply_domain(username, domain)
    rel = "\\".join(segments)
    try:
        raw = _with_deadline(
            lambda: _list_folder_blocking(
                host, share, rel, username, password, timeout, port, ntlm_hash
            ),
            timeout,
        )
    except SmbBrowseError:
        raise
    except TimeoutError as exc:
        raise SmbBrowseError(
            "timeout",
            f"Timed out after {timeout:g}s. The target did not respond in time.",
        ) from exc
    return _parse_entries(raw)


# ---------------------------------------------------------------------------
# File download
# ---------------------------------------------------------------------------


@dataclass
class SmbFileHandle:
    """An open remote file. The caller owns it and must call :meth:`close`.

    The handle keeps the whole connection stack alive (connection, session,
    tree) until it is closed, so it outlives the context managers used to
    create it.
    """

    name: str
    _connection: Connection = field(repr=False)
    _open: Open = field(repr=False)
    _offset: int = field(default=0, repr=False)
    _closed: bool = field(default=False, repr=False)

    def iter_chunks(self) -> Iterator[bytes]:
        while True:
            try:
                chunk = self._open.read(self._offset, CHUNK_SIZE)
            except EndOfFile:
                break
            except Exception as exc:
                raise _map_error(exc) from exc
            if not chunk:
                break
            self._offset += len(chunk)
            yield chunk
            if len(chunk) < CHUNK_SIZE:
                break

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._open.close(False)
        except Exception:
            pass
        _safe_disconnect(self._connection)


def _open_file_blocking(
    host: str,
    share: str,
    rel: str,
    filename: str,
    username: str,
    password: str,
    timeout: float,
    port: int = SMB_PORT,
    ntlm_hash: str = "",
) -> SmbFileHandle:
    """Blocking SMB I/O for :func:`open_file_for_read`; runs in the SMB pool."""
    user, pwd = _session_credentials(username, password, ntlm_hash)
    conn = _establish(host, username, password, timeout, port)
    try:
        session = Session(conn, user, pwd, require_encryption=True)
        session.connect()
        tree = _tree_connect(session, host, share)
        file_open = Open(tree, rel)
        file_open.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.GENERIC_READ,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SEQUENTIAL_ONLY,
        )
    except Exception as exc:
        _safe_disconnect(conn)
        raise _map_error(exc) from exc
    return SmbFileHandle(name=filename, _connection=conn, _open=file_open)


def open_file_for_read(
    host: str,
    share: str,
    path: str,
    filename: str,
    username: str,
    password: str,
    timeout: float = DEFAULT_TIMEOUT,
    domain: str = "",
    port: Union[int, str] = SMB_PORT,
    ntlm_hash: str = "",
) -> SmbFileHandle:
    """Open a file for reading and return a handle that owns its connection.

    ``domain``, ``port`` and ``ntlm_hash`` work as in :func:`list_share`.
    The blocking
    connect/auth/open phase is bounded by a wall-clock ``timeout`` (expiry
    raises :class:`SmbBrowseError` with code ``timeout``).  Reads after the
    open are bounded by TCP keepalives (a dead peer kills the socket within
    ~45 s) rather than a per-read deadline.

    Any failure (validation, connect, auth, missing file) raises
    :class:`SmbBrowseError` and the connection is cleaned up, so the caller
    only receives a handle that is safe to stream from.
    """
    host = validate_host(host)
    share = validate_share(share)
    segments = validate_path(path)
    filename = _validate_segment(filename, "file")
    port = validate_port(port)
    username = _apply_domain(username, domain)
    rel = "\\".join(segments + [filename])
    try:
        return _with_deadline(
            lambda: _open_file_blocking(
                host, share, rel, filename, username, password, timeout, port,
                ntlm_hash,
            ),
            timeout,
        )
    except SmbBrowseError:
        raise
    except TimeoutError as exc:
        raise SmbBrowseError(
            "timeout",
            f"Timed out after {timeout:g}s. The target did not respond in time.",
        ) from exc


# ---------------------------------------------------------------------------
# File preview (content sniffing + optional local cache)
# ---------------------------------------------------------------------------

#: Files larger than this are still previewable but are not cached locally.
PREVIEW_MAX_BYTES = 10 * 1024 * 1024
#: Leading sample read to classify a file's content kind.
SNIFF_SIZE = 8 * 1024


def sniff_kind(sample: bytes, total_size: Optional[int] = None) -> str:
    """Classify a leading file sample as ``text``, ``image`` or ``binary``.

    Image detection is magic-byte based (PNG/JPEG/GIF/WEBP/BMP/ICO/SVG);
    everything else is ``text`` when the sample is NUL-free and mostly
    printable, and ``binary`` otherwise.  ``total_size`` (from the
    directory listing) is used to disambiguate BMPs, whose two-byte
    signature is easy to hit by accident.
    """
    if not sample:
        return "binary"
    if sample.startswith(
        (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")
    ):
        return "image"
    if sample[:4] == b"RIFF" and sample[8:12] == b"WEBP":
        return "image"
    if sample.startswith(b"\x00\x00\x01\x00"):
        return "image"  # ICO icon-directory header (reserved, type, count)
    if sample[:2] == b"BM" and len(sample) >= 14:
        # BMP: signature + little-endian file size + 2 reserved words +
        # offset of the pixel data.  With a known total size the header
        # field must match it exactly; otherwise the pixel offset must
        # look plausible (14..256 covers the standard header variants).
        try:
            declared = struct.unpack_from("<I", sample, 2)[0]
            offset = struct.unpack_from("<I", sample, 10)[0]
        except struct.error:
            declared, offset = 0, 0
        if total_size is not None:
            if declared == int(total_size):
                return "image"
        elif declared >= len(sample) and 14 <= offset <= 256:
            return "image"
    if b"<svg" in sample[:2048].lower():
        return "image"
    if b"\x00" in sample:
        return "binary"
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        text = sample.decode("latin-1")
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return "text" if printable / len(text) >= 0.9 else "binary"


class SmbPreview:
    """A file opened for preview, optionally backed by a local cache.

    ``kind`` is one of ``text``, ``image`` or ``binary`` (see
    :func:`sniff_kind`).  ``from_cache`` is true when the bytes come from
    the local cache folder instead of the share.  The caller must call
    :meth:`close`.  Consuming :meth:`iter_chunks` to the end promotes the
    temporary cache copy to its final name; an abandoned stream drops the
    temporary file.
    """

    def __init__(self) -> None:
        self.kind = "binary"
        self.from_cache = False
        self.size = None
        self._first: bytes = b""
        self._file = None     # cache hit: open file handle for the remainder
        self._rest = None     # live: remaining iterator of the SMB handle
        self._handle = None   # live: the SMB handle (closed in close())
        self._tmp_fh = None
        self._tmp_path = None
        self._bin_path = None
        self._hasher = None
        self._cached_bytes = 0
        self._closed = False

    def iter_chunks(self) -> Iterator[bytes]:
        def gen():
            finalized = False
            try:
                if self._first:
                    yield from self._emit(self._first)
                if self._file is not None:
                    while True:
                        chunk = self._file.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        yield from self._emit(chunk)
                else:
                    for chunk in self._rest:
                        yield from self._emit(chunk)
                finalized = self._finish_cache()
            finally:
                if not finalized:
                    self._abort_cache()

        return gen()

    def _emit(self, chunk: bytes):
        if self._tmp_fh is not None:
            try:
                self._tmp_fh.write(chunk)
                self._hasher.update(chunk)
                self._cached_bytes += len(chunk)
            except OSError:
                self._abort_cache()
        yield chunk

    def _start_cache(self, tmp_path: Path, bin_path: Path) -> None:
        try:
            fh = tmp_path.open("wb")
        except OSError:
            return
        self._tmp_fh = fh
        self._tmp_path = tmp_path
        self._bin_path = bin_path
        self._hasher = hashlib.sha256()

    def _finish_cache(self) -> bool:
        if self._tmp_fh is None:
            return False
        try:
            self._tmp_fh.close()
        except OSError:
            self._tmp_fh = None
            self._abort_cache()
            return False
        self._tmp_fh = None
        tmp_path, bin_path = self._tmp_path, self._bin_path
        meta_tmp = None
        try:
            tmp_path.replace(bin_path)
            meta = {
                "size": self._cached_bytes,
                "sha256": self._hasher.hexdigest(),
                "saved_at": datetime.now().isoformat(),
            }
            meta_tmp = bin_path.with_name(
                bin_path.stem + ".json.tmp" + uuid.uuid4().hex[:8]
            )
            meta_tmp.write_text(json.dumps(meta), "utf-8")
            meta_tmp.replace(bin_path.with_name(bin_path.stem + ".json"))
            _evict_cache(tmp_path.parent)
        except OSError:
            for p in (tmp_path, meta_tmp):
                if p is not None:
                    try:
                        p.unlink()
                    except OSError:
                        pass
        self._tmp_path = None
        self._bin_path = None
        self._hasher = None
        return True

    def _abort_cache(self) -> None:
        if self._tmp_fh is not None:
            try:
                self._tmp_fh.close()
            except OSError:
                pass
            self._tmp_fh = None
        if self._tmp_path is not None:
            try:
                self._tmp_path.unlink()
            except OSError:
                pass
            self._tmp_path = None
        self._bin_path = None
        self._hasher = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._abort_cache()
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None
        self._rest = None
        if self._handle is not None:
            self._handle.close()
            self._handle = None


def _cache_key(host: str, share: str, path: str, filename: str) -> str:
    return hashlib.sha256(
        f"{host}\0{share}\0{path}\0{filename}".encode("utf-8")
    ).hexdigest()


def _evict_cache(
    cache_dir,
    max_bytes: int = 256 * 1024 * 1024,
    target: int = 128 * 1024 * 1024,
) -> None:
    """Drop the oldest cache entries once the folder outgrows ``max_bytes``."""
    try:
        entries = []
        for p in Path(cache_dir).glob("*.bin"):
            try:
                st = p.stat()
            except OSError:
                continue
            entries.append((st.st_mtime, st.st_size, p))
        total = sum(size for _, size, _ in entries)
        if total <= max_bytes:
            return
        for _mtime, size, p in sorted(entries):
            if total <= target:
                break
            try:
                p.unlink()
                (p.parent / (p.stem + ".json")).unlink(missing_ok=True)
                total -= size
            except OSError:
                pass
    except OSError:
        pass


def _cache_hit(
    cache_dir,
    host: str,
    share: str,
    path: str,
    filename: str,
    expected_size: int,
) -> Optional[SmbPreview]:
    """Return a preview served from the cache, or None on any mismatch.

    Freshness is judged by size: SMB directory listings carry no hash, so a
    file whose listed size equals the cached size is assumed unchanged.
    """
    key = _cache_key(host, share, path, filename)
    bin_path = Path(cache_dir) / (key + ".bin")
    meta_path = Path(cache_dir) / (key + ".json")
    fh = None
    try:
        meta = json.loads(meta_path.read_text("utf-8"))
        if int(meta.get("size", -1)) != int(expected_size):
            return None
        fh = bin_path.open("rb")
        sample = fh.read(SNIFF_SIZE)
    except (OSError, ValueError, TypeError):
        if fh is not None:
            fh.close()
        return None
    preview = SmbPreview()
    preview.kind = sniff_kind(sample, expected_size)
    preview.from_cache = True
    preview.size = int(expected_size)
    preview._first = sample
    preview._file = fh
    return preview


def preview_file(
    host: str,
    share: str,
    path: str,
    filename: str,
    username: str,
    password: str,
    timeout: float = DEFAULT_TIMEOUT,
    domain: str = "",
    port: Union[int, str] = SMB_PORT,
    expected_size: Optional[int] = None,
    cache_dir=None,
    ntlm_hash: str = "",
) -> SmbPreview:
    """Open a remote file for preview and classify its content.

    Unlike :func:`open_file_for_read` the first read happens here, because
    the content kind must be known before any bytes are streamed to the
    caller.  When ``cache_dir`` is given and ``expected_size`` (as reported
    by the directory listing) fits in :data:`PREVIEW_MAX_BYTES`, an
    existing cache copy whose stored size matches is served without
    touching the network, and a new cache copy is written on a miss — so
    re-previewing an unchanged file does not re-download it.
    """
    host = validate_host(host)
    share = validate_share(share)
    validate_path(path)
    filename = _validate_segment(filename, "file")
    port = validate_port(port)

    if (
        cache_dir is not None
        and expected_size is not None
        and 0 < expected_size <= PREVIEW_MAX_BYTES
    ):
        hit = _cache_hit(cache_dir, host, share, path, filename, expected_size)
        if hit is not None:
            return hit

    handle = open_file_for_read(
        host,
        share,
        path,
        filename,
        username,
        password,
        timeout,
        domain=domain,
        port=port,
        ntlm_hash=ntlm_hash,
    )
    preview = SmbPreview()
    preview._handle = handle
    it = handle.iter_chunks()
    try:
        preview._first = next(it, b"")
    except SmbBrowseError:
        handle.close()
        raise
    preview._rest = it
    preview.kind = sniff_kind(preview._first, expected_size)
    preview.size = expected_size
    if (
        cache_dir is not None
        and expected_size is not None
        and expected_size <= PREVIEW_MAX_BYTES
    ):
        key = _cache_key(host, share, path, filename)
        cache_dir = Path(cache_dir)
        preview._start_cache(
            cache_dir / (key + ".tmp" + uuid.uuid4().hex[:8]),
            cache_dir / (key + ".bin"),
        )
    return preview
