#!/usr/bin/env python3
"""
Lightweight JSONL viewer for very large files (1GB–30GB).
Uses a sparse index + mmap to avoid loading the file into RAM.
Supports .jsonl and .jsonl.zst (via zstdcat; requires zstd on PATH).
Standard library only; single-file with embedded HTML/JS.
"""

import argparse
import json
import mmap
import os
import struct
import subprocess
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

CHUNK_SIZE = 1000  # index every N lines
IDX_MAGIC = b"JVL\x01"  # JSONL Viewer Index v1 (plain)
IDX_MAGIC_ZST = b"JVL\x02"  # JSONL Viewer Index v2 (zstd: line count only)
STRUCT_Q = "Q"  # unsigned long long
SIZE_Q = 8
MAX_LINES_PER_REQUEST = 200
ZSTDCAT_CMD = ["zstdcat"]  # or "zstd -d -c" on some systems


# ---------------------------------------------------------------------------
# Index: build or load sparse offsets
# ---------------------------------------------------------------------------

def _is_zst_path(path):
    return path.endswith(".zst")


class IndexManager:
    """Build or load a sparse index of byte offsets (every CHUNK_SIZE lines).
    For .zst files, index stores only total_lines (no byte offsets); reading uses zstdcat.
    """

    def __init__(self, jsonl_path):
        self.jsonl_path = os.path.abspath(jsonl_path)
        self.idx_path = self.jsonl_path + ".idx"
        self.total_lines = 0
        self.offsets = []  # offset of line 0, CHUNK_SIZE, 2*CHUNK_SIZE, ...
        self.is_zst = _is_zst_path(self.jsonl_path)

    def exists(self):
        return os.path.isfile(self.idx_path)

    def load(self):
        """Load total_lines and offsets from .idx file. Returns True on success."""
        try:
            with open(self.idx_path, "rb") as f:
                magic = f.read(4)
                if magic == IDX_MAGIC_ZST:
                    self.is_zst = True
                elif magic == IDX_MAGIC:
                    self.is_zst = False
                else:
                    return False
                self.total_lines = struct.unpack(STRUCT_Q, f.read(SIZE_Q))[0]
                self.offsets = []
                while True:
                    b = f.read(SIZE_Q)
                    if len(b) < SIZE_Q:
                        break
                    self.offsets.append(struct.unpack(STRUCT_Q, b)[0])
            return True
        except (OSError, struct.error):
            return False

    def build(self, progress_callback=None):
        """Scan JSONL (or zstd stream) once and write .idx. progress_callback(line_count) optional."""
        self.total_lines = 0
        self.offsets = []
        if self.is_zst:
            return self._build_zst(progress_callback)
        try:
            with open(self.jsonl_path, "rb") as f:
                while True:
                    pos = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    if self.total_lines % CHUNK_SIZE == 0:
                        self.offsets.append(pos)
                    self.total_lines += 1
                    if progress_callback and self.total_lines % 100_000 == 0:
                        progress_callback(self.total_lines)
        except OSError as e:
            raise RuntimeError(f"Cannot read JSONL file: {e}") from e

        with open(self.idx_path, "wb") as f:
            f.write(IDX_MAGIC)
            f.write(struct.pack(STRUCT_Q, self.total_lines))
            for off in self.offsets:
                f.write(struct.pack(STRUCT_Q, off))
        return True

    def _build_zst(self, progress_callback=None):
        """Count lines via zstdcat (no byte offsets). Requires zstd on PATH."""
        try:
            proc = subprocess.Popen(
                ZSTDCAT_CMD + [self.jsonl_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=65536,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "zstd not found. Install zstd (e.g. apt install zstd) to view .zst files."
            ) from None
        try:
            for line in proc.stdout:
                self.total_lines += 1
                if progress_callback and self.total_lines % 100_000 == 0:
                    progress_callback(self.total_lines)
        finally:
            proc.wait()
            if proc.returncode != 0:
                err = (proc.stderr.read() or b"").decode("utf-8", errors="replace")
                raise RuntimeError(f"zstdcat failed (code {proc.returncode}): {err}")
        with open(self.idx_path, "wb") as f:
            f.write(IDX_MAGIC_ZST)
            f.write(struct.pack(STRUCT_Q, self.total_lines))
            f.write(struct.pack(STRUCT_Q, 0))  # single dummy offset for zst
        return True

    def get_offset_for_line(self, line_index):
        """Return (byte_offset, lines_to_skip) to reach line_index.
        For .zst, always (0, line_index) so reader streams from start and skips.
        """
        if line_index >= self.total_lines or line_index < 0:
            return None, 0
        if self.is_zst:
            return 0, line_index
        chunk = line_index // CHUNK_SIZE
        if chunk >= len(self.offsets):
            return self.offsets[-1] if self.offsets else 0, line_index
        base_offset = self.offsets[chunk]
        skip = line_index - chunk * CHUNK_SIZE
        return base_offset, skip


# ---------------------------------------------------------------------------
# Streamer: read lines via mmap using the sparse index
# ---------------------------------------------------------------------------

class JSONLStreamer:
    """Read requested line range from JSONL using mmap and sparse index."""

    def __init__(self, jsonl_path, index_manager):
        self.jsonl_path = jsonl_path
        self.index = index_manager
        self._file = None
        self._mm = None

    def _ensure_mmap(self):
        if self._mm is not None:
            return
        self._file = open(self.jsonl_path, "rb")
        try:
            size = os.path.getsize(self.jsonl_path)
            self._mm = mmap.mmap(self._file.fileno(), size, access=mmap.ACCESS_READ)
        except (OSError, OverflowError):
            self._file.close()
            self._file = None
            raise RuntimeError("mmap failed (file too large or not supported)")

    def close(self):
        if self._mm is not None:
            try:
                self._mm.close()
            except OSError:
                pass
            self._mm = None
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None

    def get_lines(self, start_line, count):
        """
        Return list of (line_index_0based, object) for lines [start_line, start_line+count).
        object is parsed JSON or {"_raw": str, "_error": True} on parse error.
        """
        total = self.index.total_lines
        if start_line >= total or count <= 0:
            return []
        count = min(count, total - start_line, MAX_LINES_PER_REQUEST)

        base_offset, skip = self.index.get_offset_for_line(start_line)
        self._ensure_mmap()

        result = []
        pos = base_offset
        end = len(self._mm)
        line_index = start_line - skip  # first line we will yield when skip is done
        to_skip = skip
        to_take = count

        while pos < end and to_take > 0:
            line_end = self._mm.find(b"\n", pos)
            if line_end == -1:
                line_end = end
            else:
                line_end += 1
            line_slice = self._mm[pos:line_end]
            if line_index >= start_line:
                raw = line_slice.rstrip(b"\n\r").decode("utf-8", errors="replace")
                try:
                    obj = json.loads(raw) if raw.strip() else {}
                except json.JSONDecodeError:
                    obj = {"_raw": raw[:500], "_error": True}
                result.append((line_index, obj))
                to_take -= 1
            else:
                to_skip -= 1
            line_index += 1
            pos = line_end

        return result

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# Zstd streamer: read lines via zstdcat (no mmap; stream and skip)
# ---------------------------------------------------------------------------

class ZstdJSONLStreamer:
    """Read requested line range from .zst by streaming zstdcat and skipping to start."""

    def __init__(self, zst_path, index_manager):
        self.zst_path = zst_path
        self.index = index_manager

    def close(self):
        pass

    def get_lines(self, start_line, count):
        """
        Return list of (line_index_0based, object) for lines [start_line, start_line+count).
        Streams zstdcat and skips first start_line lines (O(start_line) per request).
        """
        total = self.index.total_lines
        if start_line >= total or count <= 0:
            return []
        count = min(count, total - start_line, MAX_LINES_PER_REQUEST)
        try:
            proc = subprocess.Popen(
                ZSTDCAT_CMD + [self.zst_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=65536,
            )
        except FileNotFoundError:
            return []

        result = []
        line_index = 0
        to_skip = start_line
        to_take = count
        try:
            for raw in proc.stdout:
                if to_skip > 0:
                    to_skip -= 1
                    line_index += 1
                    continue
                line = raw.rstrip(b"\n\r").decode("utf-8", errors="replace")
                try:
                    obj = json.loads(line) if line.strip() else {}
                except json.JSONDecodeError:
                    obj = {"_raw": line[:500], "_error": True}
                result.append((line_index, obj))
                line_index += 1
                to_take -= 1
                if to_take <= 0:
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        return result

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# HTTP server: serve UI and /api/lines
# ---------------------------------------------------------------------------

def _html_content():
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>JSONL Viewer</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 12px; background: #1a1a2e; color: #eaeaea; min-height: 100vh; }
    h1 { font-size: 1.25rem; margin: 0 0 12px 0; color: #a0a0c0; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }
    .toolbar input, .toolbar button { padding: 6px 10px; border-radius: 6px; border: 1px solid #444; background: #252538; color: #eaeaea; }
    .toolbar button { cursor: pointer; }
    .toolbar button:hover { background: #353550; }
    .toolbar button:disabled { opacity: 0.5; cursor: not-allowed; }
    .info { color: #888; font-size: 0.9rem; margin-left: 8px; }
    #list { background: #16162a; border: 1px solid #333; border-radius: 8px; padding: 12px; max-height: 70vh; overflow-y: auto; }
    .line-block { margin-bottom: 16px; border-left: 3px solid #3a3a5c; padding-left: 10px; }
    .line-num { font-weight: 600; color: #7a7aaa; margin-bottom: 4px; }
    .line-json { font-family: ui-monospace, monospace; font-size: 12px; color: #c0c0d0; }
    .line-json .key { color: #8ab4f8; }
    .line-json .str { color: #a8e6a0; }
    .line-json .num { color: #f0b060; }
    .line-json .bool { color: #e080e0; }
    .line-json .null { color: #666; }
    .error { color: #f08080; }
    .loading { color: #888; }
    .tree-root { margin: 0; padding: 0; list-style: none; }
    .tree-node { margin: 0; padding: 0; }
    .tree-row { display: flex; align-items: baseline; cursor: pointer; padding: 1px 0; min-height: 18px; }
    .tree-row:hover { background: rgba(255,255,255,0.05); border-radius: 2px; }
    .tree-toggle { display: inline-block; width: 16px; text-align: center; color: #7a7aaa; user-select: none; flex-shrink: 0; }
    .tree-toggle.empty { visibility: hidden; }
    .tree-key { color: #8ab4f8; margin-right: 6px; }
    .tree-value { word-break: break-all; }
    .tree-value.str { color: #a8e6a0; }
    .tree-value.num { color: #f0b060; }
    .tree-value.bool { color: #e080e0; }
    .tree-value.null { color: #666; }
    .tree-children { margin-left: 16px; border-left: 1px solid #333; padding-left: 8px; }
    .tree-children.collapsed { display: none; }
    .tree-preview { color: #666; font-style: italic; }
  </style>
</head>
<body>
  <h1>JSONL Viewer</h1>
  <div class="toolbar">
    <button id="prev" type="button">Previous</button>
    <button id="next" type="button">Next</button>
    <span class="info">Lines <span id="range">-</span> of <span id="total">-</span></span>
    <label>Jump to line <input id="jump" type="number" min="1" placeholder="1" style="width: 100px;"> <button id="go" type="button">Go</button></label>
    <span id="status" class="info"></span>
  </div>
  <div id="list" class="loading">Loading…</div>

  <script>
    var pageSize = 50;
    var totalLines = 0;
    var currentStart = 0;

    function setStatus(msg) { document.getElementById('status').textContent = msg; }
    function setLoading(loading) {
      document.getElementById('list').className = loading ? 'loading' : '';
      document.getElementById('prev').disabled = loading;
      document.getElementById('next').disabled = loading;
      document.getElementById('go').disabled = loading;
    }

    function escapeHtml(s) {
      var d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    function treeNodeHtml(key, value, depth) {
      var keyPart = key === null ? '' : '<span class="tree-key">' + escapeHtml(JSON.stringify(key)) + ':</span> ';
      var t = typeof value;
      if (value === null) {
        return '<div class="tree-row"><span class="tree-toggle empty"></span>' + keyPart + '<span class="tree-value null">null</span></div>';
      }
      if (t === 'boolean') {
        return '<div class="tree-row"><span class="tree-toggle empty"></span>' + keyPart + '<span class="tree-value bool">' + value + '</span></div>';
      }
      if (t === 'number') {
        return '<div class="tree-row"><span class="tree-toggle empty"></span>' + keyPart + '<span class="tree-value num">' + value + '</span></div>';
      }
      if (t === 'string') {
        var s = value.length > 80 ? value.slice(0, 80) + '…' : value;
        return '<div class="tree-row"><span class="tree-toggle empty"></span>' + keyPart + '<span class="tree-value str">' + escapeHtml(JSON.stringify(s)) + '</span></div>';
      }
      if (Array.isArray(value)) {
        var len = value.length;
        var preview = 'Array (' + len + ')';
        var children = value.map(function(v, i) { return treeNodeHtml(i, v, depth + 1); }).join('');
        var id = 'tree-' + Math.random().toString(36).slice(2);
        return '<div class="tree-node">' +
          '<div class="tree-row" data-toggle="' + id + '"><span class="tree-toggle">▶</span>' + keyPart + '<span class="tree-preview">' + preview + '</span></div>' +
          '<div class="tree-children" id="' + id + '">' + children + '</div></div>';
      }
      if (t === 'object') {
        var keys = Object.keys(value);
        var preview = 'Object (' + keys.length + ')';
        var children = keys.map(function(k) { return treeNodeHtml(k, value[k], depth + 1); }).join('');
        var id = 'tree-' + Math.random().toString(36).slice(2);
        return '<div class="tree-node">' +
          '<div class="tree-row" data-toggle="' + id + '"><span class="tree-toggle">▶</span>' + keyPart + '<span class="tree-preview">' + preview + '</span></div>' +
          '<div class="tree-children collapsed" id="' + id + '">' + children + '</div></div>';
      }
      return '<div class="tree-row"><span class="tree-toggle empty"></span>' + keyPart + '<span class="tree-value">' + escapeHtml(String(value)) + '</span></div>';
    }

    function buildTreeHtml(obj, rootId) {
      rootId = rootId || ('root-' + Math.random().toString(36).slice(2));
      if (obj === null || typeof obj !== 'object') {
        return '<div class="tree-root">' + treeNodeHtml(null, obj, 0) + '</div>';
      }
      if (Array.isArray(obj)) {
        var parts = obj.map(function(v, i) { return treeNodeHtml(i, v, 0); }).join('');
        return '<div class="tree-root"><div class="tree-node">' +
          '<div class="tree-row" data-toggle="' + rootId + '"><span class="tree-toggle">▼</span> <span class="tree-preview">Array (' + obj.length + ')</span></div>' +
          '<div class="tree-children" id="' + rootId + '">' + parts + '</div></div></div>';
      }
      var keys = Object.keys(obj);
      var parts = keys.map(function(k) { return treeNodeHtml(k, obj[k], 0); }).join('');
      return '<div class="tree-root"><div class="tree-node">' +
        '<div class="tree-row" data-toggle="' + rootId + '"><span class="tree-toggle">▼</span> <span class="tree-preview">Object (' + keys.length + ')</span></div>' +
        '<div class="tree-children" id="' + rootId + '">' + parts + '</div></div></div>';
    }

    function attachTreeToggles(container) {
      container.querySelectorAll('.tree-row[data-toggle]').forEach(function(row) {
        row.onclick = function() {
          var id = row.getAttribute('data-toggle');
          var el = document.getElementById(id);
          if (!el) return;
          var toggle = row.querySelector('.tree-toggle');
          el.classList.toggle('collapsed');
          toggle.textContent = el.classList.contains('collapsed') ? '▶' : '▼';
        };
      });
    }

    function render(lines) {
      var html = '';
      for (var i = 0; i < lines.length; i++) {
        var lineNum = lines[i][0] + 1;
        var obj = lines[i][1];
        var isErr = obj && obj._error;
        var content = isErr ? '<span class="error">' + escapeHtml(obj._raw) + '</span>' : buildTreeHtml(obj);
        html += '<div class="line-block"><div class="line-num">Line ' + lineNum + '</div><div class="line-json">' + content + '</div></div>';
      }
      document.getElementById('list').innerHTML = html || '<div class="info">No lines in this range.</div>';
      document.querySelectorAll('#list .line-block').forEach(function(block) {
        attachTreeToggles(block);
      });
    }

    function updateRangeLabel() {
      var a = currentStart + 1;
      var b = Math.min(currentStart + pageSize, totalLines);
      document.getElementById('range').textContent = totalLines ? (a + '–' + b) : '-';
      document.getElementById('total').textContent = totalLines;
      document.getElementById('prev').disabled = currentStart <= 0;
      document.getElementById('next').disabled = currentStart + pageSize >= totalLines;
    }

    function fetchLines() {
      setLoading(true);
      setStatus('Fetching…');
      fetch('/api/lines?start=' + currentStart + '&count=' + pageSize)
        .then(function(r) { return r.json(); })
        .then(function(data) {
          totalLines = data.total;
          render(data.lines);
          updateRangeLabel();
          setStatus('');
          setLoading(false);
        })
        .catch(function(e) {
          setStatus('Error: ' + e.message);
          document.getElementById('list').innerHTML = '<div class="error">Request failed.</div>';
          setLoading(false);
        });
    }

    document.getElementById('prev').onclick = function() {
      currentStart = Math.max(0, currentStart - pageSize);
      fetchLines();
    };
    document.getElementById('next').onclick = function() {
      if (currentStart + pageSize < totalLines) { currentStart += pageSize; fetchLines(); }
    };
    document.getElementById('go').onclick = function() {
      var n = parseInt(document.getElementById('jump').value, 10);
      if (!isNaN(n) && n >= 1) {
        currentStart = Math.min(n - 1, Math.max(0, totalLines - 1));
        fetchLines();
      }
    };
    document.getElementById('jump').onkeydown = function(e) {
      if (e.key === 'Enter') document.getElementById('go').click();
    };

    fetchLines();
  </script>
</body>
</html>"""


class JSONLViewerHandler(BaseHTTPRequestHandler):
    """Serve embedded HTML and /api/lines from the shared streamer."""

    def log_message(self, format, *args):
        pass  # quiet by default

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(_html_content().encode("utf-8"))
            return

        if path == "/api/lines":
            try:
                start = int(query.get("start", [0])[0])
                count = int(query.get("count", [50])[0])
            except (ValueError, IndexError):
                start, count = 0, 50
            start = max(0, start)
            count = min(max(1, count), MAX_LINES_PER_REQUEST)

            streamer = self.server.streamer
            total = streamer.index.total_lines
            lines_data = streamer.get_lines(start, count)
            payload = {
                "total": total,
                "lines": [[idx, obj] for idx, obj in lines_data],
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def end_headers(self):
        # Prevent default Server header if desired (optional)
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(
        description="View large JSONL or .jsonl.zst files in the browser (sparse index + mmap/zstdcat, low RAM)."
    )
    parser.add_argument(
        "file",
        type=str,
        help="Path to the .jsonl or .jsonl.zst file",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for the local web server (default: 8765)",
    )
    parser.add_argument(
        "--rebuild-index",
        action="store_true",
        help="Force rebuild of the .idx file",
    )
    args = parser.parse_args()

    file_path = os.path.abspath(args.file)
    if not os.path.isfile(file_path):
        print(f"Error: file not found: {file_path}")
        return 1

    # Reject single-JSON files: this tool expects JSONL (one JSON object per line)
    base = file_path.lower()
    if base.endswith(".json") and not (base.endswith(".jsonl") or base.endswith(".jsonl.zst")):
        print("Error: This tool expects JSONL format (one JSON object per line), not a single JSON document.")
        print("  Use a file with extension .jsonl or .jsonl.zst.")
        print("  If you have a .json file (single object or array), convert it to JSONL first (e.g. one object per line).")
        return 1

    index_mgr = IndexManager(file_path)
    if not index_mgr.exists() or args.rebuild_index:
        kind = "zstd stream" if index_mgr.is_zst else "sparse index"
        print(f"Building {kind} (one-time scan)...")
        def progress(n):
            print(f"  Indexed {n:,} lines...", end="\r")
        try:
            index_mgr.build(progress_callback=progress)
        except RuntimeError as e:
            print(f"Error: {e}")
            return 1
        print(f"  Done. Total lines: {index_mgr.total_lines:,}. Index saved to {index_mgr.idx_path}")
    else:
        if not index_mgr.load():
            print("Error: invalid or corrupted .idx file. Use --rebuild-index to rebuild.")
            return 1
        print(f"Loaded index: {index_mgr.total_lines:,} lines.")

    if index_mgr.is_zst:
        streamer = ZstdJSONLStreamer(file_path, index_mgr)
    else:
        streamer = JSONLStreamer(file_path, index_mgr)
    try:
        server = HTTPServer(("127.0.0.1", args.port), JSONLViewerHandler)
        server.streamer = streamer
        print(f"Open http://127.0.0.1:{args.port}/ in your browser.")
        print("Press Ctrl+C to stop.")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        streamer.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
