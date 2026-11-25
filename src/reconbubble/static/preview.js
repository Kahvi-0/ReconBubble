// Shared file-preview renderer. Used by the OSINT hub doc overlay and the
// document detail page; mirrors the SMB share preview pane exactly:
// the server sniffs the file and reports its kind via X-Preview-Kind
// (text/image/pdf/binary), legacy .doc files come back as PDF after a
// headless LibreOffice conversion (X-Preview-Cache: hit on a cached PDF,
// X-Preview-Note: needs-libreoffice | conversion-failed on failure), and
// .docx / .xlsx / .xls render client-side with mammoth / SheetJS
// (loaded per page, same vendor builds as the SMB page).
(function () {
  "use strict";

  var PREVIEW_MAX_BYTES = 10 * 1024 * 1024;
  var SHEET_MAX_ROWS = 500;
  var IMAGE_EXT_MIME = {
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
    webp: 'image/webp', bmp: 'image/bmp', ico: 'image/x-icon', svg: 'image/svg+xml'
  };

  function countReplacement(s) {
    var n = 0, i = s.indexOf('\uFFFD');
    while (i !== -1) { n++; i = s.indexOf('\uFFFD', i + 1); }
    return n;
  }
  function fileExt(name) {
    var dot = name.lastIndexOf('.');
    return dot >= 0 ? name.slice(dot + 1).toLowerCase() : '';
  }

  // Cap on rendered rows so a huge workbook doesn't hang the DOM.
  // Builds a <div> with an optional sheet picker and the rendered table.
  // Synchronous; throws on a corrupt or unreadable workbook.
  function buildSheetPreview(buf) {
    var wb = XLSX.read(buf, { type: 'array' });
    var wrap = document.createElement('div');
    var host = document.createElement('div');
    function renderSheetInto(hostEl, name) {
      hostEl.innerHTML = '';
      var ws = wb.Sheets[name];
      var rows = XLSX.utils.sheet_to_json(ws, { header: 1, raw: false, defval: '' });
      var table = document.createElement('table');
      table.className = 'smb-preview-sheet';
      var shown = 0;
      for (var i = 0; i < rows.length && shown < SHEET_MAX_ROWS; i++) {
        var row = rows[i];
        if (!row) continue;
        var empty = true;
        for (var j = 0; j < row.length; j++) {
          if (String(row[j] == null ? '' : row[j]) !== '') { empty = false; break; }
        }
        if (empty) continue;
        var tr = document.createElement('tr');
        for (var c = 0; c < row.length; c++) {
          var cell = document.createElement('td');
          cell.textContent = row[c] == null ? '' : String(row[c]);
          tr.appendChild(cell);
        }
        table.appendChild(tr);
        shown++;
      }
      hostEl.appendChild(table);
      if (shown === 0) {
        var s = document.createElement('span');
        s.className = 'muted';
        s.style.fontSize = '12px';
        s.textContent = '(sheet is empty)';
        hostEl.appendChild(s);
      } else if (rows.length > SHEET_MAX_ROWS) {
        var note = document.createElement('div');
        note.className = 'muted';
        note.style.fontSize = '11px';
        note.textContent = 'Showing first ' + SHEET_MAX_ROWS + ' of ' + rows.length + ' rows.';
        hostEl.appendChild(note);
      }
    }
    if (wb.SheetNames.length > 1) {
      var bar = document.createElement('div');
      bar.className = 'smb-preview-sheetbar';
      var label = document.createElement('label');
      label.textContent = 'Sheet: ';
      bar.appendChild(label);
      var sel = document.createElement('select');
      wb.SheetNames.forEach(function(n) {
        var o = document.createElement('option');
        o.value = n;
        o.textContent = n;
        sel.appendChild(o);
      });
      sel.addEventListener('change', function() { renderSheetInto(host, sel.value); });
      bar.appendChild(sel);
      wrap.appendChild(bar);
    }
    wrap.appendChild(host);
    renderSheetInto(host, wb.SheetNames[0]);
    return wrap;
  }
  // mammoth resolves to { value: html, messages: [...] }; HTML is generated
  // by mammoth (not copied raw from the docx), so it needs no sanitising.
  function buildDocxHtml(buf) {
    return mammoth.convertToHtml({ arrayBuffer: buf });
  }

  // Local (no-network) preview message: empty file, too large, etc.
  function previewLocal(into, name, message) {
    if (into.controller) { into.controller.abort(); into.controller = null; }
    if (into.blobUrl) { URL.revokeObjectURL(into.blobUrl); into.blobUrl = null; }
    into.innerHTML = '';
    var s = document.createElement('span');
    s.className = 'muted';
    s.style.fontSize = '12px';
    s.textContent = message;
    into.appendChild(s);
    if (typeof into.onStatus === 'function') into.onStatus('');
  }

  // Reset a preview pane to its idle state (called on close/reopen).
  function resetPreview(into, hint) {
    if (into.controller) { into.controller.abort(); into.controller = null; }
    if (into.blobUrl) { URL.revokeObjectURL(into.blobUrl); into.blobUrl = null; }
    into.innerHTML = '';
    var h = document.createElement('span');
    h.className = 'muted';
    h.style.fontSize = '12px';
    h.textContent = hint || 'Loading…';
    into.appendChild(h);
    if (typeof into.onStatus === 'function') into.onStatus('');
  }

  // opts:
  //   url        - preview endpoint (X-Preview-* contract)
  //   name       - file name (drives extension-based rendering + titles)
  //   size       - file size in bytes (0 = unknown)
  //   into       - { element, statusEl?, controller?, blobUrl?, onStatus? }
  //   timeoutSec - fetch abort timeout (server conversion can be slow)
  //   downloadUrl - shown in the "use Download" message when set
  function renderPreview(opts) {
    var into = opts.into;
    var name = opts.name || '';
    var size = opts.size || 0;
    if (size === 0) {
      previewLocal(into, name, '(empty file)');
      return;
    }
    if (size > PREVIEW_MAX_BYTES) {
      previewLocal(into, name, 'Too large to preview (limit 10 MB). Use Download instead.');
      return;
    }
    if (into.controller) into.controller.abort();
    if (into.blobUrl) { URL.revokeObjectURL(into.blobUrl); into.blobUrl = null; }

    var timeoutSec = Math.max(1, Math.min(120, opts.timeoutSec || 90));
    var controller = new AbortController();
    into.controller = controller;
    into.innerHTML = '';
    var hint = document.createElement('span');
    hint.className = 'muted';
    hint.style.fontSize = '12px';
    hint.textContent = 'Loading \u2026';
    into.appendChild(hint);
    var abortTimer = setTimeout(function() { controller.abort(); }, (timeoutSec + 15) * 1000);

    fetch(opts.url, { signal: controller.signal })
      .then(function(r) {
        var ct = r.headers.get('content-type') || '';
        if (ct.indexOf('application/json') !== -1) {
          return r.json().then(function(j) { throw { apiError: j }; });
        }
        return r.blob().then(function(blob) {
          return {
            blob: blob,
            kind: r.headers.get('x-preview-kind'),
            note: r.headers.get('x-preview-note'),
            cached: r.headers.get('x-preview-cache') === 'hit'
          };
        });
      })
      .then(function(res) {
        if (into.controller !== controller) return;  // a newer preview took over
        if (typeof into.onStatus === 'function') {
          into.onStatus(res.cached ? 'Served from local cache.' : '');
        }
        into.innerHTML = '';
        if (res.kind === 'text') {
          // TextDecoder needs an ArrayBuffer, not a Blob: decode async.
          // Return the promise so .finally waits for the decode; otherwise
          // the staleness guard below skips the render.
          return res.blob.arrayBuffer().then(function(buf) {
            if (into.controller !== controller) return;
            var text = new TextDecoder('utf-8').decode(buf);
            if (text.length && countReplacement(text) / text.length > 0.01) {
              text = new TextDecoder('iso-8859-1').decode(buf);
            }
            var pre = document.createElement('pre');
            pre.textContent = text;
            into.appendChild(pre);
          }).catch(function() {
            if (into.controller !== controller) return;
            if (typeof into.onStatus === 'function') into.onStatus('Could not decode file text.');
          });
        } else if (res.kind === 'image') {
          var blob = res.blob;
          if (!blob.type || blob.type === 'image/octet-stream') {
            var mime = IMAGE_EXT_MIME[fileExt(name)] || blob.type || 'image/octet-stream';
            blob = new Blob([blob], { type: mime });
          }
          into.blobUrl = URL.createObjectURL(blob);
          var img = document.createElement('img');
          img.src = into.blobUrl;
          img.alt = name;
          into.appendChild(img);
        } else if (res.kind === 'pdf') {
          // Native browser PDF viewer via object URL; reuses the shared
          // blob-URL lifecycle so every reset revokes it.
          into.blobUrl = URL.createObjectURL(new Blob([res.blob], { type: 'application/pdf' }));
          var frame = document.createElement('iframe');
          frame.src = into.blobUrl;
          frame.title = name;
          into.appendChild(frame);
        } else if (fileExt(name) === 'xlsx' || fileExt(name) === 'xls') {
          return res.blob.arrayBuffer().then(function(buf) {
            if (into.controller !== controller) return;
            var el;
            try {
              el = buildSheetPreview(buf);
            } catch (ex) {
              if (typeof into.onStatus === 'function') into.onStatus('Could not read spreadsheet \u2014 file may be corrupt.');
              return;
            }
            into.appendChild(el);
          }).catch(function() {
            if (into.controller !== controller) return;
            if (typeof into.onStatus === 'function') into.onStatus('Could not read spreadsheet.');
          });
        } else if (fileExt(name) === 'docx') {
          return res.blob.arrayBuffer().then(function(buf) {
            if (into.controller !== controller) return null;
            return buildDocxHtml(buf).then(function(result) {
              return result && result.value;
            });
          }).then(function(html) {
            if (into.controller !== controller || html == null) return;
            var div = document.createElement('div');
            div.className = 'smb-preview-docx';
            div.innerHTML = html;
            into.appendChild(div);
          }).catch(function() {
            if (into.controller !== controller) return;
            if (typeof into.onStatus === 'function') into.onStatus('Could not read document \u2014 file may be corrupt.');
          });
        } else {
          var msg;
          if (res.note === 'needs-libreoffice') {
            msg = 'This legacy .doc needs LibreOffice on the server to render as PDF, and it is not installed. Install it, then preview the file again:';
          } else if (res.note === 'conversion-failed') {
            msg = 'This .doc could not be converted to PDF for preview (corrupt file or converter error). Use Download instead.';
          } else {
            msg = fileExt(name) === 'doc'
              ? 'Legacy .doc file \u2014 preview not supported. Use Download instead.'
              : 'Binary file \u2014 cannot be previewed. Use Download instead.';
          }
          var s = document.createElement('span');
          s.className = 'muted';
          s.style.fontSize = '12px';
          s.textContent = msg;
          into.appendChild(s);
          if (res.note === 'needs-libreoffice') {
            var code = document.createElement('code');
            code.textContent = 'sudo apt-get install -y --no-install-recommends libreoffice-writer';
            code.style.display = 'block';
            code.style.marginTop = '6px';
            into.appendChild(code);
          }
          if (opts.downloadUrl) {
            var a = document.createElement('a');
            a.href = opts.downloadUrl;
            a.style.display = 'block';
            a.style.marginTop = '8px';
            a.textContent = 'Download file';
            into.appendChild(a);
          }
        }
      })
      ['catch'](function(err) {
        if (into.controller !== controller) return;
        if (err && err.name === 'AbortError') {
          if (typeof into.onStatus === 'function') into.onStatus('Preview timed out after ' + timeoutSec + 's.');
        } else if (err && err.apiError) {
          var msg = err.apiError.error ||
            (typeof err.apiError.detail === 'string' ? err.apiError.detail : '');
          if (typeof into.onStatus === 'function') into.onStatus(msg || 'Preview failed.');
        } else {
          if (typeof into.onStatus === 'function') into.onStatus('Could not reach the ReconBubble server.');
        }
      })
      .finally(function() {
        clearTimeout(abortTimer);
        if (into.controller === controller) into.controller = null;
      });
  }

  window.ReconPreview = {
    PREVIEW_MAX_BYTES: PREVIEW_MAX_BYTES,
    renderPreview: renderPreview,
    resetPreview: resetPreview
  };
})();
