package report

import (
	"html/template"
	"io"
)

// WriteHTML renders a self-contained report page (inline CSS/JS, no external
// assets) with summary cards and a filterable findings table.
func WriteHTML(w io.Writer, r *Report) error {
	return htmlTmpl.Execute(w, r.ForOutput())
}

var htmlTmpl = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Tool}} — PII Scan Report</title>
<style>
  :root {
    --bg: #f6f7f9; --card: #ffffff; --ink: #1c2733; --muted: #66727f;
    --accent: #0b5fff; --line: #e3e7ec;
    --high: #c62828; --medium: #ef6c00; --low: #607d8b;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--ink); }
  header { background: var(--ink); color: #fff; padding: 28px 32px; }
  header h1 { margin: 0 0 4px; font-size: 22px; }
  header .meta { color: #aab6c2; font-size: 13px; }
  main { max-width: 1200px; margin: 0 auto; padding: 24px 32px 64px; }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 0 0 24px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 18px; min-width: 150px; }
  .card .num { font-size: 26px; font-weight: 700; }
  .card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
  .controls { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
  .controls input, .controls select { padding: 8px 12px; border: 1px solid var(--line); border-radius: 8px; font-size: 14px; background: var(--card); }
  .controls input { flex: 1; min-width: 220px; }
  .doc { background: var(--card); border: 1px solid var(--line); border-radius: 10px; margin-bottom: 12px; overflow: hidden; }
  .doc-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 14px; padding: 12px 16px; background: #eef1f5; border-bottom: 1px solid var(--line); }
  .doc-head .path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; font-weight: 600; word-break: break-all; }
  .chip { display: inline-block; padding: 2px 10px; border-radius: 20px; background: #dbe4f0; color: #1c2733; font-size: 11.5px; font-weight: 600; white-space: nowrap; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 9px 16px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  tr:last-child td { border-bottom: none; }
  td.ctx { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; color: #37474f; word-break: break-all; }
  td.match { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; white-space: nowrap; }
  td.loc { white-space: nowrap; font-size: 13px; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 20px; color: #fff; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .badge.high { background: var(--high); } .badge.medium { background: var(--medium); } .badge.low { background: var(--low); }
  .cat { white-space: nowrap; font-weight: 600; font-size: 13px; }
  .notice { margin: 18px 0 0; padding: 12px 16px; border-radius: 8px; font-size: 13.5px; }
  .notice.masked { background: #e8f1ff; border: 1px solid #bcd4ff; }
  .notice.full { background: #fdecea; border: 1px solid #f5c6c1; }
  .notice.ocr { background: #fff7e6; border: 1px solid #f2d59b; }
  .notice.ocr ul { margin: 8px 0 0; padding-left: 20px; font-family: ui-monospace, Menlo, monospace; font-size: 12.5px; }
  .card.ocr .num { color: var(--medium); }
  .mailloc { color: #66727f; font-size: 11.5px; margin-top: 2px; }
  .empty { padding: 48px; text-align: center; color: var(--muted); background: var(--card); border: 1px solid var(--line); border-radius: 10px; }
</style>
</head>
<body>
<header>
  <h1>{{.Tool}} — PII Scan Report</h1>
  <div class="meta">
    Generated {{.GeneratedAt.Format "Jan 2, 2006 15:04 MST"}} · v{{.Version}} · Duration {{.Duration}} ·
    Scanned: {{range $i, $r := .Roots}}{{if $i}}, {{end}}{{$r}}{{end}}
  </div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="num">{{len .Findings}}</div><div class="label">Total findings</div></div>
    <div class="card"><div class="num">{{.Stats.FilesScanned}}</div><div class="label">Files scanned</div></div>
    <div class="card"><div class="num">{{.Stats.FilesSkipped}}</div><div class="label">Files skipped</div></div>
    {{if .Stats.FilesNeedOCR}}
    <div class="card ocr"><div class="num">{{.Stats.FilesNeedOCR}}</div><div class="label">Need OCR (not searched)</div></div>
    {{end}}
    {{range .CategoryCounts}}
    <div class="card"><div class="num">{{.Count}}</div><div class="label">{{.Category}}</div></div>
    {{end}}
  </div>

  {{if .Findings}}
  <div class="controls">
    <input id="search" type="search" placeholder="Filter by file, category, or context…">
    <select id="catFilter">
      <option value="">All categories</option>
      {{range .CategoryCounts}}<option>{{.Category}}</option>{{end}}
    </select>
    <select id="confFilter">
      <option value="">All confidence</option>
      <option value="high">High only</option>
      <option value="medium">Medium+</option>
    </select>
  </div>
  <div id="findings">
  {{range .FileGroups}}
    <div class="doc">
      <div class="doc-head">
        <span class="path">{{.Path}}</span>
        {{range .CategoryCounts}}<span class="chip">{{.Category}} ×{{.Count}}</span>{{end}}
      </div>
      <table>
        <thead><tr><th>Category</th><th>Confidence</th><th>Location</th><th>Match</th><th>Context</th></tr></thead>
        <tbody>
        {{range .Findings}}
          <tr data-cat="{{.Category}}" data-conf="{{.Confidence}}">
            <td class="cat">{{.Category}}</td>
            <td><span class="badge {{.Confidence}}">{{.Confidence}}</span></td>
            <td class="loc">{{if or .Folder .Subject}}{{.Folder}} / {{.Subject}} · msg {{.Line}}{{else if .Page}}page {{.Page}}, line {{.Line}}{{else}}line {{.Line}}{{end}}</td>
            <td class="match">{{.Match}}</td>
            <td class="ctx">{{.Context}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
    </div>
  {{end}}
  </div>
  {{if .Masked}}
  <p class="notice masked">Matched values are partially masked. Re-run the scan with <code>-show-full</code> to generate a report with complete values.</p>
  {{else}}
  <p class="notice full"><strong>Warning:</strong> this report contains unmasked PII. Store, transmit, and dispose of it with the same care as the source data.</p>
  {{end}}
  {{else}}
	  <div class="empty"><h2>No PII matches found</h2><p>Nothing matched the detection rules in the content that was successfully searched. Review any coverage notices below before treating the scan as clean.</p></div>
  {{end}}
  {{if .Stats.NeedOCR}}
  <div class="notice ocr"><strong>{{.Stats.FilesNeedOCR}} document(s) were NOT searched</strong> — they appear to be
  scans or images with no embedded text layer, so any PII inside them is invisible to this scan
  (re-run with OCR enabled and the OCR tools installed to read them):
    <ul>{{range .Stats.NeedOCR}}<li>{{.}}</li>{{end}}</ul>
  </div>
  {{end}}
  {{if .Stats.MailSkipped}}
  <div class="notice ocr"><strong>{{.Stats.FilesMail}} Outlook mail store(s) were NOT searched</strong> — mailbox
  files (.pst/.ost) are only opened by a targeted mail scan (<code>privacylens -mail</code>, or the
  "Mail scan" option in the GUI):
    <ul>{{range .Stats.MailSkipped}}<li>{{.}}</li>{{end}}</ul>
  </div>
  {{end}}
</main>
<script>
(function () {
  var search = document.getElementById('search');
  var cat = document.getElementById('catFilter');
  var conf = document.getElementById('confFilter');
  if (!search) return;
  function apply() {
    var q = search.value.toLowerCase();
    var c = cat.value;
    var cf = conf.value;
    document.querySelectorAll('#findings .doc').forEach(function (doc) {
      var pathMatch = !q || doc.querySelector('.doc-head').textContent.toLowerCase().indexOf(q) !== -1;
      var visible = 0;
      doc.querySelectorAll('tbody tr').forEach(function (tr) {
        var okText = pathMatch || tr.textContent.toLowerCase().indexOf(q) !== -1;
        var okCat = !c || tr.dataset.cat === c;
        var okConf = !cf ||
          (cf === 'high' && tr.dataset.conf === 'high') ||
          (cf === 'medium' && tr.dataset.conf !== 'low');
        var ok = okText && okCat && okConf;
        tr.style.display = ok ? '' : 'none';
        if (ok) visible++;
      });
      doc.style.display = visible ? '' : 'none';
    });
  }
  search.addEventListener('input', apply);
  cat.addEventListener('change', apply);
  conf.addEventListener('change', apply);
})();
</script>
</body>
</html>
`))
