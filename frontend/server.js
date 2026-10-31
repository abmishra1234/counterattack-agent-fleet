const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const publicRoot = path.resolve(__dirname);
const port = Number(process.env.PORT || 4173);
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8'));
}

function localRunTime() {
  try {
    const stat = fs.statSync(path.join(root, 'out', 'run_report.json'));
    return stat.mtime.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  } catch { return null; }
}

const server = http.createServer((req, res) => {
  const pathname = new URL(req.url, `http://${req.headers.host}`).pathname;
  if (pathname === '/api/data') {
    try {
      const payload = {
        alerts: readJson('out/alerts.json'),
        needsHuman: readJson('out/needs_human.json'),
        report: readJson('out/run_report.json'),
        advisories: readJson('data/advisories.json'),
        inventory: readJson('data/inventory.json'),
        kev: readJson('data/kev.json'),
        lastRun: localRunTime(),
      };
      res.writeHead(200, { 'Content-Type': mime['.json'], 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(payload));
    } catch (error) {
      res.writeHead(503, { 'Content-Type': mime['.json'], 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: error.message }));
    }
    return;
  }

  const requested = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
  const filePath = path.resolve(publicRoot, requested);
  if (!filePath.startsWith(publicRoot + path.sep) || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }
  res.writeHead(200, { 'Content-Type': mime[path.extname(filePath)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
  fs.createReadStream(filePath).pipe(res);
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`Counterstrike UI preview: http://127.0.0.1:${port}\n`);
  process.stdout.write('Data source: local out/ and data/ fixture files.\n');
});
