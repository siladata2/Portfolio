'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, 'sila');
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif', '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.ico': 'image/x-icon' };
const server = http.createServer((req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  if (!['GET', 'HEAD'].includes(req.method)) {
    res.writeHead(405, { Allow: 'GET, HEAD' }); return res.end('Method not allowed');
  }
  let name;
  try { name = decodeURIComponent(new URL(req.url, 'http://localhost').pathname); }
  catch { res.writeHead(400); return res.end('Bad request'); }
  if (name === '/sila' || name === '/sila/') {
    res.writeHead(302, { Location: '/' }); return res.end();
  }
  const filename = path.resolve(root, '.' + (name === '/' ? '/index.html' : name));
  if (!filename.startsWith(root + path.sep) || name.includes('\0') || name.split('/').some(p => p.startsWith('.'))) {
    res.writeHead(404); return res.end('Not found');
  }
  fs.stat(filename, (err, stat) => {
    if (err || !stat.isFile()) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, {
      'Content-Type': types[path.extname(filename).toLowerCase()] || 'application/octet-stream',
      'Content-Length': stat.size,
      'Cache-Control': filename.endsWith('.html') ? 'no-cache' : 'public, max-age=86400'
    });
    if (req.method === 'HEAD') return res.end();
    const stream = fs.createReadStream(filename);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  });
});
if (require.main === module) server.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('SILA TECH website is running'));
module.exports = server;
