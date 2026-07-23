/**
 * KOR DA — CONTENT BUILDER (scripts/build-content.js)
 * Compiles markdown/JSON from /content/* into /content/compiled/*.json
 * Run: node scripts/build-content.js
 */

const fs = require('fs');
const path = require('path');

const contentDir = path.join(__dirname, '..', 'content');
const compiledDir = path.join(contentDir, 'compiled');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readJsonFiles(dir) {
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  return files.map(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf-8')));
}

function readMarkdownFiles(dir) {
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.md'));
  return files.map(f => {
    const raw = fs.readFileSync(path.join(dir, f), 'utf-8');
    const parts = raw.split('---');
    if (parts.length < 3) return null;
    const frontmatter = {};
    parts[1].trim().split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const key = line.slice(0, idx).trim();
        let val = line.slice(idx + 1).trim();
        if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
        frontmatter[key] = val;
      }
    });
    const body = parts.slice(2).join('---').trim();
    return { ...frontmatter, body };
  }).filter(Boolean);
}

function compileCollection(name, reader) {
  const dir = path.join(contentDir, name);
  if (!fs.existsSync(dir)) return [];
  const items = reader(dir);
  const outPath = path.join(compiledDir, `${name}.json`);
  fs.writeFileSync(outPath, JSON.stringify(items, null, 2));
  console.log(`Compiled ${items.length} ${name} → ${outPath}`);
}

ensureDir(compiledDir);

// Properties: JSON files
compileCollection('properties', readJsonFiles);
// Blog: markdown files
compileCollection('blog', readMarkdownFiles);
// FAQs: JSON files
compileCollection('faqs', readJsonFiles);
// Testimonials: JSON files
compileCollection('testimonials', readJsonFiles);
// Areas: JSON files
compileCollection('areas', readJsonFiles);

// Copy homepage.json if exists
const hpPath = path.join(contentDir, 'homepage.json');
if (fs.existsSync(hpPath)) {
  fs.copyFileSync(hpPath, path.join(compiledDir, 'homepage.json'));
  console.log('Copied homepage.json → content/compiled/homepage.json');
}

console.log('Content build complete.');
