/**
 * build-content.js — Compiles Decap CMS Markdown (.md) frontmatter files
 * into compiled JSON for fast browser-side data access.
 *
 * Usage: node scripts/build-content.js
 *
 * Watches content/collections/*.md and produces content/compiled/*.json
 */

const fs = require('fs');
const path = require('path');

const CONTENT_DIR = path.join(__dirname, '..', 'content');
const COMPILED_DIR = path.join(CONTENT_DIR, 'compiled');

const COLLECTIONS = {
  properties: { ext: '.md', idField: 'slug' },
  blog: { ext: '.md', idField: 'slug' },
  faqs: { ext: '.md', idField: 'question' },
  testimonials: { ext: '.md', idField: 'name' },
  areas: { ext: '.markdown', idField: 'id' },
};

function parseFrontmatter(raw) {
  const match = raw.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
  if (!match) return null;

  const yamlBlock = match[1];
  const body = (match[2] || '').trim();

  const entry = {};
  let currentKey = null;
  let currentList = null;
  let isInList = false;

  const lines = yamlBlock.split('\n');
  for (const line of lines) {
    const listItemMatch = line.match(/^\s+-\s+"(.+)"$/);
    if (listItemMatch) {
      if (currentList) currentList.push(listItemMatch[1]);
      continue;
    }

    const listItemSimple = line.match(/^\s+-\s+(.+)$/);
    if (listItemSimple) {
      if (currentList) currentList.push(listItemSimple[1]);
      continue;
    }

    if (isInList && !line.match(/^\s+-/)) {
      isInList = false;
      currentList = null;
    }

    const keyVal = line.match(/^(\w+):\s*(.*)$/);
    if (!keyVal) continue;

    currentKey = keyVal[1];
    const val = keyVal[2].trim();

    if (val === '' || val === '[]') {
      entry[currentKey] = [];
      currentList = [];
      isInList = true;
      continue;
    }

    if (val === 'true') entry[currentKey] = true;
    else if (val === 'false') entry[currentKey] = false;
    else if (/^\d+$/.test(val)) entry[currentKey] = parseInt(val, 10);
    else if (/^\d+\.\d+$/.test(val)) entry[currentKey] = parseFloat(val);
    else if (/^\[.*\]$/.test(val)) {
      entry[currentKey] = val.slice(1, -1).split(',').map(s => s.trim().replace(/^"|"$/g, '')).filter(Boolean);
    }
    else entry[currentKey] = val.replace(/^"(.*)"$/, '$1');
  }

  if (body) entry.body = body;
  return entry;
}

function compileCollection(name, ext, idField) {
  const dir = path.join(CONTENT_DIR, name);
  const results = [];

  if (!fs.existsSync(dir)) {
    console.warn(`  [warn] Collection directory missing: ${dir}`);
    return results;
  }

  const files = fs.readdirSync(dir).filter(f => f.endsWith(ext));
  for (const file of files) {
    const raw = fs.readFileSync(path.join(dir, file), 'utf-8');
    const entry = parseFrontmatter(raw);
    if (entry) {
      const id = entry[idField] || file.replace(ext, '');
      entry.id = String(id).toLowerCase().replace(/\s+/g, '-');
      results.push(entry);
    } else {
      console.warn(`  [warn] Could not parse: ${name}/${file}`);
    }
  }

  return results;
}

function build() {
  console.log('Building content...\n');

  if (!fs.existsSync(COMPILED_DIR)) {
    fs.mkdirSync(COMPILED_DIR, { recursive: true });
  }

  for (const [name, config] of Object.entries(COLLECTIONS)) {
    const items = compileCollection(name, config.ext, config.idField);
    const outPath = path.join(COMPILED_DIR, `${name}.json`);
    fs.writeFileSync(outPath, JSON.stringify(items, null, 2), 'utf-8');
    console.log(`  ${name}: ${items.length} items → content/compiled/${name}.json`);
  }

  // Copy homepage.json through unchanged
  const homepageSrc = path.join(CONTENT_DIR, 'homepage.json');
  const homepageDst = path.join(COMPILED_DIR, 'homepage.json');
  if (fs.existsSync(homepageSrc)) {
    fs.copyFileSync(homepageSrc, homepageDst);
    console.log('  homepage: copied → content/compiled/homepage.json');
  }

  console.log('\nDone.');
}

build();