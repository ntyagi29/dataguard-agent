require('dotenv').config();
const express  = require('express');
const multer   = require('multer');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');

const { validateFile }                       = require('./src/validator');
const { runAgent, generateLocalSuggestions } = require('./src/agent');
const {
  loadRulesFromCSV, saveRuleToCSV, deleteRuleFromCSV, deleteRulesBySource,
  toggleRuleInCSV, updateRuleInCSV, nextRuleId, getEnabledFraudHeuristicConfigs, RULES_CSV_PATH
}                                            = require('./src/ruleManager');
const { parseNaturalLanguageRule }           = require('./src/nlpParser');
const { testConnection, fetchData, listTables, getColumns, rowsToFileContent } = require('./src/dbConnector');
const { getRulePack, getAmlPack, PACK_METADATA } = require('./src/regulatoryRulePacks');
const { FRAUD_RULE_CATALOG, runFraudHeuristics } = require('./src/fraudHeuristics');
const { introspectSchema, searchFieldInSchema, buildConnectedSubgraph,
        introspectFileSchema, buildCrossSourceLineage, focusLineageOnColumn } = require('./src/lineage');
const { sendNotificationEmail } = require('./src/emailNotifier');
const { getAll, getById, create, update, remove, saveState, loadState, PROJECTS_PATH } = require('./src/projects');
const git         = require('./src/gitConnector');
const users    = require('./src/users');
const cloudStorage = require('./src/cloudStorage');
const { loadFile }                           = require('./src/fileLoader');

const app  = express();
const PORT = process.env.PORT || 3000;
const USE_TUNNEL = process.argv.includes('--tunnel');

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ACCEPTED_EXTENSIONS = ['.txt', '.csv', '.json', '.parquet'];
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    ACCEPTED_EXTENSIONS.includes(ext)
      ? cb(null, true)
      : cb(new Error(`Unsupported file type "${ext}". Accepted: ${ACCEPTED_EXTENSIONS.join(', ')}`));
  }
});

// ── Tunnel public URL (set after tunnel starts) ────────────────────────────────
let publicUrl = null;

// ══════════════════════════════════════════════════════════
//  CSV SYNC — called after every rule mutation
// ══════════════════════════════════════════════════════════
function syncCSV() {
  // The ruleManager already writes to RULES_CSV_PATH.
  // This hook logs it and could be extended (e.g. S3, email, webhook).
  const rules = loadRulesFromCSV();
  const ts    = new Date().toLocaleString();
  console.log(`[${ts}] 📁 CSV synced — ${rules.length} rules → ${RULES_CSV_PATH}`);
}

// ══════════════════════════════════════════════════════════
//  VALIDATION ROUTES
// ══════════════════════════════════════════════════════════
// Merge ad-hoc fraud heuristics (from the Validate Data checkbox panel) with any
// persisted, enabled AML pack entries — so importing the AML pack means those
// heuristics run automatically on every validation, same as BCBS/CCAR rules,
// without the user having to also tick the matching checkbox each time.
function mergeFraudHeuristics(adHoc) {
  const persisted = getEnabledFraudHeuristicConfigs();
  const seenKeys  = new Set((adHoc || []).map(h => h.key));
  const merged    = [...(adHoc || [])];
  for (const p of persisted) {
    if (!seenKeys.has(p.key)) { merged.push({ key: p.key, params: p.params }); seenKeys.add(p.key); }
  }
  return merged;
}

app.post('/api/validate', upload.array('files', 20), async (req, res) => {
  try {
    if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });
    const useAI  = req.body.useAI === 'true';
    const apiKey = req.body.apiKey || process.env.ANTHROPIC_API_KEY || '';
    let fraudHeuristics = [];
    try { fraudHeuristics = req.body.fraudHeuristics ? JSON.parse(req.body.fraudHeuristics) : []; } catch {}
    fraudHeuristics = mergeFraudHeuristics(fraudHeuristics);
    const results = await Promise.all(
      req.files.map(f => validateFile(f.buffer, f.originalname, { fraudHeuristics }))
    );
    let aiAnalysis = null, localSuggestions = null;
    if (useAI && apiKey) {
      try { aiAnalysis = await runAgent(results, apiKey); }
      catch { localSuggestions = generateLocalSuggestions(results); }
    } else { localSuggestions = generateLocalSuggestions(results); }
    res.json({ success:true, results, aiAnalysis, localSuggestions,
      summary:{ totalFiles:results.length, filesPass:results.filter(r=>r.passed).length,
        filesFail:results.filter(r=>!r.passed).length, totalErrors:results.reduce((s,r)=>s+r.summary.totalErrors,0),
        totalFraudFlags: results.reduce((s,r)=>s+(r.summary.totalFraudFlags||0),0) }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/validate/filepath', async (req, res) => {
  try {
    let { filePath, useAI, apiKey: bk, fraudHeuristics, activeRuleIds } = req.body;
    if (!filePath) return res.status(400).json({ error: 'filePath is required' });

    // Normalize: expand ~, strip quotes, resolve relative paths
    filePath = filePath.trim().replace(/^['"]|['"]$/g, '');
    if (filePath.startsWith('~')) filePath = filePath.replace(/^~/, require('os').homedir());
    filePath = path.resolve(filePath);

    // Distinguish permission error from missing file
    try { fs.accessSync(filePath, fs.constants.R_OK); }
    catch (e) {
      if (e.code === 'EACCES' || e.code === 'EPERM') {
        return res.status(403).json({ error: `Permission denied reading file. Fix with: chmod 644 "${filePath}"` });
      }
      return res.status(404).json({ error: `File not found: ${filePath}` });
    }

    const result  = await validateFile(fs.readFileSync(filePath), path.basename(filePath), { fraudHeuristics: mergeFraudHeuristics(fraudHeuristics), activeRuleIds: activeRuleIds || null });
    const apiKey  = bk || process.env.ANTHROPIC_API_KEY || '';
    let aiAnalysis=null, localSuggestions=null;
    if (useAI && apiKey) { try { aiAnalysis=await runAgent([result],apiKey); } catch { localSuggestions=generateLocalSuggestions([result]); } }
    else localSuggestions=generateLocalSuggestions([result]);
    res.json({ success:true, results:[result], aiAnalysis, localSuggestions,
      summary:{ totalFiles:1, filesPass:result.passed?1:0, filesFail:result.passed?0:1, totalErrors:result.summary.totalErrors, totalFraudFlags:result.summary.totalFraudFlags||0 }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/validate/database', async (req, res) => {
  try {
    const { dbConfig, useAI, apiKey: bk, fraudHeuristics, activeRuleIds } = req.body;
    if (!dbConfig?.type) return res.status(400).json({ error: 'dbConfig.type is required' });
    const rows   = await fetchData(dbConfig);
    const result = await validateFile(rowsToFileContent(rows),
      `${dbConfig.type}://${dbConfig.host||''}/${dbConfig.database||dbConfig.filePath}/${dbConfig.table||'query'}.csv`,
      { fraudHeuristics: mergeFraudHeuristics(fraudHeuristics), activeRuleIds: activeRuleIds || null });
    const apiKey = bk || process.env.ANTHROPIC_API_KEY || '';
    let aiAnalysis=null, localSuggestions=null;
    if (useAI && apiKey) { try { aiAnalysis=await runAgent([result],apiKey); } catch { localSuggestions=generateLocalSuggestions([result]); } }
    else localSuggestions=generateLocalSuggestions([result]);
    res.json({ success:true, results:[result], aiAnalysis, localSuggestions, rowsFetched:rows.length,
      summary:{ totalFiles:1, filesPass:result.passed?1:0, filesFail:result.passed?0:1, totalErrors:result.summary.totalErrors, totalFraudFlags:result.summary.totalFraudFlags||0 }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════
//  DATABASE UTILITIES
// ══════════════════════════════════════════════════════════
app.post('/api/db/test',    async (req,res) => { try { res.json(await testConnection(req.body)); } catch(e){ res.status(500).json({success:false,message:e.message}); } });
app.post('/api/db/tables',  async (req,res) => { try { res.json({tables:await listTables(req.body)}); } catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/db/columns', async (req,res) => { try { res.json({columns:await getColumns(req.body)}); } catch(e){ res.status(500).json({error:e.message}); } });

// ══════════════════════════════════════════════════════════
//  DATA LINEAGE — schema-level (table.column structure) and column-level
//  (which tables/columns a field name appears in) lineage across one or
//  more database connections. NOT row-value tracing — see lineage.js header.
// ══════════════════════════════════════════════════════════

// Introspect a single connection's full schema (tables, columns, foreign keys).
app.post('/api/lineage/schema', async (req, res) => {
  try {
    const schema = await introspectSchema(req.body);
    res.json({ success: true, schema, tableCount: schema.tables.length, fkCount: schema.foreignKeys.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Search for a field name across one or more connections' schemas.
// Body: { connections: [dbConfig, dbConfig, ...], fieldQuery: "ssn" }
app.post('/api/lineage/search', async (req, res) => {
  try {
    const { connections, fieldQuery } = req.body;
    if (!connections?.length) return res.status(400).json({ error: 'At least one connection is required' });
    if (!fieldQuery?.trim()) return res.status(400).json({ error: 'fieldQuery is required' });

    const results = [];
    const errors  = [];

    for (const conn of connections) {
      try {
        const schema = await introspectSchema(conn.dbConfig);
        const matches = searchFieldInSchema(schema, fieldQuery);
        if (matches.length) {
          results.push({
            connectionLabel: conn.label || `${conn.dbConfig.type}://${conn.dbConfig.host||conn.dbConfig.filePath}/${conn.dbConfig.database||''}`,
            connectionType: conn.dbConfig.type,
            matches,
            schema // included so the UI can immediately render the FK graph for any match without a second round trip
          });
        } else {
          results.push({
            connectionLabel: conn.label || `${conn.dbConfig.type}://${conn.dbConfig.host||conn.dbConfig.filePath}/${conn.dbConfig.database||''}`,
            connectionType: conn.dbConfig.type,
            matches: [],
            schema
          });
        }
      } catch (err) {
        errors.push({ connectionLabel: conn.label || conn.dbConfig?.database || 'unknown', error: err.message });
      }
    }

    const totalMatches = results.reduce((s, r) => s + r.matches.length, 0);
    res.json({ success: true, results, errors, totalMatches });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Build the FK-connected subgraph around a specific table within an already-
// introspected schema (avoids re-querying the DB if the caller already has it).
app.post('/api/lineage/subgraph', (req, res) => {
  try {
    const { schema, startTable, maxDepth } = req.body;
    if (!schema || !startTable) return res.status(400).json({ error: 'schema and startTable are required' });
    const subgraph = buildConnectedSubgraph(schema, startTable, maxDepth || 3);
    res.json({ success: true, subgraph });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── File-level lineage endpoints ───────────────────────────────────────────

// Introspect a single file's schema (headers + inferred column types).
// ── Directory scan — list all files in a directory (with optional glob filter)
// Body: { dirPath: '/abs/path/to/dir', pattern: '*.csv' }  pattern is optional
app.post('/api/lineage/scan-directory', async (req, res) => {
  try {
    const { dirPath, pattern } = req.body;
    if (!dirPath) return res.status(400).json({ error: 'dirPath is required' });
    if (!fs.existsSync(dirPath)) return res.status(404).json({ error: `Directory not found: ${dirPath}` });
    const stat = fs.statSync(dirPath);
    if (!stat.isDirectory()) return res.status(400).json({ error: `Path is not a directory: ${dirPath}` });

    const SUPPORTED_EXTS = ['.csv', '.txt', '.json', '.parquet'];
    let entries = fs.readdirSync(dirPath, { withFileTypes: true });

    // Filter to files only (no sub-directories at this level, keep it simple)
    let files = entries
      .filter(e => e.isFile())
      .map(e => ({
        name: e.name,
        ext: path.extname(e.name).toLowerCase(),
        fullPath: path.join(dirPath, e.name),
        size: fs.statSync(path.join(dirPath, e.name)).size
      }))
      .filter(f => SUPPORTED_EXTS.includes(f.ext));

    // Apply pattern filter (e.g. *.csv → only .csv files)
    if (pattern && pattern.trim() && pattern !== '*') {
      const ext = pattern.trim().replace(/^\*/, '').toLowerCase();
      files = files.filter(f => f.ext === ext || f.name.toLowerCase().endsWith(ext.toLowerCase()));
    }

    // Group by extension for the UI
    const byExt = {};
    files.forEach(f => {
      byExt[f.ext] = (byExt[f.ext] || 0) + 1;
    });

    res.json({
      success: true,
      dirPath,
      files: files.map(f => ({ name: f.name, fullPath: f.fullPath, ext: f.ext, size: f.size })),
      count: files.length,
      byExt
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/lineage/file-schema', async (req, res) => {
  try {
    const { filePath } = req.body;
    if (!filePath) return res.status(400).json({ error: 'filePath is required' });
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: `File not found: ${filePath}` });
    const schema = await introspectFileSchema(filePath);
    res.json({ success: true, schema });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Accept uploaded files (browser multipart) and return schema for each —
// works for any user regardless of where the server runs.
app.post('/api/lineage/upload-schema', upload.array('files', 20), async (req, res) => {
  try {
    if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });
    const results = [];
    const errors  = [];
    for (const f of req.files) {
      try {
        const { loadFile } = require('./src/fileLoader');
        const { headers, rows, format } = await loadFile(f.buffer, f.originalname);
        const { inferColumnType } = require('./src/lineage');
        const sampleRows = rows.slice(0, 100);
        const columns = headers.map((name, ci) => {
          const vals = sampleRows.map(r => r[ci] || '').filter(v => v !== '');
          return { name, type: inferColumnType(vals), isPrimaryKey: false };
        });
        const stem = path.basename(f.originalname, path.extname(f.originalname));
        results.push({
          source: 'file', label: f.originalname, filePath: null, format,
          rowCount: rows.length,
          tables: [{ name: stem, columns }], foreignKeys: []
        });
      } catch (err) { errors.push({ source: f.originalname, error: err.message }); }
    }
    res.json({ success: true, schemas: results, errors });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Build a cross-source lineage graph from multiple files + databases.
// Body: {
//   filePaths: ['/abs/path/...'],          (server-side paths, local operator only)
//   uploadedSchemas: [{ schema object }],  (pre-parsed from /api/lineage/upload-schema)
//   dbConnections: [{ label, dbConfig }]
// }
app.post('/api/lineage/cross-source', async (req, res) => {
  try {
    const { filePaths = [], uploadedSchemas = [], dbConnections = [] } = req.body;
    if (!filePaths.length && !uploadedSchemas.length && !dbConnections.length)
      return res.status(400).json({ error: 'Provide at least one file or database source' });

    const sources = [];
    const errors  = [];

    // Pre-parsed uploaded schemas (from browser upload endpoint)
    for (const schema of uploadedSchemas) {
      sources.push(schema);
    }

    // Server-side file paths (local operator)
    for (const fp of filePaths) {
      try {
        if (!fs.existsSync(fp)) throw new Error(`File not found: ${fp}`);
        const schema = await introspectFileSchema(fp);
        sources.push(schema);
      } catch (err) {
        errors.push({ source: fp, error: err.message });
      }
    }

    // DB connections
    for (const conn of dbConnections) {
      try {
        const schema = await introspectSchema(conn.dbConfig);
        sources.push({
          source: 'database',
          label: conn.label || `${conn.dbConfig.type}://${conn.dbConfig.host || conn.dbConfig.filePath}/${conn.dbConfig.database || ''}`,
          format: null, filePath: null, rowCount: null,
          ...schema
        });
      } catch (err) {
        errors.push({ source: conn.label || conn.dbConfig?.database || 'db', error: err.message });
      }
    }

    if (!sources.length)
      return res.status(400).json({ error: 'All sources failed to load', errors });

    const graph = buildCrossSourceLineage(sources);
    res.json({ success: true, graph, errors, sourceCount: sources.length, nodeCount: graph.nodes.length, edgeCount: graph.edges.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Focus the cross-source graph on a specific column — returns only the nodes/edges
// touching that field, used by the "trace this field" UI interaction.
app.post('/api/lineage/focus', (req, res) => {
  try {
    const { graph, columnName } = req.body;
    if (!graph || !columnName) return res.status(400).json({ error: 'graph and columnName are required' });
    const focused = focusLineageOnColumn(graph, columnName);
    res.json({ success: true, graph: focused });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════
//  CONTACT FORM — routes to nigamvivek@zohomail.com via Resend
// ══════════════════════════════════════════════════════════
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, company, sector, message, apiKey } = req.body;
    if (!name || !email || !message) return res.status(400).json({ error: 'name, email, and message are required' });

    const key = apiKey || process.env.RESEND_API_KEY || '';
    if (!key) return res.status(400).json({ error: 'Email service not configured. Please set RESEND_API_KEY in .env' });

    const html = `
      <div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto">
        <div style="background:linear-gradient(135deg,#1e40af,#7c3aed);padding:24px;border-radius:8px 8px 0 0">
          <h2 style="color:#fff;margin:0;font-size:20px">New Contact Form Submission — DataGuard</h2>
        </div>
        <div style="background:#f8fafc;padding:24px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 8px 8px">
          <table style="width:100%;border-collapse:collapse;font-size:14px">
            <tr><td style="padding:8px 0;color:#64748b;width:120px">Name</td><td style="padding:8px 0;font-weight:600">${name}</td></tr>
            <tr><td style="padding:8px 0;color:#64748b">Email</td><td style="padding:8px 0"><a href="mailto:${email}">${email}</a></td></tr>
            ${company ? `<tr><td style="padding:8px 0;color:#64748b">Company</td><td style="padding:8px 0">${company}</td></tr>` : ''}
            ${sector ? `<tr><td style="padding:8px 0;color:#64748b">Sector</td><td style="padding:8px 0"><span style="background:#dbeafe;color:#1e40af;padding:2px 8px;border-radius:99px;font-size:12px;font-weight:600">${sector}</span></td></tr>` : ''}
          </table>
          <div style="margin-top:16px;padding:16px;background:#fff;border:1px solid #e2e8f0;border-radius:6px">
            <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Message</div>
            <div style="font-size:14px;line-height:1.6;color:#1e293b;white-space:pre-wrap">${message}</div>
          </div>
          <div style="margin-top:16px;font-size:11px;color:#94a3b8">Sent from dataguard.dataquality.health</div>
        </div>
      </div>`;

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
      body: JSON.stringify({
        from: 'DataGuard Contact <onboarding@resend.dev>',
        to: ['email.nehatyagi@gmail.com'],
        reply_to: email,
        subject: `[DataGuard] New inquiry from ${name}${company ? ` at ${company}` : ''}`,
        html
      })
    });

    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.message || `Email API error ${response.status}`);
    res.json({ success: true, id: result.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════
//  EMAIL NOTIFICATIONS — sends a high-level validation summary
//  (errors, exceptions, top triggered rules) via the Resend transactional email API.
// ══════════════════════════════════════════════════════════
app.post('/api/notify/email', async (req, res) => {
  try {
    const { apiKey, to, from, results, aiAnalysis, subject } = req.body;
    const key = apiKey || process.env.RESEND_API_KEY || '';
    if (!key) return res.status(400).json({ error: 'Resend API key is required (pass apiKey, or set RESEND_API_KEY in the environment)' });
    if (!to)  return res.status(400).json({ error: 'Recipient email address (to) is required' });
    if (!results?.length) return res.status(400).json({ error: 'No validation results to email' });

    const sendResult = await sendNotificationEmail({ apiKey: key, to, from, results, aiAnalysis, subject });
    res.json({ success: true, ...sendResult });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════
//  FILE CHECK
// ══════════════════════════════════════════════════════════
app.post('/api/file/check', async (req,res) => {
  let { filePath } = req.body;
  if (!filePath) return res.status(400).json({ error:'filePath required' });

  // Normalize path: expand ~, resolve relative paths, trim whitespace/quotes
  filePath = filePath.trim().replace(/^['"]|['"]$/g, ''); // strip accidental quotes
  if (filePath.startsWith('~')) {
    filePath = filePath.replace(/^~/, require('os').homedir());
  }
  filePath = path.resolve(filePath); // resolve relative paths to absolute

  // Check existence — distinguish "not found" from "permission denied"
  let exists = false;
  let permissionDenied = false;
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    exists = true;
  } catch (e) {
    if (e.code === 'EACCES' || e.code === 'EPERM') {
      permissionDenied = true;
    }
  }

  // If exists, check read permission separately
  if (exists) {
    try {
      fs.accessSync(filePath, fs.constants.R_OK);
    } catch (e) {
      permissionDenied = true;
      exists = false;
    }
  }

  if (permissionDenied) {
    return res.status(403).json({
      exists: false,
      permissionDenied: true,
      resolvedPath: filePath,
      error: `Permission denied: the server cannot read this file. Run: chmod 644 "${filePath}" in Terminal to fix this.`
    });
  }

  if (!exists) {
    // Give a helpful diagnostic — list what IS in the parent directory
    const parentDir = path.dirname(filePath);
    let parentContents = [];
    try {
      const SUPPORTED = ['.csv','.txt','.json','.parquet'];
      parentContents = fs.readdirSync(parentDir)
        .filter(f => {
          const ext = path.extname(f).toLowerCase();
          return SUPPORTED.includes(ext);
        })
        .slice(0, 10);
    } catch {}

    return res.status(404).json({
      exists: false,
      resolvedPath: filePath,
      parentDir,
      parentContents, // files in same folder the server CAN see
      error: `File not found: ${filePath}`
    });
  }

  let size=null, lines=null, format=null, columns=null;
  try {
    size = fs.statSync(filePath).size;
    const loaded = await loadFile(fs.readFileSync(filePath), path.basename(filePath));
    lines   = loaded.rows.length;
    columns = loaded.headers.length;
    format  = loaded.format;
  } catch (e) {
    lines = null;
  }

  res.json({ exists: true, size, lines, columns, format, filePath, resolvedPath: filePath });
});

// ══════════════════════════════════════════════════════════
//  REGULATORY RULE PACKS — BCBS 239 / CCAR (data-quality templates)
// ══════════════════════════════════════════════════════════

// List available packs and their disclaimer text
app.get('/api/rule-packs', (req, res) => {
  res.json({ packs: PACK_METADATA });
});

// Preview a pack's rules without saving
app.get('/api/rule-packs/:packId/preview', (req, res) => {
  try {
    const rules = req.params.packId === 'aml' ? getAmlPack() : getRulePack(req.params.packId);
    if (!rules.length) return res.status(404).json({ error: `Unknown pack: ${req.params.packId}` });
    res.json({ packId: req.params.packId, metadata: PACK_METADATA[req.params.packId], rules, count: rules.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ID prefix per pack — keeps imported rules visually and structurally
// distinguishable in the CSV (BCBS_001, CCAR_001, AML_001, …) from manual/AI rules (RULE_NNN).
const PACK_ID_PREFIX = {
  bcbs239: 'BCBS', ccar: 'CCAR', aml: 'AML',
  insurance: 'INS', reinsurance: 'REINS',
  manufacturing_retail: 'MFG', supply_chain: 'SC',
  life_sciences: 'LS'
};

// Import (save) a pack's rules into the CSV — assigns sequential, prefixed IDs to each
app.post('/api/rule-packs/:packId/import', (req, res) => {
  try {
    const rules = req.params.packId === 'aml' ? getAmlPack() : getRulePack(req.params.packId);
    if (!rules.length) return res.status(404).json({ error: `Unknown pack: ${req.params.packId}` });

    const prefix = PACK_ID_PREFIX[req.params.packId] || 'RULE';
    const imported = [];
    for (const rule of rules) {
      const ruleToSave = { ...rule, rule_id: nextRuleId(prefix), created_at: new Date().toISOString(), source: `pack:${req.params.packId}` };
      const savedId = saveRuleToCSV(ruleToSave);
      imported.push({ ...ruleToSave, rule_id: savedId });
    }
    syncCSV();
    res.json({ success: true, packId: req.params.packId, imported, count: imported.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Unimport a pack — bulk-deletes every rule whose source matches "pack:<packId>"
app.post('/api/rule-packs/:packId/unimport', (req, res) => {
  try {
    const source  = `pack:${req.params.packId}`;
    const deleted = deleteRulesBySource(source);
    if (!deleted.length) {
      return res.status(404).json({ error: `No imported rules found for pack "${req.params.packId}" — nothing to remove.` });
    }
    syncCSV();
    res.json({ success: true, packId: req.params.packId, deleted, count: deleted.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get current import counts per pack (used to show "Imported: N" / disable Import vs show Unimport in the UI)
app.get('/api/rule-packs/status', (req, res) => {
  try {
    const rules = loadRulesFromCSV();
    const counts = {};
    for (const r of rules) {
      if (r.source && r.source.startsWith('pack:')) {
        const packId = r.source.slice(5);
        counts[packId] = (counts[packId] || 0) + 1;
      }
    }
    res.json({ counts });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════
//  FRAUD HEURISTICS CATALOG (advisory pattern flags — see fraudHeuristics.js)
// ══════════════════════════════════════════════════════════
app.get('/api/fraud-heuristics', (req, res) => {
  res.json({
    heuristics: FRAUD_RULE_CATALOG,
    disclaimer: 'These are basic rule-of-thumb heuristics for surfacing potentially anomalous patterns. ' +
      'They are NOT sanctions/watchlist screening, real-time AML monitoring, or a substitute for a licensed ' +
      'AML/fraud detection platform. They do not on their own satisfy NYDFS 23 NYCRR 500 or other AML ' +
      'regulatory program requirements. Treat results as advisory signals for human review only.'
  });
});

// ══════════════════════════════════════════════════════════
//  RULES CRUD — every mutation calls syncCSV()
// ══════════════════════════════════════════════════════════
app.get('/api/rules', (req,res) => {
  try { res.json({ rules:loadRulesFromCSV(), csvPath:RULES_CSV_PATH, nextId:nextRuleId() }); }
  catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/rules', (req,res) => {
  try {
    const rule = req.body;
    if (!rule.column_name||!rule.rule_type||!rule.error_message)
      return res.status(400).json({error:'column_name, rule_type, error_message are required'});
    rule.rule_id    = nextRuleId();
    rule.created_at = new Date().toISOString();
    rule.source     = 'manual';
    const savedId   = saveRuleToCSV(rule);
    syncCSV();
    res.json({ success:true, rule:{...rule, rule_id:savedId} });
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.put('/api/rules/:id', (req,res) => {
  try {
    const updates = req.body;
    if (!updates.column_name||!updates.rule_type||!updates.error_message)
      return res.status(400).json({error:'column_name, rule_type, error_message are required'});
    if (typeof updates.column_aliases==='string')
      updates.column_aliases = updates.column_aliases.split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
    const updated = updateRuleInCSV(req.params.id, updates);
    syncCSV();
    res.json({ success:true, rule:updated });
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/rules/:id', (req,res) => {
  try { deleteRuleFromCSV(req.params.id); syncCSV(); res.json({success:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

app.patch('/api/rules/:id/toggle', (req,res) => {
  try { toggleRuleInCSV(req.params.id, req.body.enabled); syncCSV(); res.json({success:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// NLP parse + optionally save
app.post('/api/rules/parse', async (req,res) => {
  try {
    const { description, apiKey, save } = req.body;
    if (!description) return res.status(400).json({error:'description is required'});
    const key = apiKey || process.env.ANTHROPIC_API_KEY || '';
    if (!key) return res.status(400).json({error:'Anthropic API key required'});
    const rule   = await parseNaturalLanguageRule(description, key);
    rule.rule_id = nextRuleId();
    rule.source  = 'nlp';
    if (save) { saveRuleToCSV(rule); syncCSV(); }
    res.json({ success:true, rule });
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════
//  AI CHAT — conversational rule management
// ══════════════════════════════════════════════════════════
app.post('/api/chat', async (req, res) => {
  try {
    const { messages, apiKey } = req.body;
    if (!messages?.length) return res.status(400).json({ error: 'messages array required' });
    const key = apiKey || process.env.ANTHROPIC_API_KEY || '';
    if (!key) return res.status(400).json({ error: 'Anthropic API key required' });

    // Current rules snapshot for the AI
    const rules    = loadRulesFromCSV();
    const nextId   = nextRuleId();
    const rulesCtx = rules.map(r =>
      `${r.rule_id} | ${r.column_name} | ${r.rule_type} | value="${r.rule_value}" | ${r.enabled?'enabled':'DISABLED'} | msg="${r.error_message}"`
    ).join('\n');

    const SYSTEM = `You are DataGuard, an expert AI assistant for managing CSV data validation rules.

CURRENT RULES IN SYSTEM (${rules.length} total, next ID will be ${nextId}):
${rulesCtx || '(no rules yet)'}

RULES CSV FILE: ${RULES_CSV_PATH}

You can help the user:
1. ADD a new rule — respond with JSON action: {"action":"add","rule":{...}}
2. EDIT an existing rule — respond with JSON action: {"action":"edit","rule_id":"RULE_XXX","updates":{...}}
3. DELETE a rule — respond with JSON action: {"action":"delete","rule_id":"RULE_XXX"}
4. ENABLE/DISABLE a rule — respond with JSON action: {"action":"toggle","rule_id":"RULE_XXX","enabled":true/false}
5. EXPLAIN rules or answer questions — just respond in plain text

RULE TYPES available: regex, starts_with, ends_with, min_length, max_length, exact_length, numeric_only, not_empty, min_value, max_value, one_of

ADDITIONAL CAPABILITIES you can tell the user about if asked:
- BCBS 239 and CCAR rule packs (field-level data quality templates inspired by those standards' principles — NOT a compliance certification) can be imported via the "Rule Packs" tab.
- Basic fraud/anomaly heuristics (large amount, round amount, velocity, duplicate row, structuring pattern, just-below-threshold) are available via the "Fraud Heuristics" section on the Validate Data tab. These are advisory pattern flags only — explicitly NOT sanctions screening or regulatory AML monitoring. If the user asks you to "add AML rules" or "add fraud detection," explain this distinction and point them to that tab/section rather than fabricating a fake compliance rule.

RESPONSE FORMAT:
- For actions: ALWAYS wrap the JSON in a <ACTION> tag on its own line, then give a human explanation. Example:
  <ACTION>{"action":"add","rule":{"column_name":"Email","column_aliases":["email","email_address"],"rule_type":"regex","rule_value":"^[^@]+@[^@]+\\.[^@]+$","error_message":"Email must be a valid address","description":"Email format check","enabled":true}}</ACTION>
  I've created a new rule that validates Email columns...

- For questions/explanations: just respond normally in markdown.
- Be conversational, helpful, and concise.
- When adding a rule, do NOT include rule_id (the system assigns it).
- When the user says "disable RULE_003" or "turn off SSN rule", use the toggle action.
- Always confirm what you did and the impact.`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'x-api-key':key, 'anthropic-version':'2023-06-01' },
      body: JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:1200, system:SYSTEM, messages })
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Claude API ${response.status}: ${err}`);
    }

    const data    = await response.json();
    const aiText  = data.content?.find(b => b.type==='text')?.text || '';

    // Parse and execute any embedded action
    const actionMatch = aiText.match(/<ACTION>([\s\S]*?)<\/ACTION>/);
    let actionResult  = null;
    let cleanText     = aiText.replace(/<ACTION>[\s\S]*?<\/ACTION>/g, '').trim();

    if (actionMatch) {
      try {
        const action = JSON.parse(actionMatch[1].trim());
        actionResult = await executeAction(action, nextId);
        if (actionResult.synced) syncCSV();
      } catch (e) {
        actionResult = { error: 'Failed to execute action: ' + e.message };
      }
    }

    res.json({ success:true, message:cleanText, actionResult, rules:loadRulesFromCSV() });
  } catch(e){ res.status(500).json({ error: e.message }); }
});

async function executeAction(action, nextId) {
  switch (action.action) {
    case 'add': {
      const rule = { ...action.rule, rule_id: nextId, created_at: new Date().toISOString(), enabled: action.rule.enabled !== false, source: 'ai_chat' };
      if (!Array.isArray(rule.column_aliases)) {
        rule.column_aliases = [rule.column_name.toLowerCase()];
      }
      const savedId = saveRuleToCSV(rule);
      return { type:'added', rule_id:savedId, rule, synced:true };
    }
    case 'edit': {
      const updates = action.updates || {};
      if (typeof updates.column_aliases === 'string')
        updates.column_aliases = updates.column_aliases.split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
      const updated = updateRuleInCSV(action.rule_id, updates);
      return { type:'edited', rule_id:action.rule_id, rule:updated, synced:true };
    }
    case 'delete': {
      deleteRuleFromCSV(action.rule_id);
      return { type:'deleted', rule_id:action.rule_id, synced:true };
    }
    case 'toggle': {
      toggleRuleInCSV(action.rule_id, action.enabled);
      return { type:'toggled', rule_id:action.rule_id, enabled:action.enabled, synced:true };
    }
    default:
      return { type:'unknown', action: action.action };
  }
}

// ══════════════════════════════════════════════════════════
//  TUNNEL STATUS
// ══════════════════════════════════════════════════════════
app.get('/api/tunnel', (req,res) => {
  res.json({ url: publicUrl, active: !!publicUrl });
});

// Health
app.get('/api/health', (req,res) =>
  res.json({ status:'ok', version:'2.2.1', csvPath:RULES_CSV_PATH, tunnel:publicUrl, hasAnthropicKey: !!(process.env.ANTHROPIC_API_KEY), hasResendKey: !!(process.env.RESEND_API_KEY) })
);

// ══════════════════════════════════════════════════════════
//  USERS — registration and identity
// ══════════════════════════════════════════════════════════
app.post('/api/users/register', (req, res) => {
  try {
    const result = users.register(req.body);
    if (!result.created && result.conflict === 'userId') {
      return res.status(409).json({ error: `User ID "${req.body.userId}" is already taken. Choose a different one.`, conflict: 'userId' });
    }
    if (!result.created && result.conflict === 'email') {
      // Email exists — return the existing user (effectively "login")
      return res.json({ user: result.user, created: false, message: 'Welcome back! User with this email already exists.' });
    }
    res.status(201).json({ user: result.user, created: true });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/users/verify', (req, res) => {
  const { userId, email } = req.body;
  const user = users.verify(userId, email);
  user ? res.json({ valid: true, user }) : res.status(401).json({ valid: false, error: 'No user found with that userId + email combination.' });
});

app.get('/api/users/find', (req, res) => {
  const user = users.findUser(req.query.identity);
  user ? res.json({ user }) : res.status(404).json({ error: 'User not found' });
});

// ══════════════════════════════════════════════════════════
//  OAUTH — GitHub and GitLab
// ══════════════════════════════════════════════════════════
app.get('/api/auth/github', (req, res) => {
  if (!process.env.GITHUB_CLIENT_ID)
    return res.status(503).send('GitHub OAuth not configured. Add GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET to .env');
  res.redirect(git.githubAuthUrl(git.randomState()));
});

app.get('/api/auth/github/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const token = await git.exchangeGitHubCode(code);
    const user  = await git.getGitHubUser(token);
    try { users.register({ userId: user.userId, email: user.email || `${user.githubLogin}@github`, fullName: user.fullName }); } catch {}
    const sessionToken = git.randomState();
    git.storeOAuthSession(sessionToken, { ...user, githubToken: token });
    res.redirect(`/validator.html?dg_token=${sessionToken}`);
  } catch(e) { res.status(500).send(`GitHub OAuth error: ${e.message}`); }
});

app.get('/api/auth/gitlab', (req, res) => {
  if (!process.env.GITLAB_CLIENT_ID)
    return res.status(503).send('GitLab OAuth not configured. Add GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET to .env');
  res.redirect(git.gitlabAuthUrl(git.randomState()));
});

app.get('/api/auth/gitlab/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const token = await git.exchangeGitLabCode(code);
    const user  = await git.getGitLabUser(token);
    try { users.register({ userId: user.userId, email: user.email || `${user.gitlabUsername}@gitlab`, fullName: user.fullName }); } catch {}
    const sessionToken = git.randomState();
    git.storeOAuthSession(sessionToken, { ...user, gitlabToken: token });
    res.redirect(`/validator.html?dg_token=${sessionToken}`);
  } catch(e) { res.status(500).send(`GitLab OAuth error: ${e.message}`); }
});

app.post('/api/users/oauth-session', (req, res) => {
  const user = git.resolveOAuthSession(req.body?.token || '');
  user ? res.json({ user }) : res.status(404).json({ error: 'Session not found or expired' });
});

// ══════════════════════════════════════════════════════════
//  GIT — Repos, code checkin, rules export, GitHub Pages
// ══════════════════════════════════════════════════════════
app.post('/api/git/repos', async (req, res) => {
  try {
    const { token, provider } = req.body;
    if (!token || !provider) return res.status(400).json({ error: 'token and provider are required' });
    const repos = await git.listRepos(token, provider);
    res.json({ success: true, repos });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/git/commit', async (req, res) => {
  try {
    const { token, provider, owner, repo, projectId, filePath, content, message, branch } = req.body;
    if (!token || !provider || !filePath || content === undefined)
      return res.status(400).json({ error: 'token, provider, filePath, and content are required' });
    let result;
    if (provider === 'github') {
      result = await git.commitToGitHub({ token, owner, repo, filePath, content, message: message||'DataGuard: update', branch: branch||'main' });
    } else {
      result = await git.commitToGitLab({ token, projectId, filePath, content, message: message||'DataGuard: update', branch: branch||'main' });
    }
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/git/export-rules', async (req, res) => {
  try {
    const { token, provider, owner, repo, projectId, branch } = req.body;
    if (!token || !provider) return res.status(400).json({ error: 'token and provider required' });
    const { loadRules } = require('./src/ruleManager');
    const allRules = loadRules();
    const ts = new Date().toISOString().slice(0,10);
    const jsonContent = JSON.stringify(allRules, null, 2);
    const csvHdr = ['rule_id','column_name','rule_type','rule_value','error_message','enabled','source','description'].join(',');
    const csvContent = [csvHdr, ...allRules.map(r => ['rule_id','column_name','rule_type','rule_value','error_message','enabled','source','description'].map(k=>`"${String(r[k]||'').replace(/"/g,'""')}"`).join(','))].join('\n');
    const results = [];
    for (const [file, content] of [[`dataguard-rules-${ts}.json`,jsonContent],[`dataguard-rules-${ts}.csv`,csvContent]]) {
      try {
        const r = provider==='github'
          ? await git.commitToGitHub({ token, owner, repo, filePath:`dataguard/${file}`, content, message:`DataGuard: export rules ${ts}`, branch:branch||'main' })
          : await git.commitToGitLab({ token, projectId, filePath:`dataguard/${file}`, content, message:`DataGuard: export rules ${ts}`, branch:branch||'main' });
        results.push({ file, ...r });
      } catch(e) { results.push({ file, error: e.message }); }
    }
    res.json({ success: true, results, ruleCount: allRules.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/git/pages', async (req, res) => {
  try {
    const { token, owner, repo, enable, branch, pagePath } = req.body;
    if (!token || !owner || !repo) return res.status(400).json({ error: 'token, owner, repo required' });
    const result = enable
      ? await git.enableGitHubPages(token, owner, repo, branch||'main', pagePath||'/')
      : await git.triggerGitHubPagesDeploy(token, owner, repo);
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
//  DOCUSMART — AI-powered metadata catalog generation
//  Scans column names + inferred types from imported sources,
//  calls Claude AI to generate business metadata for each column.
// ══════════════════════════════════════════════════════════
app.post('/api/docu/scan', async (req, res) => {
  try {
    const { schemas = [] } = req.body;
    if (!schemas.length) return res.status(400).json({ error: 'schemas array is required' });

    const apiKey = process.env.ANTHROPIC_API_KEY || '';
    if (!apiKey) return res.status(400).json({
      error: 'ANTHROPIC_API_KEY is not set. Add it to your .env file and restart the server.',
      hint: 'Open your .env file and add: ANTHROPIC_API_KEY=sk-ant-your-key-here'
    });

    // Flatten all columns across all sources
    const allColumns = [];
    for (const src of schemas) {
      for (const table of (src.tables || [])) {
        for (const col of (table.columns || [])) {
          allColumns.push({
            sourceLabel: src.label,
            sourceType: src.type || 'file',
            tableName: table.name,
            technicalName: col.name,
            inferredType: col.type || 'text'
          });
        }
      }
    }

    if (!allColumns.length) return res.status(400).json({ error: 'No columns found in provided schemas' });

    // Build prompt — batch in groups of 40 to stay within context
    const BATCH = 40;
    const catalog = [];
    const batches = [];
    for (let i = 0; i < allColumns.length; i += BATCH) batches.push(allColumns.slice(i, i + BATCH));

    const https = require('https');
    async function callClaude(prompt) {
      const body = JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 4096,
        messages: [{ role: 'user', content: prompt }]
      });
      return new Promise((resolve, reject) => {
        const opts = {
          hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST', port: 443,
          headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(body) }
        };
        const rq = https.request(opts, rs => {
          let data = '';
          rs.on('data', c => data += c);
          rs.on('end', () => {
            try { resolve(JSON.parse(data)); } catch(e) { reject(new Error('JSON parse error: ' + data.slice(0,200))); }
          });
        });
        rq.on('error', reject);
        rq.write(body); rq.end();
      });
    }

    for (const batch of batches) {
      const columnList = batch.map((c, i) =>
        `${i+1}. Source="${c.sourceLabel}" Table="${c.tableName}" Column="${c.technicalName}" InferredType="${c.inferredType}"`
      ).join('\n');

      const prompt = `You are a senior enterprise data architect generating a comprehensive data catalog / metadata dictionary.

For each column below, return a JSON array where each element has EXACTLY these fields:
- technicalName: the exact column name as provided
- businessName: human-readable business name (Title Case, spaces, e.g. "Customer Date of Birth")
- description: 1-2 sentence plain-English description of what the column stores
- dataType: recommended canonical data type (VARCHAR(255), INTEGER, DATE, DECIMAL(18,4), BOOLEAN, TIMESTAMP, TEXT, etc.)
- nullable: boolean — true if the field could reasonably be optional, false if it should always have a value
- pii: boolean — true if this column likely contains Personally Identifiable Information (name, email, phone, address, SSN, DOB, IP, device ID, etc.)
- phi: boolean — true if this column likely contains Protected Health Information (diagnosis, medication, lab result, medical record number, treatment, insurance ID, etc.)
- industryStandard: boolean — true if this is a recognised industry-standard field name (ISIN, LEI, NPI, NDC, ICD10, USUBJID, CUSIP, IBAN, VIN, DUNS, EAN, GTIN, etc.)
- defaultValue: reasonable default value if the field is empty/null, or "" if no sensible default
- recommendedValue: canonical format note or allowed values list, e.g. "ISO 8601 YYYY-MM-DD" or "active|inactive|pending"
- probableUsage: one of: "identifier", "measure", "dimension", "date", "flag", "code", "text", "financial", "contact", "audit"
- recommendedRules: comma-separated list of data quality checks recommended for this column, e.g. "not_empty, regex:^\\d{4}-\\d{2}-\\d{2}$, min_length:1"
- sensitivityLevel: one of: "public", "internal", "confidential", "restricted"

IMPORTANT: Return ONLY a valid JSON array starting with [ and ending with ]. No markdown fences, no prose, no explanation before or after.

Columns to catalog:
${columnList}`;

      let resp;
      try { resp = await callClaude(prompt); }
      catch(e) { throw new Error(`Anthropic API call failed: ${e.message}`); }

      // Check for API-level errors (authentication, rate limit, etc.)
      if (resp.type === 'error' || resp.error) {
        const errMsg = resp.error?.message || JSON.stringify(resp.error) || 'Unknown API error';
        throw new Error(`Anthropic API error: ${errMsg}`);
      }

      const text = (resp.content || []).map(c => c.text || '').join('').trim();

      if (!text) {
        const hint = resp.stop_reason ? ` (stop_reason: ${resp.stop_reason})` : '';
        throw new Error(`Anthropic returned empty response${hint}. Check your API key and model access.`);
      }

      let parsed;
      try {
        // Strip markdown fences if present
        const cleaned = text
          .replace(/^```json\s*/i, '').replace(/^```\s*/i, '')
          .replace(/```\s*$/,'').trim();
        parsed = JSON.parse(cleaned);
      } catch(e) {
        // Try to extract just the JSON array from surrounding prose
        const match = text.match(/\[[\s\S]*\]/);
        if (match) {
          try { parsed = JSON.parse(match[0]); } catch(e2) {}
        }
        if (!parsed) {
          // Build fallback catalog from column names rather than failing
          console.warn('[DocuSmart] JSON parse failed, using fallback. Raw response:', text.slice(0, 500));
          parsed = batch.map(col => ({
            technicalName: col.technicalName,
            businessName: col.technicalName.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase()),
            description: `Column "${col.technicalName}" of type ${col.inferredType}.`,
            dataType: col.inferredType, nullable: true, pii: false, phi: false,
            industryStandard: false, defaultValue: '', recommendedValue: '',
            probableUsage: 'dimension', recommendedRules: 'not_empty',
            sensitivityLevel: 'internal'
          }));
        }
      }

      // Merge AI results back with source/table info
      batch.forEach((col, i) => {
        const ai = parsed[i] || {};
        catalog.push({
          sourceLabel:      col.sourceLabel,
          sourceType:       col.sourceType,
          tableName:        col.tableName,
          technicalName:    col.technicalName,
          businessName:     ai.businessName     || col.technicalName.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase()),
          description:      ai.description      || '',
          dataType:         ai.dataType         || col.inferredType,
          nullable:         ai.nullable         !== undefined ? ai.nullable : true,
          pii:              ai.pii              || false,
          phi:              ai.phi              || false,
          industryStandard: ai.industryStandard || false,
          defaultValue:     ai.defaultValue     || '',
          recommendedValue: ai.recommendedValue || '',
          probableUsage:    ai.probableUsage    || '',
          recommendedRules: ai.recommendedRules || '',
          sensitivityLevel: ai.sensitivityLevel || 'internal',
        });
      });
    }

    res.json({ success: true, catalog, totalColumns: catalog.length });
  } catch(err) { res.status(500).json({ error: err.message }); }
});


//  All endpoints require ?userId= (or userId in body).
//  Projects are visible to their owner + anyone in sharedWith[].
// ══════════════════════════════════════════════════════════
function resolveUserId(req) {
  return (req.query.userId || req.body?.userId || req.headers['x-user-id'] || '').trim().toLowerCase();
}

app.get('/api/projects', (req, res) => {
  const uid = resolveUserId(req);
  if (!uid) return res.status(400).json({ error: 'userId is required (pass as ?userId= or X-User-Id header)' });
  const all = getAll();
  const visible = all.filter(p =>
    p.ownerId === uid ||
    (p.sharedWith || []).some(s => s.toLowerCase() === uid)
  );
  res.json({ projects: visible });
});

app.get('/api/projects/:id', (req, res) => {
  const uid = resolveUserId(req);
  const p = getById(req.params.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  if (p.ownerId !== uid && !(p.sharedWith||[]).some(s => s.toLowerCase() === uid))
    return res.status(403).json({ error: 'Access denied — this project belongs to another user' });
  res.json(p);
});

app.post('/api/projects', (req, res) => {
  try {
    const uid = resolveUserId(req);
    if (!uid) return res.status(400).json({ error: 'userId is required' });
    const p = create({ ...req.body, ownerId: uid, sharedWith: req.body.sharedWith || [] });
    res.status(201).json(p);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/projects/:id', (req, res) => {
  const uid = resolveUserId(req);
  const p = getById(req.params.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  if (p.ownerId !== uid) return res.status(403).json({ error: 'Only the project owner can update it' });
  const updated = update(req.params.id, req.body);
  res.json(updated);
});

app.delete('/api/projects/:id', (req, res) => {
  const uid = resolveUserId(req);
  const p = getById(req.params.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  if (p.ownerId !== uid) return res.status(403).json({ error: 'Only the project owner can delete it' });
  remove(req.params.id);
  res.json({ success: true });
});

// Save/load per-page state within a project (lineageState, validatorState, etc.)
app.put('/api/projects/:id/state/:stateKey', (req, res) => {
  const result = saveState(req.params.id, req.params.stateKey, req.body.state);
  result ? res.json({ success: true }) : res.status(404).json({ error: 'Project not found' });
});
app.get('/api/projects/:id/state/:stateKey', (req, res) => {
  const state = loadState(req.params.id, req.params.stateKey);
  res.json({ state });
});

// ══════════════════════════════════════════════════════════
//  CLOUD STORAGE — S3, Azure Blob, Google Cloud Storage
// ══════════════════════════════════════════════════════════

// List files in a cloud storage bucket/container
app.post('/api/cloud/list', async (req, res) => {
  try {
    const { provider, ...config } = req.body;
    let files;
    switch (provider) {
      case 's3':    files = await cloudStorage.listS3Files(config); break;
      case 'azure': files = await cloudStorage.listAzureBlobs(config); break;
      case 'gcs':   files = await cloudStorage.listGCSFiles(config); break;
      default: return res.status(400).json({ error: `Unknown cloud provider: ${provider}. Use s3, azure, or gcs.` });
    }
    res.json({ success: true, files, count: files.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Fetch a single cloud file and return its lineage schema
app.post('/api/cloud/fetch-schema', async (req, res) => {
  try {
    const { provider, ...config } = req.body;
    let result;
    switch (provider) {
      case 's3':    result = await cloudStorage.fetchFromS3(config); break;
      case 'azure': result = await cloudStorage.fetchFromAzure(config); break;
      case 'gcs':   result = await cloudStorage.fetchFromGCS(config); break;
      default: return res.status(400).json({ error: `Unknown provider: ${provider}` });
    }
    const { loadFile } = require('./src/fileLoader');
    const { inferColumnType } = require('./src/lineage');
    const { headers, rows, format } = await loadFile(result.buffer, result.fileName);
    const sampleRows = rows.slice(0, 100);
    const columns = headers.map((name, ci) => {
      const vals = sampleRows.map(r => r[ci] || '').filter(v => v !== '');
      return { name, type: inferColumnType(vals), isPrimaryKey: false };
    });
    const stem = result.fileName.replace(/\.[^.]+$/, '');
    const schema = {
      source: 'file', label: result.fileName,
      filePath: null, format, rowCount: rows.length,
      cloudProvider: provider,
      tables: [{ name: stem, columns }], foreignKeys: []
    };
    res.json({ success: true, schema });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Fetch a cloud file for validation (returns it as multipart to the validate endpoint)
app.post('/api/cloud/validate', async (req, res) => {
  try {
    const { provider, ...config } = req.body;
    let result;
    switch (provider) {
      case 's3':    result = await cloudStorage.fetchFromS3(config); break;
      case 'azure': result = await cloudStorage.fetchFromAzure(config); break;
      case 'gcs':   result = await cloudStorage.fetchFromGCS(config); break;
      default: return res.status(400).json({ error: `Unknown provider: ${provider}` });
    }
    const { validateFile } = require('./src/validator');
    const fraudHeuristics = [];
    const validationResult = await validateFile(result.buffer, result.fileName, { fraudHeuristics });
    res.json({ success: true, results: [validationResult], fileName: result.fileName });
  } catch(e) { res.status(500).json({ error: e.message }); }
});



// SPA fallback — serve landing page for unknown paths
app.get('*', (req,res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

// ══════════════════════════════════════════════════════════
//  START SERVER + OPTIONAL TUNNEL
// ══════════════════════════════════════════════════════════
app.listen(PORT, async () => {
  console.log(`\n🚀 DataGuard Agent v2.9 running at http://localhost:${PORT}`);
  console.log(`   Validator:    http://localhost:${PORT}`);
  console.log(`   Rule Builder: http://localhost:${PORT}/rules.html`);
  console.log(`   Rules CSV:    ${RULES_CSV_PATH}`);

  if (USE_TUNNEL) {
    console.log('\n🌐 Starting Cloudflare tunnel…');
    try {
      const { connectToCloudflare } = require('./src/tunnel');
      publicUrl = await connectToCloudflare(PORT);
      console.log(`\n✅ PUBLIC URL: ${publicUrl}`);
      console.log(`   Share this link to access from anywhere!\n`);
      // Write public URL to a file for easy copy-paste
      fs.writeFileSync(path.join(__dirname, '.tunnel-url'), publicUrl, 'utf8');
    } catch (e) {
      console.error('⚠️  Tunnel failed:', e.message);
      console.log('   Run with "npm start" for local access only.\n');
    }
  } else {
    console.log('\n   💡 Tip: Run "npm run tunnel" to expose publicly via Cloudflare\n');
  }
});

module.exports = app;
