<<<<<<< HEAD
# DataGuard Agent — CSV/TXT File Validator

An AI-powered data validation agent with a full web UI that checks comma-separated `.txt` files against defined business rules.

---

## Validation Rules

| Column | Rule |
|--------|------|
| **SSN** | Must match `000-00-0000` (3 digits, hyphen, 2 digits, hyphen, 4 digits). Numbers only. |
| **Account Number** | Must start with `AA_000` and be **at least 12 characters** long. |
| **Year of Birth** | Must be a **number** and must be **≥ 1980**. |

Column detection is **case-insensitive** and supports common aliases (e.g. `year_of_birth`, `yob`, `acct_number`, etc.).

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure (optional — for AI analysis)
```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### 3. Start the server
```bash
npm start
```

### 4. Open the UI
Visit **http://localhost:3000** in your browser.

---

## Usage

1. **Upload** one or more comma-separated `.txt` files via drag-and-drop or file picker
2. **Optionally** enable AI Analysis and enter your Anthropic API key
3. Click **Run Validation**
4. Review the results:
   - Summary stats (files passed/failed, total errors)
   - Per-column analysis (min/max/avg character lengths, error counts)
   - Detailed error table with row numbers, column names, rule violated, and the bad value
   - AI-generated analysis with root cause analysis and fix recommendations

---

## Deployment Options

### Option A: Node.js (any server/VPS)
```bash
npm install
npm start
# Runs on port 3000 by default; set PORT env var to change
```

### Option B: Docker
```bash
docker build -t dataguard-agent .
docker run -p 3000:3000 -e ANTHROPIC_API_KEY=sk-ant-... dataguard-agent
```

### Option C: Docker Compose
```yaml
version: '3.8'
services:
  dataguard:
    build: .
    ports:
      - "3000:3000"
    environment:
      - ANTHROPIC_API_KEY=sk-ant-your-key-here
    restart: unless-stopped
```

### Option D: Railway / Render / Fly.io
Push this repo and set the `ANTHROPIC_API_KEY` environment variable in the dashboard. These platforms auto-detect Node.js apps.

### Option E: Heroku
```bash
heroku create your-app-name
heroku config:set ANTHROPIC_API_KEY=sk-ant-...
git push heroku main
```

---

## API Reference

### `POST /api/validate`
Validate uploaded files.

**Form fields:**
- `files` — one or more `.txt` files (multipart/form-data)
- `useAI` — `"true"` or `"false"`
- `apiKey` — Anthropic API key (optional if set in env)

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "fileName": "data.txt",
      "totalRows": 100,
      "totalColumns": 5,
      "headers": ["Name", "SSN", "Account Number", "Year of Birth", "Email"],
      "columnStats": [...],
      "errors": [
        {
          "row": 3,
          "column": "SSN",
          "value": "1234567890",
          "rule": "SSN Format",
          "message": "SSN must match format 000-00-0000..."
        }
      ],
      "summary": {
        "totalErrors": 4,
        "errorsByRule": { "SSN Format": 2, "Account Number Length": 2 },
        "errorsByColumn": { "SSN": 2, "Account Number": 2 }
      },
      "passed": false
    }
  ],
  "aiAnalysis": "## Executive Summary...",
  "summary": {
    "totalFiles": 1,
    "filesPass": 0,
    "filesFail": 1,
    "totalErrors": 4
  }
}
```

### `GET /api/rules`
Returns the list of active validation rules and column aliases.

### `GET /api/health`
Health check endpoint.

---

## Project Structure

```
csv-validator/
├── server.js               # Express server + API routes
├── src/
│   ├── validator.js        # Core validation engine
│   └── agent.js            # AI agent (Claude API integration)
├── public/
│   └── index.html          # Full-featured web UI
├── sample-data/
│   ├── sample_clean.txt    # Example passing file
│   └── sample_with_errors.txt  # Example failing file
├── Dockerfile
├── .env.example
├── package.json
└── README.md
```

---

## Adding New Rules

Edit `src/validator.js` and add a new entry to the `RULES` object:

```js
MY_NEW_RULE: {
  name: 'My Field',
  aliases: ['my field', 'myfield', 'my_field'],
  validate: (value, rowIndex, colName) => {
    const errors = [];
    // your validation logic here
    if (!value.startsWith('X')) {
      errors.push({
        row: rowIndex,
        column: colName,
        value,
        rule: 'My Field Prefix',
        message: `My Field must start with X. Got: "${value}"`
      });
    }
    return errors;
  }
}
```
=======
# dataguard-agent
>>>>>>> d5c9d1c (Initial commit)
