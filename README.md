# pyOraSQL v2.0 (Evaluation Build)

> ⚠️ **STATUS: IN EVALUATION / WORK IN PROGRESS** ⚠️
>
> This software is currently in an alpha/evaluation stage. While the core connection, querying, and basic snapshots work, several audit modules (Indexes, Constraints, Sequences) are currently placeholders. **Do not use for critical production auditing without verification.**

## Overview

**pyOraSQL** is a secure, interactive Command Line Interface (CLI) client for Oracle Database 19c (and compatible versions). It is designed for developers and DBAs who need a fast, keyboard-centric tool with advanced capabilities like schema snapshots, dependency graphing, and source code searching.

## Key Features (Implemented)

*   **🔒 Security:** Credentials are encrypted using `cryptography.fernet` (replaces legacy Base64).
*   **🖥️ Rich UI:** Colored tables, syntax highlighting, and auto-completion using `prompt_toolkit` and `rich`.
*   **📸 Schema Audit (Basic):** Take snapshots of Tables, Views, and PL/SQL code (Procedures, Functions, Packages) to detect changes over time.
*   **🔍 Advanced Search:**
    *   **Source Search:** Find text within PL/SQL code with context lines (grep-like).
    *   **Object Search:** Quickly find tables, views, or objects by name pattern.
*   **🕸️ Dependency Visualization:** View object dependencies as ASCII trees or graphs.
*   **📂 Export:** Export results to CSV or JSON.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/Zintre0/pyOraSQL.git
    cd pyOraSQL
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  (Optional) Install Oracle Instant Client if not using "Thin Mode".

## Configuration

Create a `connections.json` file in the root directory:

```json
{
  "dev": {
    "user": "MY_USER",
    "password": "MY_PASSWORD",
    "dsn": "localhost:1521/ORCLPDB1"
  },
  "prod": {
    "user": "ADMIN",
    "password": "SECURE_PASSWORD",
    "dsn": "192.168.1.10:1521/PROD"
  }
}
```

## Usage

Run the client:

```bash
python pyOraSQL_v2.0_closF4.py
```

### Common Commands

| Category | Command | Description |
|----------|---------|-------------|
| **Connection** | `connect dev` | Connect to the 'dev' profile defined in JSON |
| **Querying** | `SELECT * FROM table;` | Run SQL (must end with `;`) |
| **Schema** | `tables` | List tables in current schema |
| | `desc EMPLOYEES` | Describe table structure |
| **Search** | `search source 'error_code'` | Search text in PL/SQL source |
| | `find %LOG%` | Find objects with "LOG" in the name |
| **Audit** | `audit snapshot HR snap1` | Take a snapshot of HR schema |
| | `audit compare HR snap1 snap2` | Compare two snapshots |
| **System** | `exit` | Close the application |

## Roadmap & Known Limitations

The following features are planned or currently being implemented:

*   **Audit Completeness:** Logic for Indexes, Constraints, and Sequences is defined but queries are not yet implemented.
*   **Transaction Control:** Currently defaults to Auto-Commit. Manual `COMMIT` / `ROLLBACK` support is pending.
*   **Profile Management:** No CLI command to add/remove connections (must edit JSON manually).
*   **Bind Variables:** Not yet supported in the SQL runner.

## License

Private / Internal Use.
