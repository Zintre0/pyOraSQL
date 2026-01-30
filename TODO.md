# Project Roadmap & Technical Debt

## 🔴 Critical / Missing Implementations

### 1. Audit System Completeness (`collect_schema_metadata`)
The data structure exists, but the extraction logic is missing for:
- [ ] **Indexes:** Query `ALL_INDEXES` / `ALL_IND_COLUMNS`.
- [ ] **Constraints:** Query `ALL_CONSTRAINTS` / `ALL_CONS_COLUMNS` (PK, FK, Check).
- [ ] **Sequences:** Query `ALL_SEQUENCES` (last_number, increment, etc.).
- [ ] **Synonyms:** Query `ALL_SYNONYMS`.
- [ ] **Grants/Privileges:** (Optional) Query `ALL_TAB_PRIVS`.

### 2. Transaction Management
- [ ] **Disable Auto-Commit:** Modify `execute_sql` to stop auto-committing DMLs.
- [ ] **Implement Commands:** Add `commit` and `rollback` commands to the main loop.

## 🟡 Improvements / Enhancements

### 3. Connection Management
- [ ] **CLI Profile Manager:** Create commands `profile add <name> ...` and `profile remove <name>` to avoid manual JSON editing.
- [ ] **Test Connection Command:** A command to test connectivity without fully switching context.

### 4. SQL Engine
- [ ] **Bind Variables:** Detect `:var` syntax in SQL and prompt user for input values before execution.
- [ ] **Multi-line Editing:** Improve the SQL input buffer (currently relies on `prompt_toolkit` basic history).

### 5. Export/Import
- [ ] **Excel Support:** Add `export xlsx <file>` using `pandas` or `openpyxl`.
- [ ] **HTML Reports:** Generate a visual HTML diff report for `audit compare` instead of just text/terminal output.

## 🟢 Housekeeping / Refactoring

- [ ] **Modularization:** Split `pyOraSQL_v2.0_closF4.py` into multiple files (e.g., `audit.py`, `ui.py`, `db.py`) for better maintainability.
- [ ] **Testing:** Create a `tests/` folder with `pytest` scripts for the audit logic.
