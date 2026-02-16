# FW-GUI Bug Report

Generated: 2026-02-15


The most impactful bugs are:
- #1 (security), 
- #3 (crash), 
- #12 (logic error), 
- #10 (returning exception objects), and 
- #14 (data corruption side effect).

The rest range from typos to resource management issues.

---

## Resolved bugs:
- [ ] 1. Path Traversal Vulnerability in `/download` endpoint
- [ ] 2. `logging` module shadowed by local variable
- [ ] 3. `filetype` referenced before assignment in `process_upload`
- [ ] 4. `ssh_keyname` KeyError on GET to `/configuration_push`
- [ ] 5. `snapshot_name` potential `IndexError` in `select_firewall_config`
- [x] 6. Typo: "musht" instead of "must"
- [x] 7. `add_hostname` has typo in parameter name
- [x] 8. Deleting last rule silently removes entire chain/filter (documented as intentional)
- [x] 9. Exception objects returned instead of strings
- [x] 10. MongoDB connections never closed
- [x] 11. Wrong key check in `add_group_to_data`
- [x] 12. `generate_config` inconsistent return type
- [ ] 13. `tag_snapshot` overwrites current config as side effect
- [x] 14. `validate_mongodb_connection` calls `sys.exit()` on failure (intentional — app requires MongoDB)

---

## 1. Path Traversal Vulnerability in `/download` endpoint

**File:** `app.py`  
**Severity:** High (Security)

The `download()` route directly uses `request.form["path"]` and `request.form["filename"]` to construct a file path with no sanitization:

```python
path = request.form["path"]
filename = request.form["filename"]
with open(path + filename, "rb") as f:
```

An attacker could supply `path=../../` and `filename=etc/passwd` to read arbitrary files on the server. The path and filename should be validated/sanitized against directory traversal.

---

## 2. `logging` module shadowed by local variable

**File:** `package/generate_config.py`  
**Severity:** Medium

In the chains config generation loop, a local variable named `logging` is assigned:

```python
logging = (
    True
    if "logging"
    in user_data[ip_version]["chains"][fw_chain][rule]
    else False
)
```

This shadows Python's `logging` module for the rest of that scope. If any `logging.info()` / `logging.debug()` call were added later in that block, it would crash with `AttributeError: 'bool' object has no attribute 'info'`.

**Fix:** Rename the variable (e.g., `rule_logging`).

---

## 3. `filetype` referenced before assignment in `process_upload`

**File:** `package/data_file_functions.py`  
**Severity:** High (Crash)

If the uploaded file has an extension that is neither `json` nor `key`, the code flashes an error but doesn't `return`. Execution continues to the `if filetype == "json":` check, but `filetype` was never assigned, causing an `UnboundLocalError`:

```python
else:
    flash("Invalid file type, only .json and .key files are allowed.", "danger")
# falls through — filetype is undefined
if filetype == "json":  # UnboundLocalError
```

**Fix:** Add `return` after the flash for invalid file types.

---

## 4. `ssh_keyname` KeyError on GET to `/configuration_push`

**File:** `app.py`  
**Severity:** Medium (Crash)

The GET branch of `configuration_push` references `session["ssh_keyname"]` in the template render, but `ssh_keyname` is only set in `select_firewall_config`. If a user navigates directly to the push page without going through `select_firewall_config`, this will raise a `KeyError`.

**Fix:** Use `session.get("ssh_keyname", "")`.

---

## 5. `snapshot_name` potential `IndexError` in `select_firewall_config`

**File:** `app.py`  
**Severity:** Medium (Crash)

When the form value contains `/` and the second segment is `"delete"`, the code does:

```python
if snapshot == "delete":
    snapshot_name = request.form["file"].split("/")[2]
```

If the form value is e.g. `firewall/delete` without a third segment, `split("/")[2]` will raise an `IndexError`.

---

## 6. Typo: "musht" instead of "must"

**Files:** `package/chain_functions.py`, `package/filter_functions.py`  
**Severity:** Low (UI)

```python
flash("New rule number musht be an integer.", "danger")
```

Appears in both `reorder_chain_rule_in_data` and `reorder_filter_rule_in_data`.

---

## 7. `add_hostname` has typo in parameter name

**File:** `package/data_file_functions.py`  
**Severity:** Low

```python
def add_hostname(session, reqest):  # "reqest" instead of "request"
```

Not a runtime error but inconsistent with every other function signature.

---

## 8. Deleting last rule silently removes entire chain/filter

**Files:** `package/chain_functions.py`, `package/filter_functions.py`  
**Severity:** Medium (Data Loss)

In `delete_rule_from_data`, when all rules are removed from a chain, the cleanup code deletes the chain entirely — including its `default` action/description:

```python
if not user_data[ip_version]["chains"][fw_chain]["rule-order"]:
    del user_data[ip_version]["chains"][fw_chain]
```

The same issue exists in `delete_filter_rule_from_data`. Users likely want to keep the chain even if it has no rules.

---

## 9. Exception objects returned instead of strings

**File:** `package/napalm_ssh_functions.py`  
**Severity:** Medium

`commit_to_firewall`, `get_diffs_from_firewall`, and `run_operational_command` all return raw exception objects on error:

```python
except Exception as e:
    ...
    return e
```

Returning the raw exception to the template will render as the exception's `repr()`, producing ugly or confusing output.

**Fix:** Return `str(e)` instead.

---

## 10. MongoDB connections never closed

**File:** `package/data_file_functions.py`  
**Severity:** Medium (Resource Leak)

Throughout `read_user_data_file`, `write_user_data_file`, `delete_user_data_file`, `list_user_files`, `list_snapshots`, etc., a new `pymongo.MongoClient` is created on every call but never explicitly closed. This is a resource leak under load.

**Fix:** Use a shared client or close connections after use.

---

## 11. Wrong key check in `add_group_to_data`

**File:** `package/group_funtions.py`  
**Severity:** Medium (Logic Error)

```python
if "group-name" not in user_data[ip_version]["groups"]:
    user_data[ip_version]["groups"][group_name] = {}
```

The check is against the literal string `"group-name"` instead of the variable `group_name`. The guard never works as intended.

**Fix:**
```python
if group_name not in user_data[ip_version]["groups"]:
    user_data[ip_version]["groups"][group_name] = {}
```

---

## 12. `generate_config` inconsistent return type

**File:** `package/generate_config.py`  
**Severity:** Low

When `diff=True`, the function returns a `list`. When `diff=False`, it returns a `tuple(str, list)`. This inconsistent return type is error-prone for callers.

---

## 13. `tag_snapshot` overwrites current config as side effect

**File:** `package/data_file_functions.py`  
**Severity:** High (Data Corruption)

`read_user_data_file` with a non-current snapshot and `diff=False` (the default) overwrites the "current" document with the snapshot data. In `tag_snapshot`, the intent is just to update a tag, but calling `read_user_data_file` with a snapshot name causes the current config to be silently replaced by the snapshot data.

**Fix:** Pass `diff=True` in `tag_snapshot` to prevent the overwrite side effect.

---

## 14. `validate_mongodb_connection` calls `sys.exit()` on failure

**File:** `package/data_file_functions.py`  
**Severity:** Low

This kills the entire process on a MongoDB connection failure rather than raising an exception or returning `False`, making the function untestable and preventing graceful error handling.

---
