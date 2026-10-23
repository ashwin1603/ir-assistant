# Windows setup notes

## SQLAlchemy blocked by Application Control

**Symptom.** The backend (or `pytest`) fails on import with:

```
ImportError: DLL load failed while importing _util_cy: An Application Control policy has blocked this file.
```

**Cause.** SQLAlchemy ships optional compiled (Cython) speed-ups as `.pyd` files.
Windows Smart App Control / App Control for Business blocks unsigned DLLs
like these, so the import fails before the app starts.

**Fix.** Reinstall SQLAlchemy as pure Python. The version stays the same as the
pin in `backend/requirements.txt`; only the build changes.

```powershell
cd backend
.venv\Scripts\Activate.ps1
$env:DISABLE_SQLALCHEMY_CEXT = "1"
pip install --force-reinstall --no-deps --no-binary sqlalchemy sqlalchemy==2.1.6
```

Check it worked (should print `2.1.6 False`):

```powershell
python -c "import sqlalchemy, sqlalchemy.util; print(sqlalchemy.__version__, sqlalchemy.util.has_compiled_ext())"
```

**Trade-off.** The pure-Python build is somewhat slower, which makes no
difference at this app's scale. Nothing about behaviour or security changes.

**After upgrading SQLAlchemy.** Repeat the reinstall. A normal
`pip install -r requirements.txt` brings back the compiled wheel.
