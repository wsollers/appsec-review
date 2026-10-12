---
id: python_service
version: 1
covers: []
standards: ["cwe", "asvs5", "api-top10-2023"]
max_tokens: 1500
---
## Runtime and framework model
A Python web service or worker: Django (with DRF), Flask, FastAPI/Starlette, aiohttp, Tornado,
Celery or RQ workers, or scripts invoked by other services. Dynamic typing and duck typing mean
values may not be the type the annotation claims unless a validator (pydantic, DRF serializers,
marshmallow) enforces it. C extensions (numpy, lxml, Pillow) carry native risk.

## Trust and interface layer
- Entry points: Django `urls.py` views and DRF viewsets, Flask `@app.route`, FastAPI path
  operations, Celery tasks (arguments come from the broker), management commands, and webhooks.
- Django middleware (`SessionMiddleware`, `CsrfViewMiddleware`, `AuthenticationMiddleware`)
  applies globally; DRF uses `DEFAULT_PERMISSION_CLASSES` and per-view `permission_classes`.
- FastAPI dependencies (`Depends(get_current_user)`) provide auth per route or router.

## Idiomatic security mechanisms
- Django ORM querysets, DB-API placeholders (`cursor.execute(sql, params)`), SQLAlchemy bound
  parameters and `text()` with `bindparams`.
- Jinja2 and Django templates with autoescape on.
- `subprocess.run([...])` without `shell=True`; `shlex.quote` only as a last resort.
- `secrets`, `hmac.compare_digest`, `django.contrib.auth.hashers`, passlib/argon2-cffi.
- `yaml.safe_load`, `defusedxml`, `json`; pydantic models with constrained types.
- DRF `IsAuthenticated` defaults and object-level `has_object_permission`.

## Stack-specific pitfalls
- `cursor.execute(f"... {x}")`, `%` formatting into SQL, `.raw()`/`.extra()`/`RawSQL`,
  SQLAlchemy `text(f"...")`.
- `pickle.loads`, `yaml.load` with `Loader=yaml.Loader`, `jsonpickle`, `shelve` on external data;
  Celery accepting pickle serializer.
- `eval`/`exec` on input; `render_template_string(user)`; `Markup(user)` or `|safe`.
- `os.path.join(base, user)` where `user` is absolute; `send_file` with request paths.
- `DEBUG = True` (Werkzeug debugger console is code execution); `ALLOWED_HOSTS = ['*']`.
- `@csrf_exempt` on cookie-authenticated views; DRF `AllowAny` defaults.
- `requests` with `verify=False`; `requests.get(user_url)` (SSRF).
- `tempfile.mktemp`; `random` for tokens; `assert` used for security checks (removed with `-O`).
- `tarfile.extractall`/`zipfile.extractall` on uploads before Python 3.12 extraction filters;
  `urllib.parse` differences from the HTTP client enabling SSRF allowlist bypass.

## Build and deployment facts to check
- Settings module used in deployment and its `DEBUG`, `SECRET_KEY` source, cookie flags, and
  `SECURE_*` settings.
- Pinned requirements or lockfiles (`poetry.lock`, `uv.lock`, hashes) and resolved versions.
- WSGI/ASGI server config (gunicorn, uvicorn) bind address and workers; Celery serializer settings.
- Python version, since stdlib defaults differ (e.g. `tarfile` extraction filters in 3.12+).
