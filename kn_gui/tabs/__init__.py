"""Per-tab UI builders for the main App window.

Each module here exposes a single `build(app)` function that populates
the pre-created `ttk.Frame` on `app.tab_*`. Event callbacks remain as
methods on App so that existing bindings continue to work.

Extracted from the monolithic `app.py` in April 2026 so that each tab
can be reasoned about (and later tested) in isolation.
"""
