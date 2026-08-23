# Brand art

Source artwork for the site, README and store listings. **Nothing here ships**
with the application: the runtime resolves assets relative to the executable,
so anything under `assets/` other than this folder is copied into a build.

A file moves out of here into `assets/` the moment a surface actually uses it.

Currently shipped instead:

- `assets/images/logo/logo-lockup-stacked.png` — startup splash
- `assets/icons/app/app.ico` — window and executable icon

`logo-mark.svg` is byte-identical to `assets/icons/app/icon.svg`, which is the
app-icon source; keep them in sync if either is redrawn.
