# Brand art

Source artwork for the site, README and store listings. **Nothing here ships** with the application: the runtime resolves assets relative to the executable, so anything under `assets/` other than this folder is copied into a build.

A file moves out of here into `assets/` the moment a surface actually uses it.

Currently shipped instead:

- `assets/images/logo/logo-lockup-stacked.png` — startup splash
- `assets/icons/app/app.ico` — window and executable icon

`NetRuleRouter-logo-symbol.png` is the router mark alone, without the app-icon plate. A copy cleaned of stray specks and cut to 512 px, `packaging/windows/art/logo-symbol.png`, draws the installers' wizard pictures; only the package build reads it, so it ships nowhere either. `logo-mark.png` (1024 px) is the app-icon source; `logo-mark.svg` embeds it and is byte-identical to `assets/icons/app/icon.svg`. When the icon is redrawn, regenerate `assets/icons/app/icon-<size>.png` and `app.ico` from it and keep the two SVGs in sync.

`logo-lockup-<locale>.png` files are language-specific versions of the logo with the name and tagline. Locale suffixes use BCP 47 casing (`en`, `ru`, `pt-BR`, `zh-CN`); `nrr` is the language-neutral wordmark. The unsuffixed `logo-lockup.png` is the legacy English source. Cleaned of specks and cut to 600 px wide, supported lockups head every page of the offline documentation and its Markdown for GitHub as `docs/images/logo-lockup-<locale>.png`, each with a `-dark` twin whose text is light for a dark page; a language without its own lockup shows the English one.

Additional translated source lockups belong here as `logo-lockup-<locale>.png`. Keep the source artwork at its original size; surface-ready copies and dark variants are generated separately. Do not use spaces in filenames.
