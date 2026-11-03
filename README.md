# SILA TECH

Template ya website kuu ya SILA TECH, iliyotokana na HTML ya mfano iliyotolewa.

## Run

Install Node.js, then run:

```bash
npm start
```

Open http://localhost:3000. No npm dependencies are required.

## Repo / Heroku

Upload the contents of this folder into the repository root. `package.json`, `index.js`, `Procfile` and `sila/` must be at the root. Heroku assigns PORT automatically. Set NODE_ENV=production. Connect silatech.site in your hosting provider's domain settings; uploading code does not change DNS.

## Files

- `index.js`: static HTTP server; only files inside `sila/` are public.
- `sila/index.html`: page layout and content.
- `sila/assets/`: CSS, images, fonts and local navigation scripts.

This is a frontend template, with direct email/WhatsApp links. It has no login, database, payment handling or contact-form backend. Some original WordPress animations are simplified. Most assets are bundled; Google Fonts and some fallback images may still require internet access.

HTML, CSS and browser JavaScript can be viewed by visitors. Never place secrets or API keys inside `sila/`. Keep future backend credentials in hosting environment variables. Security headers do not replace a security review of future backend features.

The original reference includes theme and image assets. Confirm the relevant usage rights before public commercial deployment.
