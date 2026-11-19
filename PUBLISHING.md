# Publishing checklist — Personal MCP 2.0 + IsItMe? ChatGPT app

Work through these in order. Steps marked 🧑 need your accounts; everything else is already in the repo.

## 1. Merge and turn on the website (10 min) 🧑

1. Push the `release/v2.0.0` branch and merge it into `main`.
2. GitHub → repo **Settings → Pages** → *Deploy from a branch* → `main` / `/docs` → Save.
3. After ~1 minute these must open (ChatGPT review needs them):
   - https://arun250492.github.io/Personal-MCP/
   - https://arun250492.github.io/Personal-MCP/privacy.html
   - https://arun250492.github.io/Personal-MCP/terms.html

## 2. Release 2.0.0 to PyPI (5 min) 🧑

Either push a tag (uses the existing GitHub Actions workflow with PyPI trusted publishing — configure it once at
https://pypi.org/manage/project/personal-mcp-arun/settings/publishing/ with workflow `publish.yml`):

```bash
git tag v2.0.0 && git push origin v2.0.0
```

…or upload by hand:

```bash
pip install build twine
python -m build
twine upload dist/*
```

Check: `pip install -U personal-mcp-arun && personal-mcp --version` → `personal-mcp 2.0.0`.

> The tag workflow also publishes `.mcp/server.json` to the MCP Registry under `io.github.arun250492/Personal-MCP`
> (the name your 1.0.5 README used). If your registry entry uses a different name, change it in both
> `.mcp/server.json` and the first line of `README.md`.

## 3. Deploy the hosted server (20–30 min) 🧑

Pick one. Use an always-on instance: a sleeping free instance makes the first ChatGPT call time out.

**Fly.io (Mumbai region, recommended)**

```bash
fly auth login
fly launch --copy-config --config deploy/fly.toml --no-deploy   # rename the app if "isitme-mcp" is taken
fly deploy --config deploy/fly.toml
```

**Render**: New → Web Service → connect the repo → Runtime *Docker* → instance *Starter* → health check
path `/healthz` → env var `ISITME_TRUST_PROXY=1`. (Or copy `deploy/render.yaml` to the repo root and use Blueprints.)

**Railway**: New project → Deploy from GitHub repo (it picks up the Dockerfile) → Settings → Networking →
Generate domain → add variable `ISITME_TRUST_PROXY=1`.

Optional: point a custom domain such as `isitme.yourdomain.com` at it. Do this **before** step 6, because the MCP
URL can't be changed after submission without contacting OpenAI support.

Verify:

```bash
curl https://<your-host>/healthz            # {"status":"ok","version":"2.0.0"}
npx @modelcontextprotocol/inspector         # connect to https://<your-host>/mcp, run diagnose on github.com
```

## 4. Test in ChatGPT Developer Mode (15 min) 🧑

In ChatGPT, enable Developer mode (Settings → Apps → Advanced settings) and create an app pointing at
`https://<your-host>/mcp` with no authentication. Run the 5 positive and 3 negative prompts from
`chatgpt-plugin/plugin.json` and check each behaves as described. This development connection is only for testing;
it isn't the submission.

## 5. Record the demo video (15 min) 🧑

2–3 minutes, screen recording of ChatGPT, upload unlisted to YouTube or Loom. No real customer data on screen.

1. "Is github.com down or is it just me?" → the verdict card appears; point out DNS/TLS/HTTP checks and the
   detected provider with its status.
2. "When does the SSL certificate for wikipedia.org expire?" → days left + issuer.
3. "Check SPF, DKIM and DMARC for google.com" → e-mail findings.
4. "Are AWS, Azure or Google Cloud having incidents right now?" → status summary.
5. Negative: "Check http://192.168.1.1" → the app refuses private addresses.
6. Click **Copy ticket summary** on a card.

## 6. Build and upload the plugin package (5 min)

```bash
python chatgpt-plugin/build.py \
  --mcp-url https://<your-host>/mcp \
  --demo-url https://<your-video-url> \
  --check-live
```

It validates every listing limit (name/description lengths, URLs, icons, 5+3 test cases, no secrets), checks that
your site and `/healthz` respond, and writes `dist/isitme-plugin-2.0.0.zip`.

## 7. Submit to OpenAI 🧑

1. https://platform.openai.com → complete **individual or business verification** for your organization (an
   organization owner must submit; others need the *Apps Management Write* role).
2. **Plugins → Create plugin → Upload ZIP** → upload `dist/isitme-plugin-2.0.0.zip`. Fix anything the package check
   reports, then re-run step 6 and upload again.
3. **Connect the MCP server.** If asked to verify the domain, copy the challenge token and set it on the server:
   - Fly: `fly secrets set OPENAI_APPS_CHALLENGE=<token>`
   - Render/Railway: add env var `OPENAI_APPS_CHALLENGE=<token>` and redeploy

   Check `curl https://<your-host>/.well-known/openai-apps-challenge` prints just the token, then click Verify.
4. Wait for the **tool scan** to pass.
5. **Review details**: authentication *none* (no reviewer account needed). For the iframe question: "The verdict card
   is a self-contained HTML resource served by our MCP server (`ui://isitme/verdict-v1.html`). It loads no external
   scripts, styles or domains and only displays the diagnose tool's result. We control the MCP domain."
6. **Submit for review.** Answer any feedback email. After approval, click **Publish plugin**.

## After launch

- Share the directory deep link from the dashboard in your README, LinkedIn and dev communities.
- Changes to tool code redeploy normally; listing changes (text, icons, test cases) need a new ZIP and review.
  New tools stay hidden until approved, so keep existing tool names and arguments compatible.
