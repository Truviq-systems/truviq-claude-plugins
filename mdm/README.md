# Company-wide rollout (R7.5)

Goal: every developer's Claude Code has TruViq Guard on, and they can't switch it off.

## 1. Publish the marketplace once
`python3 release/export_marketplace.py /tmp/truviq-export`, push that folder to a GitHub repo, and put the repo name
in `managed-settings.json` (replace `OWNER/truviq-claude-plugins`).

## 2. Deploy the managed settings file with your device-management tool (Jamf, Intune, Kandji, Ansible)
Claude Code reads an organisation-level settings file that users cannot edit. Documented locations at the time of writing
(**check the current Claude Code settings docs before deploying; paths and keys can change**):

| OS | File |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

`enabledPlugins: true` in managed settings force-enables the plugin. Optional keys documented for plugin control:
`strictKnownMarketplaces` (allow-list of marketplaces) and `blockedMarketplaces`.

## 3. Per-machine setup (run by the same tool, as the user)
```
python3 plugins/truviq-guard/bin/truviq.py setup --import-env <org .env with Supabase anon + Resend keys>
python3 plugins/truviq-guard/bin/truviq.py enroll --org <company>
python3 plugins/truviq-guard/bin/truviq.py install --source <owner>/<repo>
python3 plugins/truviq-guard/bin/truviq.py doctor --online
```
Never give the Supabase service-role key to developer machines. Only the admin machine that runs the dashboard and
`watchdog` needs it.

## 4. Central policy
Admin: write `org-policy.json` (any normal policy keys, e.g. `{"mode": "enforce", "egress_allow_hosts": [...]}`), then
`truviq.py policy-publish org-policy.json`. Machines pull it at every session start (hourly) or with `truviq.py policy-sync`.
Layers: default → organisation → user → repository (a repository can only tighten).

## 5. Keep an eye on it
On the admin machine, run `truviq.py watchdog` every hour (cron: `0 * * * * python3 /path/truviq.py watchdog`).
It emails when a machine stops reporting, runs in monitor/off mode, loses its hook files, runs an old version, or has not
applied the latest org policy. The dashboard shows the same in the *Fleet health* panel.
