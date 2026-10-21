---
title: Your AI agent can read your Supabase service key. Here is how to stop it.
tags: supabase, security, ai, claudecode
---

If your app uses Supabase and you build it with Cursor, Claude Code or a similar agent, check one file first: `.env`.

Many projects keep `SUPABASE_SERVICE_ROLE_KEY` (or a new `sb_secret_...` key) there. That key skips every Row Level Security (RLS) rule. Anyone who has it can read, change or delete every row in every table.

Your AI agent works in the same folder. Claude Code reads files in your project without asking you first. So the agent has that key too.

## Why this matters

You may trust the agent. But an agent can be wrong, or it can be tricked by text hidden in a web page, an issue or your own data. In April 2026 a Cursor agent deleted a production data volume and its backups in about 9 seconds. It used a token it found in a file that had nothing to do with the task ([OECD incident report](https://oecd.ai/en/incidents/2026-04-27-6153)).

## Step 1: Does your frontend need the key? (Almost never.)

A browser app only needs the public key (`anon` or `sb_publishable_...`). The service key belongs on a server: an Edge Function, an API route, or a backend job.

- If the key is in a `VITE_`, `NEXT_PUBLIC_`, `EXPO_PUBLIC_` or `REACT_APP_` variable, it is shipped to every visitor. Treat it as leaked. Rotate it today.
- If only server code uses it, store it in your host's secret settings (Vercel, Netlify, Cloudflare, Supabase Edge Function secrets) instead of a file in the repo.

## Step 2: Rotate the key if it was ever exposed

If the key was committed to git, shipped to the browser, or pasted into a chat, rotate it:

- New API keys: in the Supabase dashboard, go to Project Settings > API Keys, create a new secret key, move your server to it, then delete the old one.
- Legacy `service_role` JWT: plan a move to the new secret keys. They can be rotated one by one.

## Step 3: Tell your agent not to read it

In Claude Code, add deny rules to `.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(./.env)",
      "Read(./.env.*)",
      "Bash(supabase db reset:*)",
      "Bash(supabase projects delete:*)"
    ]
  }
}
```

Be honest about what this does. A `Read` deny rule blocks Claude's file tools, but a shell command could still print the file. A deny rule is a seatbelt, not a lock. The real fix is Step 1: keep the service key out of the folder your agent works in.

## Step 4: Check it

Karchi Guard is a free, open-source check that does this for you. It reads your repo, finds Supabase keys an agent can reach, and checks your Claude Code rules. It never prints a key and uses no network.

```
git clone https://github.com/karthikkushi/karchi-guard
cd karchi-guard
PYTHONPATH=src python3 -m karchi_guard scan /path/to/your/app
```

It does not check your RLS policies. For those, run `supabase db advisors --type security`.
