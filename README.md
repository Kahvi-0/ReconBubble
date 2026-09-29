# ReconBubble
Tool used to help organize pentest scope, scan results, OSINT information, assets and more! Built with Local, grass fed LLM models.

<img width="1569" height="588" alt="image" src="https://github.com/user-attachments/assets/e9f5f7ae-ae31-4562-9d89-42bb8dddfb12" />

https://github.com/user-attachments/assets/2dfe0dc7-563c-4753-810b-720e26ad51e6

=== Features  ===
- Ingest and parse automatically such as:
  - [Prowler](https://github.com/waffl3ss/Prowler)
  - nmap
  - bbot
  - subenum
- Automatic marking and sorting of inscope domains and IPs
- Track and organize OSINT, webapps, Internal attack paths
- Parsing of users and hashes then sorting them to the designated user automatically
- Add assets (users, domains, hosts) to the attack topology to better visualize collected information and attack paths

=== Run With UVX ===
```
mkdir reconbubble && cd reconbubble
uvx --from git+https://github.com/Kahvi-0/ReconBubble reconbubble --database bubbledb.sqlite --project "Client Pentest" run --port 5000 --install-browser
```
=== pip Install ===

```
git clone https://github.com/Kahvi-0/ReconBubble.git && cd ReconBubble
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

mkdir reconbubble && cd reconbubble
reconbubble --database workspace.sqlite --project ProjectName run --port 5000
```

```
-p, --port	TCP port to listen on (Default 5000).
--bind ADDRESS 	Bind address. Defaults to localhost only.
--browser-dir PATH	  Workspace browser directory	Explicit Playwright browser directory.
--listen-all  	Listen on all interfaces.
--proxy address:port   SOCKs proxy 

# Headless browser used with some web features
--install-browser		(recommneded) Install Playwright Chromium before starting if it is missing inside the workspace directory.
--with-deps		Pass --with-deps to Playwright when installing Chromium. Only used with --install-browser.
--ephemeral-browser		Use a temporary Playwright browser directory for this run.
--ram-browser		Use a temporary RAM-backed browser directory when /dev/shm is available.


--help	—	Show run help.

Notes:
--browser-dir cannot be combined with --ephemeral-browser or --ram-browser.
--bind 0.0.0.0 is refused unless --listen-all is used.
Ephemeral browser directories are removed when the server exits.
```
