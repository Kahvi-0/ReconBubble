# ReconBubble
Tool used to help organize pentest scope, scan results, OSINT information, assets and more! 

<img width="1569" height="588" alt="image" src="https://github.com/user-attachments/assets/e9f5f7ae-ae31-4562-9d89-42bb8dddfb12" />

https://github.com/user-attachments/assets/2dfe0dc7-563c-4753-810b-720e26ad51e6

=== Features  ===
- Ingest and parse automatically such as [Prowler](https://github.com/waffl3ss/Prowler)
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
uvx --from git+https://github.com/Kahvi-0/ReconBubble reconbubble --database bubbledb.sqlite --project "Client Pentest" run --port 5000
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
