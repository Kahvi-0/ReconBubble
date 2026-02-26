# ReconBubble
Tool used to help organize pentest information 

=== Supported Tool Injest  ===
- https://github.com/waffl3ss/Prowler
- nmap

=== Install ===

```
git clone
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .

reconbubble --database workspace.sqlite init
reconbubble --database workspace.sqlite run --port 5000
```
