# ReconBubble
Tool used to help organize pentest information 
<img width="1569" height="588" alt="image" src="https://github.com/user-attachments/assets/e9f5f7ae-ae31-4562-9d89-42bb8dddfb12" />

=== Supported Tool Injest  ===
- https://github.com/waffl3ss/Prowler
- nmap

to do 
- bbot
- subenum




https://github.com/user-attachments/assets/2dfe0dc7-563c-4753-810b-720e26ad51e6




=== Install ===

```
git clone https://github.com/Kahvi-0/ReconBubble.git && cd ReconBubble
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

mkdir project && cd project

reconbubble --database workspace.sqlite init
reconbubble --database workspace.sqlite run --port 5000
```
