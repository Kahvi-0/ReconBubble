# ReconBubble
Tool used to help organize pentest information 
<img width="1569" height="588" alt="image" src="https://github.com/user-attachments/assets/e9f5f7ae-ae31-4562-9d89-42bb8dddfb12" />

=== Supported Tool Injest  ===
- https://github.com/waffl3ss/Prowler
- nmap

to do 
- bbot
- subenum


<img width="2522" height="833" alt="image" src="https://github.com/user-attachments/assets/8e4ed887-a98d-4a28-b58a-4dee9c818c9a" />



=== Install ===

```
git clone https://github.com/Kahvi-0/ReconBubble.git && cd ReconBubble
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

reconbubble --database workspace.sqlite init
reconbubble --database workspace.sqlite run --port 5000
```
