(function () {
  const checkboxes = document.querySelectorAll(".checklist-checkbox");
  if (!checkboxes.length) return;

  async function loadData() {
    const resp = await fetch("/api/osint/checklist");
    const data = await resp.json();
    Object.entries(data).forEach(([key, val]) => {
      const chk = document.getElementById(key);
      if (chk) chk.checked = val;
    });
  }

  checkboxes.forEach(chk => {
    chk.addEventListener("change", function () {
      const id = this.id;
      const checked = this.checked;
      const data = { [id]: checked };
      fetch("/api/osint/checklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      }).then(resp => console.log("Saved")).catch(err => console.error(err));
    });
  });

  document.querySelectorAll(".copy-icon").forEach(icon => {
    const codeBox = icon.parentElement;
    const pre = codeBox.querySelector("pre");
    icon.addEventListener("click", async () => {
      const code = pre.innerText;
      try {
        await navigator.clipboard.writeText(code);
        icon.textContent = "✅";
        setTimeout(() => icon.textContent = "📋", 2000);
      } catch (err) {
        console.error("Copy failed:", err);
      }
    });
  });

  loadData();
})();
