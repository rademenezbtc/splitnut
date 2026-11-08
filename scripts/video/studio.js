// Injected into the live dashboard to film the demo: a wallet terminal on the right, a caption
// on the dashboard, and full-screen title cards. Driven by scripts/video/record.py through
// window.studio.
(() => {
  const css = `
    body { padding-right: 640px; }
    .wrap { margin: 0 !important; }
    #st-term { position: fixed; top: 0; right: 0; width: 640px; height: 100vh; background: #1C2740;
      color: #E9EDF1; padding: 30px 30px 40px; box-sizing: border-box; overflow: hidden;
      font: 18px/1.5 ui-monospace, "SF Mono", Menlo, "DejaVu Sans Mono", monospace; z-index: 50; }
    #st-term h3 { font: 600 20px/1.2 "Source Sans 3", system-ui, sans-serif; color: #AEB8CC; margin: 0 0 18px; }
    #st-lines { display: flex; flex-direction: column; justify-content: flex-end; height: calc(100% - 44px); }
    #st-lines div { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0 0 4px; }
    #st-lines .cmd .who { color: #A9A2FF; }
    #st-lines .ok { color: #E8D7A6; }
    #st-lines .bad { color: #FF9C93; }
    #st-lines .dim { color: #8592AA; }
    #st-cap { position: fixed; left: 28px; bottom: 30px; width: 1224px; z-index: 60; background: #1C2740;
      color: #F4F6F8; padding: 18px 24px; border-radius: 6px; font: 500 28px/1.3 "Spectral", Georgia, serif;
      box-shadow: 0 6px 24px rgba(28,39,64,.25); transition: opacity .35s; }
    #st-cap.hide { opacity: 0; }
    #st-card { position: fixed; inset: 0; z-index: 100; background: #E9EDF1; display: flex;
      flex-direction: column; justify-content: center; padding: 0 180px; transition: opacity .6s; }
    #st-card.hide { opacity: 0; pointer-events: none; }
    #st-card h1 { font: 500 64px/1.12 "Spectral", Georgia, serif; color: #1C2740; margin: 0 0 22px; max-width: 24ch; }
    #st-card p { font: 400 30px/1.4 "Source Sans 3", system-ui, sans-serif; color: #55607A; margin: 0; max-width: 52ch; }
    #st-card .brand { font: 600 30px/1 "Spectral", Georgia, serif; color: #4B3FD6; margin-bottom: 40px; }
  `;
  const style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  const term = document.createElement("div");
  term.id = "st-term";
  term.innerHTML = `<h3>Wallets and operator</h3><div id="st-lines"></div>`;
  document.body.appendChild(term);
  const cap = document.createElement("div");
  cap.id = "st-cap";
  cap.className = "hide";
  document.body.appendChild(cap);
  const card = document.createElement("div");
  card.id = "st-card";
  card.className = "hide";
  document.body.appendChild(card);

  const lines = document.getElementById("st-lines");
  const trim = () => { while (lines.children.length > 26) lines.removeChild(lines.firstChild); };

  window.studio = {
    // Type a command after a prompt, character by character; resolves when done.
    type(who, text) {
      return new Promise((done) => {
        const d = document.createElement("div");
        d.className = "cmd";
        d.innerHTML = `<span class="who"></span><span class="t"></span>`;
        d.querySelector(".who").textContent = `${who} $ `;
        lines.appendChild(d);
        trim();
        const t = d.querySelector(".t");
        let i = 0;
        const step = () => {
          t.textContent = text.slice(0, ++i);
          if (i < text.length) setTimeout(step, 28); else setTimeout(done, 250);
        };
        step();
      });
    },
    out(text, kind) {
      for (const line of String(text).split("\n")) {
        const d = document.createElement("div");
        if (kind) d.className = kind;
        d.textContent = line;
        lines.appendChild(d);
      }
      trim();
    },
    gap() { const d = document.createElement("div"); d.innerHTML = "&nbsp;"; lines.appendChild(d); trim(); },
    cap(text) {
      if (!text) { cap.classList.add("hide"); return; }
      cap.textContent = text;
      cap.classList.remove("hide");
    },
    card(brand, title, sub) {
      if (title === null) { card.classList.add("hide"); return; }
      card.innerHTML = `${brand ? `<div class="brand"></div>` : ""}<h1></h1>${sub ? "<p></p>" : ""}`;
      if (brand) card.querySelector(".brand").textContent = brand;
      card.querySelector("h1").textContent = title;
      if (sub) card.querySelector("p").textContent = sub;
      card.classList.remove("hide");
    },
    scrollTo(selector) {
      const el = document.querySelector(selector);
      if (el) window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 24, behavior: "smooth" });
    },
    top() { window.scrollTo({ top: 0, behavior: "smooth" }); },
  };
})();
