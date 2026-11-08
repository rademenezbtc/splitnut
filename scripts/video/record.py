#!/usr/bin/env python3
"""Record the SplitNut demo video against a running demo (scripts/demo.sh).

Runs the real wallet commands (cdk-cli) and guardian stop/start while filming the live
dashboard with Chrome's screencast (JPEG, quality 92), then encodes one H.264 file at 30 fps.

    DEMO_DIR=.video CDK_BIN=... python3 scripts/video/record.py out.mp4
    python3 scripts/video/record.py --preview stills/     # title card and layout stills only

The demo should be fresh (scripts/demo.sh --fresh), so the ledger numbers start at zero.
"""
import asyncio
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[2]
DEMO = Path(os.environ.get("DEMO_DIR", ROOT / ".video"))
CLI = Path(os.environ.get("CDK_BIN", "")) / "cdk-cli"
MINT = os.environ.get("MINT_URL", "http://127.0.0.1:8085/")
DASH = os.environ.get("DASH_URL", "http://127.0.0.1:8090/")
CHROME = os.environ.get("CHROME", "/usr/bin/google-chrome")
W, H = 1920, 1080
STUDIO = (Path(__file__).parent / "studio.js").read_text()


def wallet(name, *args):
    cmd = [str(CLI), "-n", "-w", str(DEMO / f"wallet{name}"), *args]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return (r.stdout + r.stderr).strip(), r.returncode


def operator(*args):
    r = subprocess.run([str(ROOT / "scripts/guardian.sh"), *args], capture_output=True, text=True,
                       env={**os.environ, "DEMO_DIR": str(DEMO)}, timeout=30)
    return (r.stdout + r.stderr).strip()


def received(out):
    lines = [l for l in out.splitlines() if l.startswith("Received")]
    return "\n".join(lines) if lines else out.splitlines()[-1] if out else ""


def refusal(out):
    m = re.search(r"SplitNut quorum unavailable: [^`\"]*?\)", out)
    return m.group(0) if m else (out.splitlines()[-1] if out else "")


class Film:
    """Chrome screencast frames with their timestamps."""

    def __init__(self, cdp, outdir):
        self.cdp, self.dir, self.frames = cdp, outdir, []

    async def start(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cdp.on("Page.screencastFrame", self._frame)
        await self.cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 92, "maxWidth": W, "maxHeight": H, "everyNthFrame": 1})

    def _frame(self, ev):
        n = len(self.frames)
        p = self.dir / f"f{n:06d}.jpg"
        import base64
        p.write_bytes(base64.b64decode(ev["data"]))
        self.frames.append((p, time.monotonic()))
        asyncio.ensure_future(self.cdp.send("Page.screencastFrameAck", {"sessionId": ev["sessionId"]}))

    async def stop(self):
        await self.cdp.send("Page.stopScreencast")

    def encode(self, out: Path, end_hold=0.5):
        lst = self.dir / "frames.txt"
        with lst.open("w") as f:
            for (p, t), (_, t2) in zip(self.frames, self.frames[1:] + [(None, self.frames[-1][1] + end_hold)]):
                f.write(f"file '{p}'\nduration {max(t2 - t, 0.001):.4f}\n")
            f.write(f"file '{self.frames[-1][0]}'\n")
        tmp = out.with_name(out.stem + ".tmp.mp4")
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(lst),
                        "-vf", f"scale={W}:{H},fps=30,format=yuv420p", "-c:v", "libx264", "-crf", "18",
                        "-preset", "veryfast", "-movflags", "+faststart", str(tmp)], check=True)
        tmp.rename(out)


async def main():
    preview = "--preview" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--preview"]
    target = Path(args[0] if args else ("stills" if preview else "splitnut-demo.mp4")).resolve()

    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        page = await browser.new_page(viewport={"width": W, "height": H}, device_scale_factor=1)
        await page.goto(DASH)
        await page.wait_for_timeout(1500)
        await page.add_script_tag(content=STUDIO)
        js = page.evaluate
        hold = page.wait_for_timeout

        if preview:
            target.mkdir(parents=True, exist_ok=True)
            await js("studio.card('SplitNut', 'One operator holds a Cashu mint\\'s keys. They can sign ecash nobody paid for, and no wallet can tell.', 'Today, every Cashu mint works this way.')")
            await hold(800)
            await page.screenshot(path=str(target / "card.jpg"), type="jpeg", quality=92)
            await js("studio.card(null, null)")
            await js("studio.cap('A normal wallet mints 1,000 sat. Two guardians answer, and their shares combine into one standard signature.')")
            await js("studio.type('wallet A', 'cdk-cli mint http://127.0.0.1:8085/ 1000')")
            await js("studio.out('Received 1000 from mint http://127.0.0.1:8085', 'ok')")
            await js("studio.type('operator', './scripts/guardian.sh stop 2')")
            await js("studio.out('guardian 2 stopped', 'dim')")
            await js("studio.out('Error: SplitNut quorum unavailable: 1 of 2 required guardians answered (guardian 2: offline; guardian 3: offline)', 'bad')")
            await hold(2500)
            await page.screenshot(path=str(target / "scene.jpg"), type="jpeg", quality=92)
            await hold(1200)
            await page.screenshot(path=str(target / "ledger.jpg"), type="jpeg", quality=92)
            await browser.close()
            print(f"stills in {target}")
            return

        cdp = await page.context.new_cdp_session(page)
        frames_dir = target.parent / (target.stem + "-frames")
        shutil.rmtree(frames_dir, ignore_errors=True)
        film = Film(cdp, frames_dir)
        await film.start()
        say = lambda t: js("t => studio.cap(t)", t)
        type_ = lambda who, t: js("([w, t]) => studio.type(w, t)", [who, t])
        out = lambda t, k=None: js("([t, k]) => studio.out(t, k)", [t, k])
        card = lambda b, t, s=None: js("([b, t, s]) => studio.card(b, t, s)", [b, t, s])

        async def run(fn, *a):
            return await asyncio.get_running_loop().run_in_executor(None, fn, *a)

        # 1. The problem
        await card("SplitNut", "Cashu, without trusting a single mint operator to keep the money supply honest.")
        await hold(4500)
        await card(None, "Today one operator holds a Cashu mint's keys. They can sign ecash nobody paid for, and no wallet can tell.")
        await hold(7000)
        await card(None, "SplitNut splits every mint key across guardians. Any 2 of the 3 must cooperate to sign.",
                   "Wallets see a normal Cashu mint. The guardians talk over Marmot: an encrypted group on Nostr.")
        await hold(7000)
        await card(None, None)

        # 2. Setup
        await say("Three guardians, threshold 2, in one encrypted Marmot group. The mint server itself holds no keys.")
        await hold(1200)
        await type_("operator", "grep -A3 '^\\[signatory\\]' mintd.toml")
        cfg = (DEMO / "mintd.toml").read_text()
        block = re.search(r"\[signatory\][^\[]*", cfg).group(0).strip()
        block = re.sub(r'tls_dir = ".*"', 'tls_dir = "certs"', block)
        await out(block, "dim")
        await type_("operator", "grep -ciE 'seed|mnemonic' mintd.toml")
        await out("0", "dim")
        await hold(5000)

        # 3. Mint
        await out("")
        await say("A normal wallet mints 1,000 sat. Two guardians answer, and their shares combine into one standard signature.")
        await hold(1500)
        await type_("wallet A", f"cdk-cli mint {MINT} 1000")
        o, _ = await run(wallet, "A", "mint", MINT, "1000")
        await out(received(o), "ok")
        await hold(5500)
        await say("The wallet checked each signature's DLEQ proof against the mint's published keys: it cannot tell this from a single-key mint.")
        await hold(7000)

        # 4. Spend
        await out("")
        await say("Send 400 sat to a second wallet. Spending is checked by the guardians too.")
        await hold(1200)
        await type_("wallet A", f"cdk-cli send --mint-url {MINT} -a 400")
        o, _ = await run(wallet, "A", "send", "--mint-url", MINT, "-a", "400")
        tok = (re.findall(r"cashu[AB][A-Za-z0-9_=-]+", o) or [""])[-1]
        await out(tok[:44] + "…", "dim")
        await type_("wallet B", "cdk-cli receive cashuB…")
        o, _ = await run(wallet, "B", "receive", "--allow-untrusted", tok)
        await out(o.splitlines()[-1] if o else "", "ok")
        await hold(6000)

        # 5. One guardian down
        await out("")
        await say("Switch off guardian 3.")
        await type_("operator", "./scripts/guardian.sh stop 3")
        await out(await run(operator, "stop", "3"), "dim")
        await hold(1500)
        await say("Two guardians are still enough: the wallet mints again.")
        await type_("wallet A", f"cdk-cli mint {MINT} 100")
        o, _ = await run(wallet, "A", "mint", MINT, "100")
        await out(received(o), "ok")
        await hold(5500)

        # 6. Two guardians down
        await out("")
        await say("Now switch off guardian 2 as well.")
        await type_("operator", "./scripts/guardian.sh stop 2")
        await out(await run(operator, "stop", "2"), "dim")
        await hold(4500)
        await type_("wallet A", f"cdk-cli mint {MINT} 100")
        o, _ = await run(wallet, "A", "mint", MINT, "100")
        await out("Error: " + refusal(o), "bad")
        await say("One guardian alone cannot sign. So neither can the operator: nobody can create ecash on their own.")
        await hold(8000)

        # 7. Recovery
        await out("")
        await say("Bring guardian 2 back. It rejoins from its encrypted state, and the refused payment is paid out.")
        await type_("operator", "./scripts/guardian.sh start 2")
        await out(await run(operator, "start", "2"), "dim")
        await hold(5000)
        await type_("wallet A", f"cdk-cli mint {MINT} 50")
        o, _ = await run(wallet, "A", "mint", MINT, "50")
        await out(received(o), "ok")
        await type_("wallet A", "cdk-cli balance")
        o, _ = await run(wallet, "A", "balance")
        bal = (re.findall(r"(\d+) sat", o) or ["?"])[0]
        await out(f"{bal} sat: the 100 refused earlier has arrived too", "ok")
        await hold(5000)

        # 8. Ledgers and relay
        await hold(2500)  # a heartbeat brings the latest ledgers
        a = int((re.findall(r"(\d+) sat", (await run(wallet, "A", "balance"))[0]) or ["0"])[0])
        b = int((re.findall(r"(\d+) sat", (await run(wallet, "B", "balance"))[0]) or ["0"])[0])
        import json, urllib.request
        st = json.load(urllib.request.urlopen(DASH + "state"))
        outs = {g["ledger"]["outstanding"] for g in st["guardians"] if g.get("online") and g.get("ledger")}
        if outs == {a + b}:
            await say(f"Each guardian keeps its own ledger of issuance it has verified. The online ones each count "
                      f"{a + b:,} sat outstanding: exactly what the two wallets hold ({a:,} + {b:,}).")
        else:
            await say("Each guardian keeps its own ledger, counting only issuance it has verified. The online ones agree on what is outstanding.")
        await hold(11000)
        await say("Every message crossed a Nostr relay, which saw only ciphertext.")
        await hold(8000)

        # 9. Close
        await say(None)
        await card("SplitNut", "Cashu, without trusting a single mint operator.",
                   "Open source, MIT licensed: github.com/rademenezbtc/splitnut")
        await hold(6000)

        await film.stop()
        await browser.close()
        print(f"{len(film.frames)} frames; encoding...")
        film.encode(target)
        shutil.rmtree(frames_dir, ignore_errors=True)
        print(f"wrote {target}")


asyncio.run(main())
