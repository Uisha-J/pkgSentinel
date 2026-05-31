"""데모 스크린샷 생성 — 실제 엔진 verdict + 실제 확장 코드로 렌더해 Edge headless 캡처.

생성물 (docs/):
  - demo_chrome_extension.png       라이트 패널 (AI 채팅 위)
  - demo_chrome_extension_dark.png  다크 패널
  - demo_popup.png                  확장 팝업 (통계 4박스)

전제: 어댑터 서버 localhost:8001 실행 중 + scripts/demo_data.json 존재.
"""
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
DATA = ROOT / "scripts" / "demo_data.json"
CHROME = ROOT / "clients" / "chrome"
COMMON_JS = (CHROME / "content" / "common.js").read_text(encoding="utf-8")
POPUP_HTML = (CHROME / "popup.html").read_text(encoding="utf-8")
POPUP_JS = (CHROME / "popup.js").read_text(encoding="utf-8")
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

results = json.loads(DATA.read_text(encoding="utf-8"))["results"]
pkgs = [r["package"] for r in results]
code_line = "pip install " + " ".join(pkgs)

CHROME_SHIM = """<script>
  window.chrome = {
    storage:{ local:{get:function(){},set:function(){}},
              sync:{get:function(k,cb){cb&&cb({hmacSecret:""});},set:function(k,cb){cb&&cb();}} },
    runtime:{ sendMessage:function(msg,cb){
                if(!cb) return;
                if(msg && msg.type==="HEALTH_CHECK") cb({ok:true});
                else if(msg && msg.type==="GET_STATS") cb({safe:23,agentic:2,suspicious:4,malicious:1});
                else cb({});
              },
              onMessage:{addListener:function(){}} }
  };
</script>"""


def shot(html_path: Path, png_path: Path, w: int, h: int):
    if png_path.exists():
        png_path.unlink()
    udd = tempfile.mkdtemp()
    cmd = [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars",
           "--force-device-scale-factor=2", f"--window-size={w},{h}",
           f"--user-data-dir={udd}", "--virtual-time-budget=3000",
           f"--screenshot={png_path}", f"file:///{html_path.as_posix()}"]
    subprocess.run(cmd, capture_output=True, timeout=90)
    return png_path.exists() and png_path.stat().st_size > 0


def autocrop(png_path: Path, pad: int = 40):
    try:
        from PIL import Image
        import numpy as np
        im = Image.open(png_path).convert("RGB")
        a = np.asarray(im)
        bg = a[5, 5].astype(int)
        diff = (np.abs(a.astype(int) - bg).sum(axis=2) > 18)
        rows = np.where(diff.any(axis=1))[0]
        if len(rows):
            bottom = min(int(rows.max()) + pad, im.size[1])
            im.crop((0, 0, im.size[0], bottom)).save(png_path)
    except Exception as e:
        print("  autocrop skip:", e)


def panel_page(dark: bool) -> str:
    if dark:
        page_bg, bubble_tx, pre_bg, code_clr, top_clr = "#0d1117", "#e6edf3", "#161b22", "#e6edf3", "#8b949e"
        avatar = "#10a37f"
    else:
        page_bg, bubble_tx, pre_bg, code_clr, top_clr = "#f7f7f8", "#1f2937", "#0d1117", "#e6edf3", "#6b7280"
        avatar = "#10a37f"
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><style>
  *{{box-sizing:border-box;}} body{{margin:0;background:{page_bg};
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;}}
  .wrap{{max-width:760px;margin:0 auto;padding:24px 20px 40px;}}
  .topbar{{display:flex;align-items:center;gap:8px;padding:10px 4px 18px;color:{top_clr};font-size:13px;}}
  .topbar .dot{{width:8px;height:8px;border-radius:50%;background:#22c55e;box-shadow:0 0 8px rgba(34,197,94,.5);}}
  .msg{{display:flex;gap:14px;}}
  .avatar{{width:30px;height:30px;border-radius:6px;background:{avatar};color:#fff;
    display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;flex-shrink:0;}}
  .bubble{{flex:1;}} .bubble p{{margin:0 0 12px;color:{bubble_tx};font-size:14.5px;line-height:1.6;}}
  pre{{background:{pre_bg};color:{code_clr};padding:12px 14px;border-radius:8px;
    font-family:"SF Mono",Consolas,monospace;font-size:13px;margin:0 0 6px;}}
</style></head><body>
<div class="wrap">
  <div class="topbar"><span class="dot"></span> pkgSentinel 확장 활성 · 분석 엔진 localhost:8001 (claude 모드)</div>
  <div class="msg"><div class="avatar">AI</div><div class="bubble">
    <p>네! 요청하신 HTTP 호출 + 유틸리티 작업에는 아래 패키지를 설치하시면 됩니다:</p>
    <pre>{code_line}</pre>
    <div id="host"></div>
    <p style="margin-top:14px;">이렇게 설치한 뒤 <code>import requests</code> 로 시작하시면 됩니다.</p>
  </div></div>
</div>
{CHROME_SHIM}
<script>{COMMON_JS}</script>
<script>
  var RESULTS = {json.dumps(results, ensure_ascii=False)};
  var panel = buildPanel(RESULTS);
  document.getElementById("host").appendChild(panel);
  var detail = panel.children[1]; if (detail) detail.style.display = "block";
</script></body></html>"""


def popup_page() -> str:
    body = POPUP_HTML.replace('<script src="popup.js"></script>', "")
    inject = CHROME_SHIM + f"\n<script>{POPUP_JS}</script>"
    return body.replace("</body>", inject + "\n</body>")


# 1) 라이트 패널
p = DOCS / "demo_screenshot.html"
p.write_text(panel_page(False), encoding="utf-8")
png = DOCS / "demo_chrome_extension.png"
print("light:", "OK" if shot(p, png, 820, 900) else "FAIL")
autocrop(png)

# 2) 다크 패널
p = DOCS / "demo_screenshot_dark.html"
p.write_text(panel_page(True), encoding="utf-8")
png = DOCS / "demo_chrome_extension_dark.png"
print("dark:", "OK" if shot(p, png, 820, 900) else "FAIL")
autocrop(png)

# 3) 팝업
p = DOCS / "demo_popup_render.html"
p.write_text(popup_page(), encoding="utf-8")
png = DOCS / "demo_popup.png"
print("popup:", "OK" if shot(p, png, 360, 560) else "FAIL")
autocrop(png, pad=20)

print("done.")
