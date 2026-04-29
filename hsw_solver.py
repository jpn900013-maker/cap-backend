import tls_client, re, jwt, asyncio, threading

from playwright.async_api import async_playwright

session = tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)
session.headers = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'no-cache',
    'pragma': 'no-cache',
    'referer': 'https://discord.com/',
    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
}

# ---- Dedicated event loop thread for HSW computation ----
# This ensures all async playwright calls run on the SAME event loop,
# preventing 'NoneType has no attribute send' errors from asyncio.run()
# creating separate loops per thread.

_loop = None
_loop_thread = None
_pw = None
_browser = None
_page = None
_hsw_js_cache = {}      # hsw_url -> js text
_current_hsw_url = None  # currently loaded hsw.js url in the page
_lock = None             # asyncio.Lock on the dedicated loop


def _start_loop(loop):
    """Run the event loop forever in a background thread."""
    asyncio.set_event_loop(loop)
    loop.run_forever()


def _ensure_loop():
    """Create the dedicated event loop and thread if not already running."""
    global _loop, _loop_thread, _lock
    if _loop is None or not _loop.is_running():
        _loop = asyncio.new_event_loop()
        _lock = asyncio.Lock()
        _loop_thread = threading.Thread(target=_start_loop, args=(_loop,), daemon=True)
        _loop_thread.start()


async def _ensure_page():
    """Get or create a persistent Playwright browser and page."""
    global _pw, _browser, _page, _current_hsw_url

    # Check if browser crashed
    if _browser is not None and not _browser.is_connected():
        _browser = None
        _page = None
        _current_hsw_url = None

    # Launch browser if needed
    if _browser is None:
        if _pw is None:
            _pw = await async_playwright().start()
        _browser = await _pw.chromium.launch(
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--disable-extensions"]
        )
        _page = None
        _current_hsw_url = None

    # Create page if needed
    if _page is None or _page.is_closed():
        context = await _browser.new_context()
        _page = await context.new_page()
        await _page.route("**/*", lambda r: r.fulfill(status=200, content_type="text/html", body="<html></html>"))
        await _page.goto("about:blank")
        await _page.wait_for_load_state('domcontentloaded')
        # Patch webdriver detection
        await _page.add_script_tag(content='Object.defineProperty(navigator, "webdriver", {"get": () => false})')
        _current_hsw_url = None

    return _page


async def _get_hsw_js(url: str) -> str:
    """Download and cache hsw.js."""
    if url not in _hsw_js_cache:
        _hsw_js_cache[url] = session.get(url).text
    return _hsw_js_cache[url]


async def _hsw_impl(req: str, site: str, sitekey: str) -> str:
    """Internal HSW implementation — runs on the dedicated event loop."""
    global _current_hsw_url

    async with _lock:
        page = await _ensure_page()

        try:
            hsw_url = "https://newassets.hcaptcha.com" + jwt.decode(req, options={"verify_signature": False})["l"] + "/hsw.js"
        except Exception:
            hsw_url = None

        if hsw_url:
            # Only reload hsw.js if the URL changed (new hCaptcha version)
            if hsw_url != _current_hsw_url:
                hsw_js = await _get_hsw_js(hsw_url)
                await page.evaluate("() => { window.hsw = undefined; }")
                await page.add_script_tag(content=hsw_js)
                _current_hsw_url = hsw_url

        try:
            result = await page.evaluate(f"hsw('{req}')")
            return result
        except Exception as e:
            # Reset page state for next call
            _current_hsw_url = None
            raise e


async def hsw(req: str, site: str, sitekey: str) -> str:
    """Compute hCaptcha HSW proof-of-work token.
    
    Thread-safe: dispatches to a dedicated event loop so multiple solver
    threads can call this concurrently without event loop conflicts.
    """
    _ensure_loop()
    future = asyncio.run_coroutine_threadsafe(_hsw_impl(req, site, sitekey), _loop)
    return future.result(timeout=30)
