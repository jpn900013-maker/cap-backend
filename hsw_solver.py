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

# ---- Persistent browser + page pool for HSW computation ----
_pw = None
_browser = None
_page = None           # single persistent page
_hsw_js_cache = {}     # hsw_url -> js text
_current_hsw_url = None  # currently loaded hsw.js url in the page
_lock = asyncio.Lock()


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


async def hsw(req: str, site: str, sitekey: str) -> str:
    """Compute hCaptcha HSW proof-of-work token using a persistent page.
    
    Only re-injects hsw.js if the version changed. Otherwise just calls hsw(token)
    on the already-loaded page, making subsequent calls near-instant.
    """
    global _current_hsw_url

    async with _lock:
        page = await _ensure_page()

        try:
            # Decode HSW URL from the JWT token
            hsw_url = "https://newassets.hcaptcha.com" + jwt.decode(req, options={"verify_signature": False})["l"] + "/hsw.js"
        except Exception:
            # Fallback: if JWT decode fails, create a fresh context
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
            # If evaluation fails, reset the page for next call
            _current_hsw_url = None
            raise e
