import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from worker import same_origin, extract_links, extract_subresources, parse_cookie_header


def test_same_origin_exact_match():
    assert same_origin("https://example.com/path", "https://example.com")
    assert same_origin("http://example.com:8080/test", "http://example.com:8080")
    assert not same_origin("https://example.com:8081/test", "https://example.com:8080")


def test_same_origin_scheme_transitions():
    # Upgrade or transition between http and https on same host
    assert same_origin("https://example.com/path", "http://example.com")
    assert same_origin("http://example.com/path", "https://example.com")


def test_same_origin_www_equivalence():
    assert same_origin("https://www.example.com/about", "https://example.com")
    assert same_origin("https://example.com/about", "https://www.example.com")
    assert same_origin("http://www.example.com/about", "https://example.com")


def test_same_origin_multiple_allowed_origins():
    origins = {"https://yandex.ru", "https://dzen.ru"}
    assert same_origin("https://yandex.ru/search", origins)
    assert same_origin("https://dzen.ru/news", origins)
    assert same_origin("https://www.dzen.ru/news", origins)
    assert not same_origin("https://google.com", origins)
    assert not same_origin("https://evil.ru", origins)


def test_same_origin_invalid_inputs():
    assert not same_origin("", "https://example.com")
    assert not same_origin("https://example.com", "")
    assert not same_origin("javascript:void(0)", "https://example.com")
    assert not same_origin("mailto:test@example.com", "https://example.com")


def test_extract_links_filters_assets_and_protocols():
    async def run():
        page = AsyncMock()
        page.eval_on_selector_all.return_value = [
            "https://example.com/page1",
            "https://example.com/style.css",
            "https://example.com/logo.PNG",
            "https://example.com/font.woff2",
            "javascript:alert(1)",
            "mailto:admin@example.com",
            "tel:+1234567890",
            "/about#section",
            "https://example.com/doc.pdf",
            "https://example.com/page2",
        ]
        page.url = "https://example.com/"

        links = await extract_links(page, "https://example.com/")

        assert "https://example.com/page1" in links
        assert "https://example.com/page2" in links
        assert "https://example.com/about" in links
        # Asset extensions must be excluded so worker doesn't fail on ERR_ABORTED
        assert "https://example.com/style.css" not in links
        assert "https://example.com/logo.PNG" not in links
        assert "https://example.com/font.woff2" not in links
        assert "https://example.com/doc.pdf" not in links
        # Protocols must be excluded
        assert not any("javascript" in l or "mailto" in l or "tel" in l for l in links)

    asyncio.run(run())


def test_extract_links_retries_on_context_destroyed():
    async def run():
        page = AsyncMock()
        page.eval_on_selector_all.side_effect = [
            Exception("Execution context was destroyed, most likely because of a navigation"),
            ["https://example.com/recovered_page"],
        ]
        page.url = "https://example.com/final"
        page.wait_for_load_state = AsyncMock()

        links = await extract_links(page, "https://example.com/")

        assert links == ["https://example.com/recovered_page"]
        assert page.eval_on_selector_all.call_count == 2

    asyncio.run(run())


def test_extract_subresources_finds_css_js_images():
    async def run():
        page = AsyncMock()
        page.eval_on_selector_all.return_value = [
            {"tag": "link", "url": "/dvwa/css/login.css"},
            {"tag": "img", "url": "/dvwa/images/login_logo.png"},
            {"tag": "script", "url": "https://example.com/app.js"},
            {"tag": "img", "url": "data:image/png;base64,123"},
        ]
        page.url = "https://example.com/login.php"

        items = await extract_subresources(page, "https://example.com/login.php")
        urls = [item["url"] for item in items]
        kinds = {item["url"]: item["kind"] for item in items}

        assert "https://example.com/dvwa/css/login.css" in urls
        assert kinds["https://example.com/dvwa/css/login.css"] == "css"
        assert "https://example.com/dvwa/images/login_logo.png" in urls
        assert kinds["https://example.com/dvwa/images/login_logo.png"] == "image"
        assert "https://example.com/app.js" in urls
        assert kinds["https://example.com/app.js"] == "script"
        assert not any(u.startswith("data:") for u in urls)

    asyncio.run(run())


def test_parse_cookie_header():
    cookies = parse_cookie_header("PHPSESSID=test12345; security=low; other=val", "http://127.0.0.1:8088/")
    assert len(cookies) == 3
    names = {c["name"]: c["value"] for c in cookies}
    assert names["PHPSESSID"] == "test12345"
    assert names["security"] == "low"
    assert names["other"] == "val"
    assert all(c["domain"] == "127.0.0.1" for c in cookies)


def test_extract_links_spa_hash_routing():
    async def run():
        page = AsyncMock()
        page.eval_on_selector_all.return_value = [
            "#/basket",
            "#/score-board",
            "/about",
            "#/administration",
            "#regular-anchor",  # Should be skipped
            "javascript:void(0)",  # Should be skipped
        ]
        page.url = "http://127.0.0.1:3000/"

        links = await extract_links(page, "http://127.0.0.1:3000/")
        assert "http://127.0.0.1:3000/#/basket" in links
        assert "http://127.0.0.1:3000/#/score-board" in links
        assert "http://127.0.0.1:3000/#/administration" in links
        assert "http://127.0.0.1:3000/about" in links
        assert not any(l.endswith("#regular-anchor") for l in links)

    asyncio.run(run())




def test_is_logout_url_and_label():
    from worker import is_logout_url, is_logout_label
    assert is_logout_url("http://x/logout.php")
    assert is_logout_url("http://x/#/logout")
    assert not is_logout_url("http://x/vulnerabilities/sqli/")
    assert is_logout_label("Logout")
    assert not is_logout_label("Submit")


def test_normalize_crawl_url_keeps_spa_hash_route():
    from worker import _normalize_crawl_url
    assert _normalize_crawl_url("http://x/#/login") == "http://x/#/login"
    assert _normalize_crawl_url("http://x/page#section") == "http://x/page"


def test_spa_soft_404_detection():
    from worker import _looks_like_spa_soft_404
    root = ("T", 100, "same", "<head>")
    assert _looks_like_spa_soft_404(("T", 100, "same", "<head>"), root)
    assert not _looks_like_spa_soft_404(("Other", 100, "same", "<head>"), root)
    assert not _looks_like_spa_soft_404(None, root)


def test_fill_auto_field_file_upload():
    from worker import fill_auto_field
    page = MagicMock()
    loc = MagicMock()
    loc.set_input_files = AsyncMock()
    page.locator.return_value.first = loc
    res = asyncio.run(fill_auto_field(page, {"selector": "input[type=file]", "kind": "file", "name": "uploaded", "label": "Upload"}))
    assert res["interaction"] == "upload"
    assert res["value"] == "rr_probe.png"
    loc.set_input_files.assert_awaited_once()
    payload = loc.set_input_files.call_args[0][0]
    assert payload["name"] == "rr_probe.png"
    assert payload["mimeType"] == "image/png"
