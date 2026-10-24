import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from worker import same_origin, extract_links


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
