"""Brand kit and the simple / advanced switch."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "app" / "static" / "brand"


def test_brand_assets_exist():
    for rel in ("favicon.ico", "favicon.svg", "favicon-32.png",
                "logo/logo-light.svg", "logo/mark-light.svg",
                "art/hero-960.webp", "art/hero-960.jpg", "art/divider-light.svg",
                "social/share-1200x630.jpg", "app/app-192.png",
                "icons/sprite.svg", "kituwa-links.css"):
        assert (BRAND / rel).exists(), rel


def test_brand_assets_are_served(client):
    for path in ("/static/brand/favicon.ico", "/static/brand/favicon.svg",
                 "/static/brand/logo/logo-light.svg",
                 "/static/brand/art/hero-960.webp",
                 "/static/brand/art/hero-960.jpg",
                 "/static/brand/social/share-1200x630.jpg",
                 "/static/brand/icons/sprite.svg",
                 "/static/brand/kituwa-links.css"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert len(r.data) > 100, path


def test_manifest_is_valid(client):
    r = client.get("/manifest.webmanifest")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/manifest+json")
    data = json.loads(r.data)
    assert data["name"] == "Kituwa Links"
    assert len(data["icons"]) == 3
    assert data["theme_color"] == "#F5F8F4"


def test_home_page_carries_the_brand(client):
    body = client.get("/").get_data(as_text=True)
    assert 'class="brand-kituwa"' in body
    assert "brand/logo/logo-light.svg" in body
    assert "brand/kituwa-links.css" in body
    assert "brand/art/hero-960.webp" in body
    assert "brand/art/divider-light.svg" in body
    assert "brand-footer" in body
    assert "brand-topbar-logo" in body
    assert 'rel="manifest"' in body
    assert "integrity=\"sha384-" in body


def test_home_page_metadata(client):
    body = client.get("/").get_data(as_text=True)
    assert "<title>Encrypted short links | Kituwa Links</title>" in body
    assert 'rel="canonical" href="https://links.kituwa.com/"' in body
    assert 'property="og:image"' in body
    assert "share-1200x630.jpg" in body
    assert 'name="twitter:card" content="summary_large_image"' in body
    assert 'name="theme-color" content="#F5F8F4"' in body


def test_simple_mode_is_the_default(client):
    body = client.get("/").get_data(as_text=True)
    assert 'data-mode-set="simple" aria-pressed="true"' in body
    assert 'data-mode-set="complex" aria-pressed="false"' in body
    assert 'class="span-2 adv"' in body or " adv" in body
    assert "A URL, how many opens and how long" in body


def test_secret_pages_are_not_branded(client):
    for path in ("/l/" + "A" * 22, "/m/" + "A" * 22):
        body = client.get(path).get_data(as_text=True)
        assert "brand-kituwa" not in body
        assert "kituwa-links.css" not in body
        assert "kituwa-network" not in body


def test_brand_css_is_same_origin_only():
    css = (BRAND / "kituwa-links.css").read_text()
    assert "http://" not in css and "https://" not in css
    assert "@import" not in css
