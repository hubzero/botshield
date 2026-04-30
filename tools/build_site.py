#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import unicodedata
from html import escape
from pathlib import Path

try:
    from markdown_it import MarkdownIt
except ImportError as exc:  # pragma: no cover - exercised by humans
    raise SystemExit(
        "markdown-it-py is required to build the docs site.\n"
        "Install it with: python3 -m pip install -r tools/requirements-docs.txt"
    ) from exc


ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "site-src"
OUTPUT_DIR = ROOT / "docs"
HEADER_LOGO = "assets/logo-botshield-icon.svg"
HERO_LOGO = "assets/logo-botshield-header.svg"


def slugify(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", ascii_text.lower()).strip("-")
    return slug or "section"


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def render_template(path: Path, context: dict[str, str]) -> str:
    text = path.read_text(encoding="utf-8")
    for key, value in context.items():
        text = text.replace(f"{{{{ {key} }}}}", value)
    return text


def relative_href(from_file: Path, to_file: Path) -> str:
    return os.path.relpath(to_file, from_file.parent).replace(os.sep, "/")


class MarkdownRenderer:
    def __init__(self) -> None:
        self.md = MarkdownIt("commonmark", {"html": True, "typographer": True})
        self.md.enable("table")
        self.md.enable("strikethrough")

    def render(self, text: str) -> dict[str, object]:
        tokens = self.md.parse(text)
        slug_counts: dict[str, int] = {}
        toc: list[dict[str, object]] = []
        title = None
        first_h1_index = None

        for index, token in enumerate(tokens):
            if token.type != "heading_open":
                continue

            level = int(token.tag[1])
            if index + 1 >= len(tokens):
                continue

            inline = tokens[index + 1]
            if inline.type != "inline":
                continue

            heading_text = inline.content.strip()
            if not heading_text:
                continue

            base_slug = slugify(heading_text)
            count = slug_counts.get(base_slug, 0)
            slug_counts[base_slug] = count + 1
            anchor = base_slug if count == 0 else f"{base_slug}-{count + 1}"
            token.attrSet("id", anchor)

            if level == 1 and title is None:
                title = heading_text
                first_h1_index = index
            elif level in (2, 3):
                toc.append({"level": level, "anchor": anchor, "text": heading_text})

        if first_h1_index is not None:
            del tokens[first_h1_index : first_h1_index + 3]

        html = self.md.renderer.render(tokens, self.md.options, {})
        return {"title": title, "toc": toc, "html": html}


def build_docs_nav(
    pages: list[dict[str, str]], current_slug: str, current_output: Path, output_dir: Path
) -> str:
    items = []
    for page in pages:
        classes = "docs-nav__item"
        if page["slug"] == current_slug:
            classes += " is-active"
        href = relative_href(current_output, output_dir / page["output"])
        items.append(
            "\n".join(
                [
                    f'<a class="{classes}" href="{escape(href)}">',
                    f'  <span class="docs-nav__title">{escape(page["title"])}</span>',
                    f'  <span class="docs-nav__summary">{escape(page["summary"])}</span>',
                    "</a>",
                ]
            )
        )
    return "\n".join(items)


def build_toc(entries: list[dict[str, object]]) -> str:
    if not entries:
        return ""

    items = []
    for entry in entries:
        level = int(entry["level"])
        classes = f"toc__item toc__item--level-{level}"
        items.append(
            f'<li class="{classes}"><a href="#{escape(str(entry["anchor"]))}">'
            f"{escape(str(entry['text']))}</a></li>"
        )
    return (
        '<section class="toc">\n'
        '  <h2 class="toc__heading">On this page</h2>\n'
        '  <ul class="toc__list">\n'
        f"{chr(10).join(items)}\n"
        "  </ul>\n"
        "</section>"
    )


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copy_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    shutil.copytree(source, destination, dirs_exist_ok=True)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the mod_botshield docs site.")
    parser.add_argument("--output", default=str(OUTPUT_DIR), help="Build output directory")
    args = parser.parse_args()

    output_dir = Path(args.output).resolve()
    config = read_json(SOURCE_DIR / "site.json")
    renderer = MarkdownRenderer()

    ensure_clean_dir(output_dir)
    copy_tree(SOURCE_DIR / "assets", output_dir / "assets")
    copy_tree(SOURCE_DIR / "static", output_dir)
    write_text(output_dir / ".nojekyll", "")

    docs_pages: list[dict[str, str]] = []
    for entry in config["docs"]:
        docs_pages.append(
            {
                "slug": entry["slug"],
                "title": entry["title"],
                "summary": entry["summary"],
                "source": entry["source"],
                "output": str(Path(entry["slug"]) / "index.html"),
                "featured": bool(entry.get("featured", False)),
            }
        )

    for page in docs_pages:
        page["href"] = page["output"].replace(os.sep, "/")

    featured_pages = [page for page in docs_pages if page["featured"]] or docs_pages

    docs_cards = []
    for page in featured_pages:
        docs_cards.append(
            "\n".join(
                [
                    '<article class="doc-card">',
                    f'  <h3><a href="{escape(page["href"])}">{escape(page["title"])}</a></h3>',
                    f'  <p>{escape(page["summary"])}</p>',
                    f'  <a class="doc-card__link" href="{escape(page["href"])}">Open</a>',
                    "</article>",
                ]
            )
        )

    hero_primary = docs_pages[0]["href"] if docs_pages else "#"
    hero_secondary = docs_pages[1]["href"] if len(docs_pages) > 1 else hero_primary
    github_href = config.get("github_href", "#")
    download_href = config.get("download_href",
                               f"{hero_primary}#build" if docs_pages else "#")

    home_html = render_template(
        SOURCE_DIR / "templates" / "home.html",
        {
            "site_name": escape(config["site_name"]),
            "brand_tagline": escape(config.get("brand_tagline", "")),
            "site_tagline": escape(config["site_tagline"]),
            "site_description": escape(config["site_description"]),
            "logo_href": escape(HEADER_LOGO),
            "hero_logo_href": escape(HERO_LOGO),
            "github_href": escape(github_href),
            "docs_href": escape(hero_primary),
            "download_href": escape(download_href),
            "primary_href": escape(hero_primary),
            "secondary_href": escape(hero_secondary),
            "docs_cards": "\n".join(docs_cards),
        },
    )
    write_text(output_dir / "index.html", home_html)

    for page in docs_pages:
        source_path = ROOT / page["source"]
        rendered = renderer.render(source_path.read_text(encoding="utf-8"))
        output_path = output_dir / page["output"]
        nav_html = build_docs_nav(docs_pages, page["slug"], output_path, output_dir)
        toc_html = build_toc(rendered["toc"])  # type: ignore[arg-type]
        asset_prefix = relative_href(output_path, output_dir / "assets" / "site.css")
        logo_href = relative_href(output_path, output_dir / HEADER_LOGO)
        home_href = relative_href(output_path, output_dir / "index.html")
        docs_href = relative_href(output_path, output_dir / docs_pages[0]["output"]) if docs_pages else "#"
        download_href = config.get("download_href",
                                   f"{docs_href}#build" if docs_pages else "#")

        doc_html = render_template(
            SOURCE_DIR / "templates" / "doc.html",
            {
                "page_title": escape(page["title"]),
                "site_name": escape(config["site_name"]),
                "site_tagline": escape(config["site_tagline"]),
                "page_summary": escape(page["summary"]),
                "assets_href": escape(asset_prefix),
                "logo_href": escape(logo_href),
                "home_href": escape(home_href),
                "github_href": escape(github_href),
                "docs_href": escape(docs_href),
                "download_href": escape(download_href),
                "docs_nav": nav_html,
                "toc": toc_html,
                "source_title": escape(str(rendered["title"] or "")),
                "content": str(rendered["html"]),
            },
        )
        write_text(output_path, doc_html)

    print(f"Built site into {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
