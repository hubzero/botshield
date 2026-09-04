#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import unicodedata
from collections.abc import Callable
from html import escape
from pathlib import Path, PurePosixPath

try:
    from markdown_it import MarkdownIt
except ImportError as exc:  # pragma: no cover - exercised by humans
    raise SystemExit(
        "markdown-it-py is required to build the docs site.\n"
        "Install it with: python3 -m pip install -r gh-pages/requirements.txt"
    ) from exc


ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "gh-pages"
OUTPUT_DIR = ROOT / "gh-pages" / "public"
ASSET_SOURCE_PREFIX = "gh-pages/assets/"
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


_HTML_HREF_RE = re.compile(
    r"""(?P<attr>\b(?:href|src|srcset)\s*=\s*)(?P<q>["'])(?P<url>[^"']*)(?P=q)"""
)


def _resolve_attr_value(attr: str, value: str, resolve: "Callable[[str], str]") -> str:
    """Resolve one HTML attribute value.

    srcset is a comma-separated candidate list, each optionally carrying a
    width or density descriptor ("logo.svg 2x"), so it cannot be handed to
    the resolver whole. Everything else is a single URL.
    """
    if "srcset" not in attr.lower():
        return resolve(value)

    candidates = []
    for candidate in value.split(","):
        stripped = candidate.strip()
        if not stripped:
            continue
        url, _, descriptor = stripped.partition(" ")
        resolved = resolve(url)
        candidates.append(f"{resolved} {descriptor.strip()}".strip())
    return ", ".join(candidates)


def rewrite_links(tokens: list, resolve: "Callable[[str], str]") -> None:
    """Walk every link in the token stream and hand its href to `resolve`.

    Markdown links arrive as link_open tokens. Raw HTML blocks do not --
    markdown-it passes those through as opaque text -- so their href, src,
    and srcset attributes are rewritten with a regex instead. The README's
    badge row and its logo <picture> are both raw HTML, and their links
    need the same treatment as any other repo-relative link.
    """
    for token in tokens:
        if token.type == "inline" and token.children:
            rewrite_links(token.children, resolve)
            continue

        if token.type in ("html_block", "html_inline"):
            token.content = _HTML_HREF_RE.sub(
                lambda m: f"{m.group('attr')}{m.group('q')}"
                f"{_resolve_attr_value(m.group('attr'), m.group('url'), resolve)}"
                f"{m.group('q')}",
                token.content,
            )
            continue

        if token.type != "link_open":
            continue
        href = token.attrGet("href")
        if href:
            token.attrSet("href", resolve(href))


def make_link_resolver(
    source: str,
    output: str,
    source_to_output: dict[str, str],
    blob_base: str,
    warn: "Callable[[str], None]",
) -> "Callable[[str], str]":
    """Rewrite a repo-relative Markdown link so it works in the built site.

    Docs are written to be read two ways: as Markdown on GitHub, and as
    pages on the site. A link like `docs/policy.md` is correct on GitHub
    and meaningless in the built output, where that page lives at
    `policy/index.html`. This maps one to the other:

      * a link to a file that IS a page in the site  -> that page, relative
      * a link to any other file tracked in the repo -> its GitHub blob URL
      * anything else (absolute URL, bare #fragment, already-built path)
        is left exactly as written
    """
    source_dir = PurePosixPath(source).parent

    def resolve(href: str) -> str:
        if not href or href.startswith(("#", "//")):
            return href
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", href):  # http:, mailto:, ...
            return href

        path_part, sep, fragment = href.partition("#")
        if not path_part:
            return href

        target = os.path.normpath(str(source_dir / path_part)).replace(os.sep, "/")
        if target.startswith(".."):  # escapes the repo; not ours to touch
            return href

        if target in source_to_output:
            rebased = relative_href(
                Path("/site") / output, Path("/site") / source_to_output[target]
            )
            return rebased + sep + fragment

        # gh-pages/assets/ is copied into the site as assets/, so a link
        # to a logo or diagram resolves inside the built output rather
        # than bouncing out to GitHub. A blob URL would render the SVG's
        # source page, which is useless as an <img src>.
        if target.startswith(ASSET_SOURCE_PREFIX):
            rebased = relative_href(
                Path("/site") / output,
                Path("/site") / "assets" / target[len(ASSET_SOURCE_PREFIX):],
            )
            return rebased + sep + fragment

        if (ROOT / target).is_file():
            return f"{blob_base}/{target}" + sep + fragment

        # Not a repo file. Either an already-built path like
        # ../policy/index.html, or a genuinely dead link.
        if path_part.endswith(".md") or "/" not in path_part:
            warn(f"{source}: link to missing file {path_part!r}")
        return href

    return resolve


class MarkdownRenderer:
    def __init__(self) -> None:
        self.md = MarkdownIt("commonmark", {"html": True, "typographer": True})
        self.md.enable("table")
        self.md.enable("strikethrough")

    def render(
        self,
        text: str,
        link_resolver: "Callable[[str], str] | None" = None,
    ) -> dict[str, object]:
        tokens = self.md.parse(text)
        if link_resolver is not None:
            rewrite_links(tokens, link_resolver)
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

    source_to_output = {
        page["source"]: page["output"].replace(os.sep, "/") for page in docs_pages
    }
    blob_base = f"{github_href.rstrip('/')}/blob/{config.get('blob_ref', 'main')}"
    link_warnings: list[str] = []

    for page in docs_pages:
        source_path = ROOT / page["source"]
        resolver = make_link_resolver(
            page["source"],
            page["output"].replace(os.sep, "/"),
            source_to_output,
            blob_base,
            link_warnings.append,
        )
        rendered = renderer.render(source_path.read_text(encoding="utf-8"), resolver)
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

    for warning in link_warnings:
        print(f"warning: {warning}", file=sys.stderr)

    print(f"Built site into {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
