"""Unit tests for the docs-site builder's link rewriting.

Docs are written to be read two ways -- as Markdown on GitHub, and as
pages on the built site -- and a link that is correct in one context is
usually wrong in the other. `docs/policy.md` is right on GitHub and
meaningless in the output tree, where that page is `policy/index.html`.
The builder reconciles the two, and these tests pin the mapping, because
a broken docs link is invisible until somebody follows it.

Run: python3 -m pytest gh-pages/test_build_site.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_site import (  # noqa: E402
    _resolve_attr_value,
    make_link_resolver,
    rewrite_links,
    slugify,
)

SOURCE_TO_OUTPUT = {
    "docs/policy.md": "policy/index.html",
    "docs/faq.md": "faq/index.html",
    "README.md": "guide/index.html",
}
BLOB = "https://github.com/hubzero/botshield/blob/main"


def resolver(source="docs/faq.md", output="faq/index.html", warn=None):
    return make_link_resolver(
        source, output, SOURCE_TO_OUTPUT, BLOB, warn if warn is not None else (lambda m: None)
    )


@pytest.mark.parametrize(
    ("href", "expected"),
    [
        # A doc that is a page in the site resolves to that page.
        ("policy.md", "../policy/index.html"),
        ("policy.md#allow-list", "../policy/index.html#allow-list"),
        # The README is a page too, one directory up from docs/.
        ("../README.md", "../guide/index.html"),
        # A repo file with no page of its own goes to GitHub.
        ("../DESIGN.md", f"{BLOB}/DESIGN.md"),
        ("../LICENSE", f"{BLOB}/LICENSE"),
        ("../.github/SECURITY.md", f"{BLOB}/.github/SECURITY.md"),
        ("../DESIGN.md#threat-model", f"{BLOB}/DESIGN.md#threat-model"),
    ],
)
def test_repo_relative_links_are_rewritten(href, expected):
    assert resolver()(href) == expected


@pytest.mark.parametrize(
    "href",
    [
        "#local-anchor",
        "https://example.com/page",
        "http://example.com/page",
        "mailto:security@example.com",
        "//cdn.example.com/x.js",
        "",
    ],
)
def test_links_that_are_not_ours_are_left_alone(href):
    assert resolver()(href) == href


def test_already_built_paths_pass_through_unchanged():
    """Docs written against the output tree keep working untouched."""
    assert resolver()("../policy/index.html") == "../policy/index.html"


def test_dead_markdown_link_warns_and_is_left_intact():
    warnings: list[str] = []
    assert resolver(warn=warnings.append)("no-such-doc.md") == "no-such-doc.md"
    assert len(warnings) == 1
    assert "no-such-doc.md" in warnings[0]


def test_readme_at_repo_root_resolves_into_docs():
    resolve = resolver(source="README.md", output="guide/index.html")
    assert resolve("docs/policy.md") == "../policy/index.html"
    assert resolve("LICENSE") == f"{BLOB}/LICENSE"


def test_links_escaping_the_repo_are_untouched():
    resolve = resolver(source="README.md", output="guide/index.html")
    assert resolve("../../outside.md") == "../../outside.md"


class FakeToken:
    """Minimal stand-in for a markdown-it token."""

    def __init__(self, type_, content="", href=None, children=None):
        self.type = type_
        self.content = content
        self.children = children
        self._attrs = {"href": href} if href else {}

    def attrGet(self, name):
        return self._attrs.get(name)

    def attrSet(self, name, value):
        self._attrs[name] = value


def test_rewrite_links_reaches_nested_inline_children():
    link = FakeToken("link_open", href="policy.md")
    tokens = [FakeToken("inline", children=[link])]
    rewrite_links(tokens, resolver())
    assert link.attrGet("href") == "../policy/index.html"


def test_rewrite_links_handles_raw_html_blocks():
    """The README's badge row is raw HTML, and markdown-it passes it
    through opaquely -- so its hrefs need rewriting too."""
    token = FakeToken(
        "html_block",
        content='<p><a href="../LICENSE"><img src="../docs/assets/x.svg"></a></p>',
    )
    rewrite_links([token], resolver())
    assert f'href="{BLOB}/LICENSE"' in token.content
    # src attributes get the same treatment as href.
    assert "src=" in token.content


def test_slugify_matches_the_anchors_headings_generate():
    assert slugify("Tier thresholds (effective)") == "tier-thresholds-effective"
    assert slugify("What's shipped") == "what-s-shipped"
    assert slugify("") == "section"


def test_site_assets_resolve_inside_the_build_not_to_github():
    """A logo must stay an image. A blob URL would render GitHub's
    source-view page, which is useless as an <img src>."""
    resolve = resolver(source="README.md", output="guide/index.html")
    assert resolve("gh-pages/assets/logo.svg") == "../assets/logo.svg"


def test_srcset_candidates_are_each_resolved():
    resolve = resolver(source="README.md", output="guide/index.html")
    out = _resolve_attr_value(
        "srcset", "gh-pages/assets/a.svg 1x, gh-pages/assets/b.svg 2x", resolve
    )
    assert out == "../assets/a.svg 1x, ../assets/b.svg 2x"


def test_srcset_without_descriptors_still_resolves():
    resolve = resolver(source="README.md", output="guide/index.html")
    assert _resolve_attr_value("srcset", "gh-pages/assets/a.svg", resolve) == "../assets/a.svg"


def test_non_srcset_attribute_is_resolved_whole():
    resolve = resolver(source="README.md", output="guide/index.html")
    assert _resolve_attr_value("src", "gh-pages/assets/a.svg", resolve) == "../assets/a.svg"


def test_picture_element_srcset_is_rewritten():
    token = FakeToken(
        "html_block",
        content='<source srcset="gh-pages/assets/logo.svg"><img src="gh-pages/assets/l.svg">',
    )
    rewrite_links([token], resolver(source="README.md", output="guide/index.html"))
    assert 'srcset="../assets/logo.svg"' in token.content
    assert 'src="../assets/l.svg"' in token.content
