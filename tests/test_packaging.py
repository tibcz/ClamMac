"""What the application bundle is obliged to carry.

The bundle can only be built on macOS, so these tests check the inputs to the
build rather than its output: that the files exist in the repository and that
the spec actually lists them. ``packaging/build_app.py`` re-checks the built
bundle itself, which is the half that cannot run here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "packaging" / "ClamMac.spec"

#: Everything the bundle must ship. The Qt libraries travel inside it under
#: the LGPL-3.0, so a copy of that licence has to travel with them (§4(b)),
#: and the relinking procedure has to be readable by someone holding only the
#: .app (§4(d)) -- the About box tells them to go and read it.
REQUIRED_DOCUMENTS = (
    "LICENSE",
    "NOTICE.md",
    "LICENSES/LGPL-3.0.txt",
    "docs/RELINKING.md",
)


@pytest.mark.parametrize("relative", REQUIRED_DOCUMENTS)
def test_the_document_exists_in_the_repository(relative):
    assert (REPO_ROOT / relative).is_file(), f"{relative} is missing from the repository"


@pytest.mark.parametrize("relative", REQUIRED_DOCUMENTS)
def test_the_spec_ships_the_document(relative):
    """Each required document has to appear in the spec's DATA_FILES."""
    spec = SPEC.read_text("utf-8")
    data_files = spec.split("DATA_FILES", 1)[1].split("analysis = Analysis", 1)[0]
    leaf = relative.rsplit("/", 1)[-1]
    assert leaf in data_files, f"{relative} is not listed in DATA_FILES"


class TestLgplText:
    """The licence file has to be the real thing, not a stub or a link."""

    def _text(self) -> str:
        return (REPO_ROOT / "LICENSES" / "LGPL-3.0.txt").read_text("utf-8")

    def test_it_is_the_lesser_gpl_version_3(self):
        text = self._text()
        assert "GNU LESSER GENERAL PUBLIC LICENSE" in text
        assert "Version 3, 29 June 2007" in text

    def test_it_carries_the_gpl_it_incorporates(self):
        """LGPL-3.0 is a set of additional permissions on top of the GPL-3.0.

        §4(b) asks for "a copy of the GNU GPL and this license document", so
        the GPL text has to be reachable too.
        """
        assert "GNU GENERAL PUBLIC LICENSE" in self._text()

    def test_it_contains_the_relinking_clause_the_bundle_relies_on(self):
        assert "Combined Work" in self._text()

    def test_it_is_not_a_truncated_stub(self):
        assert len(self._text()) > 20_000


class TestRelinkingDoc:
    def test_it_documents_the_section_4d_procedure(self):
        text = (REPO_ROOT / "docs" / "RELINKING.md").read_text("utf-8")
        assert "4(d)" in text
        assert "install_name_tool" in text
        assert "codesign" in text


class TestAboutBoxPromises:
    """The About box points the reader at files; they have to be there."""

    def test_every_repository_path_it_names_exists(self):
        about = (REPO_ROOT / "clammac" / "ui" / "about.py").read_text("utf-8")
        # Stop before the full stop that ends the sentence: a path segment
        # ends on a word character, never on the punctuation after it.
        referenced = set(re.findall(r"\b((?:docs|LICENSES)/[\w\-]+(?:\.[\w\-]+)*)", about))
        assert referenced, "expected the About box to cite its licence documents"
        for relative in sorted(referenced):
            assert (REPO_ROOT / relative).is_file(), (
                f"the About box tells the reader to read {relative}, "
                "which does not exist"
            )
