from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class BuildCatalogTest(unittest.TestCase):
    def test_builder_generates_bumblebee_catalog(self) -> None:
        fixture_dir = REPO_ROOT / "tests" / "fixtures" / "ossf" / "malicious"
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts" / "build_bumblebee_catalog.py"),
                    "--input-dir",
                    str(fixture_dir),
                    "--output-dir",
                    str(output_dir),
                    "--source-ref",
                    "fixture-sha",
                ],
                check=True,
            )

            catalog = json.loads((output_dir / "openssf-malicious-packages.json").read_text())
            metadata = json.loads((output_dir / "metadata.json").read_text())

        self.assertEqual(catalog["schema_version"], "0.1.0")
        self.assertEqual(len(catalog["entries"]), 1)
        self.assertEqual(catalog["entries"][0]["package"], "api-typings")
        self.assertEqual(catalog["entries"][0]["versions"], ["100.2.0"])
        self.assertEqual(metadata["source"]["ref"], "fixture-sha")
        self.assertEqual(metadata["stats"]["emitted_entries"], 1)
        self.assertEqual(metadata["stats"]["skipped_unsupported_ecosystem"], 1)


if __name__ == "__main__":
    unittest.main()
