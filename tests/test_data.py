"""Verify the public payload and both pinned copies without touching trust stores."""
import base64
import csv
import hashlib
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CertificateDataTest(unittest.TestCase):
    def test_pinned_payload_and_provenance(self):
        data = (ROOT / "data/certificates.tsv").read_bytes()
        digest = hashlib.sha256(data).hexdigest().upper()
        for script in ("macos.sh", "windows.ps1"):
            self.assertIn(digest, (ROOT / script).read_text())
        rows = list(csv.DictReader(data.decode("ascii").splitlines(), delimiter="\t"))
        sources = json.loads((ROOT / "data/provenance.json").read_text())["certificates"]
        self.assertEqual(len(rows), 23)
        self.assertEqual(len({r["sha256"] for r in rows}), 23)
        self.assertEqual(sum(r["type"] == "root" for r in sources), 7)
        self.assertEqual(sum(r["type"] == "intermediate" for r in sources), 8)
        self.assertEqual(sum(r["type"] == "cross-signed intermediate" for r in sources), 8)
        for row, source in zip(rows, sources):
            der = base64.b64decode(row["der_base64"], validate=True)
            self.assertEqual(hashlib.sha256(der).hexdigest().upper(), row["sha256"])
            self.assertEqual(hashlib.sha1(der).hexdigest().upper(), row["sha1"])
            for key in ("name", "sha1", "sha256"):
                self.assertEqual(row[key], source[key])
        for path in ROOT.rglob("*"):
            if path.is_file() and path.suffix in {".sh", ".ps1", ".tsv", ".json", ".pem", ".md"}:
                text = path.read_text()
                self.assertNotRegex(text, r"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----")
                self.assertNotRegex(text, r"/Users/[^/]+/|gh[pousr]_[A-Za-z0-9]{20,}")


if __name__ == "__main__":
    unittest.main()
