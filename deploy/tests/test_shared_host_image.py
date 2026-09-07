#!/usr/bin/env python3
"""Fail-closed tests for fixed-source build and scoped registry publication."""
import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("shared_host_image", ROOT / "deploy/shared-host/image.py")
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)
SHA = "a" * 40
IMAGE_ID = "sha256:" + "b" * 64


class ImageWorkflowTests(unittest.TestCase):
    def test_checkout_must_match_approved_sha(self):
        with patch.object(image, "run", return_value="c" * 40) as run:
            with self.assertRaisesRegex(ValueError, "HEAD"):
                image.checked_source(SHA)
            self.assertEqual(run.call_count, 1)

    def test_dirty_checkout_is_rejected_before_build(self):
        with patch.object(image, "run", side_effect=[SHA, " M _docker/Dockerfile"]):
            with self.assertRaisesRegex(ValueError, "clean fixed"):
                image.checked_source(SHA)

    def test_other_repository_is_rejected(self):
        with patch.object(image, "run", side_effect=[SHA, "", "https://example.invalid/unapproved.git"]):
            with self.assertRaisesRegex(ValueError, "origin"):
                image.checked_source(SHA)

    def test_evidence_never_overwrites_existing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileExistsError):
                image.evidence_directory(Path(directory))

    def test_evidence_must_not_pollute_the_fixed_checkout(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            image.evidence_directory(ROOT / "image-evidence")

    def test_publish_requires_actual_image_id_and_approved_test_registry(self):
        for image_id, target, approved in (
            ("local:tag", "registry.test:5000/filebrowser:fixed", "registry.test:5000"),
            (IMAGE_ID, "ghcr.io/company/filebrowser:fixed", "ghcr.io"),
            (IMAGE_ID, "registry.test:5000/filebrowser:fixed", "wrong.test:5000"),
        ):
            with self.subTest(target=target, image=image_id):
                args = argparse.Namespace(image=image_id, target=target, approved_registry=approved)
                with patch.object(image, "run") as run:
                    with self.assertRaises(ValueError):
                        image.publish(args)
                    run.assert_not_called()

    def test_publish_revision_mismatch_does_not_tag_or_push(self):
        args = argparse.Namespace(image=IMAGE_ID, target="registry.test:5000/filebrowser:fixed",
                                  approved_registry="registry.test:5000", source_sha=SHA)
        with patch.object(image, "image_info", return_value={"Config": {"Labels": {}}}):
            with patch.object(image, "run") as run:
                with self.assertRaisesRegex(ValueError, "revision"):
                    image.publish(args)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
