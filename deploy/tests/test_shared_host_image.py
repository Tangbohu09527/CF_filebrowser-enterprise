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

    def test_base_reference_validation_preserves_tags_and_registry_digests(self):
        for reference in (*image.BASES.values(),
                          "registry.test:5000/team/base:fixed",
                          "registry.test:5000/team/base@sha256:" + "c" * 64,
                          "registry.test:5000/team/base:fixed@sha256:" + "c" * 64):
            with self.subTest(reference=reference):
                image.checked_reference(reference)

    def test_publish_rejects_unsafe_or_implicit_targets_before_docker(self):
        sentinel = "credential-sentinel"
        targets = (
            "registry.test:5000/filebrowser",
            "registry.test/filebrowser",
            "registry.test:5000/filebrowser@sha256:" + "c" * 64,
            "registry.test:5000/filebrowser:fixed@sha256:" + "c" * 64,
            "https://registry.test:5000/filebrowser:fixed",
            "registry.test:5000/" + sentinel + "@filebrowser:fixed",
            "registry.test:5000/filebrowser:fixed\n" + sentinel,
            "registry.test:5000/filebrowser:fixed\x00" + sentinel,
            "registry.test:5000/filebrowser:fixed other",
            "registry.test:5000/filebrowser:",
            "registry.test:5000/../filebrowser:fixed",
        )
        for target in targets:
            with self.subTest(target_kind=targets.index(target)):
                args = argparse.Namespace(image=IMAGE_ID, target=target,
                                          approved_registry="registry.test:5000")
                with patch.object(image, "run") as run:
                    with patch.object(image, "image_info", side_effect=AssertionError("must reject before Docker inspection")):
                        with self.assertRaises(ValueError) as error:
                            image.publish(args)
                run.assert_not_called()
                self.assertNotIn(sentinel, str(error.exception))

    def test_base_references_are_validated_before_any_pull_or_evidence_write(self):
        sentinel = "credential-sentinel"
        invalid = (
            "https://user:" + sentinel + "@registry.test/base:fixed",
            "user:" + sentinel + "@registry.test/base:fixed",
            "node:jod-slim\n" + sentinel,
            "node:jod-slim\x00" + sentinel,
            "node:latest;whoami",
            "node:latest extra",
        )
        for key in image.BASES:
            for reference in invalid:
                with self.subTest(base=key, reference_kind=invalid.index(reference)):
                    fields = {name.lower(): None for name in image.BASES}
                    fields[key.lower()] = reference
                    args = argparse.Namespace(source_sha=SHA, image="cf-filebrowser:fixed",
                                              evidence=Path("unused-evidence"), **fields)
                    with patch.object(image, "checked_source"):
                        with patch.object(image, "evidence_directory") as evidence:
                            with patch.object(image, "run", side_effect=AssertionError("must reject before Docker pull")):
                                with self.assertRaises(ValueError) as error:
                                    image.build(args)
                    evidence.assert_not_called()
                    self.assertNotIn(sentinel, str(error.exception))

    def test_publish_explicit_tag_preserves_registry_port_and_records_digest(self):
        target = "registry.test:5000/team/filebrowser:fixed-sha"
        pinned = "registry.test:5000/team/filebrowser@sha256:" + "c" * 64
        args = argparse.Namespace(image=IMAGE_ID, target=target, approved_registry="registry.test:5000",
                                  source_sha=SHA, evidence=Path("unused-evidence"))
        inspected = [
            {"Config": {"Labels": {"org.opencontainers.image.revision": SHA}}},
            {"RepoDigests": [pinned]},
        ]
        with patch.object(image, "image_info", side_effect=inspected):
            with patch.object(image, "evidence_directory"):
                with patch.object(image, "write_record") as record:
                    with patch.object(image, "run") as run:
                        with patch("builtins.print"):
                            image.publish(args)
        self.assertEqual(run.call_args_list[0].args, ("docker", "tag", IMAGE_ID, target))
        self.assertEqual(run.call_args_list[1].args, ("docker", "push", target))
        self.assertEqual(record.call_args.args[1]["registry_reference"], pinned)
        self.assertEqual(record.call_args.args[1]["image_id"], IMAGE_ID)

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
