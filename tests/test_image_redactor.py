"""Tests for optional local ONNX image redaction."""

from __future__ import annotations

from io import BytesIO

import pytest

from llm_redactor.config import ImageRedactionConfig
from llm_redactor.image.redactor import OnnxImageRedactor


# JPEG as well as PNG: several Pillow advisories fixed in 13.0 sit in the JPEG
# decoder, and lossy re-encoding is the path most likely to change in a release.
@pytest.mark.parametrize("fmt,media_type", [("PNG", "image/png"), ("JPEG", "image/jpeg")])
def test_onnx_image_redactor_paints_detected_region(fmt: str, media_type: str):
    np = pytest.importorskip("numpy")
    image = pytest.importorskip("PIL.Image")

    class Input:
        name = "pixel_values"

    class Session:
        def get_inputs(self):
            return [Input()]

        def run(self, _outputs, _inputs):
            boxes = np.array([[[0.5, 0.5, 0.5, 0.5]]], dtype=np.float32)
            logits = np.zeros((1, 1, 13), dtype=np.float32)
            logits[0, 0, 0] = 10.0
            return boxes, logits

    source_image = image.new("RGB", (20, 20), color=(255, 0, 0))
    source = BytesIO()
    source_image.save(source, format=fmt)
    config = ImageRedactionConfig(enabled=True, license_acknowledged=True, score_threshold=0.8)

    output, detections = OnnxImageRedactor(config, session=Session()).redact(
        source.getvalue(), media_type
    )

    assert [(item.label, item.x, item.y, item.width, item.height) for item in detections] == [
        ("private_person", 5, 5, 10, 10)
    ]
    with image.open(BytesIO(output)) as redacted:
        assert redacted.format == fmt
        # JPEG is lossy: the painted box is black give or take a few levels.
        assert max(redacted.getpixel((10, 10))) <= (0 if fmt == "PNG" else 16)
