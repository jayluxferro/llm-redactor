"""ONNX-backed screen/image PII detector with irreversible raster redaction."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from ..config import ImageRedactionConfig

CLASSES = (
    "private_person",
    "private_email",
    "private_phone",
    "private_address",
    "private_url",
    "private_company",
    "private_repo",
    "private_handle",
    "private_channel",
    "private_id",
    "private_date",
    "secret",
)
SUPPORTED_MEDIA_TYPES = {"image/jpeg": "JPEG", "image/png": "PNG"}


class ImageRedactionUnavailable(RuntimeError):
    """Raised when the optional local image runtime or configured model is unavailable."""


class InvalidImage(ValueError):
    """Raised when request bytes cannot be handled as a supported image."""


@dataclass(frozen=True)
class ImageDetection:
    label: str
    score: float
    x: int
    y: int
    width: int
    height: int


class OnnxImageRedactor:
    """Load a local RF-DETR-compatible ONNX detector lazily and redact all hits."""

    def __init__(self, config: ImageRedactionConfig, session: Any | None = None) -> None:
        self.config = config
        self._session = session

    def redact(self, source: bytes, media_type: str) -> tuple[bytes, list[ImageDetection]]:
        self._ensure_enabled()
        image_format = SUPPORTED_MEDIA_TYPES.get(media_type.lower())
        if image_format is None:
            raise InvalidImage("only image/jpeg and image/png are supported")
        if len(source) > self.config.max_image_bytes:
            raise InvalidImage("image exceeds configured maximum size")

        image, image_draw, np = self._image_modules()
        try:
            with image.open(BytesIO(source)) as opened:
                original = opened.convert("RGB")
        except Exception as exc:
            raise InvalidImage("body is not a readable image") from exc

        detections = self.detect(original, np)
        # Opaque rectangles are deliberate: blurred text/faces are recoverable.
        draw = image_draw.Draw(original)
        for detection in detections:
            draw.rectangle(
                [
                    detection.x,
                    detection.y,
                    detection.x + detection.width,
                    detection.y + detection.height,
                ],
                fill=(0, 0, 0),
            )
        output = BytesIO()
        original.save(output, format=image_format)
        return output.getvalue(), detections

    def detect(self, image: Any, np: Any) -> list[ImageDetection]:
        width, height = image.size
        size = self.config.input_size
        session = self._get_session()
        input_info = session.get_inputs()[0]
        input_dtype = np.float16 if "float16" in getattr(input_info, "type", "") else np.float32
        resized = image.resize((size, size))
        values = np.asarray(resized, dtype=np.float32) / 255.0
        values = (values - [0.485, 0.456, 0.406]) / [0.229, 0.224, 0.225]
        values = values.transpose(2, 0, 1)[None].astype(input_dtype)

        try:
            boxes, logits = session.run(None, {input_info.name: values})
        except Exception as exc:
            raise ImageRedactionUnavailable("ONNX image inference failed") from exc

        boxes, logits = boxes[0], logits[0]
        if logits.shape[-1] < len(CLASSES):
            raise ImageRedactionUnavailable("configured model does not expose expected PII classes")
        probabilities = 1.0 / (1.0 + np.exp(-logits[:, : len(CLASSES)]))
        best_classes = probabilities.argmax(axis=1)
        best_scores = probabilities[np.arange(len(probabilities)), best_classes]

        detections: list[ImageDetection] = []
        for index in np.where(best_scores >= self.config.score_threshold)[0]:
            center_x, center_y, box_width, box_height = boxes[index]
            x1 = max(0, int((center_x - box_width / 2) * width))
            y1 = max(0, int((center_y - box_height / 2) * height))
            x2 = min(width, int((center_x + box_width / 2) * width))
            y2 = min(height, int((center_y + box_height / 2) * height))
            if x2 <= x1 or y2 <= y1:
                continue
            detections.append(
                ImageDetection(
                    CLASSES[int(best_classes[index])],
                    float(best_scores[index]),
                    x1,
                    y1,
                    x2 - x1,
                    y2 - y1,
                )
            )
        return detections

    def _get_session(self) -> Any:
        if self._session is not None:
            return self._session
        self._ensure_enabled()
        model_path = Path(self.config.model_path).expanduser()
        if not self.config.model_path or not model_path.is_file():
            raise ImageRedactionUnavailable("configured ONNX image model does not exist")
        try:
            import onnxruntime as ort  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImageRedactionUnavailable(
                "install llm-redactor[image] to enable image redaction"
            ) from exc

        available = ort.get_available_providers()
        preferred = [
            provider
            for provider in (
                "CoreMLExecutionProvider",
                "CUDAExecutionProvider",
                "DmlExecutionProvider",
                "CPUExecutionProvider",
            )
            if provider in available
        ]
        self._session = ort.InferenceSession(str(model_path), providers=preferred)
        return self._session

    def _ensure_enabled(self) -> None:
        if not self.config.enabled or not self.config.license_acknowledged:
            raise ImageRedactionUnavailable(
                "image redaction is disabled or its license is not acknowledged"
            )

    @staticmethod
    def _image_modules() -> tuple[Any, Any, Any]:
        try:
            import numpy as np
            from PIL import Image, ImageDraw
        except ImportError as exc:
            raise ImageRedactionUnavailable(
                "install llm-redactor[image] to enable image redaction"
            ) from exc
        return Image, ImageDraw, np
