"""First-run setup: get an engine and some definitions, with as little fuss as possible.

The wizard is honest about what it is doing, because it is downloading and
running third-party software on the user's behalf. It names the package, shows
where it comes from, and says that the download is checked against a known
digest before anything is unpacked.
"""

from __future__ import annotations

import threading

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from ..core import engine as engine_module
from ..core.freshclam import UpdateOutcome, UpdateProgress
from ..core.log import get_logger
from ..core.provisioner import (
    EngineProvisioner,
    Progress,
    ProvisionCancelled,
    ProvisionError,
)
from ..core.service import AppService
from ..version import APP_NAME
from .icons import app_icon_pixmap
from .theme import Metrics
from .widgets.common import button, caption, label, subtitle

log = get_logger(__name__)

__all__ = ["SetupWizard"]


class _Signals(QObject):
    progress = Signal(object)
    finished = Signal(bool, str)
    updateProgress = Signal(object)
    updateFinished = Signal(object)


class SetupWizard(QDialog):
    """Walks the user from nothing to a working, up-to-date scanner."""

    def __init__(self, service: AppService, parent: QWidget | None = None, *, force: bool = False) -> None:
        super().__init__(parent)
        self.service = service
        self.force = force
        self.signals = _Signals()
        self._cancel = threading.Event()
        self._worker: threading.Thread | None = None
        self._finished_ok = False

        self.setWindowTitle(f"Set up {APP_NAME}")
        self.setModal(True)
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 28, 30, 24)
        layout.setSpacing(Metrics.GAP)

        icon = QLabel()
        icon.setPixmap(app_icon_pixmap(72).scaled(
            72, 72, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        ))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)

        self.title_label = label(f"Welcome to {APP_NAME}", role="title")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.title_label)

        self.body_label = subtitle("")
        self.body_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.body_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.hide()
        layout.addWidget(self.progress)

        self.detail_label = caption("")
        self.detail_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.detail_label)

        layout.addSpacing(6)

        buttons = QHBoxLayout()
        buttons.setSpacing(Metrics.GAP)
        buttons.addStretch(1)
        self.secondary_button = button("Not now", on_click=self.reject)
        self.primary_button = button("Get started", variant="primary", on_click=self.advance)
        buttons.addWidget(self.secondary_button)
        buttons.addWidget(self.primary_button)
        layout.addLayout(buttons)

        self.signals.progress.connect(self._on_progress)
        self.signals.finished.connect(self._on_finished)
        self.signals.updateProgress.connect(self._on_update_progress)
        self.signals.updateFinished.connect(self._on_update_finished)

        self._show_intro()

    # -- steps ------------------------------------------------------------

    def _show_intro(self) -> None:
        existing = None if self.force else self.service.engine
        manifest_release = EngineProvisioner().manifest.preferred()
        size_mb = (manifest_release.size / 1e6) if manifest_release else 170

        if existing is not None:
            self.title_label.setText("ClamAV is already installed")
            self.body_label.setText(
                f"ClamMac found ClamAV {existing.engine_version} "
                f"({existing.tools.origin}) and will use it. Nothing needs downloading.\n\n"
                "Next it will fetch the current virus definitions, which is about 250 MB."
            )
            self.primary_button.setText("Download definitions")
            self._step = "definitions"
        else:
            version = manifest_release.version if manifest_release else "the latest release"
            self.title_label.setText(f"Welcome to {APP_NAME}")
            self.body_label.setText(
                f"{APP_NAME} needs the ClamAV scanning engine, which it does not include.\n\n"
                f"It will download the official ClamAV {version} package "
                f"({size_mb:.0f} MB) published by the ClamAV project, check it against a "
                "known SHA-256 digest, and unpack it into ClamMac's own folder inside your "
                "home directory.\n\n"
                "This does not require your password and nothing is installed system-wide."
            )
            self.primary_button.setText("Install ClamAV")
            self._step = "engine"

    def advance(self) -> None:
        if self._step == "engine":
            self._install_engine()
        elif self._step == "definitions":
            self._download_definitions()
        else:
            self.accept()

    # -- engine -----------------------------------------------------------

    def _install_engine(self) -> None:
        self.primary_button.setEnabled(False)
        self.secondary_button.setText("Cancel")
        self.secondary_button.clicked.disconnect()
        self.secondary_button.clicked.connect(self._cancel_work)
        self.progress.show()
        self.progress.setRange(0, 0)
        self.title_label.setText("Installing the scanning engine")
        self.body_label.setText("")

        def work() -> None:
            provisioner = EngineProvisioner(
                on_progress=self.signals.progress.emit,
                should_cancel=self._cancel.is_set,
            )
            try:
                root = provisioner.install()
                provisioner.prune_old_versions(root.name)
                provisioner.discard_download_cache()
                self.signals.finished.emit(True, "")
            except ProvisionCancelled:
                self.signals.finished.emit(False, "")
            except ProvisionError as exc:
                self.signals.finished.emit(False, str(exc))
            except Exception as exc:
                log.exception("engine provisioning failed")
                self.signals.finished.emit(False, str(exc))

        self._worker = threading.Thread(target=work, name="provision", daemon=True)
        self._worker.start()

    def _on_progress(self, progress: Progress) -> None:
        if progress.fraction < 0:
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, 100)
            self.progress.setValue(progress.percent)
        self.detail_label.setText(progress.message)

    def _on_finished(self, success: bool, message: str) -> None:
        self.service.refresh_engine()
        if not success:
            self.progress.hide()
            self.detail_label.setText("")
            if message:
                self.title_label.setText("The engine could not be installed")
                self.body_label.setText(
                    message + "\n\nYou can try again, or install ClamAV yourself with "
                    "Homebrew and ClamMac will find it."
                )
                self.primary_button.setText("Try again")
            else:
                self.title_label.setText("Setup cancelled")
                self.body_label.setText("You can set ClamMac up later from the Overview screen.")
                self.primary_button.setText("Close")
                self._step = "done"
            self.primary_button.setEnabled(True)
            self._restore_secondary()
            return

        self._step = "definitions"
        self.title_label.setText("Engine installed")
        engine = self.service.engine
        self.body_label.setText(
            f"ClamAV {engine.engine_version} is ready.\n\n"
            "Next, ClamMac needs the virus definitions. That is roughly 250 MB the first "
            "time; after this only the daily changes are downloaded."
            if engine
            else "Next, ClamMac needs the virus definitions."
        )
        self.progress.hide()
        self.detail_label.setText("")
        self.primary_button.setText("Download definitions")
        self.primary_button.setEnabled(True)
        self._restore_secondary()
        QTimer.singleShot(400, self._download_definitions)

    # -- definitions ------------------------------------------------------

    def _download_definitions(self) -> None:
        if self.service.engine is None:
            self.service.refresh_engine()
        if self.service.engine is None:
            self._on_finished(False, "No scanning engine is available.")
            return

        self.primary_button.setEnabled(False)
        self.secondary_button.setText("Cancel")
        try:
            self.secondary_button.clicked.disconnect()
        except (RuntimeError, TypeError):
            pass
        self.secondary_button.clicked.connect(self._cancel_update)

        self.title_label.setText("Downloading virus definitions")
        self.body_label.setText(
            "This is the biggest part of setup and only happens once. You can leave it "
            "running and come back."
        )
        self.progress.show()
        self.progress.setRange(0, 0)

        self._update_job = self.service.update_definitions(
            on_progress=self.signals.updateProgress.emit,
            on_finished=self.signals.updateFinished.emit,
        )

    def _on_update_progress(self, progress: UpdateProgress) -> None:
        self.detail_label.setText(progress.message)
        if progress.fraction >= 0:
            self.progress.setRange(0, 100)
            self.progress.setValue(int(progress.fraction * 100))
        else:
            self.progress.setRange(0, 0)

    def _on_update_finished(self, job) -> None:
        self.progress.hide()
        self.detail_label.setText("")
        self._restore_secondary()
        self.primary_button.setEnabled(True)
        self._step = "done"

        database = engine_module.database_info()
        if job.outcome is UpdateOutcome.FAILED and not database.present:
            self.title_label.setText("Definitions could not be downloaded")
            self.body_label.setText(
                f"{job.failure}\n\nClamMac is installed but cannot detect anything until "
                "the definitions have been downloaded. You can retry from the Definitions "
                "screen at any time."
            )
            self.primary_button.setText("Close")
            return

        self.service.settings.interface.completed_first_run = True
        self.service.save_settings()

        engine = self.service.engine
        self.title_label.setText(f"{APP_NAME} is ready")
        self.body_label.setText(
            f"ClamAV {engine.engine_version if engine else ''} is installed with "
            f"{engine.database_version:,} definitions.\n\n"
            "Run a quick scan to check the places threats usually arrive, or turn on "
            "real-time protection to have new files checked automatically."
            if engine
            else "Setup is complete."
        )
        self.primary_button.setText("Done")
        self._finished_ok = True

    # -- cancelling -------------------------------------------------------

    def _cancel_work(self) -> None:
        self._cancel.set()
        self.detail_label.setText("Stopping…")

    def _cancel_update(self) -> None:
        if getattr(self, "_update_job", None) is not None:
            self._update_job.cancel()
        self.detail_label.setText("Stopping…")

    def _restore_secondary(self) -> None:
        self.secondary_button.setText("Close")
        try:
            self.secondary_button.clicked.disconnect()
        except (RuntimeError, TypeError):
            pass
        self.secondary_button.clicked.connect(self.reject)

    def reject(self) -> None:
        self._cancel.set()
        if getattr(self, "_update_job", None) is not None:
            self._update_job.cancel()
        super().reject()
