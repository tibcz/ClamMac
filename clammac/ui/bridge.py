"""Carrying results from worker threads onto the interface thread.

Scans, updates and the folder watcher all run on background threads and report
through plain callbacks. Qt widgets may only be touched from the thread that
created them, so every callback is turned into a signal here. A signal emitted
from another thread is delivered through the receiving object's event loop,
which is exactly the hand-off that is needed.

Nothing else in the interface should ever call a widget method from a worker
thread; everything goes through this object.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

__all__ = ["ServiceBridge"]


class ServiceBridge(QObject):
    """Signals mirroring every callback the core layer offers."""

    # Scanning
    scanProgress = Signal(object)  # ScanProgress
    scanDetection = Signal(object)  # FileResult
    scanFinished = Signal(object)  # ScanJob
    scanLog = Signal(str)

    # Definition updates
    updateProgress = Signal(object)  # UpdateProgress
    updateFinished = Signal(object)  # UpdateJob
    updateLog = Signal(str)

    # Network audit
    auditProgress = Signal(object)  # network.AuditProgress
    auditFinished = Signal(object)  # network.NetworkAudit

    # Engine provisioning
    provisionProgress = Signal(object)  # provisioner.Progress
    provisionFinished = Signal(bool, str)  # success, message

    # Protection and overall state
    statusChanged = Signal(object)  # ProtectionStatus
    threatHandled = Signal(object, str)  # FileResult, action taken
    watcherState = Signal(object, str)  # WatcherState, detail
