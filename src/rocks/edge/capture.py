from __future__ import annotations

import threading
from collections.abc import Callable

from scapy.all import AsyncSniffer, get_if_list
from scapy.packet import Packet

from rocks.logging_config import configure_logging


PacketCallback = Callable[[Packet], None]


class CaptureError(RuntimeError):
    """Raised when authorized live capture cannot be started safely."""


class PacketCapture:
    """Callback-based live capture wrapper that never stores packet payloads."""

    def __init__(self, interface: str, callback: PacketCallback) -> None:
        if not interface:
            raise ValueError("A network interface is required for live capture")
        self.interface = interface
        self.callback = callback
        self._stop_event = threading.Event()
        self._logger = configure_logging()

    @staticmethod
    def available_interfaces() -> list[str]:
        return list(get_if_list())

    def validate_interface(self) -> None:
        if self.interface not in self.available_interfaces():
            available = ", ".join(self.available_interfaces()) or "none detected"
            raise CaptureError(
                f"Network interface '{self.interface}' does not exist. Available interfaces: {available}"
            )

    def start(self) -> None:
        self.validate_interface()
        self._stop_event.clear()
        self._logger.info("Edge capture started on interface %s", self.interface)
        started = threading.Event()
        sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            started_callback=started.set,
        )
        try:
            sniffer.start()
            while not started.wait(timeout=0.1):
                if not sniffer.thread.is_alive():
                    sniffer.join()
                    raise CaptureError("Live capture stopped before it was ready")
            while not self._stop_event.wait(timeout=0.1):
                if not sniffer.thread.is_alive():
                    sniffer.join()
                    raise CaptureError("Live capture stopped unexpectedly")
            if sniffer.thread.is_alive() and sniffer.running:
                sniffer.stop(join=True)
            else:
                sniffer.join()
        except PermissionError as exc:
            raise CaptureError(
                "Live capture permission denied; run authorized capture with appropriate privileges"
            ) from exc
        except OSError as exc:
            raise CaptureError(f"Unable to capture on interface '{self.interface}': {exc}") from exc
        finally:
            self._logger.info("Edge capture stopped on interface %s", self.interface)

    def stop(self) -> None:
        self._stop_event.set()
        self._logger.info("Edge capture stop requested")

    def _handle_packet(self, packet: Packet) -> None:
        try:
            self.callback(packet)
        except Exception:
            self._logger.exception("Edge packet callback failed")
