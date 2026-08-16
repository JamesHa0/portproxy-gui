"""Unit tests for the tray event dispatch logic (pure, no window needed)."""

from portproxy_gui import PortProxyApp


class FakeApp:
    """Duck-typed stand-in for PortProxyApp with the tray handler mixed in."""

    _handle_tray_event = PortProxyApp._handle_tray_event
    _poll_tray_events = PortProxyApp._poll_tray_events

    def __init__(self):
        self.calls = []

    def show_from_tray(self):
        self.calls.append("show")

    def _tray_menu(self):
        self.calls.append("menu")


def test_show_event_dispatches():
    app = FakeApp()
    app._handle_tray_event("show")
    assert app.calls == ["show"]


def test_menu_event_dispatches():
    app = FakeApp()
    app._handle_tray_event("menu")
    assert app.calls == ["menu"]


def test_unknown_event_ignored():
    app = FakeApp()
    app._handle_tray_event("bogus")
    assert app.calls == []


def test_poll_loop_reschedules():
    """_poll_tray_events must drain the queue and reschedule itself."""
    import queue as _queue

    app = FakeApp()
    # Give the app a queue with one event and a recorder for the reschedule.
    class Q(_queue.Queue):
        def __init__(self):
            super().__init__()
            self.rescheduled = False

        def get_nowait(self):
            raise _queue.Empty

    # Replace the reschedule call: bind a no-op after that records the call.
    app._tray_thread = type("T", (), {"events": Q()})()
    app.root = type("R", (), {"after": lambda self, ms, fn: app._tray_thread.events.__setattr__("rescheduled", True)})()
    app._poll_tray_events()
    assert app._tray_thread.events.rescheduled is True
