from svc.app import handle


def test_handle() -> None:
    assert handle("/") == "ok /"
