from hello import message


def test_message() -> None:
    assert message() == "hello from python"
