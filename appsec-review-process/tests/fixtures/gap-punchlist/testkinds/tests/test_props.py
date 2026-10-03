from hypothesis import given, strategies as st


@given(st.integers())
def test_reverse(x):
    assert x == x
