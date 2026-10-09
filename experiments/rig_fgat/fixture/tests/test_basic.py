from src.app.parse import load
from src.app.metrics import top

def test_load():
    assert load('{"a": 1}') == {'a': 1}

def test_top():
    assert top(['a','a','b'], 1) == [('a', 2)]
