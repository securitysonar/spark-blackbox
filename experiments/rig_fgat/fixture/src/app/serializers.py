import json
from dataclasses import asdict

def to_json(obj):
    return json.dumps(asdict(obj), sort_keys=True)
