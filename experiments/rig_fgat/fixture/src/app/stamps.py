import datetime

def from_epoch(ts):
    return datetime.datetime.utcfromtimestamp(ts)
