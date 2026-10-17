import logging

log = logging.getLogger(__name__)

def warn_slow(ms):
    logging.warn('slow request: %d ms', ms)
