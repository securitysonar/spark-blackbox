import unittest

def build(case_cls):
    return unittest.makeSuite(case_cls)
