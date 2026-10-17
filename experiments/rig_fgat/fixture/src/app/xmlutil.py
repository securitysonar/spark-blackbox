import xml.etree.cElementTree as ET

def root_tag(text):
    return ET.fromstring(text).tag
