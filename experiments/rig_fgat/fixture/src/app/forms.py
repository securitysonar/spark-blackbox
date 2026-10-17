import cgi

def content_type(header):
    value, params = cgi.parse_header(header)
    return value, params
