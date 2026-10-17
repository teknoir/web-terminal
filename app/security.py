"""Anti-framing headers for every response of the app."""
import re

from tornado.web import OutputTransform

FRAME_ANCESTORS = "frame-ancestors 'none'"
_FA_RE = re.compile(r"^\s*frame-ancestors\b", re.IGNORECASE)


def merge_csp(values):
    """Merge frame-ancestors 'none' into existing CSP header values (list of str).

    An existing frame-ancestors directive is replaced; other directives are kept.
    Returns the list of header values to send (one CSP header per input value,
    or a single new one if there was none).
    """
    if not values:
        return [FRAME_ANCESTORS]
    merged = []
    for value in values:
        directives = [d.strip() for d in value.split(';') if d.strip() and not _FA_RE.match(d)]
        directives.append(FRAME_ANCESTORS)
        merged.append('; '.join(directives))
    return merged


class FrameGuard(OutputTransform):
    """Tornado output transform: runs on every response, including errors and
    the websocket handshake (101), so no handler can forget the headers."""

    def __init__(self, request):
        pass

    def transform_first_chunk(self, status_code, headers, chunk, finishing):
        existing = headers.get_list('Content-Security-Policy')
        if existing:
            del headers['Content-Security-Policy']
        for value in merge_csp(existing):
            headers.add('Content-Security-Policy', value)
        headers['X-Frame-Options'] = 'DENY'
        return status_code, headers, chunk

    def transform_chunk(self, chunk, finishing):
        return chunk


TRANSFORMS = [FrameGuard]
