"""Peak-memory probe for the inspect shaping jobs, run in a FRESH process per case (ru_maxrss is a
high-water mark of the whole process, so cases cannot share one).

    python rss_probe.py gen   <app_dir> <case> <input_path>     write the case's input
    python rss_probe.py run   <app_dir> <case> <input_path>     print {"peak_mib": .., "outcome": ..}

`peak_mib` is the process peak (ru_maxrss) above the peak right after the imports, so it contains the
input held in memory (what the pod holds while it shapes). Every string in every input holds one
astral (non-BMP) character, which makes CPython store the whole string at 4 bytes per character
(a string of ASCII text plus one emoji is 4 times its UTF-8 size), and every input passes the value
and depth scan, so the memory is spent before any size verdict."""
import base64
import gzip
import json
import os
import resource
import sys

ASTRAL = '\U0001F600'

# case -> the outcome the probe must see (a Failure code, or 'ok')
CASES = {
    'shape_single': 'too_large', 'shape_long': 'too_large', 'shape_many': 'too_large',
    'shape_objects': 'too_large',         # over the 2 MiB compact cap: the memory is spent first
    'shape_ok': 'ok',                     # the largest answer that is accepted (about 2 MiB compact)
    'decode_single': 'ok', 'decode_long': 'ok', 'decode_many': 'ok',
    'decode_values': 'too_large',         # one astral string, then more JSON values than allowed
    'events': 'ok',
}


def _entries(total, entry_chars, indent):
    """Pretty-printed `"kN": "aaa..<astral>",` lines up to `total` UTF-8 bytes."""
    filler = 'a' * entry_chars
    lines, size, n = [], 0, 0
    while True:
        line = '%s"k%d": "%s%s",\n' % (indent, n, filler, ASTRAL)
        if size + len(line.encode()) > total:
            break
        lines.append(line)
        size += len(line.encode())
        n += 1
    lines[-1] = lines[-1].replace('",\n', '"\n')
    return ''.join(lines)


def kubectl_stdout(case, size):
    head = '{\n    "apiVersion": "v1",\n    "kind": "ConfigMap",\n    "metadata": {"name": "big"},\n    "data": {\n'
    tail = '    }\n}\n'
    budget = size - len(head) - len(tail) - 64
    if case == 'shape_ok':
        return (head + _entries(1900 * 1024, 1000, '        ') + tail).encode()
    if case == 'shape_single':
        body = _entries(budget, budget - 100, '        ')
        return (head + body + tail).encode()
    if case == 'shape_long':
        return (head + _entries(budget, 1000, '        ') + tail).encode()
    if case == 'shape_many':
        return (head + _entries(budget, 150, '        ') + tail).encode()
    if case == 'shape_objects':          # 1500 objects (cap 2000), the stream is one after the other
        per = size // 1500 - 400
        one = ('{\n    "apiVersion": "v1",\n    "kind": "ConfigMap",\n    "metadata": {"name": "o%d"},\n'
               '    "data": {\n        "k": "' + 'a' * per + ASTRAL + '"\n    }\n}\n')
        return ''.join(one % i for i in range(1500)).encode()
    raise ValueError(case)


def release_record(case, size):
    """A helm release record (JSON) of about `size` bytes: the strings sit in chart.files."""
    head = ('{"name":"nvr","namespace":"teknoir-demo","version":3,"info":{"status":"deployed",'
            '"last_deployed":"2026-10-02T10:00:00Z"},"chart":{"metadata":{"name":"nvr","version":"0.4.2",'
            '"appVersion":"1.2.0"},"files":[')
    tail = ']},"manifest":""}'
    budget = size - len(head) - len(tail) - 64
    if case == 'decode_values':
        pad = '{"data":"%s"}' % ASTRAL
        return (head + pad + ',1' * ((budget - len(pad)) // 2) + tail).encode()
    unit = {'decode_single': budget - 64, 'decode_long': 200000, 'decode_many': 90}[case]
    one = '{"data":"%s%s"}' % ('a' * unit, ASTRAL)
    n = max(1, budget // (len(one.encode()) + 1))
    return (head + ','.join([one] * n) + tail).encode()


def secret_text(record):
    return base64.b64encode(base64.b64encode(gzip.compress(record))).decode()


def events_json(size):
    items = []
    total = 0
    n = 0
    while total < size - 400:
        item = ('{"metadata":{"name":"e%d"},"type":"Warning","reason":"BackOff","message":"%s%s",'
                '"involvedObject":{"kind":"Pod","name":"p"}}' % (n, 'a' * 3000, ASTRAL))
        items.append(item)
        total += len(item.encode()) + 1
        n += 1
    return ('{"apiVersion":"v1","kind":"List","items":[' + ','.join(items) + ']}').encode()


def _load(app_dir):
    sys.path.insert(0, app_dir)
    import inspect_ops
    return inspect_ops


def _peak_mib():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def gen(app_dir, case, path):
    mod = _load(app_dir)
    if case.startswith('shape_'):
        data = kubectl_stdout(case, mod.KUBECTL_OUT_CAP)
        assert len(data) <= mod.KUBECTL_OUT_CAP, (len(data), mod.KUBECTL_OUT_CAP)
    elif case.startswith('decode_'):
        data = secret_text(release_record(case, mod.RELEASE_JSON_CAP)).encode()
        assert len(data) <= mod.RELEASE_SECRET_CAP, (len(data), mod.RELEASE_SECRET_CAP)
    elif case == 'events':
        data = events_json(mod.EVENTS_CAP)
        assert len(data) <= mod.EVENTS_CAP
    else:
        raise ValueError(case)
    with open(path, 'wb') as fh:
        fh.write(data)


def run(app_dir, case, path):
    mod = _load(app_dir)
    import gzip, json  # noqa: F401  (imported before the baseline)
    base = _peak_mib()
    with open(path, 'rb') as fh:
        data = fh.read()
    outcome = 'ok'
    try:
        if case.startswith('shape_'):
            kept = {'status': 'deployed', 'chart': 'nvr', 'chartVersion': '1', 'appVersion': '', 'last_deployed': ''}
            mod.shape_release_objects(kept, [(3, 'deployed')], 'nvr', 'teknoir-demo', 3, 0, data, b'')
        elif case.startswith('decode_'):
            mod.decode_checked(data.decode('ascii'), 'nvr', 'teknoir-demo', 3)
        else:
            mod.shape_events_json(data, None)
    except mod.Failure as f:
        outcome = f.code
    print(json.dumps({'peak_mib': round(_peak_mib() - base, 1), 'outcome': outcome}))


if __name__ == '__main__':
    mode, app_dir, case, path = sys.argv[1:5]
    {'gen': gen, 'run': run}[mode](os.path.abspath(app_dir), case, path)
