"""Peak-memory probe for the inspect shaping jobs, run in a FRESH process per case (a peak is a
high-water mark of the whole process, so cases cannot share one).

    python rss_probe.py gen   <app_dir> <case> <input_path>     write the case's input
    python rss_probe.py run   <app_dir> <case> <input_path>     print {"baseline_mib", "peak_mib", "outcome", ..}

The peak is VmHWM of /proc/self/status, not ru_maxrss: ru_maxrss survives fork+exec (the child starts
with the parent's high-water mark, so a probe started from a big test process would measure the
parent), VmHWM belongs to the address space of the new image and starts from the exec. `baseline_mib`
is VmHWM right after the imports (a fresh interpreter: the caller asserts it is small, so an inherited
mark fails loudly); `peak_mib` is VmHWM at the end above that baseline, so it contains the
input held in memory (what the pod holds while it shapes). Every string in every input holds one
astral (non-BMP) character, which makes CPython store the whole string at 4 bytes per character
(a string of ASCII text plus one emoji is 4 times its UTF-8 size), and every input passes the value
and depth scan, so the memory is spent before any size verdict."""
import base64
import gzip
import json
import os
import sys
import tracemalloc

ASTRAL = '\U0001F600'

# case -> the outcome the probe must see (a Failure code, or 'ok')
CASES = {
    'shape_single': 'too_large', 'shape_long': 'too_large', 'shape_many': 'too_large',
    'shape_objects': 'too_large',         # over the 2 MiB compact cap: the memory is spent first
    'shape_ok': 'ok',                     # the largest answer that is accepted (about 2 MiB compact)
    'decode_single': 'ok', 'decode_long': 'ok', 'decode_many': 'ok',
    'decode_values': 'too_large',         # one astral string, then more JSON values than allowed
    'events': 'ok',
    'release_op': 'ok',                   # a whole release op (list, secret, manifest, shaping)
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


def _status_mib(key):
    """A `Vm*` line of /proc/self/status in MiB (VmHWM: the peak of this address space)."""
    with open('/proc/self/status') as fh:
        for line in fh:
            if line.startswith(key + ':'):
                return int(line.split()[1]) / 1024.0
    raise RuntimeError(key)


def _peak_mib():
    return _status_mib('VmHWM')


RELEASE_MANIFEST_BYTES = 1500 * 1024      # about the largest manifest whose record fits the secret cap


def release_op_secret(mod):
    """The `data.release` text (k8s base64) of a record with an incompressible manifest of about
    1.5 MiB plus one astral character: as a Python str it is 4 bytes per character (6 MiB)."""
    manifest = base64.b64encode(os.urandom(RELEASE_MANIFEST_BYTES * 3 // 4)).decode() + ASTRAL
    record = json.dumps({'name': 'nvr', 'namespace': 'teknoir-demo', 'version': 3,
                         'info': {'status': 'deployed'}, 'chart': {'metadata': {'name': 'nvr', 'version': '1'}},
                         'manifest': manifest}, ensure_ascii=False).encode()
    return secret_text(record)


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
    elif case == 'release_op':
        data = release_op_secret(mod).encode()
        assert len(data) <= mod.RELEASE_SECRET_CAP, (len(data), mod.RELEASE_SECRET_CAP)
    else:
        raise ValueError(case)
    with open(path, 'wb') as fh:
        fh.write(data)


KUBECTL_ONE_OBJECT = (b'{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c"},"data":{"k":"v"}}\n')


def release_op(mod, path):
    """One release op through InspectRunner._dispatch with the ssh calls replaced by canned answers
    (listing, the secret read afresh from `path` on every call so the probe holds no copy of it, the
    kubectl answer). Returns (outcome, MiB held at the manifest call, MiB held when the shaping job
    starts), both above the process right before the op. "Held" is tracemalloc's current traced size,
    not VmRSS: glibc keeps freed memory of a worker thread's arena, so the RSS does not fall when a
    copy is dropped, while the traced size is exactly what is still referenced."""
    import asyncio
    import wg_mode
    config = wg_mode.WireGuardConfig(hub_url='http://wg-hub.teknoir-ztna.svc:8081', namespace='teknoir-demo',
                                     device='cam-1', sa_token_file='/x', remote_username='teknoir',
                                     rsa_key_file='/y')
    seen = {}
    tracemalloc.start()
    start = tracemalloc.get_traced_memory()[0]

    async def remote(st, argv, max_out, stdin_data=None):
        if stdin_data is not None:
            seen['manifest_call'] = (tracemalloc.get_traced_memory()[0] - start) / 1048576.0
            return 0, KUBECTL_ONE_OBJECT, b'', False
        if 'get' in argv and 'secret' in argv:
            with open(path, 'rb') as fh:
                return 0, fh.read(), b'', False
        return 0, b'3\tdeployed\n', b'', False

    real_shape = mod.shape_release_objects

    def shape(*args, **kw):
        seen['shape_job'] = (tracemalloc.get_traced_memory()[0] - start) / 1048576.0
        return real_shape(*args, **kw)

    async def main():
        runner = mod.InspectRunner(config)
        runner._remote = remote
        mod.shape_release_objects = shape
        req = mod.parse_request({'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr',
                                 'revision': 3})
        try:
            result, _ = await runner._dispatch(None, req)
            assert result['objects'][0]['kind'] == 'ConfigMap', result
            return 'ok'
        except mod.Failure as f:
            return f.code
        finally:
            await runner.close()
    outcome = asyncio.run(main())
    return outcome, seen.get('manifest_call'), seen.get('shape_job')


def run(app_dir, case, path):
    mod = _load(app_dir)
    import gzip, json  # noqa: F401  (imported before the baseline)
    baseline = _peak_mib()
    extra = {}
    outcome = 'ok'
    try:
        if case == 'release_op':
            outcome, at_call, at_shape = release_op(mod, path)
            extra = {'held_at_manifest_call_mib': round(at_call, 1), 'held_at_shaping_mib': round(at_shape, 1)}
        else:
            with open(path, 'rb') as fh:
                data = fh.read()
            if case.startswith('shape_'):
                kept = {'status': 'deployed', 'chart': 'nvr', 'chartVersion': '1', 'appVersion': '', 'last_deployed': ''}
                mod.shape_release_objects(kept, [(3, 'deployed')], 'nvr', 'teknoir-demo', 3, 0, data, b'')
            elif case.startswith('decode_'):
                mod.decode_checked(data.decode('ascii'), 'nvr', 'teknoir-demo', 3)
            else:
                mod.shape_events_json(data, None)
    except mod.Failure as f:
        outcome = f.code
    print(json.dumps(dict(extra, baseline_mib=round(baseline, 1), peak_mib=round(_peak_mib() - baseline, 1),
                          outcome=outcome)))


if __name__ == '__main__':
    mode, app_dir, case, path = sys.argv[1:5]
    {'gen': gen, 'run': run}[mode](os.path.abspath(app_dir), case, path)
