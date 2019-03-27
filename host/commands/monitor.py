from invoke import run, exceptions


def set_current_tracer():
    assert get_current_tracer() == 'nop'
    run('adb shell \'su -c \"echo hwiotrace > /sys/kernel/debug/tracing/current_tracer\"\'')


def unset_current_tracer():
    assert get_current_tracer() == 'hwiotrace'
    deactivate()
    run('adb shell \'su -c \"echo nop > /sys/kernel/debug/tracing/current_tracer\"\'')


def get_current_tracer():
    ret = run('adb shell \'su -c \"cat /sys/kernel/debug/tracing/current_tracer\"\'', hide=True)
    return ret.stdout.strip()


def activate(id=None, ctx=None, drv=None):
    assert id or ctx or drv
    assert get_current_tracer() == 'hwiotrace'

    if id:
        set_id_filter(str(id))
    elif ctx:
        set_ctx_filter(str(ctx))
    elif drv:
        set_drv_filter(str(drv))


def deactivate():
    assert get_current_tracer() == 'hwiotrace'

    _, probes = get_available_probes()

    for probe in probes:
        if probe['state'] == 'TRACING':
            unset_id_filter(probe['id'])


def is_active(id=None, ctx=None):
    assert id or ctx
    assert get_current_tracer() == 'hwiotrace'

    _, probes = get_available_probes()

    for probe in probes:
        if id and id == probe['id']:
            return probe['state'] == 'ACTIVE'
        if ctx and ctx == probe['ctx']:
            return probe['state'] == 'ACTIVE'

    return False


def trace(seconds=1):
    assert get_current_tracer() == 'hwiotrace'

    _, probes = get_active_probes()
    if len(probes) == 0:
        raise Exception('No active probes')

    run('adb shell \'su -c \"echo 1 > /sys/kernel/debug/tracing/tracing_on\"\'')

    try:
        run('adb shell \'su -c \"timeout %s cat /sys/kernel/debug/tracing/trace_pipe > /sdcard/Download/trace_pipe\"\'' % seconds, echo=True)
    except exceptions.UnexpectedExit as e:
        print e
    except KeyboardInterrupt as e:
        run('adb shell \'su -c \"echo 0 > /sys/kernel/debug/tracing/tracing_on\"\'')
        raise e

    run('adb shell \'su -c \"echo 0 > /sys/kernel/debug/tracing/tracing_on\"\'')

    probe_ctxs = ','.join([probe['ctx'] for probe in probes])
    run('adb pull /sdcard/Download/trace_pipe trace_pipe.%s' % probe_ctxs, echo=True)


def is_tracing():
    ret = run('adb shell \'su -c \"cat /sys/kernel/debug/tracing/tracing_on\"\'', hide=True)
    if ret.stdout.strip() == '1':
        return True
    else:
        return False


def pull_trace_pipe():
    run('adb pull /sdcard/Download/trace_pipe', echo=True)


def get_active_probes():
    return get_available_probes(True)


def get_available_probes(active_only=False):
    probes = []

    ret = run('adb shell \'su -c \"cat /sys/kernel/debug/tracing/options/hwio_available_probes\"\'', hide=True)

    lines = ret.stdout.strip().split('\n')
    columns = [col.lower() for col in lines.pop(0).split()]

    for i in range(1, len(lines)):
        tr = lines[-i].split()
        probe = {}
        for j in range(0, len(columns)):
            probe[columns[j]] = tr[j].strip()
        if active_only:
            if probe['state'] != 'TRACING':
                continue
        probes.append(probe)

    return columns, probes


def get_available_mappings():
    mappings = []

    ret = run('adb shell \'su -c \"cat /sys/kernel/debug/tracing/options/hwio_available_mappings\"\'', hide=True)

    lines = ret.stdout.strip().split('\n')
    columns = [col.lower() for col in lines.pop(0).split()]
    for i in range(1, len(lines)):
        tr = lines[-i].split()
        mapping = {}
        for j in range(0, len(columns)):
            mapping[columns[j]] = tr[j]
            if columns[j].isnumeric():
                mapping[columns[j]] = int(tr[j])
        mappings.append(mapping)

    return columns, mappings


def set_drv_filter(drv_filter):
    run('adb shell \'su -c \"echo ' + drv_filter + ' > /sys/kernel/debug/tracing/options/hwio_drv_set_filter\"\'')


def unset_drv_filter(drv_filter):
    run('adb shell \'su -c \"echo ' + drv_filter + ' > /sys/kernel/debug/tracing/options/hwio_drv_unset_filter\"\'')


def set_ctx_filter(ctx_filter):
    run('adb shell \'su -c \"echo ' + ctx_filter + ' > /sys/kernel/debug/tracing/options/hwio_ctx_set_filter\"\'')


def unset_ctx_filter(ctx_filter):
    run('adb shell \'su -c \"echo ' + ctx_filter + ' > /sys/kernel/debug/tracing/options/hwio_ctx_unset_filter\"\'')


def set_id_filter(id_filter):
    run('adb shell \'su -c \"echo ' + id_filter + ' > /sys/kernel/debug/tracing/options/hwio_id_set_filter\"\'')


def unset_id_filter(id_filter):
    run('adb shell \'su -c \"echo ' + id_filter + ' > /sys/kernel/debug/tracing/options/hwio_id_unset_filter\"\'')
