def parse(tracefile):
    tasks = list()

    try:
        started = False
        buffers = dict()
        cur_task = {
            'buffers': dict(),
            'accesses': list()
        }
        trace = open(tracefile, 'r')
        line = trace.readline()

        while line:
            columns = line.split()
            kind = columns[0]

            if kind == 'START':
                started = True
            elif started and kind == 'END':
                started = False

                for map_id in buffers:
                    cur_task['buffers'][map_id] = buffers[map_id]

                if cur_task['accesses'] and cur_task['buffers']:
                    tasks.append(cur_task)
                    cur_task = {
                        'buffers': dict(),
                        'accesses': list()
                    }

            if kind == 'MAP':
                map_id = columns[2]
                size = int(columns[5], 16)
                ctx = int(columns[6], 16)
                buffers[map_id] = {
                    'size': size,
                    'ctx': ctx
                }
            elif kind == 'UNMAP':
                map_id = columns[2]
                if map_id in buffers:
                    cur_task['buffers'][map_id] = buffers[map_id]
                    buffers.pop(map_id)

            elif started and (kind == 'R' or kind == 'W'):
                width = int(columns[1])
                map_id = columns[3]
                offset = int(columns[4], 16)
                vaddr = int(columns[5], 16)
                value = int(columns[6], 16)
                ctx = int(columns[7], 16)
                if map_id in buffers:
                    cur_task['accesses'].append({
                        'kind': kind,
                        'map_id': map_id,
                        'ctx': ctx,
                        'offset': offset,
                        'vaddr': vaddr,
                        'width': width,
                        'value': value
                    })

            line = trace.readline()
    finally:
        trace.close()

    return tasks
