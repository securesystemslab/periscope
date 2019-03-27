import glob
import os


MAX_INPUT_LENGTH = 24
MAX_INPUT_FILES = 100

RED = '\033[0;31m'
GREEN = '\033[0;32m'
BLUE = '\033[0;34m'
GRAY = '\033[0;35m'
ENDC = '\033[0m'

NEW = '[' + GREEN + ' NEW ' + ENDC + '] '
REJECTED = '[' + GRAY + ' REJ ' + ENDC + '] '
DONE = '[' + BLUE + ' DONE' + ENDC + '] '
FATAL = '[' + RED + 'FATAL' + ENDC + '] '


def to_bytes(n, length, endianess='big'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]


def print_overlap(a_begin, a_end, a_value, b_begin, b_end, b_value):
    # normalize
    pivot = min(a_begin, b_begin)
    a_begin -= pivot
    a_end -= pivot
    b_begin -= pivot
    b_end -= pivot

    # visualize
    print (' ' * a_begin + '*' * (a_end - a_begin) + ' ' * max(0, (b_end - a_end))) + (' (value=0x%x)' % a_value)
    print (' ' * b_begin + '+' * (b_end - b_begin) + ' ' * max(0, a_end - b_end)) + (' (value=0x%x)' % b_value)


def generate_seed(tasks, seed_dir):
    if not os.path.exists(seed_dir):
        raise Exception('Seed dir does not exist.')

    print 'Generating seed files in %s:' % seed_dir

    total = 0
    new = 0
    rejected = 0

    # Create a file for each task
    for task in tasks:
        accesses = task['accesses']
        buffers = task['buffers']
        accessed_buffers = dict()

        if not accesses:
            continue

        if new >= MAX_INPUT_FILES:
            break

        total += 1
        input_length = 0

        # Filter out multi-reads of an equal or smaller size
        # Note: should match the algorithm included in the kernel-space fuzzer
        for i in range(0, len(accesses)):

            access = accesses[i]

            access_width = access['width']
            if access_width == 0 or access_width > 16:
                print FATAL + 'invalid access width: %s' % access_width
                raise Exception('implementation bug')

            map_id = access['map_id']
            if map_id in buffers:
                accessed_buffers[map_id] = buffers[map_id]

            access['multi_read'] = False

            # scan previous accesses to find overlapping fetches
            for j in range(0, i):
                prev_access = accesses[j]

                if prev_access['map_id'] == access['map_id']:
                    prev_start = prev_access['vaddr']
                    prev_end = prev_start + prev_access['width']
                    cur_start = access['vaddr']
                    cur_end = cur_start + access['width']

                    if prev_start <= cur_start and prev_end >= cur_end:
                        # print 'multi-read at 0x%x' % cur_start
                        access['multi_read'] = True
                        break
                    elif (prev_start <= cur_start and cur_start < prev_end) or (prev_start < cur_end and cur_end <= prev_end):
                        print FATAL + 'partial overlap at 0x%x not handled' % cur_start
                        print_overlap(prev_start, prev_end, prev_access['value'], cur_start, cur_end, access['value'])

            if not access['multi_read']:
                input_length += access['width']

        if input_length == 0:
            print REJECTED + 'reason: zero-length input (length=%d)' % input_length
            rejected += 1
            continue

        if input_length > MAX_INPUT_LENGTH:
            print REJECTED + 'reason: input (length=%d) larger than %d' % (input_length, MAX_INPUT_LENGTH)
            rejected += 1
            continue

        if len(accessed_buffers) > 1:
            print REJECTED + 'reason: more than one buffers (total=%d) accessed' % len(accessed_buffers)
            rejected += 1
            continue

        ctx = 'ctx:%s' % '_'.join(['0x%x' % buffers[map_id]['ctx'] for map_id in accessed_buffers])

        if not os.path.exists(os.path.join(seed_dir, ctx)):
            os.mkdir(os.path.join(seed_dir, ctx))

        input_attr = ','.join(['size:%d' % input_length])

        input_bytes = bytearray(input_length)

        hwm = 0
        for access in accesses:
            if access['multi_read']:
                continue

            width = access['width']
            value = access['value']
            b = to_bytes(value, width)

            for i in range(0, width):
                input_bytes[hwm+i] = b[i]

            hwm += width

        last_idx = -1
        cur_idx = -1
        duplicate = ''

        files_to_check = glob.glob(os.path.join(seed_dir, ctx, '%s.*' % input_attr))

        for f in files_to_check:
            cur_idx = int(os.path.basename(f).split('.')[1])
            if cur_idx > last_idx:
                last_idx = cur_idx
            try:
                existing_file = open(f, 'r')
                if existing_file.read() == input_bytes:
                    duplicate = f
                    break
            finally:
                existing_file.close()

        if duplicate != '':
            print REJECTED + 'reason: duplicate - same as %s' % duplicate
            rejected += 1
        else:
            try:
                input_filename = '%s.%s' % (input_attr, str(last_idx + 1).zfill(len(str(MAX_INPUT_FILES-1))))
                input_file = open(os.path.join(seed_dir, ctx, input_filename), 'w')
                input_file.write(input_bytes)
                new += 1
                print NEW + '%s' % os.path.join(seed_dir, ctx, input_filename)
            finally:
                input_file.close()
    
    print DONE + 'new+rej=total: %d+%d=%d' % (new, rejected, total)

    if new + rejected != total:
        print FATAL + 'but something may have gone wrong'
