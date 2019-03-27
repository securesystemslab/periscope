import filecmp
import glob
import os
import shutil


blacklistdir = 'blacklist'


def get_size():
    files = glob.glob(os.path.join(blacklistdir, '*.cur_input'))
    return len(files)


def find(blacklistdir, item):
    for existing in glob.glob(os.path.join(blacklistdir, '*.cur_input')):
        if filecmp.cmp(item, existing):
            return int(os.path.basename(existing).split('.')[0])
    return -1


def queue(blacklistdir, item):
    idx = find(blacklistdir, item)
    if idx > -1:
        return idx

    idx = 1
    while os.path.exists(os.path.join(blacklistdir, str(idx) + '.cur_input')):
        idx += 1

    shutil.copy(item, os.path.join(blacklistdir, str(idx) + '.cur_input'))
    return idx
