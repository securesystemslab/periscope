import invoke
import os
import filecmp
import glob
import shutil


def run():
    kill()
    invoke.run('adb shell \'su -c \"/data/local/tmp/run-afl.sh\"\' &')


def check():
    proc_ids = []
    try:
        ret = invoke.run('adb shell \'su -c \"ps -ef | grep -v grep | grep fuzzer\"\'', hide=True)
        for proc in ret.stdout.strip().split('\n'):
            print proc
            columns = proc.split()
            if len(columns) > 1:
                proc_ids.append(columns[1])
    except BaseException as e:
        print e

    return proc_ids


def kill():
    proc_ids = check()
    if proc_ids:
        try:
            invoke.run('adb shell \'su -c \"kill ' + ' '.join(proc_ids) + '\"\'')
        except BaseException as e:
            print e


def minimize_corpus(dir_host):
    if dir_host.endswith('/'):
        dir_host = dir_host[:-1]

    if not os.path.exists(dir_host):
        raise Exception("corpus dir " + dir_host + " does not exist")

    if not os.path.isdir(dir_host):
        raise Exception("corpus dir " + dir_host + " must be a directory")

    kill()

    dir_device = '/sdcard/Download/%s' % os.path.basename(dir_host)

    try:
        invoke.run('adb shell \'su -c \"' + ' '.join(['rm', '-rf', dir_device]) + '\"\'', echo=True)
    except invoke.exceptions.UnexpectedExit as e:
        print e

    invoke.run('adb push %s %s' % (dir_host, dir_device))

    backup_device = dir_device + '.bak'
    minimized_device = dir_device + '.min'

    try:
        invoke.run('adb shell \'su -c \"' + ' '.join(['rm', '-rf', minimized_device]) + '\"\'', echo=True)
    except invoke.exceptions.UnexpectedExit as e:
        print e

    # Perform corpus minimization
    invoke.run('adb shell \'su -c \"/data/local/tmp/afl-cmin -i ' + dir_device + ' -o ' + minimized_device + ' -- /data/local/tmp/executor @@\"\'', echo=True)

    try:
        invoke.run('adb shell \'su -c \"' + ' '.join(['rm', '-rf', backup_device]) + '\"\'', echo=True)
    except invoke.exceptions.UnexpectedExit as e:
        print e

    invoke.run('adb shell \'su -c \"' + ' '.join(['mv', dir_device, backup_device]) + '\"\'', echo=True)
    invoke.run('adb shell \'su -c \"' + ' '.join(['mv', minimized_device, dir_device]) + '\"\'', echo=True)

    minimized_host = dir_host + '.min'
    try:
        invoke.run('rm -rf %s' % minimized_host, echo=True)
    except invoke.exceptions.UnexpectedExit as e:
        print e

    invoke.run('adb pull %s %s' % (dir_device, minimized_host), echo=True)


def get_fuzzer_stats():
    ret = invoke.run('adb shell \'su -c \"' + ' '.join(['cat', '/data/local/tmp/out/fuzzer_stats']) + '\"\'', hide=True)
    return ret.stdout.strip()


def push_executor(basedir):
    invoke.run('adb push ' + os.path.join(basedir, 'bin/arm64/executor') + ' /sdcard/Download')
    invoke.run('adb shell \'su -c \"mv /sdcard/Download/executor /data/local/tmp\"\'')
    invoke.run('adb shell \'su -c \"chmod +x /data/local/tmp/executor\"\'')


def push_fuzzer(basedir):
    invoke.run('adb push ' + os.path.join(basedir, 'bin/arm64/fuzzer ') + ' /sdcard/Download')
    invoke.run('adb shell \'su -c \"mv /sdcard/Download/fuzzer /data/local/tmp\"\'')
    invoke.run('adb shell \'su -c \"chmod +x /data/local/tmp/fuzzer\"\'')


def push_fuzzer_scripts(basedir):
    invoke.run('adb push ' + os.path.join(basedir, 'fuzzer/run-afl.sh ') + ' /sdcard/Download')
    invoke.run('adb shell \'su -c \"mv /sdcard/Download/run-afl.sh /data/local/tmp\"\'')
    invoke.run('adb shell \'su -c \"chmod +x /data/local/tmp/run-afl.sh\"\'')

    invoke.run('adb push ' + os.path.join(basedir, 'bin/arm64/afl-cmin ') + ' /sdcard/Download')
    invoke.run('adb shell \'su -c \"mv /sdcard/Download/afl-cmin /data/local/tmp\"\'')
    invoke.run('adb shell \'su -c \"chmod +x /data/local/tmp/afl-cmin\"\'')

    invoke.run('adb push ' + os.path.join(basedir, 'bin/arm64/afl-showmap ') + ' /sdcard/Download')
    invoke.run('adb shell \'su -c \"mv /sdcard/Download/afl-showmap /data/local/tmp\"\'')
    invoke.run('adb shell \'su -c \"chmod +x /data/local/tmp/afl-showmap\"\'')


def push_executables(basedir):
    push_executor(basedir)
    push_fuzzer(basedir)
    push_fuzzer_scripts(basedir)


def push_seed(seeddir):
    invoke.run('adb push ' + seeddir + ' /sdcard/Download', echo=True)

    basename = os.path.basename(os.path.relpath(seeddir))
    invoke.run('adb shell \'su -c \"rm -rf /data/local/tmp/%s\"\'' % basename, echo=True)
    invoke.run('adb shell \'su -c \"mv /sdcard/Download/' + basename + ' /data/local/tmp/\"\'', echo=True)


def pull_corpus():
    if os.path.exists('./queue'):
        shutil.rmtree('./queue')
    invoke.run('adb shell \'su -c \"rm -rf /sdcard/Download/queue\"\'', echo=True)
    invoke.run('adb shell \'su -c \"mkdir /sdcard/Download/queue\"\'', echo=True)
    try:
        invoke.run('adb shell \'su -c \"cp /data/local/tmp/out/queue/* /sdcard/Download/queue\"\'', echo=True)
    except invoke.exceptions.UnexpectedExit as e:
        print e
    invoke.run('adb pull /sdcard/Download/queue')


def check_queue_len():
    pull_corpus()
    files = glob.glob('./queue/*')
    return len(files)


def remove_from_corpus(cur_input):
    if not os.path.exists(cur_input):
        raise Exception("cur_input " + cur_input + " does not exist")

    pull_corpus()

    for existing in glob.glob('./queue/*'):
        if filecmp.cmp(cur_input, existing):
            invoke.run('adb shell \'su -c \"rm /data/local/tmp/out/queue/' + os.path.basename(existing) + '\"\'')
            return True
    return False


def remove_from_corpus_all(path):
    if not os.path.isdir(path):
        raise Exception("dir " + path + " does not exist")

    pull_corpus()

    for item in glob.glob(os.path.join(path, '*')):
        for corpus_item in glob.glob('./queue/*'):
            if filecmp.cmp(item, corpus_item):
                invoke.run('adb shell \'su -c \"rm /data/local/tmp/out/queue/' + os.path.basename(corpus_item) + '\"\'')


def pull_cur_input():
    if os.path.exists('.cur_input'):
        os.remove('.cur_input')
    invoke.run('adb shell \'su -c \"cp /data/local/tmp/out/.cur_input /sdcard/Download/.cur_input\"\'', echo=True)
    invoke.run('adb pull /sdcard/Download/.cur_input', echo=True)


def blacklist(input):
    # just to make sure we have created dir
    try:
        invoke.run('adb shell \'su -c \"mkdir -p /data/local/tmp/out/blacklist\"\'')
    except invoke.exceptions.UnexpectedExit as e:
        print e

    invoke.run('adb push ' + input + ' /sdcard/Download')
    invoke.run('adb shell \'su -c \"cp /sdcard/Download/' + os.path.basename(input) + ' /data/local/tmp/out/blacklist\"\'')


def check_crashes():
    ret = invoke.run('adb shell \'su -c \"ls /data/local/tmp/out/crashes\"\'')
    return ret.stdout.strip()
