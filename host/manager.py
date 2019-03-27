import argparse
import json
import os
import shutil
import threading
import time
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import TCPServer
import logging
import blacklist
import db
from commands import afl, dmesg, device, monitor, syz
from invoke import exceptions


BOOT_WAIT_SEC = 15
BOOT_WAIT_INCREMENT_SEC = 4
REBOOT_COOLING_OFF_SEC = 60
POLL_SEC = 10
OFFLINE_POLL_SEC = POLL_SEC * 3
OFFLINE_REBOOT_THRESOLD_SEC = 180
CORPUS_MINIMIZE_THRESHOLD = 300 # depends on the presumed state space


intermittent_crashes = [
    'Title: unable to handle kernel paging request in el1_dbg',
    'Title: kernel BUG at arch/arm64/mm/khwio.c:LINE'
]


def run_dashboard(workdir, port):
    os.chdir(workdir)
    TCPServer.allow_reuse_address = True
    httpd = TCPServer(('', port), SimpleHTTPRequestHandler)
    httpd.serve_forever()


def check_tracing(probe_ctx):
    if monitor.get_current_tracer() == 'nop':
        monitor.set_current_tracer()

    if not monitor.is_active(ctx=probe_ctx):
        monitor.activate(ctx=probe_ctx)


def check_fuzzing():
    if not afl.check():
        raise SystemExit("No afl instance running")


def run_instance(probe_ctx):
    device.unset_kptr_restrict()

    check_tracing(probe_ctx)

    queue_len = afl.check_queue_len()

    if queue_len > CORPUS_MINIMIZE_THRESHOLD:
        logger.info('Checking if any of blacklist items exist in corpus...')
        afl.remove_from_corpus_all('blacklist')
        logger.info('Initiating corpus minimization...')
        afl.minimize_corpus('/data/local/tmp/out/queue')
        logger.info('Done. Blacklist check again on the new set of corpus...')
        afl.remove_from_corpus_all('blacklist')
    else:
        logger.info('Skipping corpus minimization... (queue_len=' + str(queue_len) + ')')

    afl.run()


def diagnose(basedir):
    logger.info('Checking last dmesg...')
    if dmesg.check_last_dmesg():
        dmesg.pull_last_dmesg()

        logger.info('Generating report...')
        try:
            report = syz.parse(basedir, 'last_dmesg')
            if report.count('Title:') > 0:
                report_title = report.split('\n')[1]
                if report_title not in intermittent_crashes:
                    logger.info('Checking last input...')
                    try:
                        afl.pull_cur_input()
                    except exceptions.UnexpectedExit as e:
                        print e

                    if os.path.exists('.cur_input'):
                        if os.path.getsize('.cur_input') > 0:
                            blacklist_id = blacklist.find('blacklist', '.cur_input')
                            if blacklist_id > -1:
                                logger.info('Same crashing input observed twice. Blacklisting it...')
                                afl.blacklist(os.path.join('blacklist', str(blacklist_id) + '.cur_input'))
                            else:
                                logger.info('Queueing last input to blacklist...')
                                blacklist_id = blacklist.queue('blacklist', '.cur_input')
                                logger.info('Blacklist id: ' + str(blacklist_id))

                            reproducer = os.path.join('blacklist', str(blacklist_id) + '.cur_input')
                            if os.path.exists(reproducer):
                                report = report.split('\n')
                                report.insert(2, 'Reproducer: ' + reproducer)
                                report = '\n'.join(report)

                            logger.info('Removing crashing input in corpus if any...')
                            try:
                                if afl.remove_from_corpus('.cur_input'):
                                    logger.info('Removed.')
                            except exceptions.UnexpectedExit as e:
                                print e

                        else:
                            logger.warning('Last input is empty')

                    report_id = 1
                    while os.path.exists('report' + str(report_id) + '.txt'):
                        report_id = report_id + 1
                    try:
                        report_file = open('report' + str(report_id) + '.txt', 'w')
                        report_file.write(report)
                        logger.info(report_file.name + ' generated: \033[1;1m' + report_title + '\033[0m')
                        shutil.copy('last_dmesg', report_file.name + '.dmesg')
                    finally:
                        report_file.close()

            else:
                logger.info('Failed to generate report: \033[1;1m' + report.split('\n')[0] + '\033[0m')

        except exceptions.UnexpectedExit as e:
            print e

    else:
        logger.info('No last dmesg exists')

    logger.info('Checking crashes...')
    crashes = afl.check_crashes()
    if crashes != '':
        logger.warning('Crashes reported')
        logger.warning(crashes)


def reboot(basedir, bootimg):
    logger.info('Rebooting...')
    device.reboot(os.path.join(basedir, bootimg))
    time.sleep(BOOT_WAIT_SEC)

    while True:
        try:
            dmesg.pull()

            if 'hwiotrace' in device.get_available_tracers():
                logger.info('boot successful!')
                logger.info('cooling off for %d seconds after reboot...' % REBOOT_COOLING_OFF_SEC)
                time.sleep(REBOOT_COOLING_OFF_SEC)
                break
            else:
                logger.info('rebooting again...')
                device.reboot(os.path.join(basedir, bootimg))
                time.sleep(BOOT_WAIT_SEC)

        except exceptions.UnexpectedExit:
            logger.info('waiting for the device to boot ' + bootimg)
            time.sleep(BOOT_WAIT_INCREMENT_SEC)


def poll_loop(basedir, probe_ctx, bootimg):
    online = False
    poll_interval = 0
    offline_duration = 0

    while True:
        time.sleep(poll_interval)

        try:
            if offline_duration > OFFLINE_REBOOT_THRESOLD_SEC:
                logger.info('Has been offline for ' + str(offline_duration) + ' seconds. Rebooting...')
                offline_duration = 0
                reboot(basedir, bootimg)

            dmesg.pull()
            shutil.copy('dmesg', 'dmesg.txt')

            if 'hwiotrace' not in device.get_available_tracers():
                diagnose(basedir)
                reboot(basedir, bootimg)

            if not online:
                logger.info('resuming fuzzing...')
                run_instance(probe_ctx)

            check_tracing(probe_ctx)
            check_fuzzing()

            online = True
            offline_duration = 0
            poll_interval = POLL_SEC

        except exceptions.UnexpectedExit:
            if not online:
                offline_duration += poll_interval
            online = False
            poll_interval = OFFLINE_POLL_SEC
            logger.warning('waiting for the device to become online for ' + str(offline_duration) + ' seconds')


def run_manager(cfg):
    basedir = os.getcwd()
    workdir = cfg['workdir']
    bootimg = 'patched_boot.img'

    if cfg['bootimg']:
        bootimg = cfg['bootimg']

    probe = cfg['probe']
    if not probe:
        raise Exception('probe must be given')

    probe_ctx = probe['ctx']
    if not probe_ctx:
        raise Exception('probe.ctx must be given')

    crashdir = os.path.join(workdir, 'crashes')
    if not os.path.exists(crashdir):
        os.makedirs(crashdir)

    blacklistdir = os.path.join(workdir, 'blacklist')
    if not os.path.exists(blacklistdir):
        os.makedirs(blacklistdir)

    logger.info('loading corpus if any...')
    corpusdir = os.path.join(workdir, 'corpus')
    corpusdb = db.db_open(corpusdir)
    logger.info(str(len(corpusdb['testcases'])) + ' test cases found')

    logger.info('starting dashboard...')
    port = int(cfg['http'].split(':')[1])
    dashboard_thread = threading.Thread(target=run_dashboard, args=(workdir, port))
    dashboard_thread.setDaemon(True)
    dashboard_thread.start()
    logger.info('dashboard running at port ' + str(port))

    poll_loop(basedir, probe_ctx, bootimg)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', dest='config_file', help='', required=True)
    args = parser.parse_args()
    cfg = json.load(open(args.config_file))

    run_manager(cfg)


logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    main()
