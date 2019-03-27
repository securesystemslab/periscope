import argparse
from commands import *
import tracefs
import os
import blacklist
import prettytable


def add_arguments(parser):
    subparsers = parser.add_subparsers(dest='command')
    device_parser = subparsers.add_parser('device')
    monitor_parser = subparsers.add_parser('monitor')
    push_parser = subparsers.add_parser('push')
    pull_parser = subparsers.add_parser('pull')
    diagnose_parser = subparsers.add_parser('diagnose')
    afl_parser = subparsers.add_parser('afl')
    blacklist_parser = subparsers.add_parser('blacklist')

    device_parser.add_argument('--info', action='store_true', help='')
    device_parser.add_argument('--list', action='store_true', help='')
    device_parser.add_argument('--unset-kptr-restrict', action='store_true', help='')
    device_parser.add_argument('--reboot', action='store_true', help='')
    device_parser.add_argument('--image', dest='bootimg', help='')
    device_parser.add_argument('--list-tracers', action='store_true', help='')

    monitor_parser.add_argument('--enable', action='store_true', help='')
    monitor_parser.add_argument('--disable', action='store_true', help='')
    monitor_parser.add_argument('--status', action='store_true', help='')
    monitor_parser.add_argument('--list-probes', action='store_true', help='')
    monitor_parser.add_argument('--list-mappings', action='store_true', help='')
    monitor_parser.add_argument('--activate', dest='probe_ctx', help='')
    monitor_parser.add_argument('--activate-by-id', dest='probe_id', help='')
    monitor_parser.add_argument('--activate-by-drv', dest='drv_name', help='')
    monitor_parser.add_argument('--deactivate', action='store_true', help='')
    monitor_parser.add_argument('--trace', dest='duration_sec', help='')
    monitor_parser.add_argument('--parse', dest='trace_file', help='')
    monitor_parser.add_argument('--generate-seed', dest='seed_dir', help='')

    push_parser.add_argument('--executables', action='store_true', help='')
    push_parser.add_argument('--seed', dest='seed_dir', default='', help='')

    pull_parser.add_argument('--dmesg', action='store_true', help='')
    pull_parser.add_argument('--last-dmesg', action='store_true', help='')
    pull_parser.add_argument('--kallsyms', action='store_true', help='')
    pull_parser.add_argument('--trace-pipe', action='store_true', help='')
    pull_parser.add_argument('--corpus', action='store_true', help='')
    pull_parser.add_argument('--cur-input', action='store_true', help='')

    diagnose_parser.add_argument('--dmesg', dest='dmesg', help='')
    diagnose_parser.add_argument('--last-crash', action='store_true', help='')

    afl_parser.add_argument('--run', action='store_true', help='')
    afl_parser.add_argument('--kill', action='store_true', help='')
    afl_parser.add_argument('--cmin', dest='corpus_dir', help='')
    afl_parser.add_argument('--stats', action='store_true', help='')

    blacklist_parser.add_argument('--dir', dest='blacklistdir', help='', required=True)
    blacklist_parser.add_argument('--find', dest='file', help='')


def parse_arguments(args):
    if args.command == 'device':
        if args.info:
            proc_version = device.get_proc_version()
            print proc_version
        if args.list:
            device.print_list()
        if args.unset_kptr_restrict:
            device.unset_kptr_restrict()
        if args.reboot:
            if args.bootimg != None:
                device.reboot(args.bootimg)
            else:
                device.reboot()
        if args.list_tracers:
            tracers = device.get_available_tracers()
            print tracers

    elif args.command == 'monitor':
        if args.enable:
            monitor.set_current_tracer()
        if args.disable:
            monitor.unset_current_tracer()
        if args.status:
            cur = monitor.get_current_tracer()
            if cur == 'hwiotrace':
                print 'enabled'
                _, active_probes = monitor.get_active_probes()
                for probe in active_probes:
                    print 'context: %s, type: %s, name: %s' % (probe['ctx'], probe['type'], probe['name'])
            else:
                print 'disabled'
        if args.probe_ctx:
            monitor.activate(ctx=args.probe_ctx)
        if args.probe_id:
            monitor.activate(id=args.probe_id)
        if args.drv_name:
            monitor.activate(drv=args.drv_name)
        if args.deactivate:
            monitor.deactivate()
        if args.duration_sec:
            monitor.trace(seconds=args.duration_sec)
        if args.list_probes:
            columns, probes = monitor.get_available_probes()
            tbl = prettytable.PrettyTable()
            tbl.field_names = columns
            count = 0
            for probe in probes:
                row = []
                for col in columns:
                    row.append(probe[col])
                tbl.add_row(row)
                count += 1
            tbl.align['id'] = 'r'
            tbl.align['name'] = 'l'
            tbl.align['size'] = 'r'
            print tbl
            print 'total: %s' % count
        if args.list_mappings:
            tbl = prettytable.PrettyTable()
            columns, mappings = monitor.get_available_mappings()
            columns.remove('ctx')
            columns.insert(0, 'ctx')
            tbl.field_names = columns
            count = 0
            for mapping in mappings:
                row = []
                for col in columns:
                    row.append(mapping[col])
                tbl.add_row(row)
                count += 1
            tbl.align['id'] = 'r'
            tbl.align['name'] = 'l'
            tbl.align['size'] = 'r'
            tbl.sortby = 'ctx'
            print tbl
            print 'total: %s' % count
        if args.trace_file:
            tasks = tracefs.parse(args.trace_file)
            if args.seed_dir:
                tracefs.generate_seed(tasks, args.seed_dir)
            else:
                import pprint
                pp = pprint.PrettyPrinter()
                pp.pprint(tasks)

    elif args.command == 'push':
        if args.executables:
            afl.push_executables(os.getcwd())
        if args.seed_dir:
            afl.push_seed(args.seed_dir)

    elif args.command == 'pull':
        if args.dmesg:
            dmesg.pull()
        if args.last_dmesg:
            dmesg.pull_last_dmesg()
        if args.kallsyms:
            device.pull_kallsyms()
        if args.trace_pipe:
            monitor.pull_trace_pipe()
        if args.corpus:
            afl.pull_corpus()
        if args.cur_input:
            afl.pull_cur_input()

    elif args.command == 'diagnose':
        if args.dmesg:
            report = syz.parse(os.getcwd(), args.dmesg)
            print report
        if args.last_crash:
            dmesg.pull_last_dmesg()
            report = syz.parse(os.getcwd(), 'last_dmesg')
            print report
            afl.pull_cur_input()

    elif args.command == 'afl':
        if args.run:
            afl.run()
        if args.kill:
            afl.kill()
        if args.corpus_dir:
            afl.minimize_corpus(args.corpus_dir)
        if args.stats:
            stats = afl.get_fuzzer_stats()
            print stats

    elif args.command == 'blacklist':
        if args.file:
            print blacklist.find(args.blacklistdir, args.file)


def main():
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args()
    parse_arguments(args)


if __name__ == '__main__':
    main()
