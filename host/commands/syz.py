from invoke import run
import os


def parse(basedir, dmesg):
    dmesg_tmp = dmesg + '.tmp'
    run('strings ' + dmesg + ' > ' + dmesg_tmp)

    ret = run('go run ' + os.path.join(basedir, 'tools/syz-parse/syz-parse.go') + ' ' + dmesg_tmp, hide=True)
    report = ret.stdout.strip()
    report = report.replace('\r\n', '\n')
    return report
