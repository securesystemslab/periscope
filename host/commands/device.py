import os
from invoke import run
from sys import platform


def get_proc_version():
    ret = run('adb shell cat /proc/version', hide=True)
    return ret.stdout.strip()


def get_available_tracers():
    ret = run('adb shell \'su -c \"cat  /sys/kernel/debug/tracing/available_tracers\"\'', hide=True)
    return ret.stdout.strip().split(' ')


def print_list():
    run('adb devices')


def reboot(bootimg=''):
    if bootimg and len(bootimg) > 0:
        if not os.path.exists(bootimg):
            raise Exception('bootimg %s does not exist' % bootimg)

        run('adb reboot bootloader')

        if 'linux' in platform:
            run('sudo `which fastboot` boot %s' % bootimg)
        else:
            run('fastboot boot %s' % bootimg)
    else:
        run('adb reboot')


def unset_kptr_restrict():
    run('adb shell \'su -c \"echo 0 \> /proc/sys/kernel/kptr_restrict\"\'', echo=True)


def pull_kallsyms():
    unset_kptr_restrict()
    run('adb shell \'su -c \"cat /proc/kallsyms \> /sdcard/Download/kallsyms\"\'')
    run('adb pull /sdcard/Download/kallsyms')


def keycode_power():
    run('adb shell input keyevent 26')


def keycode_menu():
    run('adb shell input keyevent 82')
