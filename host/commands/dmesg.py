from invoke import run


def show(str, num_lines=10):
    if str:
        run('adb shell \'su -c \"dmesg | grep %s\"\'' % str)
    else:
        run('adb shell \'su -c \"dmesg | tail -%d\"\'' % num_lines)


def pull():
    run('adb shell \'su -c \"dmesg > /sdcard/Download/dmesg\"\'')
    ret = run('adb pull /sdcard/Download/dmesg')
    return ret


def check_last_dmesg():
    ret = run('adb shell \'su -c \"find /sys/fs/pstore -name console-ramoops\"\'')
    if ret.stdout == '':
        return False
    return True


def pull_last_dmesg():
    run('adb shell \'su -c \"cat /sys/fs/pstore/console-ramoops > /sdcard/Download/last_dmesg\"\'')
    run('adb pull /sdcard/Download/last_dmesg')