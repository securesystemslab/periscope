from invoke import run


def testcase1():
    # local('adb shell su -c "am start -n com.android.chrome/org.chromium.chrome.browser.ChromeTabbedActivity -d google.com/search?q=GooglePixel2 --activity-clear-task"')
    run('adb shell su -c am start -n "com.android.chrome/com.google.android.apps.chrome.Main"')
