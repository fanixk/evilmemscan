rules = {
    'System': {
        'pid': 0,
        'path': None,
        'parent': 0,
        'instances': 1,
        'user_account': 'Local System',
        'start_time': None
    },
    'wininit.exe': {
        'instances': '1+'
    },
    'lsass.exe': {
        'instances': 1
    },
    'winlogon.exe': {
        'instances': '1+'
    },
    'csrss.exe': {
        'instances': '2+'
    },
    'services.exe': {
        'instances': 1
    },
    'svchost.exe': {
        'instances': '5+'
    },
    'lsm.exe': {
        'instances': 1
    },
    'explorer.exe': {
        'instances': '1+'
    }
}