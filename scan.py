import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.taskmods as taskmods
import volatility.plugins.filescan as filescan
import volatility.plugins.connscan as connscan
import volatility.plugins.connections as connections
import volatility.utils as utils
from geoip import geolite2
from process_rules import rules

config = conf.ConfObject()
addr_space = {}


def init_volatility_config():
    global config
    global addr_space
    registry.PluginImporter()
    registry.register_global_options(config, commands.Command)
    registry.register_global_options(config, addrspace.BaseAddressSpace)
    config.parse_options()
    config.PROFILE = 'WinXPSP2x86'
    config.LOCATION = 'file:///Users/fanix/projects/evilmemscan/vmem/zeus.vmem'
    addr_space = utils.load_as(config)


def get_diffs(list, scan):
    # if scan_module == 'PSList':
    #     for i in scanner.calculate():
    #         print i.ImageFileName
    #         print i.InheritedFromUniqueProcessId
    #         print i.CreateTime

    list_addrs = set(list.keys())
    scan_addrs = set(scan.keys())

    differences = [scan[diff] for diff in (scan_addrs - list_addrs)]
    return differences

def scanner(scan_module, scan_method):
    scanner = getattr(scan_module, scan_method)(config)
    scan = dict((res.obj_offset, res) for res in scanner.calculate())
    return scan


def lister(list_module, list_method):
    lister = getattr(list_module, list_method)(config)
    list = dict((addr_space.vtop(res.obj_offset), res) for res in lister.calculate())
    return list


def check_instances(list):
    instances = dict()
    processes = [str(item.ImageFileName) for item in list.values()]
    possible_infections = []

    for i in list:
        process_name = str(list[i].ImageFileName)
        # pid = list[i].UniqueProcessId
        # print process_name, pid, processes.count(process_name)
        instances[process_name] = processes.count(process_name)

    for ps in instances:
        if rules.has_key(ps) and rules[ps]['instances'] != instances[ps]:
            possible_infections.append(ps)

    return possible_infections
#
def main():
    init_volatility_config()

    pslist = lister(taskmods, 'PSList')
    psscan = scanner(filescan, 'PSScan')

    process_diffs = get_diffs(pslist, psscan)
    for diff in process_diffs:
        print '%s: %s' %(diff.ImageFileName, diff.UniqueProcessId)

    conns = lister(connections, 'Connections')
    connscanner = scanner(connscan, 'ConnScan')

    conn_diffs = get_diffs(conns, connscanner)

    for diff in conn_diffs:
        ip = str(diff.RemoteIpAddress)
        match = geolite2.lookup(ip)
        print match.country
        print '%s: %s' %(ip, diff.RemotePort)

    possible_infections = check_instances(psscan)
    for inf in possible_infections:
        print inf

    # for i in rules:
    #     print rules[i]['start_time']

if __name__== '__main__':
    main()