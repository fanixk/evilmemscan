import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.taskmods as taskmods
import volatility.plugins.filescan as filescan
import volatility.plugins.connscan as connscan
import volatility.plugins.sockets as sockets
import volatility.plugins.sockscan as sockscan
import volatility.plugins.connections as connections
import volatility.plugins.modules as modules
import volatility.plugins.modscan as modscan
import volatility.utils as utils
import volatility.protos as protos
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
        # get name of running process
        process_name = str(list[i].ImageFileName)

        # pid = list[i].UniqueProcessId
        # ppid = list[i].InheritedFromUniqueProcessId
        # start_time = list[i].CreateTime
        # print process_name, pid, processes.count(process_name)

        # calc number of process instances and save it in a dictionary
        instances[process_name] = processes.count(process_name)

    for ps in instances:
        # check if correct number of instances are running for each process
        # save incorrent counts in a list to be returned
        if rules.has_key(ps) and rules[ps]['instances'] != instances[ps]:
            possible_infections.append(ps)

    return possible_infections
#

def main():
    init_volatility_config()

    # Get pslist & psscan differences
    pslist = lister(taskmods, 'PSList')
    psscan = scanner(filescan, 'PSScan')
    process_diffs = get_diffs(pslist, psscan)

    for diff in process_diffs:
        print 'Possible malware at process %s with PID %s. (pslist-psscan difference)' \
            %(diff.ImageFileName, diff.UniqueProcessId)

    # Get connections-connscan differences
    conns = lister(connections, 'Connections')
    connscanner = scanner(connscan, 'ConnScan')
    conn_diffs = get_diffs(conns, connscanner)

    for diff in conn_diffs:
        ip = str(diff.RemoteIpAddress)
        port = diff.RemotePort
        country = geolite2.lookup(ip).country
        print 'Possible malicious connection at %s: %s (Country: %s)' %(ip, port, country)

    # Get sockets-sockscan differences
    socks = lister(sockets, 'Sockets')
    sockscanner = scanner(sockscan, 'SockScan')
    sock_diffs = get_diffs(socks, sockscanner)

    for diff in sock_diffs:
        protocol = protos.protos.get(diff.Protocol.v(), '-')
        print 'Possible malicious socket connection from Address-%s, Port-%s, Protocol-%s, PID-%s at %s' \
                %(diff.LocalIpAddress, diff.LocalPort, protocol, diff.Pid, diff.CreateTime)

    # Get modules-modscanner differences
    mods = lister(modules, 'Modules')
    modscanner = scanner(modscan, 'ModScan')
    mod_diffs = get_diffs(mods, modscanner)

    for diff in mod_diffs:
        print 'Possible malicious module %s' %(diff.Name)

    # Check number of process running instances
    possible_infections = check_instances(psscan)
    for inf in possible_infections:
        print inf


if __name__== '__main__':
    main()