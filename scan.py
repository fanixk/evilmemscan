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
import volatility.plugins.netscan as netscan
import volatility.plugins.registry.hivescan as hivescan
import volatility.plugins.registry.hivelist as hivelist
import volatility.utils as utils
import volatility.protos as protos
from geoip import geolite2
from process_rules import rules
import os
import sys

config = conf.ConfObject()
addr_space = {}


def init_volatility_config():
    global config
    global addr_space
    registry.PluginImporter()
    registry.register_global_options(config, commands.Command)
    registry.register_global_options(config, addrspace.BaseAddressSpace)
    config.parse_options()
    config.PROFILE = 'Win7SP1x86'
    mem_image_path = os.path.abspath(sys.argv[1])
    config.LOCATION = 'file://' + mem_image_path
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

        # calc number of process instances and save it in a dictionary
        instances[process_name] = processes.count(process_name)

    for ps in instances:
        # check if correct number of instances are running for each process
        # save incorrent counts in a list to be returned
        if rules.has_key(ps):
            if str(rules[ps]['instances']).endswith('+'):
                ins = int(rules[ps]['instances'][:-1])
                if instances[ps] < ins:
                    possible_infections.append(ps)
            elif rules[ps]['instances'] != instances[ps]:
                possible_infections.append(ps)

    return possible_infections


def main():
    if len(sys.argv) < 2:
        print 'Usage: %s <memory image file>' %(sys.argv[0])
        return

    init_volatility_config()

    # Get pslist & psscan differences
    pslist = lister(taskmods, 'PSList')
    psscan = scanner(filescan, 'PSScan')
    process_diffs = get_diffs(pslist, psscan)

    for diff in process_diffs:
        print 'Possible malware at process %s with PID %s. (pslist-psscan difference)' \
            %(diff.ImageFileName, diff.UniqueProcessId)

    if not process_diffs:
        print 'No differences found between pslist and psscan'

    # Get modules-modscan differences
    mods = lister(modules, 'Modules')
    modscanner = scanner(modscan, 'ModScan')
    mod_diffs = get_diffs(mods, modscanner)

    for diff in mod_diffs:
        print 'Possible malicious module %s' %(diff.Name)

    if not mod_diffs:
        print 'No differences found between modlist and modscan'

    # Get hivelist-hivescan differences
    hives = lister(hivelist, 'HiveList')
    hivescanner = scanner(hivescan, 'HiveScan')
    hive_diffs = get_diffs(hives, hivescanner)

    for diff in hive_diffs:
        print 'Possible malicious hive %s' %diff.get_name()

    if not hive_diffs:
        print 'No differences found between hivelist and hivescan'

    # check for valid win7 or win8 profile
    if not netscan.Netscan.is_valid_profile(addr_space.profile):
        print 'Invalid Profile'
        return

    netscanner = netscan.Netscan(config)
    conns = [res for res in netscanner.calculate()]
    for conn in conns:
        local_ip = str(conn[2])
        local_port = str(conn[3])
        remote_ip = str(conn[4])
        remote_port = str(conn[5])

        if remote_ip is '*':
            continue

        lookup = geolite2.lookup(remote_ip)
        if lookup is not None:
            country = lookup.country
            print 'Connection from %s:%s to %s:%s (Country: %s)' \
              %(local_ip, local_port, remote_ip, remote_port, country)

    # Check number of process running instances
    ins = psscan or pslist
    possible_infections = check_instances(ins)
    for inf in possible_infections:
        print 'Invalid number of process instances %s' %(inf)

    if not possible_infections:
        print 'Valid number of process instances.'

    # Get connections-connscan differences
    # conns = lister(connections, 'Connections')
    # connscanner = scanner(connscan, 'ConnScan')
    # conn_diffs = get_diffs(conns, connscanner)
    #
    # for diff in conn_diffs:
    #     ip = str(diff.RemoteIpAddress)
    #     port = diff.RemotePort
    #     country = geolite2.lookup(ip).country
    #     print 'Possible malicious connection from %s:%s to %s:%s (Country: %s)' \
    #           %(diff.LocalIpAddress, diff.LocalPort, ip, port, country)
    #
    # # Get sockets-sockscan differences
    # socks = lister(sockets, 'Sockets')
    # sockscanner = scanner(sockscan, 'SockScan')
    # sock_diffs = get_diffs(socks, sockscanner)
    #
    # for diff in sock_diffs:
    #     protocol = protos.protos.get(diff.Protocol.v(), '-')
    #     print 'Possible malicious socket connection from Address-%s, Port-%s, Protocol-%s, PID-%s at %s' \
    #             %(diff.LocalIpAddress, diff.LocalPort, protocol, diff.Pid, diff.CreateTime)

if __name__== '__main__':
    main()