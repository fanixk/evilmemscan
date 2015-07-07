import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.taskmods as taskmods
import volatility.plugins.filescan as filescan
import volatility.plugins.connscan as connscan
import volatility.plugins.connections as connections
# import volatility.win32.network as network
import volatility.utils as utils

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

def base_diffscanner(list_module, list_method, scan_module, scan_method):
    lister = getattr(list_module, list_method)(config)
    scanner = getattr(scan_module, scan_method)(config)

    list = dict((res.obj_offset, res) for res in lister.calculate())
    scan = dict((addr_space.vtop(res.obj_offset), res) for res in scanner.calculate())

    list_addrs = set(list.keys())
    scan_addrs = set(scan.keys())

    differences = [scan[diff] for diff in (scan_addrs - list_addrs)]
    return differences

def process_scan():
    found = False
    # initialize volatility
    config = init_volatility_config()
    addr_space = utils.load_as(config)

    # initialize scans
    pslist_scanner = taskmods.PSList(config)
    psscanner = filescan.PSScan(config)

    # get pslist & psscan results
    procs_list = dict((p.obj_offset, p) for p in pslist_scanner.calculate())
    procs_scan = dict((addr_space.vtop(p.obj_offset), p) for p in psscanner.calculate())

    list_addrs = set(procs_list.keys())
    scan_addrs = set(procs_scan.keys())

    differences = []

    # calc differences
    for diff in (scan_addrs - list_addrs):
        found = True
        malware = procs_scan[diff].ImageFileName + ': ' + str(procs_scan[diff].UniqueProcessId)
        differences.append(malware)
    return found, differences

def main():
    # found, diffs = process_scan()
    # processes = (diff for diff in diffs if found)
    # for ps in processes:
    #     print ps
    #
    # conns = conn_scan()
    # for conn in conns:
    #     print 'Connection to: ' + conn.RemoteIpAddress
    #
    # if not found:
    #     print 'No malware found!'
    init_volatility_config()

    diffs = base_diffscanner(taskmods, 'PSList', filescan, 'PSScan')
    for diff in diffs:
        print diff.ImageFileName + ': ' + str(diff.UniqueProcessId)

    diffs = base_diffscanner(connections, 'Connections', connscan, 'ConnScan')
    for diff in diffs:
        print diff.RemoteIpAddress + ':' + str(diff.RemotePort)

if __name__== '__main__':
    main()