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


def main():
    init_volatility_config()

    diffs = base_diffscanner(taskmods, 'PSList', filescan, 'PSScan')
    for diff in diffs:
        print diff.ImageFileName + ': ' + str(diff.UniqueProcessId)

    diffs = base_diffscanner(connections, 'Connections', connscan, 'ConnScan')
    for diff in diffs:
        match = geolite2.lookup(str(diff.RemoteIpAddress))
        print match.country
        print diff.RemoteIpAddress + ':' + str(diff.RemotePort)

if __name__== '__main__':
    main()