# basic recreation of the connections 
# command using Volatility Framework 
# as a Library

import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.win32.network as network
import volatility.utils as utils

# load up some pseudo data
registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, commands.Command)
the_file = "file:////Users/fanix/projects/evilmemscan/vmem/zeus.vmem"

# default config (note my .volatilityrc is missing some values, 
# so I just used pdb to figure out which values needed setting

base_conf = {'profile': 'WinXPSP2x86',
    'use_old_as': None, 
    'kdbg': None, 
    'help': False, 
    'kpcr': None, 
    'tz': None, 
    'pid': None, 
    'output_file': None, 
    'physical_offset': None, 
    'conf_file': None, 
    'dtb': None, 
    'output': None, 
    'info': None, 
    'location': the_file, 
    'plugins': None, 
    'debug': None, 
    'cache_dtb': True, 
    'filename': None, 
    'cache_directory': None, 
    'verbose': None, 'write':False}

# set the default config
for k,v in base_conf.items():
    config.update(k, v)


# load up the address space
# pretty interesting to note that this is actually an iterative process
# first the FileAddressSpace from plugins/addr_spaces/standard/ is created
# with the file, and then a JKIA32PagedMemoryPae from volatility/plugins/addrspaces/intel
# is created.  If ['write', 'cache_dtb', 'kdbg'] are not set, this fails

addr_space = utils.load_as(config)


# now create the connections like in
# plugins/connections.py
conns = [conn for conn in  network.determine_connections(addr_space)]
for i in conns:
    offset = conn.obj_vm.vtop(conn.obj_offset)
    local = "{0}:{1}".format(conn.LocalIpAddress, conn.LocalPort)
    remote = "{0}:{1}".format(conn.RemoteIpAddress, conn.RemotePort)
    print ('w00t, now I know that %s ===> %s'%(local, remote))
