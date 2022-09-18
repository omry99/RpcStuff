import re
import subprocess
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException

UUID_REGEX = r"\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
VERSION_REGEX = r"v(\d\.\d)"
BINDING_REGEX = r"ncacn_ip_tcp:[^\]]+]"  # TODO: how do you connect to non-tcp?


def exec_command(command):
    proc = subprocess.Popen(command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True,
                            )
    stdout, stderr = proc.communicate()
    return str(stdout)


def get_rpc_endpoints(ip):
    inter_dict = {}
    output = exec_command(f"rpcdump.py {ip}")[113:-32]
    interfaces = output.split("\\r\\n\\r\\n")
    interfaces.remove('')
    for i in interfaces:
        _uuid = re.search(UUID_REGEX, i).group(0)
        ver = re.search(VERSION_REGEX, i).group(1)
        string_bindings = re.findall(BINDING_REGEX, i)
        if len(string_bindings) > 0:
            inter_dict[_uuid] = (ver, string_bindings)
    return inter_dict


def connect_to_interface(interface_uuid, version, binding_string):
    transport = DCERPCTransportFactory(binding_string)
    dce = transport.get_dce_rpc()
    dce.connect()
    # print("[*] Connected to the remote target")
    uuidtup_bin = uuidtup_to_bin((interface_uuid, version))
    dce.bind(uuidtup_bin)
    # print(f"[*] Binded to {interface_uuid}")
    return dce


def find_no_auth_endpoints(endpoint_dict):
    """ find interfaces that don't require creds """
    result_dict = {}
    for uuid in endpoint_dict:
        version = endpoint_dict[uuid][0]
        for string_binding in endpoint_dict[uuid][1]:
            dce = connect_to_interface(uuid, version, string_binding)
            dce.call(42, "A" * 1000)
            try:
                print(dce.recv())
            except DCERPCException as e:
                if "rpc_s_access_denied" not in str(e):
                    if uuid not in result_dict:
                        result_dict[uuid] = (version, [string_binding])
                    else:
                        result_dict[uuid][1].append(string_binding)
    return result_dict


#print(get_rpc_endpoints("192.168.1.125"))
#print(find_no_auth_endpoints(get_rpc_endpoints("192.168.1.125")))
#print(get_rpc_endpoints("127.0.0.1"))
print(find_no_auth_endpoints(get_rpc_endpoints("127.0.0.1")))
# uuid = '1088A980-EAE5-11D0-8D9B-00A02453C337'
# dce = connect_to_interface(uuid, "1.0", 'ncacn_ip_tcp:127.0.0.1[2105]')
# print(f"[*] Binded to {uuid}")
# dce.call(8, "A" * 1000)
# print(dce.recv())
