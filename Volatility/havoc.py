# Copyright (C) 2024 Kev Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/HavocC2-Forensics
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import logging
from typing import List

from volatility3.framework import exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, vadyarascan

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise


signatures = {
    'havoc_key_marker': """rule havoc_aes_marker
                                {
                                strings:
                                  $AES_KEY_MARKER = { 00 00 ?? ?? de ad be ef ?? ?? ?? ?? 00 00 00 63 00 00 00 00 }
                                condition:
                                  $AES_KEY_MARKER
                                }"""
}


class Havoc(interfaces.plugins.PluginInterface):
    """Scans process memory for each process to identify Havoc Demons and Keys"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.PluginRequirement(name = 'vadyarascan', plugin = vadyarascan.VadYaraScan, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)
        ]


    def _generator(self, procs):

        # Compile the list of rules
        rules = yara.compile(sources = signatures)

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            vollog.debug(f'Scanning Process {process_name}\n')

            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            layer = self.context.layers[proc_layer_name]

            # Run the yara scan with our collection of rules. The offset is the important part here. 
            for offset, rule_name, _name, _value in layer.scan(context = self.context,
                                                             scanner = yarascan.YaraScanner(rules = rules),
                                                             sections = vadyarascan.VadYaraScan.get_vad_maps(proc)):

                if rule_name == 'havoc_aes_marker':
                    # Read 1024 bytes from the layer at the offset and try to parse out some values. 
                    raw_data = layer.read(offset, 1024, False)
                    vollog.debug(f'Found AES Key Marker at {hex(offset)} in {process_name}\n')
                    vollog.debug(f'Raw Data: {raw_data}\n')

                    agent_id = raw_data[8:12].hex()
                    vollog.debug(f'Agent ID: {agent_id}\n')
                    aes_key = raw_data[20:52].hex()
                    vollog.debug(f'AES Key: {aes_key}\n')
                    aes_iv = raw_data[52:68].hex()
                    vollog.debug(f'AES IV: {aes_iv}\n')

                    yield (0, (
                        proc.UniqueProcessId,
                        process_name,
                        agent_id,
                        aes_key,
                        aes_iv,
                        ))


    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        #ToDo: Add an option to change the magic marker

        return renderers.TreeGrid([
                ("PID", int),
                ("Process", str),
                ("Agent ID", str),
                ("AES Key", str),
                ("AES IV", str),
            ],
            self._generator(
                pslist.PsList.list_processes(context = self.context,
                                             layer_name = kernel.layer_name,
                                             symbol_table = kernel.symbol_table_name,
                                             filter_func = filter_func)))
