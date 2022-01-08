"""Library of miscellaneous cachedump analysis routines."""
# pylint: disable=no-self-use

import re
import os

import capstone

class L1CacheConfig:
    """Configuration and csv parameters for Cortex A72 per-core L1 cache."""
    def __init__(self):
        pass
    def get_field_names(self):
        """Return field names for the csv file written by ../cache_operations.c"""
        return [] \
          + ["way", "set"] \
          + ["pid", "pid_x"] \
          + ["t1" , "rawtag", "pa"] \
          + ["d_%02d" % (i,) for i in range(0, 16)]
    def get_nway(self):
        """Return number of ways in the cache."""
        return 3
    def get_nset(self):
        """Return number of sets."""
        return 256

class L2CacheConfig:
    """Configuration and csv parameters for Cortex A72 unified L2 cache"""
    def __init__(self):
        pass
    def get_field_names(self):
        """Return field names for the csv file written by ../cache_operations.c"""
        return [] \
          + ["check"] \
          + ["way", "set"] \
          + ["moesi"] \
          + ["pid", "pid_x"] \
          + ["t1", "rawtag", "pa"] \
          + ["d_%02d" % (i,) for i in range(0, 16)]
    def get_nway(self):
        """Return number of ways in the cache."""
        return 16
    def get_nset(self):
        """Return number of sets."""
        return 1024

def configuration_factory(kind):
    """Return an object describing the cache."""
    if kind == "L1":
        return L1CacheConfig()
    if kind == "L2":
        return L2CacheConfig()
    assert False, "Unknown cache config %s" % (kind,)
    return None

RE_FILENAME_CMDLINE = re.compile(r'^(\d+)\.cmdline\.txt')
def read_saved_command_info(data_path):
    """Read all saved copies of /proc/$pid/cmdline and return
    a map from pid to short process name.
    """
    pid_map = {}
    for input_file_name in os.listdir(data_path):
        match = RE_FILENAME_CMDLINE.match(input_file_name)
        if match:
            pid = int(match.group(1))
            with open("./data/" + input_file_name, "rb") as input_fd:
                cmdline_raw = input_fd.read()
                raw_splits = cmdline_raw.split(b'\0')
                name = raw_splits[0].decode()
                path_splits = name.split("/")
                base_name = path_splits[-1]
                space_splits = base_name.split(" ")
                pname = space_splits[0].trim(":")  # for sshd:
                pid_map[pid] = pname
    return pid_map

class InstructionDecoder:
    """Given a 4-byte uint32_t ARM64 instruction,
    decode it into a mnemonic and op_str, if possible.
    Cache the results, as Capstone takes a long time.
    """
    def __init__(self):
        self.capstone_engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self.insn_value_to_decode = {}

    def dump(self):
        """Print out the cache."""
        # print(self.insn_value_to_decode)
        print("%d instructions in the decode cache" % (len(self.insn_value_to_decode),))

    def decode_to_str(self, phys_addr, insn_value):
        """decode the instruction to a printable string."""
        decoded = self.decode(phys_addr, insn_value)
        if decoded is None:
            return "??"
        if len(decoded) == 1:
            return decoded[0]
        return "%s %s" % (decoded[0], decoded[1],)

    def decode(self, phys_addr, insn_value):
        """Returns None if insn_value isn't decodable.
        Otherwise returns a list of length 1 or 2,
        the first item is the mnemonic(opcode), 2nd the op_str.
        """
        if insn_value in self.insn_value_to_decode:
            return self.insn_value_to_decode[insn_value]
        ndecoded = 0
        decode_value = None
        for insn in self.capstone_engine.disasm(insn_value.to_bytes(4, "little"), phys_addr):
            decode_value = [insn.mnemonic, insn.op_str]
            ndecoded += 1
        assert 0 <= ndecoded <= 1
        if ndecoded == 0:
            self.insn_value_to_decode[insn_value] = None
            return None
        self.insn_value_to_decode[insn_value] = decode_value
        return decode_value

    def is_instruction(self, phys_addr, insn_value):
        """Return True if this decodes as a valid instruction."""
        return self.decode(phys_addr, insn_value) is not None
