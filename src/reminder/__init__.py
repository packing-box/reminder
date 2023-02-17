# -*- coding: UTF-8 -*-
import lief
import os


__all__ = ["REMINDer"]


THRESHOLDS = {
    'default': 6.85,
    'PE':      6.85,
}


class REMINDer:
    def __init__(self, entropy_threshold=None, logger=None, **kwargs):
        """ Configure the detector with various parameters. """
        self.__entropy = entropy_threshold
        self.logger = logger
    
    def detect(self, executable):
        """ Analyze the input executable file using the custom heuristic. """
        # parse the input executable using LIEF (catch warnings from stderr)
        tmp_fd, null_fd = os.dup(2), os.open(os.devnull, os.O_RDWR)
        os.dup2(null_fd, 2)
        binary = lief.parse(str(executable))
        os.dup2(tmp_fd, 2)  # restore stderr
        os.close(null_fd)
        if binary is None:
            raise TypeError("Not an executable")
        etype = "ELF" if type(binary) is lief.ELF.Binary else \
                "Mach-O" if type(binary) is lief.MachO.Binary else \
                "PE" if type(binary) is lief.PE.Binary else None
        # locate the entry point and its section
        ep = binary.rva_to_offset(binary.optional_header.addressof_entrypoint)
        ep_section = binary.section_from_rva(binary.optional_header.addressof_entrypoint)
        section_name = ep_section.name.rstrip("\x00")
        if self.logger:
            self.logger.debug("EP at 0x%.8x in %s" % (ep, section_name))
        # now apply the heuristic from https://ieeexplore.ieee.org/document/5404211
        # 1) check if the EP section is writable
        if ep_section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
            threshold = self.__entropy or THRESHOLDS.get(etype, THRESHOLDS['default'])
            if self.logger:
                self.logger.debug("%s is writable" % section_name)
                self.logger.debug("entropy = %.3f (threshold: %.3f)" % (ep_section.entropy, threshold))
            # 2) check if the entropy of the EP section is above a given threshold
            if ep_section.entropy > threshold:
                return True
        return False

