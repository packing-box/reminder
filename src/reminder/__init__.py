# -*- coding: UTF-8 -*-
import lief
import os


__all__ = ["REMINDer"]


THRESHOLDS = {
    'default': 6.85,
    'PE':      6.85,
    #'ELF': TODO
    #'MACHO': TODO
}


class REMINDer:
    def __init__(self, entropy_threshold=None, logger=None, **kwargs):
        """ Configure the detector with various parameters. """
        self.__entropy = entropy_threshold
        self.logger = logger
    
    def _get_ep_and_section(self):
        """ Helper for computing the entry point and finding its section for each supported format.
        :param binary: LIEF-parsed binary object
        :return:       (binary_type, ep_file_offset, name_of_ep_section)
        """
        bn = self.binary
        btype, fn = bn.format.name, os.path.basename(bn.name)
        try:
            if btype in ["ELF", "MACHO"]:
                ep = bn.virtual_address_to_offset(bn.entrypoint)
                # e.g. with UPX, the section table header gets packed too, hence LIEF gives 0 section parsed
                ep_section = bn.section_from_offset(ep) if len(bn.sections) > 0 else None
                # when #sections=0, the sample will be considered as packed anyway, so set wflag=False
                wflag = ep_section.has(lief.ELF.SECTION_FLAGS.WRITE) if len(bn.sections) > 0 else False
            elif btype == "PE":
                ep_addr = bn.optional_header.addressof_entrypoint
                ep, ep_section = bn.rva_to_offset(ep_addr), bn.section_from_rva(ep_addr)
                wflag = ep_section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)
            else:
                if self.logger:
                    self.logger.warning("%s has an unsupported format" % fn)
                else:
                    raise OSError("%s has an unsupported format" % fn)
                return None, None, None, False
            return btype, ep, ep_section, wflag
        except (AttributeError, lief.not_found, lief.conversion_error):
            return btype, None, None, False
    
    def detect(self, executable):
        """ Analyze the input executable file using the custom heuristic. """
        # parse the input executable using LIEF (catch warnings from stderr)
        tmp_fd, null_fd = os.dup(2), os.open(os.devnull, os.O_RDWR)
        os.dup2(null_fd, 2)
        self.binary = lief.parse(str(executable))
        os.dup2(tmp_fd, 2)  # restore stderr
        os.close(null_fd)
        if self.binary is None:
            if self.logger:
                self.logger.error("%s is not an executable" % executable)
                return
            else:
                raise TypeError("%s is not an executable" % executable)
        # get the EP, EP's section and the WRITE flag for EP's section
        btype, ep, ep_section, ep_section_writable = self._get_ep_and_section()
        # in rare cases, it may occur that the EP could not be determiend with LIEF, then output accordingly
        if ep is None:
            return "?"
        # in some ELF-related cases, it may occur that there is no section table header (e.g. when packed with UPX) ;
        #  if so, consider as packed
        if ep_section is None:
            return True
        # display some debug information
        section_name = ep_section.name.rstrip("\x00")
        if self.logger:
            self.logger.debug("EP at 0x%.8x in %s" % (ep, section_name))
        # now apply the heuristic from https://ieeexplore.ieee.org/document/5404211
        # 1) check if the EP section is writable
        if ep_section_writable:
            threshold = self.__entropy or THRESHOLDS.get(btype, THRESHOLDS['default'])
            if self.logger:
                self.logger.debug("%s is writable" % section_name)
                self.logger.debug("entropy = %.3f (threshold: %.3f)" % (ep_section.entropy, threshold))
            # 2) check if the entropy of the EP section is above a given threshold
            if ep_section.entropy > threshold:
                return True
        return False

