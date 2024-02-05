# -*- coding: UTF-8 -*-
import lief
import os

lief.logging.disable()


__all__ = ["REMINDer"]


THRESHOLDS = {
    'default': 6.85,
    'PE':      6.85,
    #'ELF': TODO
    #'MACHO': TODO
}


class REMINDer:
    logger = None
    
    def __init__(self, entropy_threshold=None, logger=None, **kwargs):
        """ Configure the detector with various parameters. """
        self.__entropy = entropy_threshold
        REMINDer.logger = logger
    
    def detect(self, executable):
        """ Analyze the input executable file using the custom heuristic. """
        btype, ep, ep_section, ep_section_writable = REMINDer._get_ep_and_section(str(executable))
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
    
    @staticmethod
    def _log(msg, exception, level="error"):
        """ Helper for either logging a message if REMINDer.logger is defined or raising an exception. """
        l = REMINDer.logger
        if l:
            getattr(l, level)(msg)
        else:
            raise exception(msg)
    
    @staticmethod
    def _get_ep_and_section(path):
        """ Helper for computing the entry point and finding its section for each supported format.
        :param binary: LIEF-parsed binary object
        :return:       (binary_type, ep_file_offset, name_of_ep_section)
        """
        # parse the input executable using LIEF (catch warnings from stderr)
        bn =lief.parse(path)
        if bn is None:
            return REMINDer._log(f"{path} is not an executable", TypeError)
        btype, fn = bn.format.__name__, os.path.basename(path)
        # get the EP, EP's section and the WRITE flag for EP's section
        try:
            if btype in ["ELF", "MACHO"]:
                ep = bn.virtual_address_to_offset(bn.entrypoint)
                # e.g. with UPX, the section table header gets packed too, hence LIEF gives 0 section parsed
                ep_section = bn.section_from_offset(ep) if len(bn.sections) > 0 else None
                # when #sections=0, the sample will be considered as packed anyway, so set wflag=False
                wflag = ep_section.has(lief.ELF.SECTION_FLAGS.WRITE if btype == "ELF" else \
                                       lief.MachO.SECTION_FLAGS.PURE_INSTRUCTIONS) if len(bn.sections) > 0 else False
            elif btype == "PE":
                ep_addr = bn.optional_header.addressof_entrypoint
                ep, ep_section = bn.rva_to_offset(ep_addr), bn.section_from_rva(ep_addr)
                wflag = ep_section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_WRITE)
            else:
                REMINDer._log(f"{fn} has an unsupported format", OSError, "warning")
                return None, None, None, False
            return btype, ep, ep_section, wflag
        #except AttributeError:
        #    return btype, None, None, False
        except Exception as e:
            REMINDer._log(str(e), RuntimeError)
            return btype, None, None, False

