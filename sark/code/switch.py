from collections import defaultdict


import idaapi

from .. import exceptions

class Switch(object):
    """IDA Switch

    Access IDA switch data with ease.

    Usage:

        >>> my_switch = Switch(switch_jump_address)
        >>> for case, target in my_switch:
        ...     print("{} -> 0x{:08X}".format(case, target))

    """
    def __init__(self, ea):
        """Initialize a switch parser.

        Args:
            ea: An address of a switch jump instruction.
        """
        self._ea = ea

        results = self._calc_cases()

        self._map = self._build_map(results)

        self._reverse_map = self._build_reverse(self._map)

    def _build_reverse(self, switch_map):
        reverse_map = defaultdict(list)
        for case, target in switch_map.items():
            reverse_map[target].append(case)
        return reverse_map

    def _calc_cases(self):
        si = idaapi.get_switch_info(self._ea)
        results = idaapi.calc_switch_cases(self._ea, si)
        if not results:
            raise exceptions.SarkNotASwitch("Seems like 0x{:08X} is not a switch jump instruction.".format(self._ea))

        return results

    def _build_map(self, results):
        switch_map = {}
        for cases, target in zip(results.cases, results.targets):
            for case in cases:
                switch_map[case] = target

        return switch_map

    @property
    def targets(self):
        """Switch Targets"""
        return list(self._map.values())

    @property
    def cases(self):
        """Switch Cases"""
        return list(self._map.keys())

    @property
    def pairs(self):
        """(case, target) pairs"""
        return iter(self._map.items())

    def __iter__(self):
        """Iterate switch cases."""
        return iter(self._map.keys())

    def __getitem__(self, case):
        """switch[case] -> target"""
        return self._map[case]

    def get_cases(self, target):
        """switch.get_cases(target) -> [case]"""
        if target in self.targets:
            return self._reverse_map[target]

        raise KeyError("Target 0x{:08X} does not exist.".format(target))


def is_switch(ea):
    try:
        switch = Switch(ea)
        return True
    except exceptions.SarkNotASwitch:
        return False