from collections import defaultdict
from itertools import izip

import idaapi

from ..exceptions import SarkNotASwitch

class Switch(object):
    def __init__(self, ea):
        self._ea = ea

        results = self._calc_cases()

        self._map = self._build_map(results)

        self._reverse_map = self._build_reverse(self._map)

    def _build_reverse(self, switch_map):
        reverse_map = defaultdict(list)
        for case, target in switch_map.iteritems():
            reverse_map[target].append(case)
        return reverse_map

    def _calc_cases(self):
        si = idaapi.get_switch_info_ex(self._ea)
        results = idaapi.calc_switch_cases(self._ea, si)
        if not results:
            raise SarkNotASwitch("Seems like 0x{:08X} is not a switch jump instruction.".format(self._ea))

    def _build_map(self, results):
        switch_map = {}
        for cases, target in izip(results.cases, results.targets):
            for case in cases:
                switch_map[case] = target

        return switch_map

    @property
    def targets(self):
        return self._map.values()

    @property
    def cases(self):
        return self._map.keys()

    def __iter__(self):
        return self._map.iteritems()

    def __getitem__(self, case):
        return self._map[case]

    def get_case(self, target):
        if target in self.targets:
            return self._reverse_map[target]

        raise KeyError("Target 0x{:08X} does not exist.".format(target))
