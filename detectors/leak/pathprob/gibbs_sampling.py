from collections import defaultdict
import numpy as np
from sortedcontainers import SortedDict
import os


class ASGraph:
    def __init__(self):
        self.graph = defaultdict(lambda: defaultdict(int))

    def _add_path(self, nodes, count):
        if not (isinstance(nodes, tuple) or isinstance(count, int)):
            print("nodes and count must be tuple and int")
            return
        for i in range(len(nodes) - 1):
            left = nodes[i - 1] if i - 1 >= 0 else None
            right = nodes[i + 2] if i + 2 < len(nodes) else None

            as1, as2 = nodes[i], nodes[i + 1]
            if as1 < as2:
                self.graph[(as1, as2)][(left, right)] += count
            else:
                self.graph[(as2, as1)][(right, left)] += count

    def load_from_paths(self, paths):
        for path, count in paths.items():
            self._add_path(path, count)

    # def load_from_file(self, filepath):
    #     with open(filepath, "r", encoding="utf-8") as file:
    #         for line in file:
    #             path, count = line.strip().split(" ")
    #             self._add_path(tuple(path.split("|")), int(count))

    def get_graph(self):
        return self.graph

    def get_link_contexts(self, link):
        return self.graph[link]


class GibbsSampling(object):

    def __init__(self, paths, init_asrel, burn_in=0) -> None:
        # self.n_iter = n_iter
        self.burn_in = burn_in

        self.graph = ASGraph()
        self.graph.load_from_paths(paths)
        self._init_asrel(init_asrel)

    def _init_asrel(self, init_asrel):
        self.asrel = SortedDict.fromkeys(self.graph.get_graph(), 0)
        for (as1, as2), rel in init_asrel.items():
            if as1 < as2 and (as1, as2) in self.asrel:
                self.asrel[(as1, as2)] = int(rel)
            elif as1 > as2 and (as2, as1) in self.asrel:
                self.asrel[(as2, as1)] = -int(rel)

    def _cal_conditional_prob(self, link):
        as1, as2 = link
        p2c_count, p2p_count, c2p_count = 0, 0, 0
        for context, count in self.graph.get_link_contexts(link).items():
            left, right = context
            last_asrel, next_asrel = 1, -1  # default last is c2p and next is p2c
            if left != None:
                last_asrel = (
                    self.asrel[(left, as1)] if left < as1 else -self.asrel[(as1, left)]
                )
            if right != None:
                next_asrel = (
                    self.asrel[(as2, right)]
                    if right > as2
                    else -self.asrel[(right, as2)]
                )

            if last_asrel == 1 and (
                next_asrel == 1 or next_asrel == 0
            ):  # c2p _ c2p/p2p : c2p
                c2p_count += count
            elif last_asrel == 1 and next_asrel == -1:  # c2p _ p2c : p2p
                p2p_count += count
                continue
            elif (
                last_asrel == 0 or last_asrel == -1
            ) and next_asrel == -1:  # p2c/p2p _ p2c : p2c
                p2c_count += count
            else:
                p2p_count += count
                # continue
        count_sum = p2c_count + p2p_count + c2p_count
        if count_sum == 0:
            return [1 / 3, 1 / 3, 1 / 3]
        return [p2c_count / count_sum, p2p_count / count_sum, c2p_count / count_sum]

    def gibbs_sampling(self, n_iter):
        # burn in
        for _ in range(1, self.burn_in + 1):
            for link in self.graph.get_graph():
                prob = self._cal_conditional_prob(link)
                self.asrel[link] = np.random.choice([-1, 0, 1], p=prob)
        # sampling
        asrel_count = SortedDict({key: [0, 0, 0] for key in self.asrel})
        for _ in range(1, n_iter + 1):
            for link in self.graph.get_graph():
                prob = self._cal_conditional_prob(link)
                self.asrel[link] = np.random.choice([-1, 0, 1], p=prob)
                asrel_count[link][self.asrel[link] + 1] += 1
        return asrel_count

    def infer_asrel_prob(self, n_iter):
        asrel_count = self.gibbs_sampling(n_iter)
        prob = SortedDict()
        for link, counts in asrel_count.items():
            self.asrel[link] = np.argmax(counts) - 1
            prob[link] = [i / np.sum(counts) for i in counts]
        return prob