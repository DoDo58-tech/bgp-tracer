from sortedcontainers import SortedDict, SortedSet
import os


class P2C_Topology(object):
    """A->B: if A is p2c then B is p2c"""

    def __init__(self) -> None:
        self.nodes = SortedDict()

    def add_list(self, aslist):
        if len(aslist) <= 2:
            return
        last_link = aslist[:2]
        for i in range(1, len(aslist) - 1):
            link = aslist[i : i + 2]
            if last_link not in self.nodes:
                self.nodes[last_link] = SortedSet()
            self.nodes[last_link].add(link)
            last_link = link

    def get_next_nodes(self, link):
        link = tuple(link)
        if link in self.nodes:
            return self.nodes[link]
        else:
            return SortedSet()

    # def write_topo(self, file):
    #     out = ""
    #     for node, next_set in self.nodes.items():
    #         out += f'{node[0]}|{node[1]}:{"|".join([link[0]+","+link[1] for link in next_set])}\n'
    #     file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'output', os.path.basename(file))
    #     with open(file, "w", encoding="utf-8", newline="\n") as f:
    #         f.write(out)


class P2CEdgeLinkInfer(object):
    def __init__(self, pathnumfile, clinks):
        self.clinks = clinks
        self.pathnumfile = pathnumfile
        self.p2c_topo = P2C_Topology()
        self.p2c_set = SortedSet()

        self.temp_paths = SortedDict()
        # self.left_paths=SortedDict()
        # self.right_paths=SortedDict()
        # self.middle_paths=SortedDict()

    def read_path_yield(self):  # path:tuple num:int
        files = self.pathnumfile if isinstance(self.pathnumfile, list) else [self.pathnumfile]
        for file in files:
            with open(file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().split(" ")
                    if len(line) == 1:
                        yield tuple(line[0].split("|")), 1
                    else:
                        p, n = line
                        yield tuple(p.split("|")), int(n)

    def _fold_path(self, th):
        for path, num in self.read_path_yield():
            left = -1  
            right = len(path) - 1  
            for i in range(len(path) - 1):
                link = path[i : i + 2]
                if left == -1 and (link in self.clinks or link[::-1] in self.clinks):
                    left = i
                elif left != -1 and (
                    link not in self.clinks and link[::-1] not in self.clinks
                ):
                    right = i
                    break
            if left == -1:  # whole path is edge link
                self.p2c_topo.add_list(path)
                self.p2c_topo.add_list(path[::-1])
                self.temp_paths[path] = self.temp_paths.get(path, 0) + num
                
                # self.middle_paths[path]=self.middle_paths.get(path,0)+num
                
            else:
                # before core path 
                first_core_link = path[left : left + 2]
                first_prob = (
                    self.clinks[first_core_link]
                    if first_core_link in self.clinks
                    else self.clinks[first_core_link[::-1]][::-1]
                )
                p2c, p2p, c2p = first_prob
                
                # max_prob = max(first_prob)
                
                # if p2c>=p2p and p2c >=c2p: 
                if p2c >= 1 - th:
                # if p2c == max_prob:
                    if left > 0:
                        self.temp_paths[path[: left + 1]] = (
                            self.temp_paths.get(path[: left + 1], 0) + num
                        )
                        
                        # self.left_paths[path[: left + 1]]=self.left_paths.get(path[: left + 1],0)+num
                        
                    if left > 1:
                        self.p2c_topo.add_list(path[: left + 1])
                        self.p2c_topo.add_list(path[left::-1])
                else:  # only c2p c2p+p2p>=th, p2c<1-th
                    if left == 1:
                        self.p2c_set.add(path[1::-1])
                    elif left > 1:
                        self.p2c_set.add(path[left : left - 2 : -1])
                        self.p2c_topo.add_list(path[left::-1])
                last_core_link = path[right - 1 : right + 1]
                last_prob = (
                    self.clinks[last_core_link]
                    if last_core_link in self.clinks
                    else self.clinks[last_core_link[::-1]][::-1]
                )
                p2c, p2p, p2c = last_prob
                
                # max_prob = max(last_prob)
                
                # if c2p>=p2p and c2p>=p2c: 
                if c2p >= 1 - th:
                # if c2p == max_prob:
                    if right < len(path) - 1:
                        self.temp_paths[path[right:]] = (
                            self.temp_paths.get(path[right:], 0) + num
                        )
                        
                        # self.right_paths[path[right:]]=self.right_paths.get(path[right:],0)+num
                        
                    if right < len(path) - 2:
                        self.p2c_topo.add_list(path[right:])
                        self.p2c_topo.add_list(path[: right - 1 : -1])
                else:  #  p2c+p2p>=th, c2p<1-th
                    if right == len(path) - 2:
                        self.p2c_set.add(path[-2:])
                    elif right < len(path) - 2:
                        self.p2c_set.add(path[right : right + 2])
                        self.p2c_topo.add_list(path[right:])

    def _bfs_p2c_links(self):
        queue_links = self.p2c_set
        self.p2c_set = SortedSet()
        while len(queue_links) > 0:
            link = queue_links.pop()
            self.p2c_set.add(link)
            next_set = self.p2c_topo.get_next_nodes(link)
            for nl in next_set:
                if nl not in self.p2c_set:
                    queue_links.add(nl)

    def infer_p2c_edge_links(self, th):
        self._fold_path(th)
        self._bfs_p2c_links()
        reserved_paths = SortedDict()
        # mid_path, r_path, l_path=SortedDict(),SortedDict(),SortedDict()
        for path, num in self.temp_paths.items():
            left = 0
            right = len(path) - 1
            for i in range(len(path) - 1):
                link = path[i : i + 2]
                if link[::-1] in self.p2c_set:
                    left = i + 1  
                if right == len(path) - 1 and link in self.p2c_set:
                    right = i 
            if right > left:
                reserved_paths[path[left : right + 1]] = (
                    reserved_paths.get(path[left : right + 1], 0) + num
                )
                
        return self.p2c_set, reserved_paths
