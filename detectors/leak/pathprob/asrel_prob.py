from sortedcontainers import SortedDict, SortedSet

from .asrel_solver import ASRelSolver
from .gibbs_sampling import GibbsSampling
from .p2c_edgelink import P2CEdgeLinkInfer
import os
import argparse
import time


class ASRelProb(object):
    def __init__(
        self, pathnumfile, clinkfile, elinkfile, log_dir, solver_type: str = "scip"
    ) -> None:

        self.corepaths = None
        self.elinks = SortedDict()
        self.clinks = None

        self.pathnumfile = pathnumfile
        self.clinkfile = clinkfile
        self.elinkfile = elinkfile
        self.log_dir = log_dir
        self.solver_type = solver_type

    def read_path_yield(self):  # path:tuple num:int
        if isinstance(self.pathnumfile, list):
            for file in self.pathnumfile:
                with open(file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip().split(" ")
                        if len(line) == 1:
                            yield tuple(line[0].split("|")), 1
                        else:
                            p, n = line
                            yield tuple(p.split("|")), int(n)
        else:
            with open(self.pathnumfile, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().split(" ")
                    if len(line) == 1:
                        yield tuple(line[0].split("|")), 1
                    else:
                        p, n = line
                        yield tuple(p.split("|")), int(n)

    def get_core_path(self, corepathfile):
        print("Processing core paths...")
        self.corepaths = SortedDict()
        if os.path.exists(corepathfile):
            with open(corepathfile, "r", encoding="utf-8") as f:
                for line in f.readlines():
                    path, num = line.strip().split(" ")
                    self.corepaths[tuple(path.split("|"))] = int(num)
            return

        links = SortedDict()

        def add_neighbour(last, link):
            if last in links:
                last_right = links[last][1]
            else:
                last = last[::-1]
                last_right = links[last][0]
            if link in links:
                link_left = links[link][0]
            else:
                link = link[::-1]
                link_left = links[link][1]
            last_right.add(link)
            link_left.add(last)

        def remove_neighbour(link, idx, neighbours):
            asn = link[idx]
            for neighbour in neighbours:
                if neighbour[0] == asn:
                    links[neighbour][0].remove(link)
                else:
                    links[neighbour][1].remove(link)

        for path, _ in self.read_path_yield():
            if len(path) <= 2:
                continue
            last = path[0:2]
            if last not in links and last[::-1] not in links:
                links[last] = [SortedSet(), SortedSet()]
            for i in range(1, len(path) - 1):
                link = path[i : i + 2]
                if link not in links and link[::-1] not in links:
                    links[link] = [SortedSet(), SortedSet()]
                add_neighbour(last, link)
                last = link
        flag = True
        while flag:
            flag = False
            remove_links = []
            for link, [leftset, rightset] in links.items():
                if len(leftset) == 0:
                    remove_links.append(link)
                    remove_neighbour(link, 1, rightset)
                    flag = True
                elif len(rightset) == 0:
                    remove_links.append(link)
                    remove_neighbour(link, 0, leftset)
                    flag = True
            for link in remove_links:
                del links[link]

        self.clinks = SortedSet()
        for path, num in self.read_path_yield():
            left = -1  # first core link idx
            right = len(path) - 1  # first non-core link idx
            for i in range(len(path) - 1):
                link = path[i : i + 2]
                if left == -1 and (link in links or link[::-1] in links):
                    self.clinks.add(link)
                    left = i
                elif left != -1 and (link not in links and link[::-1] not in links):
                    right = i
                    break
            if left == -1:
                continue
            corepath = path[left : right + 1]
            if corepath not in self.corepaths:
                self.corepaths[corepath] = 0
            self.corepaths[corepath] += num

        print("Writing core paths...")
        out = ""
        for corepath, num in self.corepaths.items():
            out += "{} {}\n".format("|".join(list(corepath)), num)
        with open(corepathfile, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)

    def infer_core_links(self):
        if self.corepaths is None:
            print("No core paths found")
            return
        if os.path.exists(self.clinkfile):
            self.clinks = SortedDict()
            with open(self.clinkfile, "r", encoding="utf-8") as f:
                for line in f.readlines():
                    as1, as2, p1, p2, p3 = line.strip().split("|")
                    self.clinks[(as1, as2)] = [float(p1), float(p2), float(p3)]
            return

        print("Inferring core links...")

        asrel_solver = ASRelSolver(self.corepaths, solver_type=self.solver_type)
        init_asrel = asrel_solver.solute_asrel_for_clinks(self.log_dir)
        with open(
            self.clinkfile.replace("core_link", "init_core_link.txt"),
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:
            for link, rel in init_asrel.items():
                f.write("{}|{}|{}\n".format(link[0], link[1], rel))

        gibbs_sampling = GibbsSampling(self.corepaths, init_asrel)
        self.clinks = gibbs_sampling.infer_asrel_prob(1000)
        print("Writing core links...")
        with open(self.clinkfile, "w", encoding="utf-8", newline="\n") as f:
            for link, prob in self.clinks.items():
                f.write(
                    "{}|{}|{}|{}|{}\n".format(
                        link[0], link[1], prob[0], prob[1], prob[2]
                    )
                )

    def infer_edge_link(self, p2c_set_file, reserved_paths_file, th):
        # if os.path.exists(self.elinkfile):
        #     with open(self.elinkfile, "r", encoding="utf-8") as f:
        #         for line in f.readlines():
        #             as1, as2, rel = line.strip().split("|")
        #             self.elinks[(as1, as2)] = int(rel)
        #     return
        if self.clinks is None:
            print("No core links found")
            return
        print("Inferring edge links...")
        # cal p2c edge link
        if os.path.exists(p2c_set_file) and os.path.exists(reserved_paths_file):
            p2c_set = SortedSet()
            with open(p2c_set_file, "r", encoding="utf-8") as f:
                for line in f.readlines():
                    p2c_set.add(tuple(line.strip().split("|")[:2]))
            reserved_paths = SortedDict()
            with open(reserved_paths_file, "r", encoding="utf-8") as f:
                for line in f.readlines():
                    path, num = line.strip().split(" ")
                    reserved_paths[tuple(path.split("|"))] = int(num)
        else:
            p2c_edgelink_infer = P2CEdgeLinkInfer(self.pathnumfile, self.clinks)
            p2c_set, reserved_paths = p2c_edgelink_infer.infer_p2c_edge_links(th)
            with open(p2c_set_file, "w", encoding="utf-8", newline="\n") as f:
                for link in p2c_set:
                    f.write("{}|{}|-1\n".format(link[0], link[1]))
            with open(reserved_paths_file, "w", encoding="utf-8", newline="\n") as f:
                for path, num in reserved_paths.items():
                    f.write("{} {}\n".format("|".join(list(path)), num))
        # cal reserved edge link
        self.elinks = SortedDict({link: [1.0, 0.0, 0.0] for link in p2c_set})

        # print("solution prob")
        asreltype_to_prob = {
            -1: [1.0, 0.0, 0.0],
            0: [0.0, 1.0, 0.0],
            1: [0.0, 0.0, 1.0],
        }

        # single links
        links_times = SortedDict()
        for path in reserved_paths:
            for i in range(len(path) - 1):
                link = (min(path[i], path[i + 1]), max(path[i], path[i + 1]))
                links_times[link] = links_times.get(link, 0) + 1
        single_links = SortedSet(
            [link for link, num in links_times.items() if num == 1]
        )
        self.elinks.update({link: [1 / 3, 1 / 3, 1 / 3] for link in single_links})
        no_single_paths = [
            path
            for path in reserved_paths
            if path not in single_links and path[::-1] not in single_links
        ]

        asrel_solver = ASRelSolver(no_single_paths, solver_type=self.solver_type)
        edge_link_asrel = asrel_solver.solute_asrel_for_elinks(self.log_dir)

        self.elinks.update(
            SortedDict(
                {link: asreltype_to_prob[rel] for link, rel in edge_link_asrel.items()}
            )
        )

        print("Writing edge probabilities...")
        out = ""
        for link, prob in self.elinks.items():
            if link[::-1] in self.elinks and link[0] > link[1]:
                continue
            out += f"{link[0]}|{link[1]}|{prob[0]}|{prob[1]}|{prob[2]}\n"
        with open(self.elinkfile, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)


if __name__ == "__main__":
    start_time = time.time()

    parser = argparse.ArgumentParser(description="ASRelProb Inference")
    parser.add_argument(
        "--path_dir", type=str, required=True, help="Directory to as paths"
    )
    parser.add_argument(
        "--print_dir",
        type=str,
        required=True,
        help="Directory to save the output files",
    )
    parser.add_argument("--label", type=str, required=False, help="label")
    parser.add_argument(
        "--solver",
        type=str,
        default="scip",
        choices=["scip", "gurobi"],
        help="Solver to use: 'scip' or 'gurobi' (default: scip)",
    )

    args = parser.parse_args()

    pathnum = [
        os.path.join(args.path_dir, file)
        for file in os.listdir(args.path_dir)
        if os.path.isfile(os.path.join(args.path_dir, file))
    ]
    label = args.label if args.label else "pathprob"
    print_dir = args.print_dir
    probability_file = os.path.join(print_dir, f"{label}.txt")
    print_dir = os.path.join(print_dir, label)

    log_dir = os.path.join(print_dir, "log")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    if not os.path.exists(print_dir):
        os.makedirs(print_dir)
    sub_print_dir = os.path.join(print_dir, "temp_dir")
    if not os.path.exists(sub_print_dir):
        os.makedirs(sub_print_dir)

    th = 0.8

    core_link_file = os.path.join(print_dir, f"{label}_core_link.txt")
    edge_link_file = os.path.join(print_dir, f"{label}_edge_link.txt")

    asrel_prob = ASRelProb(
        pathnum, core_link_file, edge_link_file, log_dir, solver_type=args.solver
    )
    asrel_prob.get_core_path(os.path.join(print_dir, "corepath.txt"))
    asrel_prob.infer_core_links()
    asrel_prob.infer_edge_link(
        os.path.join(sub_print_dir, f"{label}_p2c_set.txt"),
        os.path.join(sub_print_dir, f"{label}_reserved_paths.txt"),
        th,
    )
    # INSERT_YOUR_CODE
    # Combine core_link_file and edge_link_file into probability_file
    with open(probability_file, "w", encoding="utf-8") as outfile:
        # Write all lines from core_link_file
        with open(core_link_file, "r", encoding="utf-8") as coref:
            for line in coref:
                outfile.write(line)
        # Write all lines from edge_link_file
        with open(edge_link_file, "r", encoding="utf-8") as edgef:
            for line in edgef:
                outfile.write(line)

    end_time = time.time()
    print(
        f"Result is saved to {probability_file} Time taken: {end_time - start_time} seconds"
    )
