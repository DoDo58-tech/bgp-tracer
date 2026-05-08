from sortedcontainers import SortedDict, SortedSet
import os
from pyscipopt import Model as SCIPModel, quicksum as scip_quicksum


class _Solver:
    def __init__(
        self,
        name: str,
        solver_type: str = "scip",
        log_path: str = None,
        time_limit: int = 1800,
        memory_limit: int = 20000,
        enable_heuristics: bool = False,
    ):
        self.solver_type = solver_type.lower()
        self._log_file = None

        if self.solver_type == "gurobi":
            import gurobipy as gp
            from gurobipy import GRB

            self.m = gp.Model(name)
            if enable_heuristics:
                self.m.setParam("Heuristics", 1)
            if log_path:
                self.m.setParam(GRB.Param.LogFile, log_path)
            self.m.setParam(GRB.Param.LogToConsole, 0)
            self.m.setParam(GRB.Param.TimeLimit, time_limit)
            self.m.setParam(GRB.Param.MemLimit, memory_limit)
            self.BINARY = GRB.BINARY
            self.MINIMIZE = GRB.MINIMIZE
            self.MAXIMIZE = GRB.MAXIMIZE
            self.quicksum = gp.quicksum
        else:  # default to scip
            self.m = SCIPModel(name)
            self.m.setRealParam("limits/time", float(time_limit))
            self.m.setParam("limits/memory", memory_limit)
            self.m.setIntParam("display/verblevel", 0)
            if log_path:
                self.m.setLogfile(log_path)
            self.BINARY = "BINARY"
            self.MINIMIZE = "minimize"
            self.MAXIMIZE = "maximize"
            self.quicksum = scip_quicksum

    def add_bin_vars(self, n: int):
        if self.solver_type == "gurobi":
            return self.m.addVars(n, vtype=self.BINARY)
        else:  # scip
            return [self.m.addVar(vtype=self.BINARY, name=f"v_{i}") for i in range(n)]

    def add_constr(self, expr):
        if self.solver_type == "gurobi":
            return self.m.addConstr(expr)
        else:  # scip
            return self.m.addCons(expr)

    def set_obj_min(self, expr):
        if self.solver_type == "gurobi":
            self.m.setObjective(expr, self.MINIMIZE)
        else:  # scip
            self.m.setObjective(expr, self.MINIMIZE)

    def set_obj_max(self, expr):
        if self.solver_type == "gurobi":
            self.m.setObjective(expr, self.MAXIMIZE)
        else:  # scip
            self.m.setObjective(expr, self.MAXIMIZE)

    def optimize(self):
        self.m.optimize()

    def val(self, var):
        if self.solver_type == "gurobi":
            return var.X
        else:  # scip
            return self.m.getVal(var)

    def close(self):
        if self.solver_type == "gurobi":
            self.m.dispose()
        else:  # scip
            pass


class ASRelSolver(object):
    def __init__(self, paths, solver_type: str = "scip") -> None:
        self.paths = paths
        self.solver_type = solver_type.lower()
        self.linknum = 0
        self.idx2link = None
        self.idxpaths = None
        self.revlinks = None

    def _link2idx(self):
        links = SortedDict()
        idxsubpaths = []
        idx = 0
        for path in self.paths:
            idxpath = [None for _ in range(len(path) - 1)]
            for i in range(len(path) - 1):
                link = path[i : i + 2]
                if link not in links:
                    links[link] = idx
                    idx += 1
                idxpath[i] = links[link]
            idxsubpaths.append(idxpath)

        self.idxpaths = idxsubpaths
        self.linknum = idx
        self.idx2link = SortedDict({v: k for k, v in links.items()})

        self.revlinks = []
        for link, idx in links.items():
            if (link[1], link[0]) in links and int(link[0]) < int(link[1]):
                self.revlinks.append([idx, links[(link[1], link[0])]])

    def solute_asrel_for_clinks(self, log_dir):
        self._link2idx()
        print("solute asrel for clinks with unsat link")

        log_path = os.path.join(log_dir, "unsat_asrel_infer.log")
        solver = _Solver(
            name="infer_asrel",
            solver_type=self.solver_type,
            log_path=log_path,
            time_limit=1800,
            enable_heuristics=True,
        )

        linknum = self.linknum
        x = solver.add_bin_vars(linknum)
        y = solver.add_bin_vars(linknum)
        z = solver.add_bin_vars(linknum)

        for i in range(linknum):
            solver.add_constr(y[i] >= x[i] - z[i])
            solver.add_constr(x[i] >= z[i])
            solver.add_constr(y[i] + z[i] <= 1)

        idx_pair = set()
        for path in self.idxpaths:
            solver.add_constr(solver.quicksum(x[i] - z[i] for i in path) <= 1)
            if len(path) >= 2:
                for i in range(1, len(path)):
                    for j in range(i):
                        idx_pair.add((path[i], path[j]))
        for i, j in idx_pair:
            solver.add_constr(y[i] + z[i] >= y[j])
            solver.add_constr(y[i] + 2 * z[i] - x[i] >= y[j] - x[j])

        revidx = SortedSet()
        for idx1, idx2 in self.revlinks:
            solver.add_constr(x[idx1] == x[idx2])
            solver.add_constr(z[idx1] == z[idx2])
            solver.add_constr(y[idx1] + y[idx2] - x[idx1] + 2 * z[idx1] == 1)
            revidx.add(idx1)

        solver.set_obj_min(solver.quicksum(z[i] for i in range(linknum)))
        solver.optimize()

        asrel = SortedDict()
        for i in range(linknum):
            if i in revidx:
                continue
            zi = solver.val(z[i])
            xi = solver.val(x[i])
            yi = solver.val(y[i])
            if zi == 1.0:
                asrel[self.idx2link[i]] = 0
            elif xi == 1.0:
                asrel[self.idx2link[i]] = 0
            elif yi == 1.0:
                asrel[self.idx2link[i]] = -1
            else:
                asrel[self.idx2link[i]] = 1

        solver.close()
        return asrel

    def solute_asrel_for_elinks(self, log_dir):
        self._link2idx()
        print("solute asrel for elinks")

        log_path = os.path.join(log_dir, "elinks_asrel_infer.log")
        solver = _Solver(
            name="infer_asrel_for_elinks",
            solver_type=self.solver_type,
            log_path=log_path,
            time_limit=1800,
        )
        linknum = self.linknum
        x = solver.add_bin_vars(linknum)
        y = solver.add_bin_vars(linknum)

        for i in range(linknum):
            solver.add_constr(y[i] >= x[i])

        revidx = SortedSet()
        for idx1, idx2 in self.revlinks:
            solver.add_constr(x[idx1] == x[idx2])
            solver.add_constr(y[idx1] + y[idx2] - x[idx1] == 1)
            revidx.add(idx1)

        idx_pair = set()
        for p in self.idxpaths:
            solver.add_constr(solver.quicksum(x[i] for i in p) <= 1)
            for i in range(len(p) - 1):
                idx_pair.add((p[i], p[i + 1]))
        for i, j in idx_pair:
            solver.add_constr(y[i] <= y[j])
            solver.add_constr(y[i] - x[i] <= y[j] - x[j])

        solver.set_obj_min(solver.quicksum(-x[path[0]] for path in self.idxpaths))
        solver.optimize()
        asrel = SortedDict()
        for i in range(linknum):
            if i in revidx:
                continue
            xi = solver.val(x[i])
            yi = solver.val(y[i])
            if xi == 1.0:
                asrel[self.idx2link[i]] = 0
            elif yi == 1.0:
                asrel[self.idx2link[i]] = -1
            else:
                asrel[self.idx2link[i]] = 1

        solver.close()
        return asrel
