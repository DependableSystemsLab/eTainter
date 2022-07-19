import logging
from collections import defaultdict
import time
from src.cfg.cfg import CFG
from src.cfg.disassembly import generate_BBs
from src.cfg.opcodes import external_data
from src.evm.evm import run, run_symbolic
from src.evm.exceptions import IntractablePath, ExternalData, TimeoutException
from src.explorer.forward import ForwardExplorer
from src.slicing import interesting_slices, slice_to_program
from src.util.z3_extra_util import concrete
from src.flow.flow import run_static
import src.flow.analysis_results as analysis_results

def load(path):
    with open(path) as infile:
        return Project(bytes.fromhex(infile.read().strip()))


def load_json(path):
    import json
    with open(path) as infile:
        return Project.from_json(json.load(infile))


class Project(object):
    def __init__(self, code, cfg=None):
        self.code = code
        self._prg = None
        self._cfg = cfg
        self._writes = None

    @property
    def writes(self):
        if not self._writes:
            self._analyze_writes()
        return self._writes

    @property
    def symbolic_writes(self):
        return self.writes[None]

    @property
    def cfg(self):
        if not self._cfg:
            self._cfg = CFG(generate_BBs(self.code))
        return self._cfg

    @property
    def prg(self):
        if not self._prg:
            self._prg = {ins.addr: ins for bb in self.cfg.bbs for ins in bb.ins}
        return self._prg

    def to_json(self):
        return {'code': self.code.hex(), 'cfg': self.cfg.to_json()}

    @staticmethod
    def from_json(json_dict):
        code = bytes.fromhex(json_dict['code'])
        cfg = CFG.from_json(json_dict['cfg'], code)
        return Project(code, cfg)

    def run(self, program):
        return run(program, code=self.code)

    def run_symbolic(self, path, inclusive=False):        
        #return run_symbolic(self.prg, path, self.code, inclusive=inclusive)
        return run_symbolic(self.prg, path, self.code, inclusive=inclusive)

    def _analyze_writes(self):        
        sstore_ins = self.filter_ins('SSTORE')
        self._writes = defaultdict(set)
        for store in sstore_ins:
            for bs in interesting_slices(store):
                bs.append(store)
                prg = slice_to_program(bs)
                path = sorted(prg.keys())
                try:
                    r = run_symbolic(prg, path, self.code, inclusive=True)
                except IntractablePath:
                    logging.exception('Intractable Path while analyzing writes')
                    continue
                addr = r.state.stack[-1]
                if concrete(addr):
                    self._writes[addr].add(store)
                else:
                    self._writes[None].add(store)
        self._writes = dict(self._writes)

    def get_writes_to (self, addr):
        concrete_writes = set()
        if concrete(addr) and addr in self.writes:
            concrete_writes = self.writes[addr]
        return concrete_writes, self.symbolic_writes

    def extract_paths(self,ssa, instructions, sinks, taintedBy, defect_type, args=None, storage_slots=None, storage_sha3_bases=None, inclusive=False, find_sstore=False, restricted=True, memory_info=None):
        # only check instructions that have a chance to reach root                        
        instructions = [ins for ins in instructions if 0 in ins.bb.ancestors | {ins.bb.start}] 
        if not instructions:
            return
        imap = {ins.addr: ins for ins in instructions}

        exp = ForwardExplorer(self.cfg)        
        if args:            
            slices = [s+(ins,)  for ins in instructions for s in interesting_slices(ins, args, memory_info, reachable=True, taintedBy=taintedBy, restricted=restricted)]        
                
        checked_ins=[]         
        c=0      
        start_time=time.time()        
        for path in exp.find(slices, avoid=[]):                  
            #print(defect_type)
            logging.debug('Path %s', ' -> '.join('%x' % p for p in path))                                                                 
            c+=1    
            try:                
                ins = imap[path[-1]]                                  
                if defect_type in set(['Unbounded-Loop','DoS-With-Failed-Call']):                    
                    if ins in  analysis_results.checked_sinks   :                        
                        continue
                    else:    
                        result= run_static(self.prg, ssa, path, sinks, self.code, inclusive,defect_type=defect_type, storage_slots=storage_slots, storage_sha3_bases=storage_sha3_bases)                                                                
                        yield ins, path, result
                else:        
                    yield ins, path, run_static(self.prg, ssa, path, sinks, self.code, inclusive,defect_type=defect_type, storage_slots=storage_slots, storage_sha3_bases=storage_sha3_bases)                                                                
                #if c>1:
                #    exit()
            except IntractablePath as e:                  
                bad_path = [i for i in e.trace if i in self.cfg._bb_at] #+ [e.remainingpath[0]]  #check: no need for this                
                dd = self.cfg.data_dependence(self.cfg._ins_at[e.trace[-1]])
                if not any(i.name in ('MLOAD', 'SLOAD') for i in dd):
                    ddbbs = set(i.bb.start for i in dd)
                    bad_path_start = next((j for j, i in enumerate(bad_path) if i in ddbbs), 0)
                    bad_path = bad_path[bad_path_start:]
                logging.debug("Bad path: %s" % (', '.join('%x' % i for i in bad_path)))
                exp.add_to_blacklist(bad_path)
                continue
            except ExternalData:
                continue
            except TimeoutException:
                raise TimeoutException("Timed out!")
            except Exception as e:
                logging.exception('Failed path due to %s', e)     
                continue
            
