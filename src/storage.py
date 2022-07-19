from collections import deque
from src.evm.exceptions import TimeoutException
from src.cfg.opcodes import storage_reads, storage_writes


class InconsistentSlot(Exception):
    pass


class UninitializedRead(Exception):
    def __init__(self, index, *args):
        super(UninitializedRead, self).__init__(*args)
        if isinstance(index, slice):
            self.start = index.start or 0
            self.end = index.stop
        else:
            self.start = index
            self.end = index + 1

    def __repr__(self):
        return '%s from: %d to %d' % (super(UninitializedRead, self).__repr__(), self.start, self.end)

    def __str__(self):
        return '%s from: %d to %d' % (super(UninitializedRead, self).__repr__(), self.start, self.end)


class StorageInfo(object):
    def __init__(self, reads, writes):
        self.reads = reads
        self.writes = writes


def get_storage_info(ins, code, memory_info=None):
    from .slicing import backward_slice, slice_to_program
    from .evm.evm import run
    from .evm.state import EVMState
    from .evm.exceptions import ExternalData
    from .util.intrange import Range
    
    targets = []
    read = False
    write = False
    if ins.name in storage_reads:
        read = True
        read_slot_info = storage_reads[ins.name]        
        if read_slot_info < 0:
            targets.append(-1 - read_slot_info)
        #if read_size_info < 0:
            #targets.append(-1 - read_size_info)
    if ins.name in storage_writes:
        write = True
        write_slot_info = storage_writes[ins.name]        
        if write_slot_info < 0:
            targets.append(-1 - write_slot_info)
        #if write_size_info < 0:
            #targets.append(-1 - write_size_info)

    if not read and not write:
        return None

    bs = backward_slice(ins, targets, memory_info)

    read_slot = set()
    write_slot = set()
    for b in bs:
        try:            
            state = run(slice_to_program(b), EVMState(code=code), check_initialized=True)            
        except UninitializedRead as e:            
            raise e
        except ExternalData as e:            
            pass
            #raise e        
        if read:    
            new_slot = state.stack[read_slot_info] if read_slot_info < 0 else read_slot_info                                                            
            """
            if not read_slot:                
                read_slot.add(new_slot)                                
            elif new_slot not in read_slot:
                print('inconsistent')
                raise InconsistentSlot()            
            """
            if new_slot not in read_slot:
                read_slot.add(new_slot) 
        if write:
            new_slot = state.stack[write_slot_info] if write_slot_info < 0 else write_slot_info            
            """
            if not write_slot:                
                write_slot.add(new_slot)
            elif write_slot != set(new_slot):                
                raise InconsistentSlot()    
            """
            if new_slot not in write_slot:
                write_slot.add(new_slot)             
    return StorageInfo(read_slot, write_slot)

def resolve_all_storage(cfg, code, memory_info=None):
    storage_infos = dict()
    resolve_later = deque(
        ins for bb in cfg.bbs for ins in bb.ins if ins.name in storage_reads or ins.name in storage_writes)
    todo = deque()    
    progress = True    
    while todo or (progress and resolve_later):
        if not todo:
            todo = resolve_later
            resolve_later = deque()
            progress = False
        ins = todo.popleft()        
        try:            
            mi = get_storage_info(ins, code, memory_info)                                                                    
            if mi:                      
                progress = True
                storage_infos[ins] = mi        
        except TimeoutException:
            raise TimeoutException("Timed out!")    
        except Exception as e:            
            resolve_later.append(ins)
    return storage_infos
