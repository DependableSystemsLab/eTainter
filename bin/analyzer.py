#!/usr/bin/env python3
import json
import logging
import resource
import sys
import argparse
import subprocess
import os
import shlex
import re
import time
from src.project import Project
from src.cfg import opcodes
from src.slicing import interesting_slices, slice_to_program
from src.explorer.forward import ForwardExplorer
import src.cfg.rattle as rattle
from collections import defaultdict
from src.flow.analysis_results import TainitAnalysisBugDetails
import src.flow.code_info as cinfo
import src.flow.analysis_results as analysis_results

logging.basicConfig(level=logging.INFO)


def hex_encode(d):
    return {k: v.hex() if isinstance(v, bytes) else v for k, v in d.items()}

def extract_bin_str(s):
    '''
    Extracts binary representation of smart contract from solc output.
    '''
    #binary_regex = r"\r?\n======= (.*?) =======\r?\nBinary of the runtime part: \r?\n(.*?)\r?\n" 
    binary_regex = r"\r?\n======= (.*?) =======\r?\nBinary of the runtime part:\r?\n(.*?)\r?\n" 

    contracts = re.findall(re.compile(binary_regex), s.decode("utf-8"))
    contracts = [contract for contract in contracts if contract[1]]
    
    if not contracts:
        logging.critical("Solidity compilation failed")
        print ("======= error =======")
        print ("Solidity compilation failed")
        print ("Check the used solc compiler version")
        exit()
    return contracts

def link_libraries(filename, libs):
    '''
    Compiles contract in filename and links libs by calling solc --link. Returns binary representation of linked contract.
    '''
    option = ""
    for idx, lib in enumerate(libs):
        lib_address = "0x" + hex(idx+1)[2:].zfill(40)
        option += " --libraries %s:%s" % (lib, lib_address)
    FNULL = open(os.devnull, 'w')
    cmd = "solc --bin-runtime %s" % filename
    p1 = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    cmd = "solc --link%s" %option
    p2 = subprocess.Popen(shlex.split(cmd), stdin=p1.stdout, stdout=subprocess.PIPE, stderr=FNULL)
    p1.stdout.close()
    out = p2.communicate()[0]
    return extract_bin_str(out)

def get_evm(contract):
    
    cmd = "solc --bin-runtime %s" % contract    
    FNULL = open(os.devnull, 'w')
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    out= solc_p.communicate()[0]      
    return extract_bin_str(out)

def analysis(p, initial_storage=dict(),
                     initial_balance=None,
                     max_calls=3, controlled_addrs=set(), flags=None):

    user_alerts = {'Unbounded-Loop':'Unbounded loop condition', \
                   'DoS-With-Failed-Call': 'DoS-With-Failed-Call'}     
    flags = flags or set(opcodes.CRITICAL)    
    tainting_type='storage'  
    ##convert_to_ssa
    sys.setrecursionlimit(10000)
    ssa = rattle.Recover(bytes.hex(p.code).encode(), edges=p.cfg.edges(), split_functions=False)    
        
    unbounded_count =0
    unbounded_restr_count = 0
    loop_calls_count = 0
    griefing_count = 0
    harcoded_count = 0
    asserts_count = 0
    temp_slots_count = 0
    slot_live_access_count = 0
    
    for defect_type in list(['Unbounded-Loop','DoS-With-Failed-Call']):
        print("Checking contract for \033[4m{0}\033[0m ".format(defect_type))
        print("------------------\n")            
        ins=[]
        taintedBy = []
        
        if defect_type =='Unbounded-Loop':
            loops=p.cfg.find_loops()                     
            for loop, heads in loops.items():                      
                for h in set(heads[1:]):                    
                    ins.append(p.cfg._bb_at[h].ins[-1])                    
                restricted=True                                                      
            
        elif defect_type =='DoS-With-Failed-Call':
            loops=p.cfg.find_loops(with_calls=True)            
            for loop, heads in loops.items():
                for h in set(heads):
                    ins.append(h)
            restricted=True           
        else:
            ins = []
        if not ins:        
            continue                
        vulnerable_loops = []
        loops_with_calls = []
        analysis_results.analyzed_sinks()            
        ins_types =(set(s.name for s in ins) & frozenset(['JUMPI','LT','GT','ISZERO']) if defect_type in set(['Unbounded-Loop']) else set(s.name for s in ins))        
        for ins_type in ins_types:                                            
            if defect_type in (['DoS-With-Failed-Call']):
                args=[1]            
            else:
                args = opcodes.CRITICAL_ARGS[ins_type]                                               
            sub_ins =set([s for s in ins if s.name == ins_type])                        
            if defect_type in (['DoS-With-Failed-Call']):            
                sinks={s.addr: [1] for s in sub_ins}
            else:                
                sinks={s.addr: opcodes.CRITICAL_ARGS[ins_type] for s in sub_ins}            

            if taintedBy ==[]:
                taintedBy=opcodes.potentially_user_controlled                      
            for i, i_path, i_r in p.extract_paths(ssa, sub_ins, sinks, taintedBy, defect_type=defect_type, args=args, restricted=restricted, memory_info=None):                
                logging.debug("%s: %s", ins_type, i)
                logging.debug("Path: %s", '->'.join('%x' % p for p in i_path))                                            
                if i_r._tainted:                    
                    logging.debug("Path: %s", '->'.join('%x' % p for p in i_path))                              
                    sload_slots= [v for i in i_r.sources for k, v in i.items() if k.startswith('SLOAD')]                                        
                    sload_sha3_bases= {i:i_r.sload_sha3_bases[i] for i in i_r.sload_sha3_bases if i in sload_slots}                                                
                    callvalue_source=[k for i in i_r.sources for k, v in i.items() if k.startswith('CALLVALUE')]                                                        
                    if len(sload_slots)==0:                                                      
                        if defect_type in (['Unbounded-Loop']) and (tainting_type !='storage' or len(callvalue_source)!=0):                                                               
                            vulnerable_loops.append({'block':i_path[-2],'function':cinfo.get_function_sig(p, i_path),'ins':i,'loop_restricted':cinfo.function_restricted_caller(p,i_path),'increased_in':None,'increase_restricted':None})
                            analysis_results.checked_sinks.append(i)
                        elif defect_type in (['DoS-With-Failed-Call']) and (tainting_type!='storage' or len(callvalue_source)!=0):
                            loops_with_calls.append({'block':i_path[-2],'function':cinfo.get_function_sig(p, i_path),'ins':i,'loop_restricted':cinfo.function_restricted_caller(p,i_path), 'increased_in':None,'increase_restricted':None})
                            analysis_results.checked_sinks.append(i)
                        elif defect_type in (['Gas-Griefing']):
                            griefing_count+=1
                        elif defect_type in (['Hardcoded-Gas']):
                            harcoded_count+=1
                        if defect_type not in (['Unbounded-Loop','DoS-With-Failed-Call']):                                               
                            print("{0} at statment {1} in function: {2}".format(user_alerts[i_r.defect_type], i, cinfo.get_function_sig(p, i_path)))                            
                            print("------------------\n")                     
                    elif defect_type in (['Gas-Griefing']) and len([v for i in i_r.sources for k, v in i.items() if not k.startswith('SLOAD')])!=0:
                        griefing_count+=1
                        print("{0} at statment {1} in function: {2}".format(user_alerts[i_r.defect_type], i, cinfo.get_function_sig(p, i_path)))
                        print("------------------\n")                        
                    else:                                                        
                        sstores = p.cfg.filter_ins('SSTORE', reachable=True)                                                                                          
                        sstore_sinks={s.addr:[1] for s in sstores}  
                        sstore_taintedBy=opcodes.potentially_direct_user_controlled                                                                                 
                        for s, s_path, s_r in p.extract_paths(ssa, sstores, sstore_sinks, sstore_taintedBy, defect_type='Storage-Tainting', args=[1], storage_slots=sload_slots,storage_sha3_bases=sload_sha3_bases, restricted=True):
                            logging.debug("%s: %s", 'SSTORE' , s)
                            logging.debug("Path: %s", '->'.join('%x' % p for p in s_path))                                                                                               
                            if s_r._tainted:           
                                analysis_results.checked_sinks.append(i)
                                logging.debug("Path: %s", '->'.join('%x' % p for p in s_path))                                                                    
                                if defect_type in (['Unbounded-Loop']):
                                    vulnerable_loops.append({'block':i_path[-2],'function':cinfo.get_function_sig(p, i_path),'ins':i,'loop_restricted':cinfo.function_restricted_caller(p,i_path), 'increased_in':cinfo.get_function_sig(p,s_path),'increase_restricted':cinfo.function_restricted_caller(p,s_path)})                                                                                    
                                elif defect_type in (['DoS-With-Failed-Call']):
                                    loops_with_calls.append({'block':i_path[-2],'function':cinfo.get_function_sig(p, i_path),'ins':i,'loop_restricted':cinfo.function_restricted_caller(p,i_path), 'increased_in':cinfo.get_function_sig(p,s_path),'increase_restricted':cinfo.function_restricted_caller(p,s_path)})
                                elif defect_type in (['Gas-Griefing']):
                                    griefing_count+=1
                                elif defect_type in (['Hardcoded-Gas']):
                                    harcoded_count+=1                                    
                                if defect_type not in (['Unbounded-Loop','DoS-With-Failed-Call']):                                               
                                    print("{0} at statment {1} in function: {2}".format(user_alerts[i_r.defect_type], i, cinfo.get_function_sig(p, i_path)))
                                    print("------------------\n")   
                                break                  
        if defect_type in (['Unbounded-Loop']):             
            for l, hd in loops.items():             
                r=0     
                v_ins= [b for b in vulnerable_loops if b['block'] in set(hd[1:])]                                
                no_storage_tnt= [b for b in vulnerable_loops if b['block'] in set(hd[1:]) and b['increased_in'] is None]
                if len(v_ins)!=0:                                                                
                    if (hd[0]<3 and len(no_storage_tnt)!=0):
                        continue
                    print("{0} in function: {1}".format(user_alerts[i_r.defect_type], v_ins[0]['function']))                                                                                           
                    for v in v_ins:
                        if v['increased_in'] is not None:
                            if v['increase_restricted']:
                                r+=1
                                print("Following loop bound is tainted in function {0} (restricted calls)".format(v['increased_in']))                                                                            
                            else:
                                print("Following loop bound is tainted in function {0}".format(v['increased_in']))                                                                            
                        print(v['ins'])                                                             
                    print('\n')     
                    if r==0:          
                        unbounded_count+=1
                    else:
                        unbounded_restr_count+=1
        if defect_type in (['DoS-With-Failed-Call']):                                                                                                
            for l, hd in loops.items():           
                r1=0 
                v_ins= [b for b in loops_with_calls if b['block'] in set([l])]
                if len(v_ins)!=0:                             
                    loop_calls_count+=1                                                   
                    print("{0} in function: {1}".format(user_alerts[i_r.defect_type], v_ins[0]['function']))                                                                       
                    for v in v_ins:
                        if v['increased_in'] is not None:
                            print("Following call target is tainted in function {0}".format(v['increased_in']))
                        print(v['ins'])                                       
                    print('\n')               
    return TainitAnalysisBugDetails(unbounded_count, unbounded_restr_count, loop_calls_count, griefing_count, harcoded_count, asserts_count, slot_live_access_count, temp_slots_count)

def main():
    parser = argparse.ArgumentParser()
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-f", "--file", type=str,
                       help="Code source file. Solidity by default. Use -b to process evm instead. Use stdin to read from stdin.")

    parser.add_argument(
        "-b", "--bytecode", help="read bytecode in source instead of solidity file.", action="store_true")    

    parser.add_argument(
        "-m", "--memory", help="Max memory limit")

    parser.add_argument(
        "--initial_storage_file", help="initial storage file")

    parser.add_argument(
        "-sf", "--savefile")

    parser.add_argument(
        "-tt", "--tainting-type", help="tainting type could be 'all' or 'storage'")
    args = parser.parse_args()
    
    if args.file is None:
        print('Usage: %s  <-f file>  [--memory] [-b] ' % \
              sys.argv[0], file=sys.stderr)
        exit(-1)
    
    savefilebase = args.savefile or args.file

    # limit default memory to 6GB
    if args.memory:
        mem_limit = int(args.memory) * 1024 * 1024 * 1024
    else:
        mem_limit = 6 * 1024 * 1024 * 1024
    try:
        rsrc = resource.RLIMIT_VMEM
    except:
        rsrc = resource.RLIMIT_AS
    resource.setrlimit(rsrc, (mem_limit, mem_limit))  

    initial_storage = dict()
    if args.initial_storage_file:
        with open(args.initial_storage_file, 'rb') as f:
            initial_storage = {int(k, 16): int(v, 16) for k, v in json.load(f).items()}
    
    if not args.tainting_type:
        tainting_type ='all'    
    elif args.tainting_type not in set(['storage','all']):
        print('Usage: wrong value for tainting_type. Valid values [''all'',''storage''] ')
        exit(-1)
    else:
        tainting_type ='storage'
    
    if not args.bytecode:
        contracts = get_evm(args.file)
        # Analyze each contract
        for cname, bin_str in contracts:
            print("Contract {0}:".format(cname))                    
            print("------------------\n")            
            code = bytes.fromhex(bin_str)            
            p = Project(code)
            with open('%s.project.json' % savefilebase, 'w') as f:
                json.dump(p.to_json(), f)                                  
            analysis(p, initial_storage=initial_storage)            
    else:
        with open(args.file)  as infile:
            inbuffer = infile.read().rstrip()            
        code = bytes.fromhex(inbuffer)
        p = Project(code)
        with open('%s.project.json' % savefilebase, 'w') as f:
            json.dump(p.to_json(), f)                    
        analysis(p, initial_storage=initial_storage)        
                
if __name__ == '__main__':    
    main()
