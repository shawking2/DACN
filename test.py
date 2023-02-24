import angr

def check_symbolic_bits(state,val):
    bits = 0
    for idx in range(state.arch.bits):
        if val[idx].symbolic:
            bits += 1
    return bits

def print_pc_overflow_msg(state,byte_s):
    print("\n[========find a pc overflow========]")
    print("over for ",hex(byte_s),"bytes")
    print("[PC]stdout:\n",state.posix.dumps(1))
    print("[PC]trigger overflow input:")
    print(state.posix.dumps(0))

def print_bp_overflow_msg(state,byte_s):
    print("\n[========find a bp overflow========]")
    print("over for ",hex(byte_s),"bytes")
    print("[PC]stdout:\n",state.posix.dumps(1))
    print("[PC]trigger overflow input:")
    print(state.posix.dumps(0))


def check_end(state):
    try:
        if state.addr==0:
            return
        
        insns=state.project.factory.block(state.addr).capstone.insns
        if len(insns)>=2:
            flag=0
            #check for : leave; ret;
            for ins in insns:
                if ins.insn.mnemonic=="leave":
                    flag+=1
                if ins.insn.mnemonic=="ret":
                    flag+=1

            # ins0=insns[0].insn
            # ins1=insns[1].insn
            # if ins0.mnemonic=="leave" and ins1.mnemonic=="ret":
            if flag==2:
                rsp=state.regs.rsp
                rbp=state.regs.rbp
                byte_s=state.arch.bytes
                stack_rbp=state.memory.load(rbp,8,endness=angr.archinfo.Endness.LE)
                stack_ret=state.memory.load(rbp+byte_s,8,endness=angr.archinfo.Endness.LE)
                pre_target=state.callstack.ret_addr
                # print(state.globals['rbp_list'])
                pre_rbp=state.globals['rbp_list'][hex(pre_target)]

                if stack_ret.symbolic:
                    num=check_symbolic_bits(state,stack_ret)
                    print_pc_overflow_msg(state,num//byte_s)
                    state.memory.store(rbp,pre_rbp,endness=angr.archinfo.Endness.LE)
                    state.memory.store(rbp+byte_s, state.solver.BVV(pre_target, 64),endness=angr.archinfo.Endness.LE)
                    return

                if stack_rbp.symbolic:
                    num=check_symbolic_bits(state,stack_rbp)
                    print_bp_overflow_msg(state,num//byte_s)
                    state.memory.store(rbp,pre_rbp,endness=angr.archinfo.Endness.LE)
    except:
        return

def check_head(state):
   
    # if ((state.addr / 0x400000) >=1) :
    try:
        insns=state.project.factory.block(state.addr).capstone.insns
        
        # print(len(insns))
        if len(insns) >=3:
            #check for : endbr64, push rbp; mov rsp,rbp;
            ins0 = insns[0].insn
            ins1=insns[1].insn
            ins2=insns[2].insn
            if len(ins1.operands)==1 and len(ins2.operands)==2 and len(ins0.operands) == 0:
                # print(insns)
                ins0_name = ins0.mnemonic #endbr64
                ins1_name=ins1.mnemonic#push 
                ins1_op0=ins1.reg_name(ins1.operands[0].reg)#rbp
                ins2_name=ins2.mnemonic#mov 
                ins2_op0=ins2.reg_name(ins2.operands[0].reg)#rsp
                ins2_op1=ins2.reg_name(ins2.operands[1].reg)#rbp

                if ins0_name == "endbr64" and ins1_name=="push" and ins1_op0=="rbp" and ins2_name=="mov" and ins2_op0=="rbp" and ins2_op1=="rsp":
                    # print("find a function head,save the rsp,rbp")
                    pre_target=state.callstack.ret_addr
                    state.globals['rbp_list'][hex(pre_target)]=state.regs.rbp
        elif len(insns) >=2:
            #check for : push rbp; mov rsp,rbp; 
            ins0=insns[0].insn
            ins1=insns[1].insn
            if len(ins0.operands)==1 and len(ins1.operands)==2:
                # print(insns)
                ins0_name=ins0.mnemonic#push 
                ins0_op0=ins0.reg_name(ins0.operands[0].reg)#rbp
                ins1_name=ins1.mnemonic#mov 
                ins1_op0=ins1.reg_name(ins1.operands[0].reg)#rsp
                ins1_op1=ins1.reg_name(ins1.operands[1].reg)#rbp

                if ins0_name=="push" and ins0_op0=="rbp" and ins1_name=="mov" and ins1_op0=="rbp" and ins1_op1=="rsp":
                    # print("find a function head,save the rsp,rbp")
                    pre_target=state.callstack.ret_addr
                    state.globals['rbp_list'][hex(pre_target)]=state.regs.rbp
    except:
        return

if __name__ == '__main__':  
    filename="./challenges/bof2"
    p = angr.Project(filename,auto_load_libs=False)
    state = p.factory.entry_state()
    state.globals['rbp_list']={}
    simgr = p.factory.simulation_manager(state,save_unconstrained=True)

    while simgr.active:
        for act in simgr.active:
            # print("||||||||||||||active head||||||||||||")
            check_head(act)
            check_end(act)
            # print("||||||||||||||active end|||||||||||||")
        simgr.step()
        # print("now->",simgr,"\n")