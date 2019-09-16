//Instrument address
//CallBack onEnter instruction

var onEnter = new NativeCallback(function(arg){
    var n = ptr(arg)
    send(n);
},'void',['uint64']);

function create_stub(add,size,ret_pointer,nat){
    console.log("Creating MEM stub for "+add);
    //Maybe we can allocate less memory
    var mem_stub = Memory.alloc(Process.pageSize);
    Memory.patchCode(mem_stub, Process.pageSize, function(code) {
        //TODO: This should be understand at runtime
        var cw   = new X86Writer(code, {pc:code});
        var x86r = new X86Relocator(add,cw);
        //For now i Want a guard
        cw.putBreakpoint();
        //Storing the register
        cw.putPushax();
        cw.putCallAddressWithArguments(nat, [add]);
        cw.putPopax();
        
        //Move the previous instructions
        var readed = 0;
        while (readed <= size){
            readed += x86r.readOne();
        }
        x86r.readOne();
        x86r.writeAll();
        cw.putJmpAddress(ret_pointer);
        cw.flush();
    });
    return mem_stub;
}
var hook_func;
//CUT HERE
hook_func = ptr("ADDRESS");
var b_hooking = {}
Interceptor.attach(hook_func, {
    onEnter: function(args) {
        //Change HERE!
        //var vector= []
        //Compute block size for instr
        //TODO: Check if it is a jmp!
        var index;
        var p;
        var i;
        var size;
        var addr;
        var ret_pointer;
        var cw;
        var mem_b;
        send(hook_func);
        for(index=0;index<vector.length;index++){
            p = vector[index];
            if (index < 5){
                continue;
            }
            console.log("Instrumenting basic block "+p);
            console.log("Computing the space..");
            i = Instruction.parse(p);
            //TODO: Check if capstone reach it eol
            size = i.size
            while (size<=16) {
                addr = i.next
                i = Instruction.parse(addr);
                if (i.groups[0] == 'branch_relative'){
                    console.log("STOP RIGHT THERE");
                    console.log(i);
                    size = 0
                    break; 
                }
                console.log("!!!!!!!!!!"+i.groups)
                console.log(i);
                size+=i.size
            }
            if (size != 0){
                addr = i.next
                ret_pointer = new NativeFunction(addr, "void",[]);
                this.mem_stub = create_stub(p,size,ret_pointer,onEnter);
                var mm = this.mem_stub
                console.log("Patching!");
                console.log("STUB:"+this.mem_stub);
            }
            else{
                console.log('Patching with illegal instruction');
                mem_b = Memory.alloc(Process.pageSize);
                b_hooking[p] = mem_b;
                //b_hooking[p] = new NativeFunction(mem_b,"void",[]);
                //b_hooking[p] = Instruction.parse(p);
                console.log(b_hooking[p]);
                ret_pointer = p.add(1);
                Memory.patchCode(mem_b,64,function(code) {
                    var cw = new X86Writer(code,{pc:code});
                    var dw = new X86Relocator(p,cw);
                    dw.readOne();
                    dw.writeOne();
                    cw.putJmpAddress(ret_pointer);
                    cw.flush();
                });
            }
            Memory.patchCode(p, 64, function(code) {
            cw = new X86Writer(code, {pc: code})
                if (size !=0){
                    cw.putJmpAddress(mm);
                    cw.flush();
                }
                else{
                    i = Instruction.parse(p)
                    cw.putU8(254);
                    cw.putNopPadding(i.size-1);
                }
            });
            if (index == 5){ break; } 
        }
    }});
Process.setExceptionHandler(function(args){
console.log(args.type)
if (args.type == 'breakpoint'){
    console.log("THIS IS PATCHING");
    console.log("THIS IS PATCHING");
    console.log("THIS IS PATCHING");
    console.log("THIS IS PATCHING");
    return true
}
else if(args.type == 'illegal-instruction'){
    console.log("Instrument with illegal instruction");
    send(args.address);
    //I should execute every fucking instruction!
    console.log(b_hooking[args.address])
    //Move instruction
    //var data = args.context['rbp'].sub(0x8).readU64();
    
    //b_hooking[args.address]();
    args.context['pc'] = b_hooking[args.address];
    return true;
}
console.log('Indirizzo '+args.address)
return false
});
