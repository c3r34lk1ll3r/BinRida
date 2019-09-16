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
        send(hook_func);
        for(index=0;index<vector.length;index++){
            p = vector[index];
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
                }
                console.log("!!!!!!!!!!"+i.groups)
                size+=i.size
            }
            addr = i.next
            ret_pointer = new NativeFunction(addr, "void",[]);
            this.mem_stub = create_stub(p,size,ret_pointer,onEnter);
            var mm = this.mem_stub
            console.log("Patching!");
            console.log("STUB:"+this.mem_stub);
            Memory.patchCode(p, 64, function(code) {
            cw = new X86Writer(code, {pc: code})
                cw.putJmpAddress(mm);
                cw.flush();
            });
            if (index == 5){ break; } 
        }
    }});
Process.setExceptionHandler(function(args){
console.log(args.type)
if (args.type == 'breakpoint'){
    console.log("THIS IS PATHCHING!");
    console.log("THIS IS PATHCHING!");
    console.log("THIS IS PATHCHING!");
    return true
}
console.log('Indirizzo '+args.address)
console.log('Base address '+mem_stub)
return false
});
