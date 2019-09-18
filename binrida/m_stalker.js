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
        //cw.putBreakpoint();
        //Storing the register
        cw.putPushax();
        cw.putCallAddressWithArguments(nat, [add]);
        cw.putPopax();
        
        //Move the previous instructions
        var readed = 0;
        while (readed != size){
            readed = x86r.readOne();
            console.log(readed+ '--->'+size);
        }
        //x86r.readOne();
        x86r.writeAll();
        cw.putJmpAddress(ret_pointer);
        cw.flush();
    });
    return mem_stub;
}

Process.setExceptionHandler(function(args){
console.log(args.type)
if(args.type == 'breakpoint'){
    send(args.address);
    //console.log(b_hooking[args.address])
    
    //b_hooking[args.address]();
    args.context['pc'] = b_hooking[args.address.sub(1)];
    return true;
}
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
send(Process.enumerateModules());
send(b_hooking);
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)
console.log('Indirizzo '+args.address)

return false
});


var hook_func;
//CUT HERE
hook_func = ptr("ADDRESS");
var b_hooking = {}
//try{
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
        send(ptr("ADDRESS"));
        /*
        for(index=0;index<jmp_hooking.length;index++){
            p = jmp_hooking[index];
            //if (index < 2){
            //    continue;
            //}
            console.log("Instrumenting basic block "+p);
            console.log("Computing the space..");
            i = Instruction.parse(p);
            //TODO: Check if capstone reach it eol
            size = i.size
            while (size<=16) {
                addr = i.next
                i = Instruction.parse(addr);
                size+=i.size
            }
            addr = i.next
            ret_pointer = new NativeFunction(addr, "void",[]);
            console.log('RETURN at '+ret_pointer);
            this.mem_stub = create_stub(p,size,ret_pointer,onEnter);

            var mm = this.mem_stub
            console.log("Patching!");
            console.log("STUB:"+this.mem_stub);
            //i = Instruction.parse(mm);
            //var inx = 0
            //var addx = mm;
            Memory.patchCode(p, 64, function(code) {
            cw = new X86Writer(code, {pc: code})
                    cw.putJmpAddress(mm);
                    cw.flush();
            });
            break;
        }*/
        for(index=0;index<br_hooking.length;index++){
            //break;
            //if (index < 10){continue;}
            p = br_hooking[index];
            console.log("Instrument basic block "+p+" with BREAKPOINT");
            i = Instruction.parse(p)
            mem_b = Memory.alloc(Process.pageSize);
            b_hooking[p] = mem_b;
            ret_pointer = p.add(1)
            console.log("Mem stub: "+mem_b+" should return to "+ret_pointer);
            Memory.patchCode(mem_b, 64, function(code) {
                var cw = new X86Writer(code, {pc:code});
                var dw = new X86Relocator(p, cw);
                dw.readOne();
                dw.writeOne();
                cw.putJmpAddress(ret_pointer);
                cw.flush();
            });
            Memory.patchCode(p, 64, function(code) {
                cw = new X86Writer(code, {pc: code})
                cw.putBreakpoint(); 
                cw.putNopPadding(i.size-1);
            });
            //if (index == 11){break;}
        }
    }
});
//}catch(err) {
    //send(err);
//}
