//Instrument address
//CallBack onEnter instruction

Process.setExceptionHandler(function(args){
if(args.type == 'breakpoint'){
    send(args.address);
    args.context['pc'] = b_hooking[args.address.sub(1)];
    return true;
}
console.log(args.type)
return false
});
var hook_func;
var b_hooking = {}
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
        var mem_b;
        send(ptr("ADDRESS"));
        for(index=0;index<br_hooking.length;index++){
            p = br_hooking[index];
            i = Instruction.parse(p)
            mem_b = Memory.alloc(Process.pageSize);
            b_hooking[p] = mem_b;
            ret_pointer = p.add(1)
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
        }
    }
});
