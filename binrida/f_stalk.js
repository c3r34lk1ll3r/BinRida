var p = ptr('ADDRESS');
var func = new NativeCallback(function(){console.log("WOOOOOOOOOOW");},'int',[]); 
var nat = new NativeFunction(func,"int",[]);
//console.log(func)
//var maxPatchSize = 64;
var i = Instruction.parse(p)
var p1 = i.next
var rest = p1.readByteArray(Instruction.parse(p1).size)
maxPatchSize = i.size
Memory.patchCode(p1, maxPatchSize, function(code) {
    var loc = new X86Writer(code, {pc: code})
    console.log(code)
    //console.log(func)
    var instr = Instruction.parse(code);
    console.log(instr.toString())
    var restore = code.readByteArray(instr.size);
    console.log(restore)
    var num = 0;
    loc.putBreakpoint()
    while (num < instr.size-1){
        loc.putNop();
        num++;
    }
    //loc.putBytes(restore)
    //loc.putCallAddress(func);
    loc.flush();
    var xx = Instruction.parse(code);
    console.log(xx.toString())
    var x1 = xx.next;
    console.log(Instruction.parse(x1).toString())
    var x2 = Instruction.parse(x1).next;
    console.log(xx.next.readByteArray(10));
    console.log(Instruction.parse(x2).toString())
});Process.setExceptionHandler(function(args){send('TTT');console.log('CIAO FROM NATIVE');
console.log(args.type)
console.log('CONTEXT')
console.log(args.context['pc'])
var pxx = args.address
args.context['eax'] = 0
var i10 = Instruction.parse(pxx)
console.log(i10)
console.log(pxx.readByteArray(i10.size))
console.log(rest);
nat()
return true
});

