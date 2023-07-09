---
layout: post
title: My ECC Service | pbctf 2023
author: Arnav Vora
tags: crypto ECC Pohlig-Hellman discrete-logarithm
description: "Cracking an ECC service using discrete logarithms."
image: /assets/posts/my-ecc-service/prompt.png
---

![My ECC Service Prompt](/assets/posts/my-ecc-service/prompt.png)

```python
from Crypto.Util.number import inverse
from hashlib import sha256
import os
import signal

class NonceGenerator:
    def __init__(self):
        self.state = os.urandom(10)
        self.db = {}
    
    def gen(self):
        self.state = sha256(self.state + b'wow').digest()[:10]
        key = sha256(self.state).digest()[:8]
        self.db[key] = self.state

        return int.from_bytes(self.state, 'big'), key

    def get(self, key: str):
        if key not in self.db:
            print("Wrong key :(")
            exit(0)

        return int.from_bytes(self.db[key], 'big')


class ECPoint:
    def __init__(self, point, mod):
        self.x = point[0]
        self.y = point[1]
        self.mod = mod

    def inf(self):
        return ECPoint((0, 0), self.mod)

    def _is_inf(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, other):
        assert self.mod == other.mod
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        assert self.mod == other.mod
        P, Q = self, other
        if P._is_inf() and Q._is_inf():
            return self.inf()
        elif P._is_inf():
            return Q
        elif Q._is_inf():
            return P

        if P == Q:
            lam = (3 * P.x**2 - 3) * inverse(2 * P.y, self.mod) % self.mod
        elif P.x == Q.x:
            return self.inf()
        else:
            lam = (Q.y - P.y) * inverse(Q.x - P.x, self.mod) % self.mod

        x = (lam**2 - P.x - Q.x) % self.mod
        y = (lam * (P.x - x) - P.y) % self.mod

        return ECPoint((x, y), self.mod)

    def __rmul__(self, other: int):
        base, ret = self, self.inf()
        while other > 0:
            if other & 1:
                ret = ret + base
            other >>= 1
            base = base + base
        return ret


class MyECCService:
    BASE_POINT = (2, 3)
    MODS = [
        942340315817634793955564145941,
        743407728032531787171577862237,
        738544131228408810877899501401,
        1259364878519558726929217176601,
        1008010020840510185943345843979,
        1091751292145929362278703826843,
        793740294757729426365912710779,
        1150777367270126864511515229247,
        763179896322263629934390422709,
        636578605918784948191113787037,
        1026431693628541431558922383259,
        1017462942498845298161486906117,
        734931478529974629373494426499,
        934230128883556339260430101091,
        960517171253207745834255748181,
        746815232752302425332893938923,
    ]

    def __init__(self):
        self.nonce_gen = NonceGenerator()

    def get_x(self, nonce: int) -> bytes:
        ret = b""
        for mod in self.MODS:
            p = ECPoint(self.BASE_POINT, mod)
            x = (nonce * p).x
            ret += x.to_bytes(13, "big")
        return ret

    def gen(self) -> bytes:
        nonce, key = self.nonce_gen.gen()
        x = self.get_x(nonce)

        return b"\x02\x03" + key + x

    def verify(self, inp: bytes) -> bool:
        assert len(inp) == 218

        nonce = self.nonce_gen.get(inp[2:10])
        self.BASE_POINT = (inp[0], inp[1])
        x = self.get_x(nonce)
        return inp[10:] == x


def handler(_signum, _frame):
    print("Time out!")
    exit(0)


def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(300)

    service = MyECCService()

    for _ in range(100):
        service.gen()

    while True:
        inp = input("> ")
        if inp == "G":
            payload = service.gen()
            print(f"Payload: {payload.hex()}")
        elif inp == "V":
            payload = bytes.fromhex(input("Payload: "))
            result = service.verify(payload)
            print(f"Result: {result}")
        elif inp == "P":
            payload = bytes.fromhex(input("Payload: "))
            answer = service.gen()

            if payload == answer:
                with open("flag.txt", "r") as f:
                    print(f.read())
            else:
                print("Wrong :(")
            exit(0)


if __name__ == "__main__":
    main()
```


## Solution
Let's connect to `nc my-ecc-service.chal.perfect.blue 1337`. Looks like its an oracle.

First, let's quickly glance at the script. In the `main` method, we have 3 inputs we can send to the connection: G, V, and P. In the main method, we create a `MyECCService` object, and call its `gen` method 100 times (this part looks to be irrelevant, just to introduce randomness). Then,
- If we send G, the service calls `gen` again, and prints the payload that it outputs
- If we send V, we input a payload and the service calls `verify` on it
- If we send P, we input a payload, the service calls `gen`, and it checks if the payload matches the payload output from `gen`

Let's examine the `MyECCService` class:
- When an object is constructed, it contains a new `NonceGenerator` object called `nonce_gen`
- This class also has a list of numbers called MODS. It also has a Base Point: (2,3)
- The `get_x` method takes a nonce (int) input, and outputs a byte string.
  - For each mod in MODS, we create an elliptic curve point with the base point, and it looks like we set the finite field of the curve to be modulo mod
  - We then multiply this base point with nonce and assign that to x. Convert x to bytes, and append it to the end of the return string (looks like x is 13 bytes long)
- The `gen` method outputs a byte string
  - It creates a nonce and key with `nonce_gen`, and it uses this nonce to create an x-value. Then, return the byte string "\x02\x03" + key + x
    - The first 2 bytes ("\x02\x03") is the base point
    - If we take a look at the `gen` method of the `NonceGenerator` class, we can see that the key is 8 bytes long (line 12). x should be 13*16 bytes long, so overall, the length is 218 bytes. This checks out if we create a payload with G
- The `verify` method outputs a boolean
  - We check if the length is 218 bytes. We then generate a nonce with the `get` method from the `NonceGenerator` class. We set the base point to the first 2 bytes in the payload, and generate a new x-value with our nonce and new base point. We then check if the input payload's x-value (`inp[10:]`) is equal to the x-value we generated.

First thing I noticed is that nonce gets reused 16 times, and so does the base point (when we run G). The only difference between the x-values generated (16 of them) is the modulus. Let's say that a point P and a nonce n creates a point Q, then we know:

$$\mathrm{Q}_{\mathrm{i}}.\mathrm{x} \ \ \mathrm{ where } \ \ \mathrm{Q}_{\mathrm{i}} = \mathrm{nP_{\mathrm{i}}} \ \ (\mathrm{mod} \ \ \mathrm{MODS}_{\mathrm{i}})$$

Wait, is it possible to just take an elliptic curve discrete log to recover n? I started researching methods to do elliptic curve discrete logs, and we found the Pohlig-Hellman algorithm. The success of this algorithm depends on the prime factors of the "order" of the elliptic curve generated by a prime modulus n. Just to make sure, each of the moduli in the MODS list is prime. I wanted to calculate the order of these curves, so I created a sage script:
```py
MODS = [
        942340315817634793955564145941,
        743407728032531787171577862237,
        738544131228408810877899501401,
        1259364878519558726929217176601,
        1008010020840510185943345843979,
        1091751292145929362278703826843,
        793740294757729426365912710779,
        1150777367270126864511515229247,
        763179896322263629934390422709,
        636578605918784948191113787037,
        1026431693628541431558922383259,
        1017462942498845298161486906117,
        734931478529974629373494426499,
        934230128883556339260430101091,
        960517171253207745834255748181,
        746815232752302425332893938923,
    ]

orders = []
factors = []
print(len(MODS))
for i in srange(16):
	p = MODS[i]
	#E = EllipticCurve(GF(p),???) 
	print(E.order())
	orders.append(E.order())
	factors.append(factor(orders[i]))
print([list(i) for i in factors])
```
Wait, what curve are we using? If we take a look at the source code of the `ECPoint` class, we can examine their calculations. Specifically, for point doubling: 
```py
if P == Q:
	lam = (3 * P.x**2 - 3) * inverse(2 * P.y, self.mod) % self.mod
```
In the point doubling algorithm for elliptic curves, the $\lambda$ parameter is equal to $\frac{3x^2 - a}{2y}$ for an elliptic curve $y^2 = x^3 + ax + b$. So, a = 3. What is b though? We can determine b with our base point (2,3). We can determine b = 7 with this information. Now, we can calculate the order of the curves and their factorization.
```py
MODS = [
        942340315817634793955564145941,
        743407728032531787171577862237,
        738544131228408810877899501401,
        1259364878519558726929217176601,
        1008010020840510185943345843979,
        1091751292145929362278703826843,
        793740294757729426365912710779,
        1150777367270126864511515229247,
        763179896322263629934390422709,
        636578605918784948191113787037,
        1026431693628541431558922383259,
        1017462942498845298161486906117,
        734931478529974629373494426499,
        934230128883556339260430101091,
        960517171253207745834255748181,
        746815232752302425332893938923,
    ]

orders = []
factors = []
print(len(MODS))
for i in srange(16):
	p = MODS[i]
	E = EllipticCurve(GF(p),[-3,7]) 
	print(E.order())
	orders.append(E.order())
	factors.append(factor(orders[i]))
print([list(i) for i in factors])
```
```
[[(2, 2), (5, 1), (23, 1), (29, 1), (47018423, 1), (1502394148449647767, 1)], [(109, 1), (181, 1), (263, 1), (743, 1), (4155839453, 1), (46400074163, 1)], [(2, 2), (3, 1), (5, 3), (59, 1), (89, 2), (421, 1), (249037, 1), (10048637870993, 1)], [(2, 3), (3, 1), (5, 1), (17, 1), (617335724764490367614697727, 1)], [(3, 4), (3352929739, 1), (3711550532590751927, 1)], [(2, 5), (11587, 1), (2944440138047836853310007, 1)], [(7, 2), (829, 1), (1451, 1), (694674991, 1), (19385577398771, 1)], [(2, 4), (3, 1), (37, 1), (2311, 1), (4721, 1), (9467, 1), (28880183, 1), (217221139, 1)], [(2, 2), (7, 1), (19, 1), (274277, 1), (21285634681, 1), (245719314227, 1)], [(29, 1), (21950986410992550283613977063, 1)], [(2, 3), (3, 1), (5106064099, 1), (8375920553543098109, 1)], [(2, 2), (3, 1), (91647588053837, 1), (925158864974849, 1)], [(5, 3), (7, 1), (353, 1), (631, 1), (2398849, 1), (6464317, 1), (243169541, 1)], [(5, 1), (7, 1), (11, 1), (313, 1), (10453, 1), (10739, 1), (115124563, 1), (599896067, 1)], [(2, 3), (7, 1), (27366370651, 1), (626758022192487851, 1)], [(2, 2), (3, 1), (5, 1), (13, 1), (29, 1), (193, 1), (34573621, 1), (4947871260839413, 1)]] 
```
If we examine the factors of the order of each curve, we can see that the curves at index 11 and 12 (or -3 and -4) have relatively small prime factors. As noted [here](https://l0z1k.com/pohlig_hellman_attack), having small prime factors makes it much easier to use this algorithm. Let's use these mods to recover the nonce (you'll see why I used 2). 
Let's generate a payload and select the two outputs that correspond to these indices:
```
'015af2b4355ec5a862f667835a' (index -3)
'05576ceaf69b38eab7298fa15c' (index -4)
```
Now, just call Sage's built-in `discrete_log` method (which essentially uses the Pohlig Hellman algorithm). Run `discrete_log` with the base point, P, and create a new point, Q, with our x-value. Here's some Sage:
```py
MODS = [
        942340315817634793955564145941,
        743407728032531787171577862237,
        738544131228408810877899501401,
        1259364878519558726929217176601,
        1008010020840510185943345843979,
        1091751292145929362278703826843,
        793740294757729426365912710779,
        1150777367270126864511515229247,
        763179896322263629934390422709,
        636578605918784948191113787037,
        1026431693628541431558922383259,
        1017462942498845298161486906117,
        734931478529974629373494426499,
        934230128883556339260430101091,
        960517171253207745834255748181,
        746815232752302425332893938923,
    ]

E = EllipticCurve(GF(MODS[-3]),[-3,7])
a = '015af2b4355ec5a862f667835a'

x = int.from_bytes(bytes.fromhex(a),"big")
P = E(2,3)
y1 = mod(pow(x,3) - 3*x + 7,MODS[-3]).sqrt()
y2 = (-1*y1) % MODS[-3]

print(x)
print(y1)
print(y2)

Q1 = E(x,y1)
Q2 = E(x,y2)

print("Q1:")
print(P.discrete_log(Q1))
print("Q2:")
print(P.discrete_log(Q2))
```
We did this for one of the two values from the payload, but you can simply substitute the a variable for the other one. I needed to consider two values for y since we only know the x value of Q, and this x value could have two y-values (due to $y^2$). This is also why we needed to test two values from the payload, to see the nonce that is common to both of them. Later, I realized that I probably don't need to do this, since one of the nonces output is much larger than the other, and the smaller one is always correct. The larger nonce is likely larger than 10 bytes (how large a nonce can be), but I didn't check this.
Running this with both of the x-values from the payload (we will need to change `a` and `MODS[i]` each time we run the script), we get:
```
Q1:
934229535825900641052189722868
Q2:
593057655811568689710667


Q1:
593057655811568689710667
Q2:
146985702648338962643309728158
```
As we can see, the nonce is 593057655811568689710667, as this is common to both outputs. Also, the other nonce seems way too big, and probably isn't correct. I think I only needed to run this script once and only chose the smaller nonce. That's ok, we having a working proof of concept.
Now that we recovered the nonce, we need to determine the output of `service.gen()` with this nonce. This means that we need to edit the state of `nonce_gen` object to correspond to the nonce. If we look at the `gen` method of the `NonceGenerator` class, we can see that it returns its `state` variable and the key, and later in `MyECCService.gen()`, the output of this method is used as the nonce. So, now that we know the nonce, we directly know the state of the `nonce_gen` object. I added the following methods into `challenge.py` to let us use the `MyECCService` class with a nonce that we input.
```py
Class NonceGenerator:
	...
	def setState(self,state):
		self.state = state

class MyECCService:
	...
	def setState(self, nonce: bytes):
		self.nonce_gen.setState(nonce)
``` 
Now, we can create a solve script. I first tested locally, with `challenge.py`. The overall process for this script was:
- Send G to generate a payload
- Split the payload into the x-values, and grab the x-values at index -3 and -4.
- Use these x-values with the appropriate elliptic curve and modulus. Call `discrete_log` in Sage to figure out 2 possible values for the nonce, and find the nonce in common
- Create a new `MyECCService` object and set its `nonce_gen`'s state to the nonce we just found. Use this new service to generate a new payload
- Send P, and enter our new payload.

(I had to change the Python script to Sage to make the math work). The local script is [here](#local-script)

Works perfectly! Now, I had to interface it with the remote connection via pwntools. The final solve script is [here](#remote-script).

## Flag: pbctf{Which_method_did_you_use?_Maybe_it_also_works_on_the_second_challenge!}
## Note
A bit embarassingly, I didn't realize that by sending V, you can send a payload that edits the base point in a `MyECCService` object. This is important because the base point can change the b-value in the curve (since b is only solved from our base point). This allows us to chose a base point that creates a singular curve, which was the *intended* solution for this challenge and the next one. Singular elliptic curves are isomorphic to the multiplicative group, making the discrete log problem much easier to solve, and making the nonce easier to recover. This idea of setting the base point and thus the curve was quite interesting in my opinion. My method to cherry pick nice prime numbers wouldn't work for the next challenge, since we needed to take a discrete log with a curve under *each* prime to find every nonce. 

## Local Script
```py
from Crypto.Util.number import inverse
from hashlib import sha256
import os
import signal


MODS = [
942340315817634793955564145941,
743407728032531787171577862237,
738544131228408810877899501401,
1259364878519558726929217176601,
1008010020840510185943345843979,
1091751292145929362278703826843,
793740294757729426365912710779,
1150777367270126864511515229247,
763179896322263629934390422709,
636578605918784948191113787037,
1026431693628541431558922383259,
1017462942498845298161486906117,
734931478529974629373494426499,
934230128883556339260430101091,
960517171253207745834255748181,
746815232752302425332893938923, 
]


class NonceGenerator:
    def __init__(self):
        self.state = os.urandom(10)
        self.db = {}
    
    def gen(self):
        self.state = sha256(self.state + b'wow').digest()[:10]
        key = sha256(self.state).digest()[:8]
        self.db[key] = self.state

        return int.from_bytes(self.state, 'big'), key

    def get(self, key: str):
        if key not in self.db:
            print("Wrong key :(")
            exit(0)

        return int.from_bytes(self.db[key], 'big')
    
    def setState(self,state):
        self.state = state

class ECPoint:
    def __init__(self, point, mod):
        self.x = point[0]
        self.y = point[1]
        self.mod = mod

    def inf(self):
        return ECPoint((0, 0), self.mod)

    def _is_inf(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, other):
        assert self.mod == other.mod
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        assert self.mod == other.mod
        P, Q = self, other
        if P._is_inf() and Q._is_inf():
            return self.inf()
        elif P._is_inf():
            return Q
        elif Q._is_inf():
            return P

        if P == Q:
            lam = (3 * P.x**2 - 3) * inverse(2 * P.y, self.mod) % self.mod
        elif P.x == Q.x:
            return self.inf()
        else:
            lam = (Q.y - P.y) * inverse(Q.x - P.x, self.mod) % self.mod

        x = (lam**2 - P.x - Q.x) % self.mod
        y = (lam * (P.x - x) - P.y) % self.mod

        return ECPoint((x, y), self.mod)

    def __rmul__(self, other: int):
        base, ret = self, self.inf()
        while other > 0:
            if other & 1:
                ret = ret + base
            other >>= 1
            base = base + base
        return ret


class MyECCService:
    BASE_POINT = (2, 3)
    def __init__(self):
        self.nonce_gen = NonceGenerator()

    def get_x(self, nonce: int) -> bytes:
        ret = b""
        for mod in MODS:
            p = ECPoint(self.BASE_POINT, mod)
            x = (nonce * p).x
            ret += int(x).to_bytes(13, "big")
        return ret

    def gen(self) -> bytes:
        nonce, key = self.nonce_gen.gen()
        x = self.get_x(nonce)

        return b"\x02\x03" + key + x

    def verify(self, inp: bytes) -> bool:
        assert len(inp) == 218

        nonce = self.nonce_gen.get(inp[2:10])
        self.BASE_POINT = (inp[0], inp[1])
        x = self.get_x(nonce)
        return inp[10:] == x

    def setState(self, nonce: bytes):
        self.nonce_gen.setState(nonce)

def handler(_signum, _frame):
    print("Time out!")
    exit(0)


def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(300)

    service = MyECCService()

    for _ in range(100):
        service.gen()

    while True:
        inp = input("> ")
        if inp == "G":
            payload = service.gen()
            print(f"Payload: {payload.hex()}")
            payloadHex = payload.hex()
            E1 = EllipticCurve(GF(MODS[-4]),[-3,7])
            E2 = EllipticCurve(GF(MODS[-3]),[-3,7])
            nums = [payloadHex[i+20:i+20+26] for i in range(0,len(payloadHex[20:]),26)]
            a1 = nums[-4]
            a2 = nums[-3]

            print(nums)


            x1 = int.from_bytes(bytes.fromhex(a1),"big")
            x2 = int.from_bytes(bytes.fromhex(a2),"big")
            P1 = E1(2,3)
            P2 = E2(2,3)
            y11 = mod(pow(x1,3)-3*x1+7,MODS[-4]).sqrt()
            y12 = (-1*y11)% MODS[-4]
            y21 = mod(pow(x2,3)-3*x2+7,MODS[-3]).sqrt()
            y22 = (-1*y21) % MODS[-3]
            print(y11)
            print(y12)
            print(y21)
            print(y22)
            print(x1)
            print(x2)
            Q11 = E1(x1,y11)
            Q12 = E1(x1,y12)
            Q21 = E2(x2,y21)
            Q22 = E2(x2,y22)
            

            nonce1 = P1.discrete_log(Q11)
            nonce2 = P1.discrete_log(Q12)

            
            nonce3 = P2.discrete_log(Q21)
            nonce4 = P2.discrete_log(Q22)
            
            nonce = 0

            if (nonce1 == nonce3 or nonce1 == nonce4):
                nonce = nonce1
            else:
                nonce = nonce2
            
            print(nonce)
            print(int(nonce).to_bytes(10,"big"))

            testService = MyECCService()
            testService.setState(int(nonce).to_bytes(10,"big"))
            newPayload = testService.gen()
            print(f"Result: {newPayload.hex()}")



        elif inp == "V":
            payload = bytes.fromhex(input("Payload: "))
            result = service.verify(payload)
            print(f"Result: {result}")
        elif inp == "P":
            payload = bytes.fromhex(input("Payload: "))
            answer = service.gen()

            if payload == answer:
                with open("flag.txt", "r") as f:
                    print(f.read())
            else:
                print("Wrong :(")
                print(f"Payload: {answer.hex()}")
            exit(0)


if __name__ == "__main__":
    main()
```

## Remote script
```py
from Crypto.Util.number import inverse
from hashlib import sha256
import os
import signal
from pwn import *

MODS = [
942340315817634793955564145941,
743407728032531787171577862237,
738544131228408810877899501401,
1259364878519558726929217176601,
1008010020840510185943345843979,
1091751292145929362278703826843,
793740294757729426365912710779,
1150777367270126864511515229247,
763179896322263629934390422709,
636578605918784948191113787037,
1026431693628541431558922383259,
1017462942498845298161486906117,
734931478529974629373494426499,
934230128883556339260430101091,
960517171253207745834255748181,
746815232752302425332893938923, 
]


class NonceGenerator:
    def __init__(self):
        self.state = os.urandom(10)
        self.db = {}
    
    def gen(self):
        self.state = sha256(self.state + b'wow').digest()[:10]
        key = sha256(self.state).digest()[:8]
        self.db[key] = self.state

        return int.from_bytes(self.state, 'big'), key

    def get(self, key: str):
        if key not in self.db:
            print("Wrong key :(")
            exit(0)

        return int.from_bytes(self.db[key], 'big')
    
    def setState(self,state):
        self.state = state

class ECPoint:
    def __init__(self, point, mod):
        self.x = point[0]
        self.y = point[1]
        self.mod = mod

    def inf(self):
        return ECPoint((0, 0), self.mod)

    def _is_inf(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, other):
        assert self.mod == other.mod
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        assert self.mod == other.mod
        P, Q = self, other
        if P._is_inf() and Q._is_inf():
            return self.inf()
        elif P._is_inf():
            return Q
        elif Q._is_inf():
            return P

        if P == Q:
            lam = (3 * P.x**2 - 3) * inverse(2 * P.y, self.mod) % self.mod
        elif P.x == Q.x:
            return self.inf()
        else:
            lam = (Q.y - P.y) * inverse(Q.x - P.x, self.mod) % self.mod

        x = (lam**2 - P.x - Q.x) % self.mod
        y = (lam * (P.x - x) - P.y) % self.mod

        return ECPoint((x, y), self.mod)

    def __rmul__(self, other: int):
        base, ret = self, self.inf()
        while other > 0:
            if other & 1:
                ret = ret + base
            other >>= 1
            base = base + base
        return ret


class MyECCService:
    BASE_POINT = (2, 3)
    def __init__(self):
        self.nonce_gen = NonceGenerator()

    def get_x(self, nonce: int) -> bytes:
        ret = b""
        for mod in MODS:
            p = ECPoint(self.BASE_POINT, mod)
            x = (nonce * p).x
            ret += int(x).to_bytes(13, "big")
        return ret

    def gen(self) -> bytes:
        nonce, key = self.nonce_gen.gen()
        x = self.get_x(nonce)

        return b"\x02\x03" + key + x

    def verify(self, inp: bytes) -> bool:
        assert len(inp) == 218

        nonce = self.nonce_gen.get(inp[2:10])
        self.BASE_POINT = (inp[0], inp[1])
        x = self.get_x(nonce)
        return inp[10:] == x

    def setState(self, nonce: bytes):
        self.nonce_gen.setState(nonce)

def handler(_signum, _frame):
    print("Time out!")
    exit(0)


def main():
    conn = remote('my-ecc-service.chal.perfect.blue',int(1337))
    conn.recvuntil(b' ')

    conn.send(b"G\n")
    payloadHex = conn.recvline().decode().strip().split()[1]
    print(payloadHex)
    
    
    E1 = EllipticCurve(GF(MODS[-4]),[-3,7])
    E2 = EllipticCurve(GF(MODS[-3]),[-3,7])
    nums = [payloadHex[i+20:i+20+26] for i in range(0,len(payloadHex[20:]),26)]
    a1 = nums[-4]
    a2 = nums[-3]

    print(nums)


    x1 = int.from_bytes(bytes.fromhex(a1),"big")
    x2 = int.from_bytes(bytes.fromhex(a2),"big")
    P1 = E1(2,3)
    P2 = E2(2,3)
    y11 = mod(pow(x1,3)-3*x1+7,MODS[-4]).sqrt()
    y12 = (-1*y11)% MODS[-4]
    y21 = mod(pow(x2,3)-3*x2+7,MODS[-3]).sqrt()
    y22 = (-1*y21) % MODS[-3]
    Q11 = E1(x1,y11)
    Q12 = E1(x1,y12)
    Q21 = E2(x2,y21)
    Q22 = E2(x2,y22)
            

    nonce1 = P1.discrete_log(Q11)
    nonce2 = P1.discrete_log(Q12)
 
    nonce3 = P2.discrete_log(Q21)
    nonce4 = P2.discrete_log(Q22)
            
    nonce = 0

    if (nonce1 == nonce3 or nonce1 == nonce4):
        nonce = nonce1
    else:
        nonce = nonce2
            
    print(nonce)
    print(int(nonce).to_bytes(10,"big"))

    testService = MyECCService()
    testService.setState(int(nonce).to_bytes(10,"big"))
    newPayload = testService.gen()
    print(f"Result: {newPayload.hex()}")
    conn.send(b"P\r\n")
    conn.interactive()
    

if __name__ == "__main__":
    main()
```
