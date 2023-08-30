---
layout: post
title: Quadprime RSA | X-MAS CTF 2022
author: Gary Song
tags: Crypto
description: "Just use random primes"
---

# Quad Prime - BuckeyeCTF 2022

A sequal to the problem "twin prime" which attempts to make the implementation more secure, but any implementation with related primes will not be secure as we will soon find out.

The code given to us in this problem is as follows

```python=
import Crypto.Util.number as cun

p = cun.getPrime(500)

while True:
    q = cun.getPrime(1024)
    r = q + 2
    if cun.isPrime(r):
        break

s = cun.getPrime(500)

n_1 = p * q
n_2 = r * s

e = 0x10001
d_1 = pow(e, -1, (p - 1) * (q - 1))
d_2 = pow(e, -1, (r - 1) * (s - 1))

FLAG = cun.bytes_to_long(b"buckeye{??????????????????????????????????????????????????????????????????????}")
c_1 = pow(FLAG, e, n_1)
c_2 = pow(FLAG, e, n_2)

assert pow(c_1, d_1, n_1) == FLAG
assert pow(c_2, d_2, n_2) == FLAG

print(f"n_1 = {n_1}")
print(f"n_2 = {n_2}")
print(f"c_1 = {c_1}")
print(f"c_2 = {c_2}")

"""
Output:
n_1 = 266809852588733960459210318535250490646048889879697803536547660295087424359820779393976863451605416209176605481092531427192244973818234584061601217275078124718647321303964372896579957241113145579972808278278954608305998030194591242728217565848616966569801983277471847623203839020048073235167290935033271661610383018423844098359553953309688771947405287750041234094613661142637202385185625562764531598181575409886288022595766239130646497218870729009410265665829
n_2 = 162770846172885672505993228924251587431051775841565579480252122266243384175644690129464185536426728823192871786769211412433986353757591946187394062238803937937524976383127543836820456373694506989663214797187169128841031021336535634504223477214378608536361140638630991101913240067113567904312920613401666068950970122803021942481265722772361891864873983041773234556100403992691699285653231918785862716655788924038111988473048448673976046224094362806858968008487
c_1 = 90243321527163164575722946503445690135626837887766380005026598963525611082629588259043528354383070032618085575636289795060005774441837004810039660583249401985643699988528916121171012387628009911281488352017086413266142218347595202655520785983898726521147649511514605526530453492704620682385035589372309167596680748613367540630010472990992841612002290955856795391675078590923226942740904916328445733366136324856838559878439853270981280663438572276140821766675
c_2 = 111865944388540159344684580970835443272640009631057414995719169861041593608923140554694111747472197286678983843168454212069104647887527000991524146682409315180715780457557700493081056739716146976966937495267984697028049475057119331806957301969226229338060723647914756122358633650004303172354762801649731430086958723739208772319851985827240696923727433786288252812973287292760047908273858438900952295134716468135711755633215412069818249559715918812691433192840
"""
```

It's very reminescent of the twin prime problem, but in this case we aren't actually using the twin primes together but rather splitting them up into two different moduli by generating two more random primes. If we were just given one of these moduli we'd probably be out of luck. But we have both, which means we do have the twin primes available to us, just in some obfuscated form. Let's see how we can use them. 

The two moduli we are given are

$$n_1 = p \cdot q$$
and
$$n_2 = r\cdot s = (q + 2)\cdot s$$

But $q$ is massive compared to $2$ and contains almost twice as many bits as $s$, so in reality we kinda have

$$n_2 = (q+2)\cdot s = qs + 2s \approx qs$$

If we had $qs$ exactly then we could take the gcd with $n_1$ to recover $q$, and then we'd be done. But we don't, and there isn't really a thing such as approximate gcd with a close value. Instead, we can find a way to cancel out this "common factor" by dividing the two moduli.

$$\frac{n_1}{n_2} = \frac{pq}{(q+2)s} = \frac{q}{q+2}\cdot\frac{p}{s} \approx \frac{p}{s}$$

with how much bigger $q$ is compared to $2$ (which, considering $q$ is $1024$ bits would be around $2^{1022}$ times bigger) this is actually a very approximation. We can actually calculate the error to see how small it is
$$error = \frac{q}{q} - \frac{q}{q+2} = \frac{2}{q+2} < \frac{2}{2^{1023}} = \frac{1}{2^{1022}}$$

with the inequality coming from the fact that $q$ is a $1024$ bit prime, and considering $2^{1023}$ isn't prime it would be some number bigger. $\frac{1}{2^{1022}}$ is already a very small number, probably small enough to not cause us any problems. 

Ok, now we have a very good approximation of $\frac{p}{s}$, but we have it in decimal form. How can we actually retrieve $p$ and $s$?

If you know about continued fractions feel free to skip this part (or read anyway to give my work some validation). Otherwise, let's start off with a simpler example. Given the decimal $1.6$, how can we recover a fractional form? Well, we know that our number is equal to $1 + some fraction$, so we can extract $1$ and we are left with $1 + .6$ and our problem reduces to finding a fraction for $.6$. You may be tempted to just write it as $\frac{6}{10}$ and call it a day, and you would be right in this case, but this won't work in our original problem as we only have a close approximation and not the exact value. This also won't work if our number was irrational!

So want do we do? Since we truncated a the integer part of our number, we are left with a value less than $1$, and thus can be written in the form $\frac{1}{a}$ for some value $a > 1$. We work to find this $a$ by taking the recipricol of $.6$, and doing so gives us $$.6 = \frac{1}{1.\overline{6}}$$ and our (in progress) expression looks like

$$1.6 = 1 + \frac{1}{1.\overline{6}}$$

Now we can run the same process on $1.\overline{6}$ to find an approximation for it. This iteration leaves us with

$$1.6 = 1 + \frac{1}{1+\overline{.6}} = 1 + \frac{1}{1+\frac{1}{1.5}}$$

The end is near. Performing another iteration gives us

$$1.6 = 1 + \frac{1}{1+\overline{.6}} = 1 + \frac{1}{1+\frac{1}{1.5}} = 1 + \frac{1}{1+\frac{1}{1 + .5}} = 1 + \frac{1}{1+\frac{1}{1 + \frac{1}{2}}}$$

our process terminates because the recipricol of $.5$ has no fractional part (it's just $2$) so there's no reason to keep going. Now we're done, and we can get our fractional expression by collapsing from the bottom up

$$1.6 = 1 + \frac{1}{1+\frac{1}{1 + \frac{1}{2}}} = 1 + \frac{1}{1+\frac{1}{\frac{3}{2}}} = 1 + \frac{1}{1+\frac{2}{3}} = 1 + \frac{1}{\frac{5}{3}} = \frac{8}{5}$$

and we're done. We now have a good algorithm for finding a fractional expression: split apart the integer part, take the recipricol of the remainder, repeat.

The real power of this method known as "continued fractions" comes from it's ability to give fractional *approximations*. Pretend that we gave up after the first iteration. Our fraction would just be 
$$1.6 = 1 + \frac{1}{1 + some number}$$

We don't really know how to express "some number", nor do we really care. So we discard it and get the expression
$$1 + \frac{1}{1} = \frac{2}{1} = 2$$

We didn't exactly get our number (which is expected considering we gave up, only hard work can get results) but we did get something *kindaa* close, which is a subjective but our result could've been something like $3$ instead, which is much further off.

Maybe our friend is a harder worker than us and he performs an extra iteration befor giving up. Now he would've gotten the fraction 
$$1 + \frac{1}{1+\frac{1}{1}} = \frac{3}{2}= 1.5$$

This is much closer than what we got! And as we saw originally, one more iteration would've gotten the result exactly. We can see that performing more and more iterations gives us a fractional expression for a closer and closer number, a result that seems fairly intuitive. These partial results are known as the **convergents** of the continued fraction, and can be used to get fractional approximations of irrational numbers.

Let's get back to our original problem. We have the decimal

$$\frac{n_1}{n_2}\approx \frac{p}{s}\approx 1.6391746978162425$$

And wish to find a fractional expression that we hope will give us $p$ and $s$. We know that continued fractions gives us fractional expressions that are extremely close to a value, so we hope to use that. Our method is as follows: keep taking higher and higher convergents until we get one where the numerator and denominator are $500$ bit primes. 

Fortunately for us, sagemath actually has support for continued fractions built in with methods to give us the values for the convergents. Usually I'd say to homeroll as much of your code as you can to gain a better understanding, but in this case the implementation for calculating the convergents is pretty simple and given the time pressure for CTFs there's no reason not to just use sage's implementaiton.

```python=
import Crypto.Util.number as cun

e = 0x10001

n_1 = 266809852588733960459210318535250490646048889879697803536547660295087424359820779393976863451605416209176605481092531427192244973818234584061601217275078124718647321303964372896579957241113145579972808278278954608305998030194591242728217565848616966569801983277471847623203839020048073235167290935033271661610383018423844098359553953309688771947405287750041234094613661142637202385185625562764531598181575409886288022595766239130646497218870729009410265665829
n_2 = 162770846172885672505993228924251587431051775841565579480252122266243384175644690129464185536426728823192871786769211412433986353757591946187394062238803937937524976383127543836820456373694506989663214797187169128841031021336535634504223477214378608536361140638630991101913240067113567904312920613401666068950970122803021942481265722772361891864873983041773234556100403992691699285653231918785862716655788924038111988473048448673976046224094362806858968008487
c_1 = 90243321527163164575722946503445690135626837887766380005026598963525611082629588259043528354383070032618085575636289795060005774441837004810039660583249401985643699988528916121171012387628009911281488352017086413266142218347595202655520785983898726521147649511514605526530453492704620682385035589372309167596680748613367540630010472990992841612002290955856795391675078590923226942740904916328445733366136324856838559878439853270981280663438572276140821766675
c_2 = 111865944388540159344684580970835443272640009631057414995719169861041593608923140554694111747472197286678983843168454212069104647887527000991524146682409315180715780457557700493081056739716146976966937495267984697028049475057119331806957301969226229338060723647914756122358633650004303172354762801649731430086958723739208772319851985827240696923727433786288252812973287292760047908273858438900952295134716468135711755633215412069818249559715918812691433192840

c = continued_fraction(Integer(n_1) / Integer(n_2))
for i in range(1, 1024):
    p = c.numerator(i)
    s = c.denominator(i)

    if p > (2 ** 499) and s > (2 ** 499) and cun.isPrime(p) and cun.isPrime(s):
        print(f"p = {p}")
        print(f"s = {s}")
        break
else:
    raise ValueError("I'm die")

q = n_1 // p
r = q + 2

d_1 = pow(e, -1, (p - 1) * (q - 1))
flag = pow(c_1, d_1, n_1)
print(cun.long_to_bytes(flag))
```

this gives us the flag
`buckeye{I_h0p3_y0u_us3D_c0nt1nu3d_fr4ct10Ns...th4nk5_d0R5A_f0r_th3_1nsp1r4t10n}`

If you're anything like me, you might still feel a little icky about this solution. Obviously, it worked, but why were $p$ and $s$ exactly returned when we only used an approximation? How close of an approximation do we need to retrieve the actual values? Well, remember that we said the error of $\frac{n_1}{n_2}$ from $\frac{p}{s}$ was some number less than $\frac{1}{2^{1022}}$. Say our continued fraction gave a close value instead, like $\frac{p+1}{s}=\frac{p}{s} + \frac{1}{s}$. This has an error from our desired value of value $\frac{1}{s}$ which is upper bounded by $\frac{1}{2^{499}}$, a value much greater than the error of our approximation. So we can be fairly sure this error won't occur since $\frac{n_1}{n_2}$ is much closer than this, and we can find solace in knowing why our method works.

## Alternate solution

That was the intended solution, as can be seen by the flag text, but this actually was not the solution I thought of during the CTF. Admittedly, the intended solution is definitely the faster and more simple way to do this, but if you want to have some more fun feel free to keep reading.

This solution comes from the fact that $q$ and $r$ are more than twice the amount of bits as $p$ and $s$. Recall the equation
$$n_2 = (q+2)\cdots = qs + 2s \approx qs$$
We saw that $qs$ is much larger than $2s$. In fact, since $qs$ is the product of a $1024$ bit number and a $500$ bit number it would be about $1524$ bits, and since $s$ is being doubled then $2s$ would be $501$ bits. When you add the two, the bottom $501$ bits of $qs$ will combine with $2s$, and assuming the case we need to carry over a number then the $502th$ of $qs$ will be affected as well. But that's the upper limit, and the remaining $1022$ bits of $qs$ are left unaffected, so we can recover this information about $qs$ from $n_2$. 

If you are familiar with coppersmith's method you may see where this is going. Recovering a number from a series of known bits is fairly common process, and if we can recover $qs$ then we can take the gcd with $n_1 = pq$ to recover $q$ and we've essentially solved the problem. Let's see how we do it.

Just knowing the upper $~1000$ bits of $qs$ isn't enough to solve this problem, we aren't going to magically guess the remaining $~502$ bits, that number is way to big. Fortunately for us, we have some extra information involving $qs$. Notice the following relation
$$n_1\cdot n_2 = (pq)(rs) = (qs)(pr)$$
So we actually have a number that is a multiple of $qs$ that we can calculate the value of. This may not seem like much, but it's all we need. To proceed, Let $u$ represent the top $1022$ bits of $qs$ (shifted to their appropriate positions) and let $x$ represent our guess for the bottom $502$ bits. Then we can write the following polynomial
$$f(x) = u + x$$
Let $r$ represent the correct value of the bottom $502$ bits. If our guess is correct, then we have 
$$f(r) = u + r = qs \equiv 0\mod{qs}$$ 
So our problem is basically just looking for a root for $f(x) \mod{qs}$. This doesn't seem to help us very much since we don't know what $qs$ is, so it would be very helpful if we could get rid of the modulus somehow. Looking at other information we have, we also know that $qs$ is a divisor of $n_1\cdot n_2$, so we can generate another polynomial that shares the same root $r$. This is simply
$$g(x) = n_1\cdot n_2$$
Pretty straightforward as we have 
$$g(r) = n_1\cdot n_2 \equiv 0 \mod{qs}$$
Another candidate is 
$$h(x) = x(u+x)$$
since
$$h(r) = r(u+r) \equiv r\cdot 0 \equiv 0 \mod{qs}$$
Notice that since we have that $f(r), g(r), h(r)$ are all equal to $0\mod{qs}$, any combination of them will also be equal to $0\mod{qs}$. (For example: $g(x) + h(x) + 2f(x)$ will still be $0\mod{qs}$)

How does this help us? Let $c(x)$ be a linear combination of $f(x),g(x),h(x)$, then we know that $c(r) \equiv 0 \mod{qs}$, so $c(r)$ could be equal to $0, qs, 2qs, \dots$ etc.$ But what if we knew that $|c(r)| < qs$? Then the only possible value that $c(r)$ could take would be $0$ and we would know for a fact that $c(r) = 0$ straight up, no modular math needed. To generate such a combination, we can actually use a lattice algorithm known as LLL. LLL guarantees an upper limit on the size of one of the vectors (which we associate with a polynomial) that it spits out. It turns out that for our case, this vector is small enough to satisfy our constraint of $|c(r)| < qs$. We first construct our lattice using the three polynomials we found above to get
$$
\begin{bmatrix}
x^2 & u & 0 \\
0 & x & u \\
0 & 0 & n_1\cdot n_2
\end{bmatrix}
$$
This actually won't work since we don't know the value of $x$, so we will replace it with a number that we do know. We know that $x < 2^{502}$ since it represents the lower $502$ bits of $qs$. Let this bound be $R = 2^{502}$. Then we instead run LLL on the lattice

$$
\begin{bmatrix}
R^2 & uR & 0 \\
0 & R & u \\
0 & 0 & n_1\cdot n_2
\end{bmatrix}
$$
Why will this work instead? Well, let the polynomial that is output instead be $c(R)$. Since $r < R$, we should have $|c(r)| < |c(R)| < qs$. 

Let the short vector that comes out be $(aR^2, bR, c)$. This vector represents $c(R)$, so we extract the coefficients then solve
$ax^2 + bx + c = 0$
for $x$, which gives us our value of $r$! From there, we can reconstruct $qs = u + r$, solve for $q$ by taking the gcd with $n_1 = pq$, and eventually solve the problem.

If this seems confusing, it may help to look at this solve script.

```python
import Crypto.Util.number as cun

n_1 = 266809852588733960459210318535250490646048889879697803536547660295087424359820779393976863451605416209176605481092531427192244973818234584061601217275078124718647321303964372896579957241113145579972808278278954608305998030194591242728217565848616966569801983277471847623203839020048073235167290935033271661610383018423844098359553953309688771947405287750041234094613661142637202385185625562764531598181575409886288022595766239130646497218870729009410265665829
n_2 = 162770846172885672505993228924251587431051775841565579480252122266243384175644690129464185536426728823192871786769211412433986353757591946187394062238803937937524976383127543836820456373694506989663214797187169128841031021336535634504223477214378608536361140638630991101913240067113567904312920613401666068950970122803021942481265722772361891864873983041773234556100403992691699285653231918785862716655788924038111988473048448673976046224094362806858968008487
c_1 = 90243321527163164575722946503445690135626837887766380005026598963525611082629588259043528354383070032618085575636289795060005774441837004810039660583249401985643699988528916121171012387628009911281488352017086413266142218347595202655520785983898726521147649511514605526530453492704620682385035589372309167596680748613367540630010472990992841612002290955856795391675078590923226942740904916328445733366136324856838559878439853270981280663438572276140821766675
c_2 = 111865944388540159344684580970835443272640009631057414995719169861041593608923140554694111747472197286678983843168454212069104647887527000991524146682409315180715780457557700493081056739716146976966937495267984697028049475057119331806957301969226229338060723647914756122358633650004303172354762801649731430086958723739208772319851985827240696923727433786288252812973287292760047908273858438900952295134716468135711755633215412069818249559715918812691433192840
bound = 1 <<502
upper = (n_2 >> 502) << 502
N = n_1 * n_2
mat = matrix([
    [bound^2, bound * upper, 0],
    [0, bound, upper],
    [0, 0, N]
])
# print(mat.LLL())
sv = mat.LLL()[0]
a = sv[0]//(bound^2)
b = sv[1] // bound
c = sv[2]
x = var('x')
eq = (a*x^2 + b*x + c == 0)
r = 0
qs = upper
for root, mult in eq.roots():
    t = upper + root
    if gcd(t, n_1) != 1:
        qs = t

q = gcd(n_1, qs)
q = int(q)
p = n_1 // q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))
p1 = pow(c_1, d, n_1)
print(cun.long_to_bytes(p1))

```

This uses sage's implmentation of LLL.

Chances are you're left unsatisfied with the ending of this solution as well. If you have questions like "how do we know that the polynomial produced by LLL is small enough?" or "What is LLL?" then I recommend first reading up on lattices and the LLL algorithm. You'll find that the first vector in the returned basis has a very convient limit to it's size. I would also recommend looking into coppersmith's method, which forms the basis for this method used. Finally, https://eprint.iacr.org/2020/1506.pdf is a good source for using this lattice method to break RSA and is what I referred to during the CTF. 



