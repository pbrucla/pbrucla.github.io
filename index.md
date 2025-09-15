---
layout: default
---

# Home

<!-- https://www.w3schools.com/w3css/w3css_slideshow.asp -->
<div class="carousel-container">
    {% assign carousel_images = site.static_files | where_exp: "f", "f.path contains '/assets/images/carousel/'" | sort: "path" %}
    {% for img in carousel_images %}
        <img class="mySlides" src="{{ img.path | relative_url }}" alt="carousel image">
    {% endfor %}
</div>

<script src="/assets/carousel.js"></script>

## Welcome to PBR!

Welcome to the home of **Psi Beta Rho** (a.k.a. **PBR** or **ψβρ**), UCLA's competitive cybersecurity team! We are a group of hackers, programmers, and security enthusiasts who love to learn and compete. We are a part of [ACM Cyber at UCLA](https://acmcyber.com/) and are advised by [Dr. Yuan Tian](https://www.ytian.info/). Whether we are pwning a binary or attacking a site using cross-site scripting, we like to have fun.

## What do we do?
We compete in **CTFs** or [Capture the Flag](https://ctftime.org/ctf-wtf/) cybersecurity events every other weekend. We also invite notable speakers from top CTF teams or industry to hear about their experiences and learn about how to improve our skills. Additinonally, we work on projects and research related to security including hosting our own CTF annually, [LA CTF](https://lactf.uclaacm.com/)!

## Join Us
Interested in joining PBR or just want to check us out? PBR is open to join, so take a look at the [ACM Cyber Discord](https://discord.gg/j9dgf2q) where we send out notifications for upcoming CTFs and more. Whether you are an **experienced** CTF player or a complete **beginner**, we would love to CTF with you.

## Contact Us

To contact us, either email us at [psibetarho@gmail.com](mailto:psibetarho@gmail.com) or join the [ACM Cyber Discord](https://discord.gg/j9dgf2q). Be sure to follow us on some of our socials such as [Twitter](https://twitter.com/psibetarho) and [Instagram](https://www.instagram.com/uclacyber/)! If you would like to see what we are up to, be sure to check out our profile on [CTF Time](https://ctftime.org/team/186494) or our [GitHub](https://github.com/pbrucla/)! If you want to see some other things our club is up to, check out the [ACM Cyber website](https://acmcyber.com/)!
