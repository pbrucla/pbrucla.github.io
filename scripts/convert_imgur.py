"""
Flameshot auto-uploads to imgur but imgur no work so I write tool to auto-download the imgur images.

Prereqs:
- requests
- swag
"""
import re
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

root = Path(__file__).parent / ".."
savepath = "assets/posts/imgur"
imgur = root / savepath
imgurlink = re.compile(r"https://i.imgur.com/[^\.]+\.png")


def save(link):
    r = requests.get(link)
    r.raise_for_status()
    dest = link.split("/")[-1]
    with open(imgur / dest, "wb+") as fout:
        fout.write(r.content)


def main():
    parser = ArgumentParser()
    parser.add_argument("post", help="post to convert imgur links of")
    args = parser.parse_args()

    with open(args.post, "r") as fin:
        post = fin.read()

    links = re.findall(imgurlink, post)
    with ThreadPoolExecutor(100) as executor:
        [*executor.map(save, links)]

    with open(args.post, "w") as fout:
        fout.write(post.replace("https://i.imgur.com", "/assets/posts/imgur"))


if __name__ == "__main__":
    main()
