"""
Updates the list of ctfs along with our place in them.

Prereqs:
- requests
- PyYAML
- beautifulsoup4
"""
from pathlib import Path

import requests
import yaml
from bs4 import BeautifulSoup

ctfsyaml = Path(__file__).parent / "../_data/ctfs.yml"
url = "https://ctftime.org/team/186494"
r = requests.get(
    url,
    headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0"
    },
)
r.raise_for_status()
soup = BeautifulSoup(r.text, "html.parser")
years = soup.select(".table.table-striped:has( .place_ico)")
yearnums = [*range(2022, 2022 + len(years))][::-1]
ctfdata = {"ctfs": []}

for year, data in zip(yearnums, years):
    yeardata = {"year": year, "ctfs": []}
    for row in data.select("tr:has( .place)"):
        place = int(row.select_one(".place").text)
        anch = row.select_one("a")
        iid = int(anch["href"].split("/")[-1])
        name = anch.text.strip()
        yeardata["ctfs"].append({"name": name, "id": iid, "place": place})
    if year == 2023:
        yeardata["ctfs"].insert(
            0, {"name": "LA CTF 2023", "id": 1732, "place": "organizers"}
        )
    ctfdata["ctfs"].append(yeardata)

with open(ctfsyaml, "w") as fout:
    yaml.safe_dump(ctfdata, fout, sort_keys=False)
