<p align="center"><img src="https://github.com/packing-box/REMINDer/raw/main/logo.png"></p>
<h1 align="center">REMINDer <a href="https://twitter.com/intent/tweet?text=REMINDer%20-%20Packer%20detector%20using%20an%20entropy-based%20heuristic.%0D%0Ahttps%3a%2f%2fgithub%2ecom%2fpacking-box%2fREMINDer%0D%0A&hashtags=python,packer,packingdetection,entropy"><img src="https://img.shields.io/badge/Tweet--lightgrey?logo=twitter&style=social" alt="Tweet" height="20"/></a></h1>
<h3 align="center">Detect packers on executable files using a simple entropy-based heuristic.</h3>

[![PyPi](https://img.shields.io/pypi/v/reminder.svg)](https://pypi.python.org/pypi/reminder/)
[![Python Versions](https://img.shields.io/pypi/pyversions/reminder.svg)](https://pypi.python.org/pypi/reminder/)
[![Known Vulnerabilities](https://snyk.io/test/github/dhondta/reminder/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/dhondta/reminder?targetFile=requirements.txt)
[![DOI](https://zenodo.org/badge/384872434.svg)](https://zenodo.org/badge/latestdoi/384872434)
[![License](https://img.shields.io/pypi/l/reminder.svg)](https://pypi.python.org/pypi/reminder/)


REMINDer (REsponse tool for Malware INDication) is an implementation based on [this paper](https://ieeexplore.ieee.org/document/5404211) into a Python package with a console script to detect whether an executable is packed.

[lief](https://github.com/lief-project/LIEF) is used for binary parsing.

```session
$ pip install reminder-detector
```

```session
$ reminder --help
[...]
usage examples:
- reminder program.exe
- reminder /bin/ls --entropy-threshold 6.9
```

## :bulb: Detection Mechanism

1. Find the EP section
2. Check whether it is writable
3. If yes, check whether entropy is beyond a threshold (depending on the executable format)
4. If yes, the input executable is packed ; otherwise, it is not


## :star: Related Projects

You may also like these:

- [Awesome Executable Packing](https://github.com/packing-box/awesome-executable-packing): A curated list of awesome resources related to executable packing.
- [Bintropy](https://github.com/packing-box/bintropy): Analysis tool for estimating the likelihood that a binary contains compressed or encrypted bytes (inspired from [this paper](https://ieeexplore.ieee.org/document/4140989)).
- [Dataset of packed ELF files](https://github.com/packing-box/dataset-packed-elf): Dataset of ELF samples packed with many different packers.
- [Dataset of packed PE files](https://github.com/packing-box/dataset-packed-pe): Dataset of PE samples packed with many different packers (fork of [this repository](https://github.com/chesvectain/PackingData)).
- [Docker Packing Box](https://github.com/packing-box/docker-packing-box): Docker image gathering packers and tools for making datasets of packed executables.
- [DSFF](https://github.com/packing-box/python-dsff): Library implementing the DataSet File Format (DSFF).
- [PEiD](https://github.com/packing-box/peid): Python implementation of the well-known Packed Executable iDentifier ([PEiD](https://www.aldeid.com/wiki/PEiD)).
- [PyPackerDetect](https://github.com/packing-box/pypackerdetect): Packing detection tool for PE files (fork of [this repository](https://github.com/cylance/PyPackerDetect)).


## :clap:  Supporters

[![Stargazers repo roster for @packing-box/REMINDer](https://reporoster.com/stars/dark/packing-box/REMINDer)](https://github.com/packing-box/REMINDer/stargazers)

[![Forkers repo roster for @packing-box/REMINDer](https://reporoster.com/forks/dark/packing-box/REMINDer)](https://github.com/packing-box/REMINDer/network/members)

<p align="center"><a href="#"><img src="https://img.shields.io/badge/Back%20to%20top--lightgrey?style=social" alt="Back to top" height="20"/></a></p>
