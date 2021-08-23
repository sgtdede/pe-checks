# pe-checks
PE file informations (VirusTotal like) for malware development and AV evasion research 

## Installation
#### *Note*: 
This script requires python3

### Check out the source code
```
git clone --recurse-submodules https://github.com/sgtdede/pe-checks.git
cd pe-checks
``` 
### Install the python dependencies
```
pip install -r requirements.txt
``` 

## Help
```
python pe-checks.py -h
usage: pe-checks.py [-h] [-a] [-c] [-s] [-v] [filename ...]

PE informations

positional arguments:
  filename

optional arguments:
  -h, --help  show this help message and exit
  -a, --all   perform all modules
  -c, --capa  perform a CAPA scan
  -s, --scan  perform a defender engine scan (WARNING:before lauching that scan you need to adjust Defender settings to: Defender ON, Submission OFF)
  -v          verbose mode
```

## Usage exemple
```
python pe-checks.py doggo.exe -v -s
```
![image](https://user-images.githubusercontent.com/5963320/130305543-46264d95-63cc-4bd5-bfbd-eeac6f4d0146.png)
![image](https://user-images.githubusercontent.com/5963320/130305528-035f8c5a-48e9-4652-82fc-b484330146d7.png)
![image](https://user-images.githubusercontent.com/5963320/130305483-aadc7dc5-4995-4411-a24f-1768c4a3440d.png)

## Thanks to
This script is powered by [pefile](https://github.com/erocarrera/pefile), [CAPA](https://github.com/fireeye/capa), [RichPE](https://github.com/RichHeaderResearch/RichPE), [PyDefenderCheck](https://gist.github.com/daddycocoaman/108d807e89a0f9731304bc848fa219f0)


## TODO
- Add signature support
- Add manifest/fileversion support
