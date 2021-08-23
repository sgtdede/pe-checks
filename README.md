# pe-checks
PE file informations (VirusTotal like) for malware development and AV evasion research

## Installation
#### *Note*:
This script requires python3

### Check out the source code
```
git clone --recurse-submodules https://github.com/sgtdede/pe-checks.git
<<<<<<< HEAD
```
=======
cd pe-checks
``` 
>>>>>>> 5486e925292832f471e660e469e169a90225c9a7
### Install the python dependencies
```
pip install -r requirements.txt
```

## Help
```
python pe-checks.py -h
usage: pe-checks.py [-h] [-s] [-v] [filename ...]

PE informations

positional arguments:
  filename

optional arguments:
  -h, --help  show this help message and exit
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
This script is powered by pefile, CAPA, RichPE, PyDefenderCheck
https://github.com/RichHeaderResearch/RichPE

## TODO
- Add signature support
- Add ThreatChecks support
- Add manifest/fileversion support
