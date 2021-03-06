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
  -y, --yara  perform a yara scan using Valhalla's free rules  
  -v          verbose mode
```

## Usage exemple
```
python pe-checks.py doggo.exe -v -s -c -y
```
![image](https://user-images.githubusercontent.com/5963320/130526489-5f79d041-e1c0-404e-be2a-bdf174a38a5b.png)
![image](https://user-images.githubusercontent.com/5963320/130305528-035f8c5a-48e9-4652-82fc-b484330146d7.png)
![image](https://user-images.githubusercontent.com/5963320/130305483-aadc7dc5-4995-4411-a24f-1768c4a3440d.png)
![image](https://user-images.githubusercontent.com/5963320/130877148-9656f14c-6842-471d-8454-679121782d67.png)


## Thanks to
This script is powered by [pefile](https://github.com/erocarrera/pefile), [capa](https://github.com/fireeye/capa), [RichPE](https://github.com/RichHeaderResearch/RichPE), [yara-python](https://github.com/VirusTotal/yara-python), [valhallaAPI](https://github.com/NextronSystems/valhallaAPI) and [PyDefenderCheck](https://gist.github.com/daddycocoaman/108d807e89a0f9731304bc848fa219f0)

## TODO
- Add signature support
- Add manifest/fileversion support
