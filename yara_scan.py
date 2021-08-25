from valhallaAPI.valhalla import ValhallaAPI
from helpers import is_running_standalone, get_default_root
from os.path import join, isfile
import yara


UPDATE_URL_SIGS = [
        # "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip",
        "https://raw.githubusercontent.com/fireeye/red_team_tool_countermeasures/master/all-yara.yar"
        # "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip"
    ]


def yara_scan(file_name, loaded_rules):
    matches = loaded_rules.match(file_name)
    return matches

def valhalla_scan(filename):
    valhalla_rules = fetch_valhalla_rules()
    matches = yara_scan(filename, valhalla_rules)
    if matches:
        print("== YARA Detection")
        for match in matches:
            show_valhalla_match(match)

def show_valhalla_match(match):
    print(f"= {match.rule}")
    print(f"Description: {match.meta.get('description')}")
    print(f"Author: {match.meta.get('description')}")
    print(f"Reference: {match.meta.get('description')}")
    print(f"Date: {match.meta.get('description')}")
    print(f"Score: {match.meta.get('description')}")
    print(f"Match: {match.strings}")
    print()

def fetch_all_yara_rules():
    valhalla_rules_path = join(get_default_root(),'valhalla-rules.yar')
    fireeye_rules_path = join(get_default_root(),'fireeye-rules.yar')
    reversinglabs_rules_path = join(get_default_root(),'reversinglabs-rules.yar')
    all_rules_compiled_path = join(get_default_root(),'all-yara-rules.compiled')
    fetch_valhalla_rules()
    fetch_fireeye_rules()
    fetch_reversinglabs_rules()
    rules = yara.compile(filepaths={
      'valhalla':valhalla_rules_path,
      'fireeye':fireeye_rules_path,
      'reversinglabs':reversinglabs_rules_path
    })
    rules = yara.save(all_rules_compiled_path)
    return rules

def fetch_fireeye_rules():
    pass

def fetch_reversinglabs_rules():
    pass

def fetch_valhalla_rules():
    v = ValhallaAPI()
    status = v.get_status()
    valhalla_rules_latest_version = str(status["version"])
    valhalla_rules_path = join(get_default_root(),'valhalla-rules.yar')
    valhalla_rules_version_path = join(get_default_root(),'valhalla-rules-versions')
    valhalla_rules_compiled_path = join(get_default_root(),'valhalla-rules.compiled')

    if isfile(valhalla_rules_path) and isfile(valhalla_rules_compiled_path):
        try:
            with open(valhalla_rules_version_path, 'r') as vvf:
                valhalla_rules_current_version = vvf.read()
            if valhalla_rules_current_version == valhalla_rules_latest_version:
                print("Valhalla rules are already up to date")
                return yara.load(valhalla_rules_compiled_path)
            else:
                print("Valhalla rules are outdated")

        except FileNotFoundError:
            pass

    print("Fetching latest valhalla rules....")
    rules = v.get_rules_text()
    with open(valhalla_rules_path, 'w') as fh:
        fh.write(rules)
    with open(valhalla_rules_version_path, 'w') as vvf:
        vvf.write(valhalla_rules_latest_version)
    rules = yara.compile(filepath=valhalla_rules_path)
    rules.save(valhalla_rules_compiled_path)
    return rules
