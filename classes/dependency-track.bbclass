# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

DEPENDENCYTRACK_DIR ??= "${DEPLOY_DIR}/dependency-track/${MACHINE}"
DEPENDENCYTRACK_SBOM ??= "${DEPENDENCYTRACK_DIR}/bom.json"
DEPENDENCYTRACK_TMP ??= "${TMPDIR}/dependency-track/${MACHINE}"
DEPENDENCYTRACK_LOCK ??= "${DEPENDENCYTRACK_TMP}/bom.lock"

# Set DEPENDENCYTRACK_UPLOAD to False if you want to control the upload in other
# steps.
DEPENDENCYTRACK_UPLOAD ??= "False"
DEPENDENCYTRACK_PROJECT ??= ""
DEPENDENCYTRACK_API_URL ??= "http://localhost:8081/api"
DEPENDENCYTRACK_API_KEY ??= ""

DT_LICENSE_CONVERSION_MAP ??= '{ "GPLv2+" : "GPL-2.0-or-later", "GPLv2" : "GPL-2.0", "LGPLv2" : "LGPL-2.0", "LGPLv2+" : "LGPL-2.0-or-later", "LGPLv2.1+" : "LGPL-2.1-or-later", "LGPLv2.1" : "LGPL-2.1"}'

python do_dependencytrack_init() {
    import uuid
    from datetime import datetime, timezone
    import hashlib

    sbom_dir = d.getVar("DEPENDENCYTRACK_DIR")
    bb.debug(2, "Creating cyclonedx directory: %s" % sbom_dir)
    bb.utils.mkdirhier(sbom_dir)

    bb.debug(2, "Creating empty sbom")
    write_sbom(d, {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "Kontron AIS GmbH",
                    "name": "dependency-track",
                    "version": "1.0"
                }
            ],
            "component": {
                "type": "operating-system",
                "bom-ref": hashlib.md5(d.getVar("MACHINE", False).encode()).hexdigest(),
                "group": d.getVar("MACHINE", False),
                "name": d.getVar("DISTRO_NAME", False) + "-" + d.getVar('MACHINE').replace("kontron-", ""),
                "version": d.getVar("SECUREOS_RELEASE_VERSION", False)
            }
        },
        "components": [],
        "dependencies": [],
    })
}
addhandler do_dependencytrack_init
do_dependencytrack_init[eventmask] = "bb.event.BuildStarted"

python do_dependencytrack_collect() {
    import json
    from pathlib import Path
    import hashlib
    # load the bom
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")
    sbom = read_sbom(d)

        # update it with the new package info


    for index, o in enumerate(get_cpe_ids(name, version)):
        bb.debug(2, f"Collecting package {name}@{version} ({o.cpe})")
        if not next((c for c in sbom["components"] if c["cpe"] == o.cpe), None):
            
            component_json = {
                "type": "application",
                "bom-ref": hashlib.md5(o.cpe.encode()).hexdigest(),
                "name": o.product,
                "group": o.vendor,
                "version": version,
                "cpe": o.cpe,
            }
            
            license_json = get_licenses(d)
            if license_json:
                component_json["licenses"] = license_json

            references = get_references(d)

            if references:
                component_json["externalReferences"] = references

            sbom["components"].append(component_json)

    # write it back to the deploy directory
    write_sbom(d, sbom)
}

addtask dependencytrack_collect before do_build after do_fetch
do_dependencytrack_collect[nostamp] = "1"
do_dependencytrack_collect[lockfiles] += "${DEPENDENCYTRACK_LOCK}"
do_rootfs[recrdeptask] += "do_dependencytrack_collect"

python do_dependencytrack_upload () {
    import json
    import base64
    import hashlib
    import urllib
    from pathlib import Path
    from oe.rootfs import image_list_installed_packages

    sbom = read_sbom(d)

    try:
        installed_pkgs = read_json(d, d.getVar("DEPENDENCYTRACK_TMP") + "/" + d.getVar("PN") + "_installed_packages.json")
    except FileNotFoundError:
        return
        
    pkgs_names = list(installed_pkgs.keys())

    bb.debug(2, f"Removing packages from SBOM: {pkgs_names}")

    sbom["components"] = [component for component in sbom["components"] if component["name"] in pkgs_names]

    components_dict = {component["name"]: component for component in sbom["components"]}

    for sbom_component in sbom["components"]:
        pkg = installed_pkgs.get(sbom_component["name"])
        
        if pkg:
            for dep in pkg.get("deps", []):
                dep_component = components_dict.get(dep)
                if dep_component:
                    depend = next((d for d in sbom["dependencies"] if d["ref"] == sbom_component["bom-ref"]), None)
                    if depend is None:
                        depend = {"ref": sbom_component["bom-ref"], "dependsOn": []}
                        depend["dependsOn"].append(dep_component["bom-ref"])
                        sbom["dependencies"].append(depend)
                    else:  
                        depend["dependsOn"].append(dep_component["bom-ref"])

    # Extract all ref values
    all_refs = {component["bom-ref"] for component in sbom["components"]}

    # Extract all dependsOn values
    all_depends_on = {ref for dependency in sbom["dependencies"] for ref in dependency.get("dependsOn", [])}

    # Find refs that are not in dependsOn
    refs_not_in_depends_on = all_refs - all_depends_on

    # add dependencies for components that are not in dependsOn
    sbom["dependencies"].append({ "ref": hashlib.md5(d.getVar("MACHINE", False).encode()).hexdigest(), "dependsOn": list(refs_not_in_depends_on) })
                
    write_sbom(d, sbom)

    dt_upload = bb.utils.to_boolean(d.getVar('DEPENDENCYTRACK_UPLOAD'))
    if not dt_upload:
        return

    
    dt_project = d.getVar("DEPENDENCYTRACK_PROJECT")
    dt_url = f"{d.getVar('DEPENDENCYTRACK_API_URL')}/v1/bom"

    payload = json.dumps({
        "project": dt_project,
        "bom": base64.b64encode(sbom.encode()).decode('ascii')
    }).encode()
    bb.debug(2, f"Uploading SBOM to project {dt_project} at {dt_url}")

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": d.getVar("DEPENDENCYTRACK_API_KEY")
    }
    req = urllib.request.Request(
        dt_url,
        data=payload,
        headers=headers,
        method="PUT")

    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        bb.error(f"Failed to upload SBOM to Dependency Track server at {dt_url}. [HTTP Error] {e.code}; Reason: {e.reason}")
    except urllib.error.URLError as e:
        bb.error(f"Failed to upload SBOM to Dependency Track server at {dt_url}. [URL Error] Reason: {e.reason}")
    else:
        bb.debug(2, f"SBOM successfully uploaded to {dt_url}")
}

python do_dependencytrack_installed () {
    from pathlib import Path
    from oe.rootfs import image_list_installed_packages

    pkgs = image_list_installed_packages(d)

    write_json(d, pkgs, d.getVar("DEPENDENCYTRACK_TMP") + "/" + d.getVar("PN")+ "_installed_packages.json")
}

ROOTFS_POSTUNINSTALL_COMMAND += "do_dependencytrack_installed;"

addhandler do_dependencytrack_upload
do_dependencytrack_upload[eventmask] = "bb.event.BuildCompleted"

def read_sbom(d):
    return read_json(d, d.getVar("DEPENDENCYTRACK_SBOM"))

def read_json(d, path):
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text())

def write_sbom(d, sbom):
    write_json(d, sbom, d.getVar("DEPENDENCYTRACK_SBOM"))

def write_json(d, data, path):
    import json
    from pathlib import Path
    Path(path).write_text(
        json.dumps(data, indent=2)
    )

def get_references(d):
    import re
    pattern = re.compile(r"http[s]*:\/\/[a-z.]*\/[a-z.\-\/]*[a-z.\-].(tar.([gxl]?z|bz2)|tgz)")
    src_uris = d.getVar("SRC_URI").split(" ")
    refs = []
    for src in src_uris:    # only check the first src uri otherwise we might end up with references of the dependencies
        if src.startswith("git://") or src.endswith(".git"):
            refs.append({"type": "vcs", "url": src})
            break
        elif pattern.match(src):
            refs.append({"type": "source-distribution", "url": src})
            break
        elif src.startswith("http://") or src.startswith("https://"):
            refs.append({"type": "website", "url": src})
            break
    return refs

def get_licenses(d) :
    from pathlib import Path
    import json
    license_expression = d.getVar("LICENSE")
    if license_expression:
        license_json = []
        licenses = license_expression.replace("|", "").replace("&", "").split()
        for license in licenses:
            license_conversion_map = json.loads(d.getVar('DT_LICENSE_CONVERSION_MAP'))
            converted_license = None
            try:
                converted_license =  license_conversion_map[license]
            except Exception as e:
                    pass
            if not converted_license:
                converted_license = license
            # Search for the license in COMMON_LICENSE_DIR and LICENSE_PATH
            for directory in [d.getVar('COMMON_LICENSE_DIR')] + (d.getVar('LICENSE_PATH') or '').split():
                try:
                    with (Path(directory) / converted_license).open(errors="replace") as f:
                        extractedText = f.read()
                        license_data = {
                            "license": {
                                "name" : converted_license,
                                "text": {
                                    "contentType": "text/plain",
                                    "content": extractedText
                                    }
                            }
                        }
                        license_json.append(license_data)
                        break
                except FileNotFoundError:
                    pass
            # license_json.append({"expression" : license_expression})
        return license_json 
    return None

def get_cpe_ids(cve_product, version):
    """
    Get list of CPE identifiers for the given product and version
    """

    version = version.split("+git")[0]

    cpe_ids = []
    for product in cve_product.split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = "*"

        cpe_id = 'cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*'.format(vendor, product, version)
        cpe_ids.append(type('',(object,),{"cpe": cpe_id, "product": product, "vendor": vendor if vendor != "*" else ""})())

    return cpe_ids