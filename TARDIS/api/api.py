from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import socket
import shutil
from stix.core import STIXPackage
import TARDIS

app = FastAPI()

class TardisRequest(BaseModel):
    file: str
    ip: str
    hostname: str = None

@app.post("/parse/")
async def parse_tardis(request: TardisRequest):
    file = request.file
    sourceIP = request.ip
    sourceHost = request.hostname
    cve = ''
    vulnObject = ''

    if not os.path.exists(file):
        raise HTTPException(status_code=404, detail=f"{file} does not exist.")

    if sourceHost is None:
        try:
            result = socket.gethostbyaddr(sourceIP)
            sourceHost = result[0]
        except:
            sourceHost = ""

    if len(sourceHost) > 0:
        if os.path.exists('Results'):
            shutil.rmtree('Results')
        directory = 'Results'
        if not os.path.exists(directory):
            os.makedirs(directory)
        if not os.path.exists(directory + '/' + sourceIP):
            os.makedirs(directory + '/' + sourceIP)

        stix_package = STIXPackage.from_xml(file)
        results = []

        if stix_package.exploit_targets is not None:
            for target in stix_package.exploit_targets:
                for vuln in target.vulnerabilities:
                    vulnObject = str(vuln.description)
                    cve = vuln.cve_id
                    results.append({"cve_id": cve, "description": vulnObject})
                    if len(cve) > 0 and len(vulnObject) > 0:
                        if not os.path.exists('VulnXML/' + vuln.cve_id + '.xml'):
                            shutil.copyfile(file, 'VulnXML/' + vuln.cve_id + '.xml')
                        TARDIS.main(cve, vulnObject, sourceIP, sourceHost)
                    else:
                        raise HTTPException(status_code=400, detail="Description missing from Exploit Target")
            if len(results) == 0:
                raise HTTPException(status_code=400, detail="CVE Missing from STIX File")
        else:
            raise HTTPException(status_code=400, detail="No exploit targets found in the STIX file.")
    else:
        raise HTTPException(status_code=400, detail="Unable to resolve hostname, please provide one with -d option")

    return {"file": file, "ip": sourceIP, "hostname": sourceHost, "results": results}
