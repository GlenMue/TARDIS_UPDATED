from fastapi import (
    FastAPI,
    File,
    UploadFile,
    Form,
    Depends,
    HTTPException,
    status,
    Query,
    Request
)
from pydantic import BaseModel
import os
import socket
import shutil
from stix.core import STIXPackage
import TARDIS
import uvicorn
import random
from typing import Annotated
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "localhost:3000",
        "https://baskket.shop"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TardisRequest(BaseModel):
    # file should be of type upload
    file: UploadFile = File(...)
    ip: str
    hostname: str = None

# to upload the file to uploadedFiles folder
# @app.post("/upload/")
# async def upload_file(file: UploadFile):
#     file_path = os.path.join("uploadedFiles", file.filename)
#     with open(file_path, "wb") as f:
#         f.write(file.file.read())
#     return {"file": file_path}

@app.post("/upload")
async def upload_file(
    file: Annotated[UploadFile, File()],
):
    print(file)
    try:
        if file.content_type:
            extension = file.content_type.split("/")[-1]
            content = await file.read()
            disk_filename = file.filename

            # check if the folder finalStix exists
            if not os.path.exists("finalStix"):
                os.makedirs("finalStix")

            # Write the file to disk
            with open(f"finalStix/{disk_filename}", "wb") as image_file:
                image_file.write(content)
            return {"image_uri": f"{disk_filename}", "msg": "Success"}
    except Exception as e:
        print(e)
        return {"msg": "Failed", "error": str(e)}

@app.post("/parse/")
async def parse_tardis(file: str, sourceIP: str, sourceHost: str=None):
    cve = ''
    vulnObject = ''

    # get the file directory path as a string
    file = "finalStix/"+file
    if not os.path.exists(file):
        print(str(file) + " does not exist.")

        raise HTTPException(status_code=404, detail=f"{file} does not exist.")

    # if sourceHost is None:
    try:
        result = socket.gethostbyaddr(sourceIP)
        sourceHost = result[0]
    except:
        sourceHost = ""

    if len(sourceHost) > 0:
        print("File: " + file)
        print("IP:   " + sourceIP)
        print("Host: " + sourceHost)
    
        if os.path.exists('Results'):
            shutil.rmtree('Results')
        directory = 'Results'
        if not os.path.exists(directory):
            os.makedirs(directory)
        if not os.path.exists(directory + '/' + sourceIP):
            os.makedirs(directory + '/' + sourceIP)

        stix_package = STIXPackage.from_xml(file)
        results = []
        print("this is the mofucking stix package:"+ str(stix_package))


        if stix_package.exploit_targets is not None:
            for target in stix_package.exploit_targets:
                for vuln in target.vulnerabilities:
                    print("CVE: " + vuln.cve_id)
                    print("DESC:" + str(vuln.description))
                    vulnObject = str(vuln.description)
                    cve = vuln.cve_id
                    results.append({"cve_id": cve, "description": vulnObject})
                    if len(cve) > 0 and len(vulnObject) > 0:
                        if not os.path.exists('VulnXML/' + vuln.cve_id + '.xml'):
                            shutil.copyfile(file, 'VulnXML/' + vuln.cve_id + '.xml')
                        print(f"inserting IP: {sourceIP} and hostname: {sourceHost} into the database")

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

