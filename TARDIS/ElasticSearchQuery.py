"""
* Copyright (C) 2015 Tripwire, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
"""

from datetime import datetime
from elasticsearch import Elasticsearch
import xml.etree.ElementTree as ET
import socket, struct
import mysql.connector


def ip2long(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]


def searchVulnerability(searchString, vulnerability, sourceIP, sourceHost):
    # Get Settings
    elasticSearch_ip = ""
    db_ip = ""
    db_user = ""
    db_name = ""
    db_pass = ""
    try:
        configFile = "config.xml"
        tree = ET.parse(configFile)
        root = tree.getroot()
    except:
        sys.exit("Not a valid XML file")
    for settings in root.findall("./elastic_search"):
        for ip in settings.findall("./ip"):
            elasticSearch_ip = ip.text
    for dbsettings in root.findall("./db"):
        for dbip in dbsettings.findall("./ip"):
            db_ip = dbip.text
        for dbname in dbsettings.findall("./db_name"):
            db_name = dbname.text
        for dbuser in dbsettings.findall("./user"):
            db_user = dbuser.text
        for dbpass in dbsettings.findall("./password"):
            db_pass = dbpass.text

    es = Elasticsearch(
        cloud_id="6b61a1c6f36b4d82a8cc05fddfc1274d:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJDY1YTFmYTRiM2IzYjRjNjdhYjYzMDI0OGY4YjIxMGZhJDVlZTc5YzI0ZDg1NDQxNzZiNTAzNWQ2NDNlNGIzMjM5",
        api_key="NWJDSVpaRUJHby15dG9CcFRCWFI6MzFsd1h1N0tRamFyM1hRVXFaZTJHZw==",
    )

	
    print("the mofucking searchString is " + str(searchString))
    res = es.search(index="logstash-*", body=searchString)
    print("the mofucking res is " + str(res))

    return res
