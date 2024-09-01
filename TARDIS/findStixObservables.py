'''
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
'''


import os, re, sys
import xml.etree.ElementTree as ET
from pprint import pprint
from stix.core import STIXPackage
from stix.core import STIXHeader
from stix.indicator import Indicator
from cybox.objects.win_event_log_object import WinEventLog
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File
import splunk
import dateutil.parser
import datetime

def buildSearchString(column, value, condition):
    logsource = ''
    try:
        configFile = 'config.xml'
        tree = ET.parse(configFile)
        root = tree.getroot()
    except:
        sys.exit("Not a valid config XML file")

    for settings in root.findall("./log_source"):
        logsource = settings.text

    if logsource == "splunk":
        searchString = "search "
        searchString += column + "=\""
        if condition == "EndsWith":
            searchString += "*"
        searchString += value
        if condition == "StartsWith":
            searchString += "*"
        searchString += "\""
        return searchString

    elif logsource == "elastic_search":
        sourceColumn = getColumnName("Source")
        searchString = {
            "from": 0,
            "size": 100,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gt": "<startTime>",
                                    "lt": "<endTime>"
                                }
                            }
                        }
                    ],
                    "should": [
                        {
                            "prefix": {
                                column: value
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "prefix": {
                                            sourceColumn: "<source_ip>"
                                        }
                                    },
                                    {
                                        "prefix": {
                                            sourceColumn: "<source_host>"
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ],
                    "minimum_should_match": "<min_count>"
                }
            }
        }
        return searchString

    else:
        sys.exit("Unknown Log Source in Config XML")

def getColumnName(column):
    # Placeholder function for getting the column name
    return column

def getColumnName(column):
	for line in open("dbColumns.config"):
		if (column + ":") in line:
			columnName = re.sub('\\S+\\:', '', line)
			columnName = re.sub('(\r\n|\r|\n)', '', columnName)
			return columnName

def run(vid):
	vulnXMLFile='VulnXML/' + vid + '.xml'
	fileCheck = os.path.exists(vulnXMLFile)
	if fileCheck==True:
		searchString = search(vulnXMLFile)
		print("searchString : " + str(searchString))

		return(searchString)
	else:
		searchString = []
		searchString.append("OR")
		searchString.append("No search file found")
		print("searchString : " + str(searchString))

		return(searchString)

def search(file):
	searchString = []
	operator="OR"
	columnName=''
	# Parse input file
	stix_package = STIXPackage.from_xml(file)

	if stix_package.indicators is not None:
		for observableList in stix_package.indicators:
			condition="equals"
			try:
				operator=observableList.observable.observable_composition.operator
			except:
				operator="OR"
			searchString.append(operator)
			try:

				print("observavles : " + str(observableList.observable.observable_composition.observables))

				for child in observableList.observable.observable_composition.observables:
					condition=""
					observableValue=''

					print("child : " + str(child))
					print("child.object_ : " + str(child.object_))
					print("child.object_.properties : " + str(child.object_.properties))
					print("NetworkConnection : " + str(File))
					if (type(child.object_.properties) == NetworkConnection):
						# a check to see if the observable is a network connection
						print("is a network connection")

						# print("child.object_.properties._fields['Layer7_Connections'] : " + str(child.object_.properties._fields["Layer7_Connections"]))
						# if (child.object_.properties._fields["Layer7_Connections"] != None):
						# 	try:
						# 		observableValue=child.object_.properties._fields["Layer7_Connections"]._fields["HTTP_Session"]._fields["HTTP_Request_Response"][0]._fields["HTTP_Client_Request"]._fields["HTTP_Request_Header"]._fields["Parsed_Header"]._fields["User_Agent"].value
						# 		HTTPUserAgentCondition=child.object_.properties._fields["Layer7_Connections"]._fields["HTTP_Session"]._fields["HTTP_Request_Response"][0]._fields["HTTP_Client_Request"]._fields["HTTP_Request_Header"]._fields["Parsed_Header"]._fields["User_Agent"].condition
						# 		columnName = getColumnName("HTTPUserAgent")
						# 		if (HTTPUserAgentCondition=="StartsWith"):
						# 			condition="StartsWith"
						# 	except:
						# 		error="don't worry about it, probably looking for a different value in field"
						# 	try:
						# 		observableValue=child.object_.properties._fields["Layer7_Connections"]._fields["HTTP_Session"]._fields["HTTP_Request_Response"][0]._fields["HTTP_Server_Response"]._fields["HTTP_Status_Line"]._fields["Status_Code"].value
						# 		columnName = getColumnName("HTTPStatusCode")
						# 	except:
						# 		error="don't worry about it, probably looking for a different value in field"
							

					if (type(child.object_.properties) == WinEventLog):
						# a check to see if the observable is a windows event log
						print("is a windows event log")
						columnName = getColumnName("WindowsEventID")
						observableValue=child.object_.properties._fields["EID"].value
					if (type(child.object_.properties) == Address):
						# a check to see if the observable is an address
						print("is an address")
						columnName = getColumnName("IPAddress")
						observableValue= child.object_.properties
					if (type(child.object_.properties) == File):
						# a check to see if the observable is a file
						print("is a file")
						try:
							for hash in child.object_.properties.hashes:
								if re.match('^\\w{40}',str(hash)):
									columnName = getColumnName("SHA1Hash")
									observableValue=hash
								if re.match('^\\w{32}',str(hash)):
									columnName = getColumnName("MD5Hash")
									observableValue=hash
						except: 
							error="don't worry about it, probably looking for a different value in field"
					searchString.append(buildSearchString(columnName,str(observableValue),condition))
			except Exception as e:
				print("error: " + str(e))
				print("observables : " + str(observableList.observable.observable_composition.observables))
				print("observables : " + str(observableList.observable.object_))
				# print("observable properties : " + str(observableList.observable.object_.properties))


				if observableList.observable.object_ is not None:

					if (type(observableList.observable.object_.properties) == File):
						hash = observableList.observable.object_.properties.hashes[0].simple_hash_value.value
						if re.match('^\\w{40}',str(hash)):
							columnName = getColumnName("SHA1Hash")
							observableValue=hash
						if re.match('^\\w{32}',str(hash)):
							columnName = getColumnName("MD5Hash")
							observableValue=hash	
						searchString.append(buildSearchString(columnName,str(observableValue),condition))
					if (type(observableList.observable.object_.properties) == Address):
						ipv4 = observableList.observable.object_.properties.address_value.value
						columnName = getColumnName("IPAddress")
						observableValue=ipv4
						condition=observableList.observable.object_.properties.address_value.condition
						searchString.append(buildSearchString(columnName,str(observableValue),str(condition)))
					if (type(observableList.observable.object_.properties) == URI):
						uri = observableList.observable.object_.properties.value.value
						observableValue = uri
						columnName = getColumnName("URI")
						searchString.append(buildSearchString(columnName,str(observableValue),str(condition)))

	if (len(searchString) < 2):
		searchString.append("No supported observables found")
	return searchString

