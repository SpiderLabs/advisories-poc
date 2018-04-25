import urllib2

host_port = "10.0.1.14:9000"
control_path = "TMSContentDirectory/Control"

soap_encoding = "http://schemas.xmlsoap.org/soap/encoding/"
soap_env = "http://schemas.xmlsoap.org/soap/envelope/"
service_ns = "urn:schemas-upnp-org:service:ContentDirectory:1"
method_name = "Browse"
soap_body = """<?xml version="1.0"?>
<s:Envelope xmlns:s="%s" s:encodingStyle="%s">
<s:Body>
<u:%s xmlns:u="%s">
<ObjectID>B</ObjectID>
<BrowseFlag>BrowseDirectChildren</BrowseFlag>
<Filter>*</Filter>
<StartingIndex>0</StartingIndex>
<RequestedCount>30</RequestedCount>
<SortCriteria></SortCriteria>
</u:%s>
</s:Body>
</s:Envelope>""" % (soap_env, soap_encoding, method_name, service_ns, method_name)

soap_action = "%s#%s" %(service_ns, method_name)
headers = {
'SOAPAction': u'"%s"' % (soap_action),
'Host': host_port,
'Content-Type': 'text/xml',
'Content-Length': len(soap_body),
}

ctrl_url = "http://%s/%s" %(host_port, control_path)

http_logger = urllib2.HTTPHandler(debuglevel = 1)
opener = urllib2.build_opener(http_logger) # put your other handlers here too!
urllib2.install_opener(opener)

request = urllib2.Request(ctrl_url, soap_body, headers)
response = urllib2.urlopen(request)
print response.read()

