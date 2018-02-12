import re
import subprocess

import urllib
import urllib2
from OpenSSL import crypto


class SSLStoreAPI():
    def __init__(self, partner_code, auth_token, sandbox=True):
        self.partner_code = str(partner_code)
        self.auth_token = auth_token
        self.sandbox = sandbox

        if sandbox:
            self.api_url = "https://sandbox-wbapi.thesslstore.com/rest/"
        else:
            self.api_url = "https://api.thesslstore.com/rest/"

    def __api_call(self, endpoint, fields):
        url = self.api_url + endpoint;
        fields['AuthRequest'] = {
            "PartnerCode": self.partner_code,
            "AuthToken": self.auth_token,
            "IsUsedForTokenSystem": False
        }
        payload = json.dumps(
            fields, sort_keys=True, indent=4, separators=(',', ': '))
        headers = {
            'Content-Type': 'application/json'
        }

        request = urllib2.Request(url, headers=headers, data=payload)
        request.get_method = lambda: 'POST'
        result = ''
        try:
            result = urllib2.urlopen(request)
        except urllib2.HTTPError as e:
            print e.read()
        except Exception as e:
            print e
        else:
            result = result.read()
        return json.loads(result)

    def get_approver_emails(self, domain, product_code='positivessl'):
        fields = {
            "DomainName": domain,
            "ProductCode": product_code
        }
        result = self.__api_call('order/approverlist', fields)
        return result['ApproverEmailList']

    def check_csr(self, csr, domain, product_code='positivessl'):
        csr = self.__escape(csr)
        fields = {
            "CSR": csr,
            "DomainName": domain,
            "ProductCode": product_code
        }
        return self.__api_call('csr', fields)

    def create_dv_ssl_order(
        self, csr, domain, product_code='positivessl',
        web_server_type="Other", custom_order_id=None, order_request=None):

        csr = self.__escape(csr)
        fields = {
            "ProductCode": product_code,
            "TechnicalContact": order_request['technical_contact'],
            "ValidityPeriod": '12',
            "WebServerType": web_server_type,
            "CSR": csr,
            "DomainName": domain,
            "ApproverEmail": order_request["ApproverEmail"],
            "isCUOrder": False,
            "isRenewalOrder": False,
            "isTrialOrder": False,
            "ServerCount": order_request["ServerCount"],
            "HTTPSFileAuthDVIndicator": True,
            "FileAuthDVIndicator": order_request["FileAuthDVIndicator"],
            "CNAMEAuthDVIndicator": False,
            "JurisdictionCountry": order_request["OrganizationInfo"]["JurisdictionCountry"],
            "OrganizationInfo": order_request["OrganizationInfo"],
            "AdminContact": order_request["AdminContact"],
            "SignatureHashAlgorithm": "SHA2-256"
        }
        if custom_order_id:
            fields['CustomOrderID'] = str(custom_order_id)
        return self.__api_call('order/neworder/', fields)

    def confirm_agreement(
        self, domain, product_code='positivessl',
        web_server_type="Other", custom_order_id=None, order_request=None):

        fields = {
            "ProductCode": product_code,
            "TechnicalContact": order_request['technical_contact'],
            "ValidityPeriod": "12",
            "WebServerType": web_server_type,
            "DomainName": domain,
            "isCUOrder": False,
            "isRenewalOrder": False,
            "isTrialOrder": False,
            "ServerCount": order_request["ServerCount"],
            "FileAuthDVIndicator": order_request["FileAuthDVIndicator"],
            "CNAMEAuthDVIndicator": False,
            "JurisdictionCountry": order_request["OrganizationInfo"]["JurisdictionCountry"],
            "OrganizationInfo": order_request["OrganizationInfo"],
            "AdminContact": order_request["AdminContact"]
        }

        if custom_order_id:
            fields['CustomOrderID'] = str(custom_order_id)
        return self.__api_call('order/agreement/', fields)

    def get_order_status(self, order_id):
        return self.__api_call('order/status', {"TheSSLStoreOrderID": order_id})

    def get_certificates(self, order_id):
        return self.__api_call(
            'order/download',
            {"TheSSLStoreOrderID": order_id}
        )

    def resend_email(self, order_id):
        try:
            return self.__api_call(
                'order/resend',
                {
                    "TheSSLStoreOrderID": order_id,
                    "ResendEmailType": "ApproverEmail"
                }
            )
        except KeyError:
            return True

    def __escape(self, s):
        return urllib.quote_plus(s.encode("utf-8"))

	@staticmethod
	def generate_chain(cert_text, separate=False):
	    issuer_re = re.compile('^CA Issuers - URI:(.*)$', re.MULTILINE)
	    store = None
	    chain = ''
	    first = True
	    found = True
	    n = 0
	    certs = []
	    while found:
	        # parse the certificate data
	        try:
	            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_text)
	        except:
	            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_text)
	        certs.append(cert)

	        # check and write the certificate
	        if cert.has_expired():
	            raise Exception("Error: Certificate expired")

	        if n != 0:
	            chain += crypto.dump_certificate(crypto.FILETYPE_PEM, cert) + "\n"
	        n = n+1
	        # check if we should stop
	        if store:
	            try:
	                crypto.X509StoreContext(store, cert).verify_certificate()
	                break
	            except:
	                pass

	        # try to fetch the next certificate
	        found = False
	        num_extensions = cert.get_extension_count()
	        for i in range(0,num_extensions-1):
	            extension = cert.get_extension(i)
	            if extension.get_short_name() == "authorityInfoAccess":
	                aia = str(extension)
	                m = issuer_re.search(aia)
	                if m:
	                    found = True
	                    infile = urllib2.urlopen(m.group(1))
	                    contenttype = infile.info().gettype()
	                    cert_text = infile.read()
	                    if contenttype == "application/x-pkcs7-mime":
	                        # HACK: call the openssl cli tool since pyOpenSSL doesn't export the functions to process PKCS#7 data
	                        proc = subprocess.Popen(["openssl", "pkcs7", "-inform", "DER", "-outform", "PEM", "-print_certs"],
	                                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	                        out, err = proc.communicate(cert_text)
	                        if proc.returncode != 0:
	                            proc = subprocess.Popen(["openssl", "pkcs7", "-inform", "PEM", "-outform", "PEM", "-print_certs"],
	                                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	                            out, err = proc.communicate(cert_text)
	                            if proc.returncode != 0:
	                                raise Exception("Invalid PKCS#7 data encountered\n")
	                        cert_text = out
	    return chain

    @staticmethod
    def createKeyPair(type=crypto.TYPE_RSA, bits=2048):
	    """
	    Create a public/private key pair.
	    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA

	               bits - Number of bits to use in the key
	    Returns:   The public/private key pair in a PKey object
	    """
	    pkey = crypto.PKey()
	    pkey.generate_key(type, bits)
	    return pkey

    @staticmethod
    def createCertRequest(pkey, digest="md5", **names):
	    """
	    Create a certificate request.
	    Arguments: pkey   - The key to associate with the request
	               digest - Digestion method to use for signing, default is md5
	               **name - The name of the subject of the request, possible
	                        arguments are:
	                          C     - Country name
	                          ST    - State or province name
	                          L     - Locality name
	                          O     - Organization name
	                          OU    - Organizational unit name
	                          CN    - Common name
	                          emailAddress - E-mail address
	    Returns:   The certificate request in an X509Req object
	    """
	    req = crypto.X509Req()
	    subj = req.get_subject()
	    for (key,value) in names.items():
	        setattr(subj, key, value)
	    req.set_pubkey(pkey)
	    req.sign(pkey, digest)
	    return (req, crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))