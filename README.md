# TheSSLStoreAPI
### Order request example:


```javascript
		technical_contact = {
			"FirstName": <string>,
			"LastName": <string>,
			"Country": <string>,
			"City": <string>,
			"AddressLine1": <string>,
			"Region": <string>,
			"PostalCode": <string>,
			"Title": <string>,
			"Phone": <string>,
			"Email": <string>
			}
			admin_contact = {
				"FirstName": <string>,
				"LastName": <string>,
				"Country": <string>,
				"City": <string>,
				"AddressLine1": <string>,
				"Region": <string>,
				"PostalCode": <string>,
				"Title": <string>,
				"OrganizationName": <string>,
				"Email": <string>,
				"Phone": <string>
				}
				organization = {
					"OrganizationName": <string>,
					"JurisdictionCountry": <string>,
					"RegistrationNumber": <string>,
					"OrganizationAddress":{
					"AddressLine1": <string>,
					"City": <string>,
					"Region": <string>,
					"PostalCode": <string>,
					"Country": <string>,
					"LocalityName": <string>,
					"Phone": <string>
				}
				}
				order_request = {
					"technical_contact": technical_contact,
					"AdminContact": admin_contact,
					"OrganizationInfo": organization,
					"FileAuthDVIndicator": <bool>,
					"ServerCount": <string>,
					"CSREmail": <string>,
					'product_code': <string>
				}
```
