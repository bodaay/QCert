package postman

//Just copy the content of postmanCollection.json file into this variable
const PostmanJsonVar = `{
	"info": {
		"_postman_id": "203f2c09-bc7d-47be-8739-b07a671dd6e9",
		"name": "QCert",
		"description": "A set of api calls, to local QCert server to generate,sign certificates easily",
		"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
	},
	"item": [
		{
			"name": "RootCA",
			"item": [
				{
					"name": "Create New Root Certificate",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "data",
									"value": "{\n\t\"CommonName\" : \"My New Root CA\",\n\t\"Organization\" : \"My Fun Organization\",\n\t\"NotAfterNumberOfYears\" : 20\n}\n",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/root/new",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"root",
								"new"
							]
						},
						"description": "This will Create a completly New Root Certificate\nThe json to be sent has to foolow this format:\n\n{\n\t\"CommonName\" : \"You Root CA CommonName\",\n\t\"Organization\" : \"You Root CA Organization Name\",\n\t\"NotAfterNumberOfYears\" : 20\n}\n\nNote: NotAfterNumberOfYears can be ignored, its optional, default value is: 20"
					},
					"response": []
				}
			],
			"description": "All API Calls to Deal with Root Certificates",
			"protocolProfileBehavior": {}
		},
		{
			"name": "Intermediate",
			"item": [
				{
					"name": "Create New Signed Intermediate Certificate",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "rootCertFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.cert"
								},
								{
									"key": "rootCertPrivateKey",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.key"
								},
								{
									"key": "data",
									"value": "{\n\t\"CommonName\" : \"My New Intermediate CA\",\n\t\"Organization\" : \"My Fun Organization\",\n\t\"NotAfterNumberOfYears\" : 15\n}\n",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/int/new",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"int",
								"new"
							]
						}
					},
					"response": []
				},
				{
					"name": "Sign Intermediate Certificate CSR with RootCA",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "csrFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate.csr"
								},
								{
									"key": "rootCertFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.cert"
								},
								{
									"key": "rootCertPrivateKey",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.key"
								},
								{
									"key": "NotAfterNumberOfYears",
									"value": "15",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/int/sign",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"int",
								"sign"
							]
						}
					},
					"response": []
				},
				{
					"name": "Create New Intermediate Certificate Sign Request",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "data",
									"value": "{\n\t\"CommonName\" : \"My New Intermediate CA\",\n\t\"Organization\" : \"My Fun Organization\"\n}\n",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/int/csr",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"int",
								"csr"
							]
						},
						"description": "This will Create a completly New Root Certificate\nThe json to be sent has to foolow this format:\n\n{\n\t\"CommonName\" : \"You Root CA CommonName\",\n\t\"Organization\" : \"You Root CA Organization Name\",\n\t\"NotAfterNumberOfYears\" : 20\n}\n\nNote: NotAfterNumberOfYears can be ignored, its optional, default value is: 20"
					},
					"response": []
				}
			],
			"description": "All API Calls to Deal with Intermediate Certificates",
			"event": [
				{
					"listen": "prerequest",
					"script": {
						"id": "12874c3a-171f-4b76-aadd-7e2d30bd913c",
						"type": "text/javascript",
						"exec": [
							""
						]
					}
				},
				{
					"listen": "test",
					"script": {
						"id": "85c05a77-7e34-46e0-a8d8-c219b54c0c1a",
						"type": "text/javascript",
						"exec": [
							""
						]
					}
				}
			],
			"protocolProfileBehavior": {}
		},
		{
			"name": "Server",
			"item": [
				{
					"name": "Create New Signed (By Root/Intermediate) Server Certificate",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "caCertFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate_signed/Out/intermediate/intermediate.cert"
								},
								{
									"key": "caPrivateKey",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate.key"
								},
								{
									"key": "data",
									"value": "{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}\n",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/server/new",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"server",
								"new"
							]
						},
						"description": "Example For Data, only commonname and Organizations are required, rest of the field can be ignored or removed\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\"\n}\n\nFull Example\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}"
					},
					"response": []
				},
				{
					"name": "Sign Server Certificate CSR with RootCA/IntermediateCA",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "csrFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate.csr"
								},
								{
									"key": "caCertFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.cert"
								},
								{
									"key": "caPrivateKey",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.key"
								},
								{
									"key": "NotAfterNumberOfYears",
									"value": "10",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/server/sign",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"server",
								"sign"
							]
						},
						"description": "You can either use RootCA or Intermediate to sign Certificate, if you do use intermediate, an extra certificate bundle will be created for you, which includes intermediate certificate"
					},
					"response": []
				},
				{
					"name": "Create New Server Certificate Sign Request",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "data",
									"value": "{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/server/csr",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"server",
								"csr"
							]
						},
						"description": "Example For Data, only commonname and Organizations are required, rest of the field can be ignored or removed\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\"\n}\n\nFull Example\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}"
					},
					"response": []
				}
			],
			"description": "All API Calls to Deal with Server Certificates",
			"event": [
				{
					"listen": "prerequest",
					"script": {
						"id": "12874c3a-171f-4b76-aadd-7e2d30bd913c",
						"type": "text/javascript",
						"exec": [
							""
						]
					}
				},
				{
					"listen": "test",
					"script": {
						"id": "85c05a77-7e34-46e0-a8d8-c219b54c0c1a",
						"type": "text/javascript",
						"exec": [
							""
						]
					}
				}
			],
			"protocolProfileBehavior": {}
		},
		{
			"name": "Client",
			"item": [
				{
					"name": "Create New Signed (By Root/Intermediate) Client Certificate",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "caCertFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate_signed/Out/intermediate/intermediate.cert"
								},
								{
									"key": "caPrivateKey",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate.key"
								},
								{
									"key": "data",
									"value": "{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"NotAfterNumberOfYears\": 5\n}\n",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/client/new",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"client",
								"new"
							]
						},
						"description": "Example For Data, only commonname and Organizations are required, rest of the field can be ignored or removed\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\"\n}\n\nFull Example\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}"
					},
					"response": []
				},
				{
					"name": "Sign Client Certificate CSR with RootCA/IntermediateCA",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "csrFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate.csr"
								},
								{
									"key": "caCertFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.cert"
								},
								{
									"key": "caPrivateKey",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.key"
								},
								{
									"key": "NotAfterNumberOfYears",
									"value": "5",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/client/sign",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"client",
								"sign"
							]
						},
						"description": "You can either use RootCA or Intermediate to sign Certificate, if you do use intermediate, an extra certificate bundle will be created for you, which includes intermediate certificate"
					},
					"response": []
				},
				{
					"name": "Create New Client Certificate Sign Request",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "data",
									"value": "{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"NotAfterNumberOfYears\": 5\n}",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/client/csr",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"client",
								"csr"
							]
						},
						"description": "Example For Data, only commonname and Organizations are required, rest of the field can be ignored or removed\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\"\n}\n\nFull Example\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"NotAfterNumberOfYears\": 5\n}"
					},
					"response": []
				}
			],
			"description": "All API Calls to Deal with Client Certificates",
			"event": [
				{
					"listen": "prerequest",
					"script": {
						"id": "12874c3a-171f-4b76-aadd-7e2d30bd913c",
						"type": "text/javascript",
						"exec": [
							""
						]
					}
				},
				{
					"listen": "test",
					"script": {
						"id": "85c05a77-7e34-46e0-a8d8-c219b54c0c1a",
						"type": "text/javascript",
						"exec": [
							""
						]
					}
				}
			],
			"protocolProfileBehavior": {}
		},
		{
			"name": "Peer ",
			"item": [
				{
					"name": "Create New Signed (By Root/Intermediate) Peer Certificate",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "caCertFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate_signed/Out/intermediate/intermediate.cert"
								},
								{
									"key": "caPrivateKey",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate.key"
								},
								{
									"key": "data",
									"value": "{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}\n",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/peer/new",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"peer",
								"new"
							]
						},
						"description": "Example For Data, only commonname and Organizations are required, rest of the field can be ignored or removed\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\"\n}\n\nFull Example\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}"
					},
					"response": []
				},
				{
					"name": "Sign Peer Certificate CSR with RootCA/IntermediateCA",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "csrFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/intermediate_csr/Out/intermediate_csr/intermediate.csr"
								},
								{
									"key": "caCertFile",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.cert"
								},
								{
									"key": "caPrivateKey",
									"type": "file",
									"src": "/C:/Users/Khalefa/Desktop/rootca/Out/rootca/rootca.key"
								},
								{
									"key": "NotAfterNumberOfYears",
									"value": "10",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/peer/sign",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"peer",
								"sign"
							]
						},
						"description": "You can either use RootCA or Intermediate to sign Certificate, if you do use intermediate, an extra certificate bundle will be created for you, which includes intermediate certificate\nPeer same as Server, difference in peer ExtKeyUsage will be for both TLS Web Server and TLS Web Client Authentication"
					},
					"response": []
				},
				{
					"name": "Create New Peer Certificate Sign Request",
					"request": {
						"method": "POST",
						"header": [],
						"body": {
							"mode": "formdata",
							"formdata": [
								{
									"key": "data",
									"value": "{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}",
									"type": "text"
								}
							],
							"options": {
								"raw": {
									"language": "json"
								}
							}
						},
						"url": {
							"raw": "http://localhost:11129/peer/csr",
							"protocol": "http",
							"host": [
								"localhost"
							],
							"port": "11129",
							"path": [
								"peer",
								"csr"
							]
						},
						"description": "Peer same as Server, difference in peer ExtKeyUsage will be for both TLS Web Server and TLS Web Client Authentication\nExample For Data, only commonname and Organizations are required, rest of the field can be ignored or removed\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\"\n}\n\nFull Example\n{\n  \"CommonName\": \"example.com\",\n  \"Organization\": \"Exmaple Company\",\n  \"Country\": \"QA\",\n  \"Province\": \"DOHA\",\n  \"Locality\": \"DOHA\",\n  \"DNSNames\": [\"www.hostname.com\",\"f.test.com\"],\n  \"IPAddresses\": [\"127.0.0.1\",\"0.0.0.0\"],\n  \"NotAfterNumberOfYears\": 10\n}"
					},
					"response": []
				}
			],
			"description": "All API Calls to Deal with Peer Certificates\nPeer same as Server, difference in peer ExtKeyUsage will be for both TLS Web Server and TLS Web Client Authentication",
			"event": [
				{
					"listen": "prerequest",
					"script": {
						"id": "12874c3a-171f-4b76-aadd-7e2d30bd913c",
						"type": "text/javascript",
						"exec": [
							""
						]
					}
				},
				{
					"listen": "test",
					"script": {
						"id": "85c05a77-7e34-46e0-a8d8-c219b54c0c1a",
						"type": "text/javascript",
						"exec": [
							""
						]
					}
				}
			],
			"protocolProfileBehavior": {}
		}
	],
	"protocolProfileBehavior": {}
}`
