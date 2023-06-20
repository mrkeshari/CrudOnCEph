import requests
import xmltodict as xmltodict
from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from requests.exceptions import RequestException, HTTPError, ConnectionError, Timeout
import json
import datetime
import hashlib
import hmac
import base64
import logging
import re
import config as con



app = Flask(__name__)
api = Api(app)


access_key = con.access_key
secret_key = con.secret_key
endpoint_url = con.endpoint_url

timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
common_headers = {
            'Host': endpoint_url,
            'Date': timestamp
        }

class BucketList(Resource):

    #This class will list out all the buckets.
    def get(self):
        try:
            string_for_signature = f'GET\n\n\n{timestamp}\n/'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')
            auth_header = f'AWS {access_key}:{signature}'
            common_headers['Authorization'] = auth_header
            response = requests.get(endpoint_url + '/', headers=common_headers)
            if response.status_code == 200:
                dict_resp = xmltodict.parse(response.text)
                resp = dict_resp['ListAllMyBucketsResult']['Buckets']
                return resp
            else:
                return {"Error": "An error occurred"}, response.status_code
        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return {'error': "Something went wrong. Please try again later"}, 500

class Bucket(Resource):

    def get(self, bucket_name):
        # this function will list out bucket usage.
        try:
            url = f'{endpoint_url}/{bucket_name}'
            string_for_signature = f'GET\n\n\n{timestamp}\n/{bucket_name}'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')
            auth_header = f'AWS {access_key}:{signature}'
            common_headers['Authorization'] = auth_header
            response = requests.get(url, headers=common_headers)
            if response.status_code == 200:
                dict_resp = xmltodict.parse(response.text)
                li = []
                bucket_name = dict_resp['ListBucketResult']['Name']

                # checking for empty bucket
                if dict_resp['ListBucketResult'].get('Contents') is None:
                    return {bucket_name: li}

                contents = dict_resp['ListBucketResult'].get('Contents')
                for content in contents:
                    key = content.get('Key')
                    last_modified = content.get('LastModified')
                    size = content.get('Size')
                    li.append({'obj_name':key,'last_modified':last_modified,'size':size})

                return {bucket_name: li}
            elif response.status_code==404:
                return {"msg":"bucket doesn't exist"}
            else:
                return {"error": "An error Occurred"},500
        except Exception as e:
            logging.error(f'error occurred:{str(e)}')
            return {"error": "Something went wrong. Please try again later"}, 500

    def delete(self,bucket_name):
        # this function will delete bucket
        try:
            url = f'{endpoint_url}/{bucket_name}'
            string_for_signature = f'DELETE\n\n\n{timestamp}\n/{bucket_name}'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')
            auth_header = f'AWS {access_key}:{signature}'
            common_headers['Authorization'] = auth_header
            response = requests.delete(url, headers=common_headers)
            if response.status_code == 204:
                return {"msg": "bucket deleted successfully"}
            elif response.status_code == 404:
                return {"msg":f"The bucket {bucket_name} doesn't exist"}
            else:
                return {"msg": "Failed to delete bucket"}, response.status_code
        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return {'error': "Something went wrong. Please try again later"}, 500

class BucketCreation(Resource):
    def put(self):
        # this function will create a bucket.
        try:
            if not request.data.strip():
                return {'error': 'Empty payload. Please provide the bucket name.'}, 400
            request_data = request.get_json()
            if request_data.get('bucket_name') is None:
                return {'bucket_name': 'This field is compulsory for creating bucket'}, 400

            bucket_name = request_data.get('bucket_name')
            # validating bucket name
            name = re.match(r'(?!.*[-.]{2})(?!.*-\.)',bucket_name)
            if name is None:
                return {"msg":"Please enter valid bucket name"}
            else:
                name = re.match(r'^[a-z0-9][a-z0-9\-.]{1,61}[a-z0-9]$', bucket_name)
                if name is None:
                    return {"msg": "Please enter valid bucket name"}

            url = f'{endpoint_url}/{bucket_name}'
            string_for_signature = f'PUT\n\n\n{timestamp}\n/{bucket_name}'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')
            auth_header = f'AWS {access_key}:{signature}'
            common_headers['Authorization'] = auth_header
            response = requests.put(url, headers=common_headers)
            if response.status_code == 200:
                return {"msg": f'Bucket {bucket_name} created successfully'}
            else:
                return {"Error": "An error occurred"}, response.status_code

        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return {'error': "Something went wrong. Please try again later"}, 500




api.add_resource(BucketList, '/buckets')
api.add_resource(Bucket, '/bucket/<string:bucket_name>')
api.add_resource(BucketCreation, '/bucket')
app.run()