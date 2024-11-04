import datetime
import jwt
import json

def generate_jwt_payload(service_account_email, resource_url):
  """Generates JWT payload for service account.

  The resource url provided must be the same as the url of the IAP secured resource.

  Args:
    service_account_email (str): Specifies service account JWT is created for.
    resource_url (str): Specifies scope of the JWT, the URL that the JWT will be allowed to access.
  Returns:
    A signed-jwt that can be used to access IAP protected applications.
    Access the application with the JWT in the Authorization Header.
    curl --verbose --header 'Authorization: Bearer SIGNED_JWT' URL
  """
  iat = datetime.datetime.now(tz=datetime.timezone.utc)
  exp = int(iat.timestamp()) + 3600
  return {
      'iss': service_account_email,
      'sub': service_account_email,
      'aud': resource_url,
      'iat': int(iat.timestamp()),
      'exp': exp,
  }

def sign_jwt_with_key_file(credential_key_file_path, resource_url):
  """Signs JWT payload using local service account credential key file.

  Args:
    credential_key_file_path (str): Path to the downloaded JSON credentials of the service
      account the JWT is being created for.
    resource_url (str): Scope of JWT token, This is the url of the IAP protected application.
  Returns:
    A service account JWT created with a downloaded private key.
  """
  with open(credential_key_file_path, 'r') as credential_key_file:
      key_data = json.load(credential_key_file)

  PRIVATE_KEY_ID_FROM_JSON = key_data["private_key_id"]
  PRIVATE_KEY_FROM_JSON = key_data["private_key"]
  SERVICE_ACCOUNT_EMAIL = key_data["client_email"]

  additional_headers = {
      "alg": "RS256",
      "typ": "JWT",
      "kid": PRIVATE_KEY_ID_FROM_JSON
  }

  payload = generate_jwt_payload(service_account_email=SERVICE_ACCOUNT_EMAIL, resource_url=resource_url)

  signed_jwt = jwt.encode(
      payload,
      PRIVATE_KEY_FROM_JSON,
      headers=additional_headers,
      algorithm='RS256',
  )
  return signed_jwt

token = sign_jwt_with_key_file("./payload_GCP.json", 'MYURL')

print(token)