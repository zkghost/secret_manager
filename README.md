# Secret Manager
A local tool to encrypt and store sensitive data.

**WARNING**:
- This is in progress
- This is by no means the best/most-secure way to do things
- This is a hack I cooked up in 3 hours.

# Usage
```
>>> import secret_manager
>>> secret_manager = secret_manager.SecretStore()
>>> sensitive_data = {'password': 'my_dogs_name'}
>>> encrypted_data = secret_manager.store_secret('my_password', sensitive_data)
>>> # now decrypt it
... decrypted_data = secret_manager.retrieve_secret('my_password', encrypted_key)
>>> decrypted_data
{'password': 'my_dogs_name'}
```

# What's it do? 
Specify a secrets location on disk, and locations of existing AES and RSA priv/pub keys. Alternatively, if they aren't specified defaults will be generated (default location of secrets is ~/.secrets)

Data will be first signed with the AES symetric encryption key, then the AES key will be signed with the RSA public key. This signed key gets returned when you insert data into the secret store via `store_secret()`.

When you want to read your secret out, pass the name of your secret and your encrypted key to `retrieve_secret()` and it will use the private RSA key to decrypt your AES key, and use the decrypted AES key to decrypt your data. 

Secrets are stored on disk under `<secrets_dir>/<secret_name>`. 

# Why?
I had some sensitive data I didn't want to store on disk in a flat file. I thought this was a better approach. 

# What's next?
I might break this out into a proper client-server architecture where the caller supplies the private key. We will see. 
