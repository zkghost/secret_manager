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
