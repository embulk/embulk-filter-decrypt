# Decrypt filter plugin for Embulk

Converts columns using an encryption algorithm such as AES.

Encrypted data is encoded using base64 or hex. For example, if you have following input records (password column was encrypted):

* Base64
```csv
id,password,comment
1,XaBAt/J3LNqKCVlWbu2E+g==,a
2,gUzzC+nJSBLbPTAzJlbbMA==,b
```
* Hex
```csv
id,password,comment
1,5DA040B7F2772CDA8A0959566EED84FA,a
2,814CF30BE9C94812DB3D30332656DB30,b
``` 
    
You can apply decryption to the password column and get following outputs:
```csv
id,password,comment
1,super,a
2,secret,b
``` 

## Overview

* **Plugin type**: filter

## Configuration

- **algorithm**: encryption algorithm (see below) (enum, required)
- **column_names**: names of string columns to encrypt (array of string, required)
- **key_type**: encryption key (enum, optional, default: inline), can be either "inline" or "s3"
- **key_hex**: encryption key (string, required if key_type is inline)
- **iv_hex**: encryption initialization vector (string, required if mode of the algorithm is CBC and key_type is inline)
- ** iv_block_size**: size of prepended initialization vector (optional, to be used if needed)
- **input_encoding**: the encoding of encrypted value, can be either "base64" or "hex" (base16)
- **aws_params**: AWS/S3 parameters (hash, required if key_type is s3)
    - **region**: a valid AWS region
    - **access_key**: a valid AWS access key
    - **secret_key**: a valid AWS secret key
    - **bucket**: a valid S3 bucket
    - **path**: a valid S3 key (S3 file path)
    
S3 key file should be in valid YAML format: (iv_hex is required if mode of the algorithm is CBC)

```yaml
key_hex: 098F6BCD4621D373CADE4E832627B4F60A9172716AE6428409885B8B829CCB05
iv_hex: C9DD4BB33B827EB1FBA1B16A0074D460
```

## Algorithms

Available algorithms are:

* AES-256-CBC
* AES-192-CBC
* AES-128-CBC
* AES-256-ECB
* AES-192-ECB
* AES-128-ECB

## Example

* Inline key type

```yaml
 filters:
   - type: decrypt
     algorithm: AES-256-CBC
     column_names: [password, ip]
     key_hex: 098F6BCD4621D373CADE4E832627B4F60A9172716AE6428409885B8B829CCB05
     iv_hex: C9DD4BB33B827EB1FBA1B16A0074D460
     iv_block_size: 16
     input_encoding: hex
 ```
* S3 key type

```yaml
 filters:
   - type: decrypt
     algorithm: AES-256-CBC
     input_encoding: hex
     column_names: [password, ip]
     key_type: s3
     aws_params:
       region: us-east-2
       access_key: XXXXXXXXXXXXXXXXXXXX
       secret_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
       bucket: com.sample.keys
       path: key.aes
```

## Build

```
$ ./gradlew gem  # -t to watch change of files and rebuild continuously
```
