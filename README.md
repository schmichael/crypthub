# crypthub

omg dont use this its just a toy im playing around if you need to encrypt things suffer through pgp/gpg i guess or listen to someone who knows what they're talking about:

![use signal](signals.png)

```
go get github.com/schmichael/crypthub

# i forget how it works
```

## envelope

```json
{
  "key": [
    {
      "comment": "<key comment string>",
      "filename": "<filename of public key>",
      "ciphertext": "<base64 encoded ciphertext>"
    }
  ],
  "nonce": "<base64 encoded nonce>",
  "ciphertext": "<base64 encoded ciphertext>"
}
```

Key is a list of multiple encrypted versions of the symmetric key used to encrypt
the ciphertext.
