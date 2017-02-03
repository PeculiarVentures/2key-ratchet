## Using

### NodeJS

```javascript
let DKeyRatchet = require("2key-ratchet");
```

## Examples


### Identity key generation

```javascript
let AliceID;
DKeyRatchet.Identity.create(16453);
    .then((id) => {
        AliceID = id;
    });
```

### Signed PreKey generation

```javascript
DKeyRatchet.PreKey.create(1)
    .then((preKey) => {
        AliceID.signedPreKeys.save(preKey.id.toString(), preKey);
    });
```

### PreKey bundle message creating

```javascript
let bundle = new DKeyRatchet.PreKeyBundleProtocol();

bundle.identity.fill(AliceID)
    .then(() => {
        bundle.registrationId = AliceID.id;
        const preKey = AliceID.signedPreKeys.load("1");
        bundle.preKeySigned.id = 1;
        bundle.preKeySigned.key = preKey.key.publicKey;
        return bundle.preKeySigned.sign(AliceID.signingKey.privateKey);
    })
    .then(() => {
        return bundle.exportProtocol();
    })
    .then((ab) => {
        console.log(ab); // ArrayBuffer {byteLength: 348}
    });
``` 

## Import PreKey bundle message from ArrayBuffer

```javascript
DKeyRatchet.PreKeyBundleProtocol.importProtocol(ab)
    .then((bundle) => {
        // check signed prekey
        return bundle.preKeySigned.verify(AliceID.signingKey.public);
    })
    .then((trusted) => {
        if (!trusted)
            throw new Error("PreKey is not trusted");
    })
```

## Init session from PreKey bundle message

```javascript
DKeyRatchet.AsymmetricRatchet.create(BobID, bundle)
    .then((cipher) => {
        return cipher.encrypt(DKeyRatchet.Convert.FromUtf8String("Hello world!"));
    })
    .then((preKeyMessage) => {
        return preKeyMessage.exportProtocol();
    })
    .then((ab) => {
        console.log(ab); // ArrayBuffer {byteLength: 408}
    });
```

## Init session from PreKey message

```javascript
DKeyRatchet.AsymmetricRatchet.create(AliceID, preKeyMessage)
    .then((cipher) => {
        return cipher.decrypt(preKeyMessage.signedMessage);
    })
    .then((message) => {
        console.log(DKeyRatchet.Convert.ToUtf8String(message)); // Hello world!
    })
```