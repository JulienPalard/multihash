# Python 3, PEP 247 compliant, multihash implementation.

From the [multihash spec](https://github.com/jbenet/multihash), this
implementation is [PEP247](https://www.python.org/dev/peps/pep-0247/)
(`update(arg)`, `digest()`, `hexdigest()`, and `copy()`) compliant:

```
>>> import multihash
>>> m = multihash.sha1()
>>> m.update('foo'.encode())
>>> print(m.hexdigest())
11140beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33
```
