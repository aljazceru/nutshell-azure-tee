# Cashu mint running in confidential containers 

### Mint
Mint is running on a custom fork of nutshell with [spark backend](https://sdk-doc-spark.breez.technology/) - you can view it at [nutshell-tee](https://github.com/nostr-net/nutshell-tee).


### Attestation

```
git clone https://github.com/aljazceru/nutshell-azure-tee.git
python verify_attestation.py https://nuttee.freedom.cash --policy-file azure/cce-policy.base64
```
