Java Threshold Secret Sharing
===

## Description
Core implementation of Threshold Secret Sharing (TSS) [http://tools.ietf.org/html/draft-mcgrew-tss-03](http://tools.ietf.org/html/draft-mcgrew-tss-03)
  It uses a finite field GF(256) instead of Shamir scheme using large integers modulo a large prime number. 
  Max number of shares is 255, max secret key bytes is 65535. 

  [KISS code](https://github.com/antik10ud/threshold-secret-sharing/blob/master/src/main/java/com/k10ud/cryptography/tss/core/ThresholdSecretSharing.java)
  
  [Tested code](https://github.com/antik10ud/threshold-secret-sharing/blob/master/src/test/java/com/k10ud/cryptography/tss/core/ThresholdSecretSharingTest.java)


## Requirements
Java 1.7

## Compile, Test & Package
    $ mvn package

## Example

	ThresholdSecretSharing tss = new ThresholdSecretSharing();

	// Create 5 shares, secret recoverable from at least 3 different shares

	byte[] secret = Hex.convert("7465737400");
	byte[][] shares = tss.createShares(secret, 5, 3, new SecureRandom());

	// Recover secret from 3 shares

	byte[] recoveredSecret = tss.recoverSecret(shares[0], shares[2], shares[3]);

	Assert.assertArrayEquals(recoveredSecret, secret);
		
		
## License
MIT License
