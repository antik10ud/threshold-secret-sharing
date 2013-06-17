Java Threshold Secret Sharing
===

## Description
Core implementation of Threshold Secret Sharing (TSS) [http://tools.ietf.org/html/draft-mcgrew-tss-03](http://tools.ietf.org/html/draft-mcgrew-tss-03)

## Requirements
Java 1.7 (But probably works with older versions) 

## Compile, Test & Package
    $ mvn package

## Example
    ThresholdSecretSharing tss = new ThresholdSecretSharing();

    # Create 5 shares, secret recoverable from at least 3 different shares

	byte[] secret = Hex.convert("7465737400");
	byte[][] shares = tss.createShares(secret, 5, 3, new Random(0));

    # Recover secret from two shares
	
	byte[][] shares = { Hex.convert("FFB9FA07E185"), Hex.convert("00F5409B4511") };
	tss.recoverSecret(shares);
		
		
## License
MIT License