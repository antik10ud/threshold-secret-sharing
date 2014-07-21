package com.k10ud.cryptography.tss.core;

import java.security.SecureRandom;

import org.junit.Assert;
import org.junit.Test;

import com.k10ud.cryptography.tss.util.Hex;

public class ReadmeTest {

	@Test
	public void test() {

		ThresholdSecretSharing tss = new ThresholdSecretSharing();

		// Create 5 shares, secret recoverable from at least 3 different shares

		byte[] secret = Hex.convert("7465737400");
		byte[][] shares = tss.createShares(secret, 5, 3, new SecureRandom());

		// Recover secret from 3 shares

		byte[] recoveredSecret = tss.recoverSecret(shares[0], shares[2], shares[3]);

		Assert.assertArrayEquals(recoveredSecret, secret);

	}

}