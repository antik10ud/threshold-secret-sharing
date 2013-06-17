package com.k10ud.cryptography.tss.core;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import junit.framework.Assert;

import org.junit.Test;

import com.k10ud.cryptography.tss.core.ThresholdSecretSharing;
import com.k10ud.cryptography.tss.testing.Combination;
import com.k10ud.cryptography.tss.testing.Hex;

public class ThresholdSecretSharingTest {

	private static Random rnd = new SecureRandom();
	private static int TEST_LOAD_FACTOR = 1;

	@Test
	public void kat() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[] secret = Hex.convert("7465737400");
		byte[][] comb = { Hex.convert("01B9FA07E185"), Hex.convert("02F5409B4511") };
		byte[] recovered = tss.recoverSecret(comb);
		Assert.assertTrue("array mismatch", Arrays.equals(secret, recovered));
	}

	@Test
	public void shareIndexNotZero() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[][] comb = { Hex.convert("FFB9FA07E185"), Hex.convert("00F5409B4511") };
		try {
			tss.recoverSecret(comb);
			Assert.fail("IllegalArgumentException expected");
		} catch (IllegalArgumentException z) {
			Assert.assertEquals("Message exception mismatch", "invalid share index: 0 (<=0)", z.getMessage());
		}
	}

	@Test
	public void mykat1() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[] secret = Hex.convert("7465737400");
		byte[][] shares = tss.createShares(secret, 2, 2, new Random(0));
		byte[] recovered = tss.recoverSecret(shares);
		Assert.assertTrue("array mismatch", Arrays.equals(secret, recovered));
	}

	@Test
	public void g256div() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		Assert.assertEquals("div fail", tss.div((byte) 4, (byte) 7), (byte) 105);
	}

	@Test
	public void mykat2() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[] secret = Hex.convert("cc4a97e7");
		byte[][] comb = { Hex.convert("01446bc13d"), Hex.convert("02c0a65764"), Hex.convert("030c6442f8"), Hex.convert("04ef14ec45") };
		byte[] recovered = tss.recoverSecret(comb);
		Assert.assertTrue("array mismatch", Arrays.equals(secret, recovered));
	}

	@Test
	public void testSmallSecrets() {
		test(500 * TEST_LOAD_FACTOR, 1, 256, 3, 10, 3, 5);
	}

	@Test
	public void testMediumSecrets() {
		test(100 * TEST_LOAD_FACTOR, 256, 512, 3, 10, 3, 5);
	}

	@Test
	public void testBigSecrets() {
		test(10 * TEST_LOAD_FACTOR, 32768, 65535, 3, 10, 3, 5);
	}

	//	@Test
	//	//TODO: slow test
	//	public void testLarger() {
	//		test(1, 65535, 65535, 255, 255, 255, 255);
	//	}
	//test fails
	//multi thread test

	private void test(int iterations, int minSecretLen, int maxSecretLen, int minShares, int maxShares, int minThreshold, int maxThreshold) {
		System.out.print(String.format("test\n iterations:%s\n secret len:%s-%s\n shares:%s-%s\n threshold:%s-%s\n", iterations, minSecretLen, maxSecretLen,
				minShares, maxShares, minThreshold, maxThreshold));

		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		long generateMs = 0;
		long recoverMs = 0;
		long T0;
		long combinations = 0;
		double secretAvg = 0;
		double thresholdAvg = 0;
		double shareAvg = 0;
		for (int i = 0; i < iterations; i++) {
			T0 = System.currentTimeMillis();
			if (i % (10 * TEST_LOAD_FACTOR) == 0)
				System.out.print(".");
			int secreLen = rnd.nextInt(maxSecretLen - minSecretLen + 1) + minSecretLen;
			byte[] secret = new byte[secreLen];
			rnd.nextBytes(secret);
			int thresholdSize = rnd.nextInt(maxThreshold - minThreshold + 1) + minThreshold;
			int sharesSize = rnd.nextInt(maxShares - minShares + 1) + minShares;
			if (thresholdSize > sharesSize)
				sharesSize = thresholdSize;

			secretAvg = (secretAvg + secreLen) / 2;
			thresholdAvg = (thresholdAvg + thresholdSize) / 2;
			shareAvg = (shareAvg + sharesSize) / 2;

			byte[][] shares = tss.createShares(secret, sharesSize, thresholdSize, rnd);
			generateMs += System.currentTimeMillis() - T0;
			T0 = System.currentTimeMillis();
			Combination combination = new Combination(shares.length, thresholdSize);
			byte[][] recoverShare = new byte[thresholdSize][];
			for (int[] x : combination) {
				++combinations;

				if (rnd.nextBoolean())
					for (int j = 0, n = x.length; j < n; j++)
						recoverShare[j] = shares[x[j]];
				else
					for (int j = 0, n = x.length - 1; j <= n; j++)
						recoverShare[n - j] = shares[x[j]];

				if (combinations % (10 * TEST_LOAD_FACTOR) == 0)
					System.out.print("*");
				byte[] recovered = tss.recoverSecret(recoverShare);
				if (!Arrays.equals(secret, recovered)) {
					System.out.println("\nsecret:" + Hex.convert(secret));
					System.out.println("secret len:" + secret.length);
					System.out.println("shares:" + sharesSize);
					for (int j = 0; j < shares.length; j++)
						System.out.println("share" + j + ":" + Hex.convert(shares[j]));
					System.out.println("threshold:" + thresholdSize);
					System.out.println("recovered:" + Hex.convert(recovered));
					for (int j = 0; j < recoverShare.length; j++)
						System.out.println("recover share" + j + ":" + Hex.convert(recoverShare[j]));
					Assert.fail("array mismatch");
				}
			}
			recoverMs += System.currentTimeMillis() - T0;
		}
		System.out.println(String.format("%ngenerating (%s secret keys): %s ms - %.2f ms/key", iterations, generateMs, (double) generateMs / iterations));
		System.out.println(String.format("recovering (%s combinations): %s ms - %.2f ms/comb", combinations, recoverMs, (double) recoverMs / combinations));
		System.out.println(String.format("secret len avg: %.1f", secretAvg));
		System.out.println(String.format("share len avg: %.1f", shareAvg));
		System.out.println(String.format("threshold len avg: %.1f", thresholdAvg));
		System.out.println();
	}

}