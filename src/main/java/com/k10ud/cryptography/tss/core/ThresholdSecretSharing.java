package com.k10ud.cryptography.tss.core;

import java.util.Arrays;
import java.util.Random;

//  http://tools.ietf.org/html/draft-mcgrew-tss-03
// TODO: timing attack solution
public class ThresholdSecretSharing {
	//	private static Logger LOG = Logger.getLogger(ThresholdSecretSharing.class.getName());
	public final static int MAX_SECRET_BYTES = 65536;
	public final static int MAX_SHARES = 255;
	private static int[] EXP_OP = { 0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35, 0x5f, 0xe1, 0x38, 0x48,
			0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa, 0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70,
			0x90, 0xab, 0xe6, 0x31, 0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd, 0x4c, 0xd4, 0x67, 0xa9,
			0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88, 0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce,
			0x49, 0xdb, 0x76, 0x9a, 0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3, 0xfe, 0x19, 0x2b, 0x7d,
			0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0, 0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56,
			0xfa, 0x15, 0x3f, 0x41, 0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75, 0x9f, 0xba, 0xd5, 0x64,
			0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80, 0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1,
			0xc8, 0x43, 0xc5, 0x54, 0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca, 0x45, 0xcf, 0x4a, 0xde,
			0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e, 0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94,
			0xa7, 0xf2, 0x0d, 0x17, 0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x00 };
	private static int[] LOG_OP = { 0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248,
			105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53,
			147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34,
			136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243,
			115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176,
			156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108,
			170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93,
			86, 242, 211, 171, 68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128,
			192, 247, 112, 7 };

	private int add(int a, int b) {
		return a ^ b;
	}

	private int mul(int x, int y) {
		if (x == 0 || y == 0)
			return 0;
		int v = (LOG_OP[0xff & x] + LOG_OP[0xff & y]) % 0xff;
		assert v >= 0 && v < 255;
		return EXP_OP[v];
	}

	private int div(int x, int y) {
		if (x == 0)
			return 0;
		if (y == 0)
			throw new IllegalArgumentException("division by 0");
		int v = LOG_OP[0xff & x] - LOG_OP[0xff & y];
		if (v < 0)
			v = 0xff + v;
		assert v >= 0 && v < 255;
		return EXP_OP[v];
	}

	/**
	 * Generate a set of shares from the secret provided. Secret reconstruction will require 'threshold' shares in order to reconstruct correctly a secret
	 * 
	 * @param secret
	 *            byte array of len 1..65536
	 * @param shares
	 *            number of shares to generate
	 * @param threshold
	 *            number of required shares in order to reconstruct a secret
	 * @param rnd
	 *            Source for random numbers (this must be a good random number generator, at least SecureRandom)
	 * @return byte array of byte arrays (a list of shares as raw bytes)
	 */
	public byte[][] createShares(byte[] secret, int shares, int threshold, Random rnd) {
		if (secret == null)
			throw new IllegalArgumentException("null secret");
		int m = secret.length;
		if (m == 0)
			throw new IllegalArgumentException("invalid secret length: 0");
		if (m > MAX_SECRET_BYTES)
			throw new IllegalArgumentException("invalid secret length: " + m + "(gt " + MAX_SECRET_BYTES + " bytes)");
		if (shares < 1)
			throw new IllegalArgumentException("not enought shares: " + shares);
		if (shares > MAX_SHARES)
			throw new IllegalArgumentException("too many shares: " + shares + "(gt" + MAX_SHARES + ")");
		if (threshold > shares)
			throw new IllegalArgumentException("threshold > shares: " + threshold + " > " + shares);
		if (rnd == null)
			throw new IllegalArgumentException("null rnd");

		byte[][] share = new byte[shares][m + 1];
		for (int i = 0; i < shares; i++)
			share[i][0] = (byte) (i + 1);

		byte[] a = null;
		try {
			a = new byte[threshold];
			for (int i = 0; i < m; i++) {
				rnd.nextBytes(a);
				a[0] = secret[i];
				for (int j = 0; j < shares; j++)
					share[j][i + 1] = (byte) eval(share[j][0], a);
			}
		} finally {
			if (a != null)
				Arrays.fill(a, (byte) 0);
		}
		return share;
	}

	private int eval(byte x, byte[] a) {
		assert x != 0;
		assert a.length > 0;
		int r = 0;
		int xi = 1;
		for (byte b : a) {
			r = add(r, mul(b, xi));
			xi = mul(xi, x);
		}
		return r;
	}

	/**
	 * Reconstructs a secret from a list of raw bytes shares
	 * 
	 * @param shares
	 *            byte array of byte arrays (a list of shares as raw bytes)
	 * @return recovered byte array secret
	 */
	public byte[] recoverSecret(byte[][] shares) {
		if (shares == null)
			throw new IllegalArgumentException("null shares");

		int threshold = shares.length;
		if (threshold == 0)
			throw new IllegalArgumentException("not enought shares:" + threshold);
		if (threshold > MAX_SHARES)
			throw new IllegalArgumentException("too many shares:" + threshold);
		int m = shares[0].length - 1;
		if (m <= 0)
			throw new IllegalArgumentException("invalid share length:" + (m + 1) + " (<=0)");
		if (m > MAX_SECRET_BYTES)
			throw new IllegalArgumentException("invalid share length:" + (m + 1) + " (>" + (MAX_SECRET_BYTES + 1) + ")");

		for (int i = 1; i < shares.length; i++) {
			if (shares[i] == null)
				throw new IllegalArgumentException("share " + i + " is null");
			if (shares[i].length != m + 1)
				throw new IllegalArgumentException("shares are not equal length, inconsistent input");

		}
		byte[] u = null;
		byte[] v = null;
		try {
			u = new byte[threshold];
			for (int i = 0; i < threshold; i++) {
				u[i] = shares[i][0];
				if ((0xff & u[i]) == 0)
					throw new IllegalArgumentException("invalid share index: " + shares[i][0]);
				for (int j = 0; j < i; j++)
					if (u[i] == u[j])
						throw new IllegalArgumentException("duplicated share index: " + u[i]);

			}
			byte[] secret = new byte[m];
			v = new byte[threshold];
			for (int j = 0; j < m; j++) {
				for (int i = 0; i < threshold; i++)
					v[i] = shares[i][j + 1];
				secret[j] = (byte) lagrange(u, v);
			}
			return secret;
		} finally {
			if (u != null)
				Arrays.fill(u, (byte) 0);
			if (v != null)
				Arrays.fill(v, (byte) 0);
		}
	}

	private int poly(int i, byte[] u) {
		int r = 1;
		for (int j = 0, m = u.length; j < m; j++)
			if (j != i)
				r = mul(r, div(u[j], add(u[j], u[i])));
		return r;
	}

	private int lagrange(byte[] u, byte[] v) {
		int m = u.length;
		assert m == v.length;
		int r = 0;
		for (int i = 0; i < m; i++)
			r = add(r, mul(poly(i, u), v[i]));
		return r;
	}

}