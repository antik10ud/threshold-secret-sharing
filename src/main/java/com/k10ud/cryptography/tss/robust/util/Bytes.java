package com.k10ud.cryptography.tss.robust.util;

import java.util.Arrays;

public class Bytes {
	public static int readInt(byte[] a, int offset) {
		return ((0xff & a[offset + 0] << 24) + (0xff & a[offset + 1] << 16) + (0xff & a[offset + 2] << 8) + (0xff & a[offset + 3] << 0));
	}

	public static long readLong(byte[] a, int offset) {
		return (((long) (0xff & a[offset + 0]) << 56) + //
				((long) (0xff & a[offset + 1] ) << 48) + //
				((long) (0xff & a[offset + 2] ) << 40) + //
				((long) (0xff & a[offset + 3] ) << 32) + //
				((long) (0xff & a[offset + 4] ) << 24) + //
				((0xff & a[offset + 5] & 255) << 16) + //
				((0xff & a[offset + 6] & 255) << 8) + //
		        ((0xff & a[offset + 7] & 255) << 0));
	}

	public static void writeInt(byte[] a, int offset, int v) {
		a[offset + 0] = (byte) ((v >>> 24) & 0xFF);
		a[offset + 1] = (byte) ((v >>> 16) & 0xFF);
		a[offset + 2] = (byte) ((v >>> 8) & 0xFF);
		a[offset + 3] = (byte) ((v >>> 0) & 0xFF);
	}

	public static void writeLong(byte[] a, int offset, long v) {
		a[offset + 0] = (byte) (v >>> 56);
		a[offset + 1] = (byte) (v >>> 48);
		a[offset + 2] = (byte) (v >>> 40);
		a[offset + 3] = (byte) (v >>> 32);
		a[offset + 4] = (byte) (v >>> 24);
		a[offset + 5] = (byte) (v >>> 16);
		a[offset + 6] = (byte) (v >>> 8);
		a[offset + 7] = (byte) (v >>> 0);
	}

	public static void wipe(byte[][] aa) {
		if (aa == null)
			return;
		for (byte[] a : aa)
			wipe(a);
	}

	public static void wipe(byte[] a) {
		if (a == null)
			return;
		Arrays.fill(a, (byte) 0);
	}

	public static byte[] strip(byte[] a, int offset) {
		int length = a.length - offset;
		byte[] r = new byte[length];
		System.arraycopy(a, offset, r, 0, length);
		return r;
	}

	public static byte[] join(byte[]... list) {
		int x = 0;
		for (byte[] a : list)
			x += a.length;
		byte[] joined = new byte[x];
		x = 0;
		for (byte[] a : list) {
			int al = a.length;
			System.arraycopy(a, 0, joined, x, al);
			x += al;
		}
		return joined;
	}

	public static byte[] toArray(int value) {
		byte[] a = new byte[4];
		writeInt(a, 0, value);
		return a;
	}

	public static byte[] toArray(long value) {
		byte[] a = new byte[8];
		writeLong(a, 0, value);
		return a;
	}

	public static byte[] readBytes(byte[] a, int offset, int len) {
		return Arrays.copyOfRange(a, offset, len);
	}

}
