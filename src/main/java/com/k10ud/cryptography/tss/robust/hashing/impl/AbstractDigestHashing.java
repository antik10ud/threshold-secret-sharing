package com.k10ud.cryptography.tss.robust.hashing.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.k10ud.cryptography.tss.robust.hashing.IHashing;

public abstract class AbstractDigestHashing implements IHashing {
	private final int identifier;
	private final String hashAlgo;
	private final int hashBytes;

	public AbstractDigestHashing(int identifier, String hashAlgo) {
		this.identifier = identifier;
		this.hashAlgo = hashAlgo;
		this.hashBytes = digest(new byte[] { 0 }).length;
	}

	@Override
	public int getIdentifier() {
		return identifier;
	}

	@Override
	public byte[] digest(byte[] a) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(hashAlgo);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		byte[] hash = digest.digest(a);
		assert hash.length == hashBytes;
		return hash;
	}
	
	@Override
	public int getHashSize() {
		return hashBytes;
	}

	@Override
	public String toString() {
		return "DigestHashing [" + (hashAlgo != null ? "hashAlgo=" + hashAlgo : "") + "]";
	}
}