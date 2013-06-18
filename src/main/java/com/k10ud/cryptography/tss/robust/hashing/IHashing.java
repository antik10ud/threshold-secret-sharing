package com.k10ud.cryptography.tss.robust.hashing;

public interface IHashing {

	public abstract int getIdentifier();

	public abstract byte[] digest(byte[] a);

	public abstract int getHashSize();

}