package com.k10ud.cryptography.tss.robust;

import com.k10ud.cryptography.tss.robust.ecc.IECC;
import com.k10ud.cryptography.tss.robust.hashing.IHashing;

public class RobustTSSConfig {
	private byte[] identifier;
	private int shares;
	private int threshold;
	private IHashing hashing;
	private IECC ecc;

	private RobustTSSConfig() {
		this.shares = 5;
		this.threshold = 3;
	}

	public int getShares() {
		return shares;
	}

	public void setShares(int shares) {
		this.shares = shares;
	}

	public RobustTSSConfig shares(int shares) {
		this.shares = shares;
		return this;
	}

	public int getThreshold() {
		return threshold;
	}

	public void setThreshold(int threshold) {
		this.threshold = threshold;
	}

	public RobustTSSConfig threshold(int threshold) {
		this.threshold = threshold;
		return this;
	}

	public IHashing getHashing() {
		return hashing;
	}

	public void setHashing(IHashing hashing) {
		this.hashing = hashing;
	}

	public RobustTSSConfig hashing(IHashing hashing) {
		this.hashing = hashing;
		return this;
	}

	public IECC getEcc() {
		return ecc;
	}

	public void setEcc(IECC ecc) {
		this.ecc = ecc;
	}

	public RobustTSSConfig ecc(IECC ecc) {
		this.ecc = ecc;
		return this;
	}

	public byte[] getIdentifier() {
		return identifier;
	}

	public void setIdentifier(byte[] identifier) {
		this.identifier = identifier;
	}

	public RobustTSSConfig id(byte[] identifier) {
		this.identifier = identifier;
		return this;
	}

	public static RobustTSSConfig make() {
		return new RobustTSSConfig();
	}

}
