package com.k10ud.cryptography.tss.robust;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.TreeMap;

import com.k10ud.cryptography.tss.core.ThresholdSecretSharing;
import com.k10ud.cryptography.tss.robust.ecc.IECC;
import com.k10ud.cryptography.tss.robust.ecc.impl.RepetitionECC;
import com.k10ud.cryptography.tss.robust.hashing.HashingException;
import com.k10ud.cryptography.tss.robust.hashing.IHashing;
import com.k10ud.cryptography.tss.robust.hashing.impl.SHA256Hashing;
import com.k10ud.cryptography.tss.robust.util.Bytes;
import com.k10ud.cryptography.tss.robust.util.Combination;
import com.k10ud.cryptography.tss.robust.util.Wiper;

public class RobustTSS {

	private ThresholdSecretSharing tss;

	public RobustTSS() {
		tss = new ThresholdSecretSharing();
	}

	public List<RobustTSSShare> createShares(byte[] secret, RobustTSSConfig config, Random rnd) {
		if (secret == null)
			throw new IllegalArgumentException("null secret");
		if (config == null)
			throw new IllegalArgumentException("null config");
		if (rnd == null)
			throw new IllegalArgumentException("null rnd");
		int m = secret.length;
		if (m == 0)
			throw new IllegalArgumentException("invalid secret length: 0");
		if (m > ThresholdSecretSharing.MAX_SECRET_BYTES)
			throw new IllegalArgumentException("invalid secret length: " + m + "(gt " + ThresholdSecretSharing.MAX_SECRET_BYTES + " bytes)");
		int shares = config.getShares();
		int threshold = config.getThreshold();
		IHashing hashing = config.getHashing();
		if (hashing == null)
			hashing = new SHA256Hashing();
		IECC ecc = config.getEcc(); 
		if (ecc == null)
			ecc = new RepetitionECC();
		byte[] identifier = config.getIdentifier();
		if (identifier == null)
			throw new IllegalArgumentException("null identifier");
		if (identifier.length != RobustTSSShare.IDENTIFIER_BYTES)
			throw new IllegalArgumentException("invalid identifier length: " + identifier.length);
		if (shares < 1)
			throw new IllegalArgumentException("not enought shares: " + shares);
		if (shares > ThresholdSecretSharing.MAX_SHARES)
			throw new IllegalArgumentException("too many shares: " + shares + "(gt" + ThresholdSecretSharing.MAX_SHARES + ")");
		if (threshold > shares)
			throw new IllegalArgumentException("threshold > shares: " + threshold + " > " + shares);
		if (!RobustTSSRegistry.instance.containsHashingId(hashing.getIdentifier()))
			throw new IllegalArgumentException("Hashingo " + hashing + " not registered");
		if (!RobustTSSRegistry.instance.containsECCId(ecc.getIdentifier()))
			throw new IllegalArgumentException("ecc " + ecc + " not registered");

		Wiper wiper = new Wiper();
		try {
			byte[][] rawShares = tss.createShares(wiper.add(Bytes.join(secret, hashing.digest(secret))), shares, threshold, rnd);
			assert shares == rawShares.length;
			ArrayList<RobustTSSShare> list = new ArrayList<RobustTSSShare>();
			for (int i = 0; i < shares; i++)
				list.add(new RobustTSSShare(identifier, hashing.getIdentifier(), threshold, ecc.getIdentifier(), rawShares[i]));
			return list;
		} finally {
			wiper.wipe();
		}
	}

	public byte[] recoverSecret(List<RobustTSSShare> shares) {
		Wiper wiper = new Wiper();
		try {
			TreeMap<Integer, Integer> thresholds = new TreeMap<>();
			for (RobustTSSShare i : shares) {
				int key = i.getThreshold();
				Integer value = thresholds.get(key);
				value = value == null ? 1 : value + 1;
				thresholds.put(key, value);
			}
			for (Integer threshold : thresholds.keySet()) {
				Combination comb = new Combination(shares.size(), threshold);
				byte[][] rawShares = new byte[threshold][];
				for (int[] v : comb) {
					HashSet<Integer> hashings = new HashSet<Integer>();
					for (int j = 0; j < threshold; j++) {
						RobustTSSShare share = shares.get(v[j]);
						rawShares[j] = share.getRaw();
						hashings.add(share.getHashingId());
					}
					byte[] secret = tss.recoverSecret(rawShares);
					for (int hashingId : hashings) {
						try {
							IHashing hashing = RobustTSSRegistry.instance.getHashing(hashingId);
							int hashSize = hashing.getHashSize();
							int secretLen = secret.length - hashSize;
							if (secretLen <= 0)
								continue;
							byte[] rawSecret = Arrays.copyOfRange(secret, 0, secretLen);
							byte[] digest = hashing.digest(rawSecret);
							if (!Arrays.equals(digest, Arrays.copyOfRange(secret, secretLen, secret.length)))
								continue;
							return rawSecret;
						} catch (HashingException e) {
							continue;
						}
					}
				}
			}
			//throw new illegal
			return null;
		} finally {
			wiper.wipe();
		}
	}

	/*
	 * Check the availability of a secret in order to be verified
	 */
	public boolean recoverableSecret(List<RobustTSSShare> shares) {
		Wiper wiper = new Wiper();
		try {
			wiper.add(recoverSecret(shares));
		} catch (Exception x) {
			return false;
		} finally {
			wiper.wipe();
		}
		return true;
	}

}
