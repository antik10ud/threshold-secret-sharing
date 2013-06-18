package com.k10ud.cryptography.tss.util;

import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

//http://msdn.microsoft.com/en-us/library/aa289166.aspx
//TODO: test + document
public class Combination implements Iterable<int[]> {
	private int n;
	private int k;
	private int[] data;

	public Combination(int n, int k) {
		if (n < 0 || k < 0) // normally n >= k
			throw new IllegalArgumentException("Negative parameter in constructor");
		if (n < k)
			throw new IllegalArgumentException("n<k");
		this.n = n;
		this.k = k;
		this.data = new int[k];
		for (int i = 0; i < k; ++i)
			this.data[i] = i;
	}

	public Combination(int n, int k, int[] a) {
		if (k != a.length)
			throw new IllegalArgumentException("Array length does not equal k");

		this.n = n;
		this.k = k;
		this.data = new int[k];
		for (int i = 0; i < a.length; ++i)
			this.data[i] = a[i];

		if (!this.isValid())
			throw new IllegalArgumentException("Bad value from array");
	}

	public boolean isValid() {
		if (this.data.length != this.k)
			return false; // corrupted

		for (int i = 0; i < this.k; ++i) {
			if (this.data[i] < 0 || this.data[i] > this.n - 1)
				return false; // value out of range

			for (int j = i + 1; j < this.k; ++j)
				if (this.data[i] >= this.data[j])
					return false; // duplicate or not lexicographic
		}

		return true;
	}

	@Override
	public String toString() {
		return "{" + Arrays.toString(data) + "}";
	}

	public Combination sucessor() {
		if (this.data[0] == this.n - this.k)
			return null;

		Combination ans = new Combination(this.n, this.k);

		int i;
		for (i = 0; i < this.k; ++i)
			ans.data[i] = this.data[i];

		for (i = this.k - 1; i > 0 && ans.data[i] == this.n - this.k + i; --i)
			;

		++ans.data[i];

		for (int j = i; j < this.k - 1; ++j)
			ans.data[j + 1] = ans.data[j] + 1;

		return ans;
	}

	public int[] getData() {
		return data;
	}

	private int choose(int n, int k) {
		if (n < 0 || k < 0)
			throw new IllegalArgumentException("Invalid negative parameter in choose()");
		if (n < k)
			return 0; // special case
		if (n == k)
			return 1;

		int delta, iMax;

		if (k < n - k) { // ex: Choose(100,3)
			delta = n - k;
			iMax = k;
		} else { // ex: Choose(100,97)
			delta = k;
			iMax = n - k;
		}

		int ans = delta + 1;

		for (int i = 2; i <= iMax; ++i)
			ans = (ans * (delta + i)) / i;

		return ans;

	}

	// return the mth lexicographic element of combination C(n,k)
	public Combination element(int m) {
		int[] ans = new int[this.k];

		int a = this.n;
		int b = this.k;
		int x = (choose(this.n, this.k) - 1) - m; // x is the "dual" of m

		for (int i = 0; i < this.k; ++i) {
			ans[i] = largestV(a, b, x); // largest value v, where v < a and vCb < x    
			x = x - choose(ans[i], b);
			a = ans[i];
			b = b - 1;
		}

		for (int i = 0; i < this.k; ++i)
			ans[i] = (n - 1) - ans[i];

		return new Combination(this.n, this.k, ans);
	}

	// return largest value v where v < a and  Choose(v,b) <= x
	private int largestV(int a, int b, int x) {
		int v = a - 1;

		while (choose(v, b) > x)
			--v;

		return v;
	}

	@Override
	public Iterator<int[]> iterator() {
		return new Iterator<int[]>() {
			private Combination current = null;
			private Combination next = Combination.this;

			@Override
			public boolean hasNext() {
				return next != null;
			}

			@Override
			public int[] next() {
				if (next == null)
					throw new NoSuchElementException();
				current = next;
				next = current.sucessor();
				return current.data;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException("cannot remove items from combination");
			}

		};
	}

}