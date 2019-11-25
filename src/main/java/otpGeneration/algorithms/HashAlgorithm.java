package otpGeneration.algorithms;

public enum HashAlgorithm {

	HMAC_SHA256("HmacSHA256",0xf),
	HMAC_SHA512("HmacSHA512",0x1f),
	;
	
	private String cryptoLabel;
	private int bitmask;
	
	private HashAlgorithm(String cryptoLabel, int bitmask) {
		this.cryptoLabel=cryptoLabel;
		this.bitmask=bitmask;
	}

	public String getCryptoLabel() {
		return cryptoLabel;
	}

	public void setCryptoLabel(String cryptoLabel) {
		this.cryptoLabel = cryptoLabel;
	}

	public int getBitmask() {
		return bitmask;
	}

	public void setBitmask(int bitmask) {
		this.bitmask = bitmask;
	}
	
	
}
