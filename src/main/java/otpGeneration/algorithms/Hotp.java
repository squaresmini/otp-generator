package otpGeneration.algorithms;

import java.nio.charset.Charset;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;

import ch.qos.logback.core.encoder.ByteArrayUtil;
import otpGeneration.algorithms.exceptions.OtpGenerationException;

public class Hotp{
	
	private static final Logger log = LoggerFactory.getLogger(Hotp.class);

	
	private int digits;
	private HashAlgorithm hashAlgorithm;
	
	public Hotp() {
		this(6,HashAlgorithm.HMAC_SHA512);
	}	
	
	public Hotp(int digits,HashAlgorithm hashAlgorithm) {
		this.digits = digits;
		this.hashAlgorithm = hashAlgorithm;
	}

	/*
	 *  1. Dovrei aggiungere un timer, dopo 5 minuti il counter viene avanzato
	 *  2. non mi serve la risincronizzazione
	 *  3. Per tutti gli algoritmi devo fare un sistema in cui prendo la chiave associata alla pwd (o una masterkey)
	 *   e calcolo il seed K = SHA-256(MK_i,tokenId) con tokenId calcolato in modo da hashare qualche dato del cliente
	 *  4. 
	 */

	public String hotp(String key, Long counter) throws OtpGenerationException {
		return hotp(key, counter, null);
	}
	
	public String hotp(String keyStr, Long counter, String... parameters) throws OtpGenerationException {
		long t0 = System.currentTimeMillis();
		
		if (keyStr == null || keyStr.isEmpty()) {
			log.error("Key is null");
			throw new OtpGenerationException("Key empty");
		}
		
		byte[] hmac = hmac(keyStr, counter, parameters);
		
		if (log.isDebugEnabled()) {
			log.debug("hmac: {} [{}ms]",ByteArrayUtil.toHexString(hmac),System.currentTimeMillis()-t0);
		}
		
		int truncated = dynamicTruncate(hmac);
		
		if (log.isDebugEnabled()) {
			log.debug("truncated: {} [{}ms]",truncated,System.currentTimeMillis()-t0);
		}
		
		double numResult = truncated % (Math.pow(10, digits));
		
		if (log.isDebugEnabled()) {
			log.debug("result: {} [{}ms]",numResult,System.currentTimeMillis()-t0);
		}
		
		String strResult = String.format("%0"+digits+"d", (int) numResult);
		
		if (log.isDebugEnabled()) {
			log.debug("strResult: {} [{}ms]",strResult,System.currentTimeMillis()-t0);
		}
		
		return strResult;
	}
	
	private byte[] hmac(String keyStr, Long counter, String... parameters) throws OtpGenerationException {
		HashFunction hashFunction = null;
		try {
			switch(hashAlgorithm) {
			case HMAC_SHA256:
				hashFunction =  Hashing.hmacSha256(keyStr.getBytes("UTF-8"));
				break;
			case HMAC_SHA512:
				hashFunction =  Hashing.hmacSha512(keyStr.getBytes("UTF-8"));
				break;
			}
			
			Hasher hasher = hashFunction.newHasher().putLong(counter);
			if (parameters != null && parameters.length!=0) {
				for (String par : parameters) {
					if (par != null) {
						hasher.putString(par, Charset.forName("UTF-8"));
					}
				}	
			}
			
			return hasher.hash().asBytes();
		} catch (Exception e) {
			throw new OtpGenerationException("Hash Algorithm is invalid",e);
		}
	}
	
	private int dynamicTruncate(byte[] hmac) {
		int offset = 0;
		
		offset = hmac[hmac.length-1] & hashAlgorithm.getBitmask();
		
		int binCode = (hmac[offset] & 0x7f) << 24 
				| (hmac[offset + 1] & 0xff) << 16 
				| (hmac[offset + 2] & 0xff) << 8
				| (hmac[offset + 3] & 0xff);
		return binCode;
		
	}
	
	public int getDigits() {
		return digits;
	}

	public HashAlgorithm getHashAlgorithm() {
		return hashAlgorithm;
	}
	
}
