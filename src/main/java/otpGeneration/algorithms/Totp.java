package otpGeneration.algorithms;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import otpGeneration.algorithms.exceptions.OtpGenerationException;

public class Totp extends Hotp{
	
	private static final Logger log = LoggerFactory.getLogger(Totp.class);

	
	private static final int DEFAULT_TIME_STEP = 30;
	private static final int DEFAULT_T0 = 0;
	
	private int timeStep;
	private long t0;
	
	public Totp() {
		this(DEFAULT_TIME_STEP,DEFAULT_T0);
	}
	
	public Totp(int timeStep,long t0) {
		super();
		this.timeStep = timeStep;
		this.t0 = t0;
	}
	
	public Totp(int timeStep, long t0, int digits, HashAlgorithm hashAlgorithm) {
		super(digits,hashAlgorithm);
		this.timeStep = timeStep;
		this.t0 = t0;		
	}
	
	/**
	 * Return a TOTP generated on a defined timestamp (in seconds), time window shifted by the offset
	 * 
	 * @param key
	 * @param timestamp Timestamp in seconds
	 * @param offset
	 * @param parameters
	 * @return
	 * @throws OtpGenerationException
	 */
	public String totp(String key, long timestamp, int offset, String... parameters) throws OtpGenerationException {
		long timeWindow = (timestamp - t0) / timeStep + offset;
		if (log.isDebugEnabled()) {
			log.debug("timeWindow: {}",timeWindow);
		}
		return hotp(key,timeWindow,parameters);
	}
	
	/**
	 * Return a TOTP generated in a time window shifted from the current by the offset.
	 * 
	 * @param key
	 * @param offset
	 * @return
	 * @throws OtpGenerationException 
	 */
	public String totp(String key, int offset) throws OtpGenerationException  {
		return totp(key,System.currentTimeMillis()/1000,offset,null);
	}
	
	/**
	 * Return current TOTP
	 * 
	 * @param key
	 * @return
	 * @throws OtpGenerationException 
	 */
	public String totp(String key) throws OtpGenerationException  {
		return totp(key,0);
	}

	/**
	 * Return current TOTP with additional parameters
	 * 
	 * @param key
	 * @param parameters
	 * @return
	 * @throws OtpGenerationException 
	 */
	public String totp(String key, String... parameters) throws OtpGenerationException  {
		return totp(key,0,parameters);
	}
	
	/**
	 * Return a TOTP generated in a time window shifted from the current by the offset with parameters
	 * 
	 * @param key
	 * @param offset
	 * @return
	 * @throws OtpGenerationException 
	 */
	public String totp(String key, int offset, String... parameters) throws OtpGenerationException  {
		return totp(key,System.currentTimeMillis()/1000,offset,parameters);
	}
}
