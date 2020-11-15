package cryptographic;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;


import javax.crypto.KeyAgreement;

/*
 * @brief: diffie hellman utils 
 */

public class DHEEC {
	private KeyPairGenerator kpg;
	private KeyPair keyPair;
	private byte [] sharedSecret;
	
	
	public DHEEC() throws DHEECException {
		try {
			this.kpg = KeyPairGenerator.getInstance("EC");
		    kpg.initialize(256);
		    keyPair = kpg.generateKeyPair();
		}
		catch (Exception e) {
			throw new DHEECException(e.getMessage());
		}
	}
	
	public byte[] getPubKey() {
		return this.keyPair.getPublic().getEncoded();
	}
	
	public byte[] getPrvkey() {
		return this.keyPair.getPrivate().getEncoded();
	}
	
	/**
	 * @brief: executes DH key agreement computation 
	 */
	
	public void computeSecretKey(byte [] otherPk) throws DHEECException{
		try {
			KeyFactory kf = KeyFactory.getInstance("EC");
		    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
		    PublicKey otherPublicKey = kf.generatePublic(pkSpec);
		    
		 // Perform key agreement
		    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		    ka.init(keyPair.getPrivate());
		    ka.doPhase(otherPublicKey, true);
		    this.sharedSecret = ka.generateSecret();
		}
		catch(Exception e) {
			throw new DHEECException(e.getMessage());
		}
	} 
	
	public byte [] getSymmetricKey() {
		return this.sharedSecret;
	}
	

}
