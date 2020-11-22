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
	 * @param: otherPK partner public key
	 * @throws: DHEECException if an error occurs
	 */
	
	synchronized public byte[] computeSecretKey(byte [] otherPk) throws DHEECException{
		byte[] sharedSecret = null;
		try {
			KeyFactory kf = KeyFactory.getInstance("EC");
		    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
		    PublicKey otherPublicKey = kf.generatePublic(pkSpec);
		    
		 	//Perform key agreement
		    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		    ka.init(keyPair.getPrivate());
		    ka.doPhase(otherPublicKey, true);
		    sharedSecret = ka.generateSecret();
		}
		catch(Exception e) {
			e.printStackTrace();
			throw new DHEECException(e.getMessage());
		}
		return sharedSecret;
	} 

}
