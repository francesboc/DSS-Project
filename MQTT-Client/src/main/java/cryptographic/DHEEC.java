package cryptographic;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;

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
			/*StringBuilder tmpPublickKey = new StringBuilder();
			for(int i=0; i<otherPk.length; i++){
				tmpPublickKey.append(Integer.toString(otherPk[i],16));
			}
			otherPk = tmpPublickKey.toString().getBytes();
			System.out.println("otherpk: " + otherPk);
			for(int i=0; i< otherPk.length;i++){
				System.out.print((char)otherPk[i]+ " ");
			}
			System.out.println();*/

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
			System.out.println(e);
			e.printStackTrace();
			throw new DHEECException(e.getMessage());
		}
	} 
	
	public byte [] getSymmetricKey() {
		return this.sharedSecret;
	}
	

}
