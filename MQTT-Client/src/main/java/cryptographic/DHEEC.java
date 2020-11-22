package cryptographic;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyAgreement;

/**
 * @brief implements prototype pf ECDHE on curve
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
	 * @brief: executes ECDH key agreement computation
	 * @param: otherPK partner public key
	 * @throws: DHEECException if an error occurs
	 */
	
	synchronized public byte[] computeSecretKey(byte [] otherPk) throws DHEECException{
		byte[] sharedSecret = null;
		byte[] symmetricKey = null;
		try {
			KeyFactory kf = KeyFactory.getInstance("EC");
		    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
		    PublicKey otherPublicKey = kf.generatePublic(pkSpec);

		    
		 	//Perform key agreement
		    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		    ka.init(keyPair.getPrivate());
		    ka.doPhase(otherPublicKey, true);
		    sharedSecret = ka.generateSecret();
			MessageDigest hash = MessageDigest.getInstance("SHA-256");
			//to reach 256 bit of randomness
			hash.update(sharedSecret);
			List<ByteBuffer> list = Arrays.asList(ByteBuffer.wrap(otherPk),ByteBuffer.wrap(this.getPubKey()));
			Collections.sort(list);
			for(ByteBuffer byteBuffer : list)
				hash.update(byteBuffer);
			symmetricKey = hash.digest();
		}
		catch(Exception e) {
			e.printStackTrace();
			throw new DHEECException(e.getMessage());
		}
		return symmetricKey;
	} 

}
