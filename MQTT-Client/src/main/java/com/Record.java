package com;
/**
 * 
 * @brief: keep information about key agreement 
 *
 */
public class Record {
	private String username;
	private byte[] pubKey;
	
	public String getUsername() {
		return username;
	}
	synchronized public void setUsername(String username) {
		this.username = username;
	}
	public byte[] getPubKey() {
		return pubKey;
	}
	synchronized public void setPubKey(byte[] pubKey) {
		this.pubKey = pubKey;
	}
	

}
