package com;
/**
 * 
 * @brief: keep information about key agreement 
 *
 */
public class Record {
	private String username;
	private String pubKey;
	
	public String getUsername() {
		return username;
	}
	synchronized public void setUsername(String username) {
		this.username = username;
	}
	public String getPubKey() {
		return pubKey;
	}
	synchronized public void setPubKey(String pubKey) {
		this.pubKey = pubKey;
	}
	

}
