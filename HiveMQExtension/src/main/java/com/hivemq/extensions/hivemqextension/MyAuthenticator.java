package com.hivemq.extensions.hivemqextension;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.EnhancedAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthConnectInput;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthOutput;
import com.hivemq.extension.sdk.api.packets.connect.ConnectPacket;
import cryptographic.AES;
import cryptographic.AesException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Optional;

public class MyAuthenticator implements EnhancedAuthenticator{

    private static final @NotNull Logger log = LoggerFactory.getLogger(MyAuthenticator.class);
    private static final String CHALLENGE = "authChallenge";
    private static final String file = System.getProperty("user.dir") + "/file.json";
    private Map<String,String> map;

    public MyAuthenticator(){
        try {
            ObjectMapper mapper = new ObjectMapper();
            // convert JSON file to map
            map = mapper.readValue(Paths.get(file).toFile(), Map.class);
        } catch (Exception e) {
            log.error("Exception thrown at extension start: ", e);
        }
    }

    @Override
    public void onConnect(EnhancedAuthConnectInput enhancedAuthInput, EnhancedAuthOutput enhancedAuthOutput) {
        log.info("BEGIN: onConnect");
        //get the contents of the MQTT connect packet from the input object
        ConnectPacket connect = enhancedAuthInput.getConnectPacket();
        final Optional<String> authenticationMethod = connect.getAuthenticationMethod();
        boolean fail = false;
        String username = "";

        //username is always required
        if (!connect.getUserName().isPresent()) {
            fail = true;
        }
        else {
            username = connect.getUserName().get();

            if(authenticationMethod.isPresent()) {
                if(CHALLENGE.equals(authenticationMethod.get())) {
                    log.info("authenticating client");
                    sendChallengeResponseAuth(enhancedAuthInput, enhancedAuthOutput, username);
                }
                else fail = true;

            }//registration by simple auth
            else if(connect.getPassword().isPresent()) {
                String password = Charset.forName("UTF-8").decode(connect.getPassword().get()).toString();
                if (!map.containsKey(username)){
                    log.info("registering client");
                    //Client not yet registered
                    registerClient(username,password);
                    enhancedAuthOutput.authenticateSuccessfully();
                }
                else fail = true;

            }
            else fail = true;
        }

        if(fail) enhancedAuthOutput.failAuthentication();
        log.info("END: onConnect");
    }

    @Override
    public void onAuth(final @NotNull EnhancedAuthInput input, final @NotNull EnhancedAuthOutput output) {
    	log.info("BEGIN: onAuth");
    	final String authententicationMethod = input.getAuthPacket().getAuthenticationMethod();
    	
    	if(CHALLENGE.equals(authententicationMethod)) {
    		final Optional<String> safeLongEncrypted = input.getConnectionInformation().getConnectionAttributeStore().getAsString(CHALLENGE);
    		final Optional<byte[]> authenticationData = input.getAuthPacket().getAuthenticationDataAsArray();
 
    		if(safeLongEncrypted.isEmpty() || authenticationData.isEmpty()) {
    			output.failAuthentication();
    			return;
    		}
    		log.debug("safeLongEcrypted: " + safeLongEncrypted.get() + " authenticationData: " + new String(authenticationData.get()));
    		if(safeLongEncrypted.get().equals(new String(authenticationData.get()))) {
    			output.authenticateSuccessfully();
    			return;
    		}
    	}
    	output.failAuthentication();
    	log.info("END: onAuth failed");
    }

    private void registerClient(String username, String password){
    	log.info("BEGIN: registerClient");
        MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        log.info("generated md");
        byte[] pass_bytes = password.getBytes(StandardCharsets.UTF_8);
        pass_bytes = md.digest(pass_bytes);
        //add client to the json file
        map.put(username, new String(pass_bytes));
        log.info("map.put");
        ObjectMapper mapper = new ObjectMapper();
        if (Files.notExists(Paths.get(file))) {
            // file is not exist
            try {
                Files.createFile(Paths.get(file));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        try {
			mapper.writeValue(Paths.get(file).toFile(), map);
            log.info("mapper.wrtievalue");
		} catch (JsonGenerationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        log.info("END: registerClient");
    }
    
    private void sendChallengeResponseAuth(EnhancedAuthConnectInput input, EnhancedAuthOutput output, String username) {
    	log.info("BEGIN: sendChallengeResponseAuth");
    	String safeLong = String.valueOf(AES.getSafeLong());
    	String password = map.get(username);
    	String safeLongEncrypted = "";
    	log.debug("safeLong: " + safeLong + " password: " + password);
    	try {
    		AES.setKey(password);
			safeLongEncrypted = AES.encrypt(safeLong);
			log.debug("safeLongEncrypted: " + safeLongEncrypted);
		} catch (AesException e) {
			log.error("Exception thrown at AES.encrypt: ", e);
		}
    	input.getConnectionInformation()
    			.getConnectionAttributeStore()  //store data to verify client  
    				.putAsString(CHALLENGE, safeLongEncrypted); //store encrypted long on broker
    	output.continueAuthentication(safeLong.getBytes(StandardCharsets.UTF_8)); //send plain long to the client
    	log.info("END: sendChallengeResponseAuth");
    }
    
}