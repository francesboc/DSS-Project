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
import com.hivemq.extension.sdk.api.packets.general.UserProperties;
import com.hivemq.extension.sdk.api.services.Services;
import com.hivemq.extension.sdk.api.services.session.ClientService;
import cryptographic.AES;
import cryptographic.AesException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class MyAuthenticator implements EnhancedAuthenticator{

    private static final @NotNull Logger log = LoggerFactory.getLogger(MyAuthenticator.class);
    private static final String CHALLENGE = "authChallenge";
    private static final String file = System.getProperty("user.dir") + File.separator +"file.json";
    private Map<String,String> registeredClientMap;
    private static final ClientService clientService = Services.clientService();
    public MyAuthenticator(){
        try {
            ObjectMapper mapper = new ObjectMapper();
            // convert JSON file to map
            if (Files.notExists(Paths.get(file))) {
                //create empty json file
                Files.createFile(Paths.get(file));
                Files.write(Paths.get(file),"{}".getBytes());
            }
            registeredClientMap = mapper.readValue(Paths.get(file).toFile(), Map.class);
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
        UserProperties userProperties = connect.getUserProperties();
        Optional<String> usernameProperty = userProperties.getFirst("username");

        //username is always required
        if (!connect.getUserName().isPresent() && (!usernameProperty.isPresent() || usernameProperty.isEmpty() )) {
            fail = true;
            log.info("username not present");
        }
        else if(!connect.getUserName().isPresent()) {
            //checking if username is present in the map
            if(!registeredClientMap.containsKey(usernameProperty.get())){
                log.info("Client with username <" + usernameProperty.get() + "> is not registered!");
                fail = true;
            }
            else {
                //authentication method
                log.info("Starting authentication for " + usernameProperty.get());
                username = usernameProperty.get();
                if (authenticationMethod.isPresent()) {
                    log.info("AuthMechanism received: " + authenticationMethod.get());
                    if (CHALLENGE.equals(authenticationMethod.get())) {
                        log.info("Sending challenge");
                        sendChallengeResponseAuth(enhancedAuthInput, enhancedAuthOutput, username);
                    } else {
                        log.info("challenge not equal " + authenticationMethod.get());
                        fail = true;
                    }
                } else {
                    log.info("auth not present");
                    fail = true;
                }
            }
        }
        else if(connect.getPassword().isPresent()) {
            //registration by simple auth
            username = connect.getUserName().get();
            log.info("Starting registration of " + username);
            String password = StandardCharsets.UTF_8.decode(connect.getPassword().get()).toString();
            if (!registeredClientMap.containsKey(username)) {
                //Client not yet registered
                boolean registrationOk = registerClient(username, password);
                if (registrationOk){
                    enhancedAuthOutput.authenticateSuccessfully();
                    log.info("Registration success");
                }
                else{
                    fail = true;
                    log.info("Registration failed");
                }
            } else fail = true;
        }
        else fail=true;

        if(fail) enhancedAuthOutput.failAuthentication();
        log.info("END: onConnect");
    }

    @Override
    public void onAuth(final @NotNull EnhancedAuthInput input, final @NotNull EnhancedAuthOutput output) {
    	log.info("BEGIN: onAuth");
    	final String authententicationMethod = input.getAuthPacket().getAuthenticationMethod();
        log.info("auth method: " + authententicationMethod);
    	if(CHALLENGE.equals(authententicationMethod)) {
    		final Optional<String> safeLongEncrypted = input.getConnectionInformation().getConnectionAttributeStore().getAsString(CHALLENGE);
    		final Optional<byte[]> authenticationData = input.getAuthPacket().getAuthenticationDataAsArray();

    		if(safeLongEncrypted.isEmpty() || authenticationData.isEmpty()) {
                log.info("empty");
    			output.failAuthentication();
    			return;
    		}
    		log.info("safeLongEcrypted: " + safeLongEncrypted.get() + " authenticationData: " + new String(authenticationData.get()));
    		if(safeLongEncrypted.get().equals(new String(authenticationData.get()))) {
    			output.authenticateSuccessfully();
    			log.info("END: onAuth");
    			return;
    		}
    	}
    	output.failAuthentication();
    	log.info("END: onAuth failed");
    }

    private boolean registerClient(String username, String password) {
        log.info("BEGIN: registerClient");
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
            log.info("generated md");
            byte[] pass_bytes = password.getBytes(StandardCharsets.UTF_8);
            pass_bytes = md.digest(pass_bytes);
            //add client to the json file
            registeredClientMap.put(username, new String(pass_bytes));
            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(Paths.get(file).toFile(), registeredClientMap);
            log.info("Client registered");
        }
         catch (Exception e) {
            e.printStackTrace();
            log.error("Error while creating json file");
            log.info("END: registerClient (failed)");
            return false;
        }
        log.info("END: registerClient");
        return true;
    }
    
    private void sendChallengeResponseAuth(EnhancedAuthConnectInput input, EnhancedAuthOutput output, String username) {
    	log.info("BEGIN: sendChallengeResponseAuth");
    	String safeLong = String.valueOf(AES.getSafeLong());
    	String password = registeredClientMap.get(username);
    	String safeLongEncrypted = "";
    	log.info("safeLong: " + safeLong + " password: " + password);
    	try {
    		AES.setKey(password);
			safeLongEncrypted = AES.encrypt(safeLong);
			log.info("safeLongEncrypted: " + safeLongEncrypted);
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