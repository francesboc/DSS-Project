package com;


import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt5.Mqtt5Client;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hivemq.extension.sdk.api.annotations.NotNull;

import cryptographic.DHEEC;
import cryptographic.DHEECException;

public class ChallengeResponseClient {

    private static Arguments clientArgs;
    private static Record record = new Record();
    private static DHEEC dheec = null;
    private static  Mqtt5Client client = null;
    private static final String AGREE_KEY = "agreekey"; //username -> pubblica la chiave pubblica a userneame/pubkey
    private static final String SEND_MESSAGE = "send"; // pubblica -> usernameDestinatorio/message
    private static final String QUIT = "quit";
    private static final @NotNull Logger log = LoggerFactory.getLogger(ChallengeResponseClient.class.getName());
   

    public static void main(String[] args) {
        try{
            checkInput(args);
        }
        catch (IllegalArgumentException e){
            log.error("Exception thrown at extension start: ", e);
            printUsage();
            System.exit(1);
        }

      client = Mqtt5Client.builder()
                .identifier(UUID.randomUUID().toString())
                .serverHost("192.168.1.10")
                .serverPort(1883)
                .build();


        if(clientArgs.isRegisterMethod()){
            client.toBlocking()
                    .connectWith()
                    .simpleAuth()
                        .username(clientArgs.getUsername())
                        .password(clientArgs.getPassword().getBytes())
                        .applySimpleAuth()
                    .send();
            log.debug("registrazione inviata");
        }
        else{
            client.toBlocking()
                    .connectWith()
                    .userProperties()
                        .add("username", clientArgs.getUsername())
                        .applyUserProperties()
                    .enhancedAuth(new ChallengeResponseAuthMechanism(clientArgs))
                    .send();
            log.debug("auth inviato");
        }
      
		try {
			dheec = new DHEEC();
		} catch (DHEECException e1) {
			//to do exception management 
			e1.printStackTrace();
			System.exit(1);
		}
        //publishing client public key
        publish(clientArgs.getUsername()+"/pubkey", new String(dheec.getPubKey()));
        String line = "";
        String [] token = null; 
        boolean done = false;
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        while(!done) {
        	try {
				line = reader.readLine();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	token = line.split(" ");
        	if(token.length != 2 && token.length != 3) {
        		log.error("command not valid: "+line);
        		continue;
        	}
        	
        	
        	switch(token[0]) {
        		case AGREE_KEY:
        			agreekey(token[1]);
        			break;
        		case SEND_MESSAGE:
        			sendMessage(token[1], token[2]);
        			break;
        		case QUIT:
        			done = true;
        			break;
        		default:
        			log.error("command not valid: "+line);
        			break;
        			
        	}
        	
        	
        }
        client.toBlocking().disconnect();
    }

    private static void checkInput(String[] args){

        if(args.length != 4 && args.length != 5) throw new IllegalArgumentException("Username and password required");
        //System.out.println("ciao" + args[0]);
        if(!args[0].equals("-u") && !args[2].equals("-p")) throw new IllegalArgumentException("Bad arguments");
        if(args.length == 5 && (!args[4].equals("-r") && !args[4].equals("--register"))) throw new IllegalArgumentException("Bad arguments");

        clientArgs = new Arguments();
        clientArgs.setUsername(args[1]);
        clientArgs.setPassword(args[2]);
        clientArgs.setAuthMethod(args.length == 5);
    }

    private static void printUsage(){
        System.out.println("TO_DO");
    }

    /*
     * @brief: subscribe this to topic topic
     * @param: topic
     */
    private static void subscribe(String topic) {
    	log.info("BEGIN subscribe to topic "+ topic);
    	;
    	client.toAsync().subscribeWith()
        					.topicFilter(topic)
        					.qos(MqttQos.AT_LEAST_ONCE)
        					.callback(publish -> {
        							//reciverUser has published its public key. I save it 
        							record.setPubKey(new String(publish.getPayloadAsBytes(), StandardCharsets.UTF_8));
        							System.out.println("Received message on topic " + publish.getTopic() + ": " +
        										new String(publish.getPayloadAsBytes(), StandardCharsets.UTF_8));
        							try {
										dheec.computeSecretKey(record.getPubKey().getBytes());
									} catch (DHEECException e) {
										//to do exception management 
										e.printStackTrace();
									}
        							
        					})
        					.send();
    	
    
    	
    	log.info("subscribe to "+ topic +" END");
    	
    }
    
    private static void publish(String topic, String data) {
    	
       log.info("BEGIN publish "+data+" at topic "+topic);
    	
    	client.toBlocking().publishWith()
						.topic(topic)
						.payload(data.getBytes(StandardCharsets.UTF_8))
						.qos(MqttQos.AT_LEAST_ONCE)
						.send();
      
    	log.info("END publish");
    	
    }
    private static void agreekey(String reciverUser) {
    	//la subscribe al topic per ricever i messaggi
    	subscribe(reciverUser+"/pubKey");
    	
    	
    }
    
    private static void sendMessage(String reciverUser, String message) {
    	
    }
    
    
}
