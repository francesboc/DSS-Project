package com;

public class Arguments{

    private String username;
    private String password;
    private String ip;
    private boolean registerPhase;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public boolean isRegisterPhase() {
        return registerPhase;
    }

    public void setRegisterPhase(boolean registerPhase) {
        this.registerPhase = registerPhase;
    }
}