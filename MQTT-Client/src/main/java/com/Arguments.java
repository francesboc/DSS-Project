package com;

public class Arguments{

    private String username;
    private String password;
    private boolean authMethod;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isRegisterMethod() {
        return authMethod;
    }

    public void setAuthMethod(boolean authMethod) {
        this.authMethod = authMethod;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

}