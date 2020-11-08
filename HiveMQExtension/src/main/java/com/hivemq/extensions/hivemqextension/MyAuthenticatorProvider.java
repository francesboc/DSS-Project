package com.hivemq.extensions.hivemqextension;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.annotations.Nullable;
import com.hivemq.extension.sdk.api.auth.Authenticator;
import com.hivemq.extension.sdk.api.auth.parameter.AuthenticatorProviderInput;
public class MyAuthenticatorProvider implements com.hivemq.extension.sdk.api.services.auth.provider.AuthenticatorProvider {
    
	@Override
	public @Nullable Authenticator getAuthenticator(@NotNull AuthenticatorProviderInput authenticatorProviderInput) {
		// TODO Auto-generated method stub
		return null;
	}

}