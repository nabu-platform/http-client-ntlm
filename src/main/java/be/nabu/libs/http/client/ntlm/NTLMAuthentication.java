package be.nabu.libs.http.client.ntlm;

import java.security.Principal;

import org.apache.http.impl.auth.NTLMEngine;
import org.apache.http.impl.auth.NTLMEngineException;

import be.nabu.libs.authentication.api.principals.NTLMPrincipal;
import be.nabu.libs.http.api.client.ClientAuthenticationHandler;

public class NTLMAuthentication implements ClientAuthenticationHandler {

	private NTLMEngine engine = new NTLMEngineImpl();
	
	@Override
	public String authenticate(Principal principal, String challenge) {
		if (challenge == null || !challenge.trim().toLowerCase().startsWith("ntlm"))
			return null;
		if (!(principal instanceof NTLMPrincipal))
			throw new SecurityException("The authentication is ntlm but the principal does is not of type NTLMPrincipal");
		NTLMPrincipal ntlmPrincipal = (NTLMPrincipal) principal;
		
		// if there is nothing after the NTLM, we need to generate a type1
		challenge = challenge.trim().substring(4).trim();
		try {
			return "NTLM " + (challenge.isEmpty() 
				? engine.generateType1Msg(ntlmPrincipal.getDomain(), ntlmPrincipal.getHostName())
				: engine.generateType3Msg(ntlmPrincipal.getName(), ntlmPrincipal.getPassword(), ntlmPrincipal.getDomain(), ntlmPrincipal.getHostName(), challenge));
		}
		catch (NTLMEngineException e) {
			return null;
		}
	}

}
