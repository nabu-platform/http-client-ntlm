/*
* Copyright (C) 2015 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

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
