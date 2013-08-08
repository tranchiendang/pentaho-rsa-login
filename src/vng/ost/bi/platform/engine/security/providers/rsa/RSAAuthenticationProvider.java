package vng.ost.bi.platform.engine.security.providers.rsa;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.Authentication;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.security.userdetails.UserDetails;
import java.lang.Class;

public class RSAAuthenticationProvider implements AuthenticationProvider{
	//~ Instance fields ================================================================================================
	private RSAAuthenticator authenticator;
    private boolean useAuthenticationRequestCredentials = true;
    
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    
    //~ Constructors ===================================================================================================
    public RSAAuthenticationProvider(RSAAuthenticator authenticator) {
        this.setAuthenticator(authenticator);
    }
    
  //~ Methods ========================================================================================================
    public void setUseAuthenticationRequestCredentials(boolean useAuthenticationRequestCredentials) {
        this.useAuthenticationRequestCredentials = useAuthenticationRequestCredentials;
    }
    
    protected Authentication createSuccessfulAuthentication(UsernamePasswordAuthenticationToken authentication,
            UserDetails user) {
        Object password = useAuthenticationRequestCredentials ? authentication.getCredentials() : user.getPassword();

        return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
    }

	public Authentication authenticate(Authentication authentication){
		Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
	            messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
	                "Only UsernamePasswordAuthenticationToken is supported"));
        UsernamePasswordAuthenticationToken userToken = (UsernamePasswordAuthenticationToken)authentication;
        UserDetails user = getAuthenticator().authenticate(authentication);
		return createSuccessfulAuthentication(userToken, user);
	}

	@SuppressWarnings("rawtypes")
	public boolean supports(Class authentication) {
		// TODO Auto-generated method stub
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}
	
    private void setAuthenticator(RSAAuthenticator authenticator) {
        Assert.notNull(authenticator, "An RSAAuthenticator must be supplied");
        this.authenticator = authenticator;
    }

    private RSAAuthenticator getAuthenticator() {
        return authenticator;
    }
}
