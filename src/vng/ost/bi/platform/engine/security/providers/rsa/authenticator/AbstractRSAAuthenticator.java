package vng.ost.bi.platform.engine.security.providers.rsa.authenticator;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.Authentication;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.util.Assert;
import vng.ost.bi.platform.engine.security.providers.rsa.*;

public abstract class AbstractRSAAuthenticator implements RSAAuthenticator, InitializingBean, MessageSourceAware{
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private String primaryURL = null;
	private String secondaryURL = null;

	public AbstractRSAAuthenticator(String primaryURL, String secondaryURL) {        
        Assert.hasText(primaryURL, "primaryURL must not be null");        
        this.primaryURL = primaryURL;
        this.secondaryURL = secondaryURL;
    }

	public UserDetails authenticate(Authentication authentication) {
		// TODO Auto-generated method stub
		return null;
	}
	
	public void setMessageSource(MessageSource messageSource) {
        Assert.notNull("Message source must not be null");
        this.messages = new MessageSourceAccessor(messageSource);
    }
	
	public String getPrimaryURL() {
		return primaryURL;
	}
	
	public String getSecondaryURL() {
		return secondaryURL;
	}
}
