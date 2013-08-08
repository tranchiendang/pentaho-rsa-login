package vng.ost.bi.platform.engine.security.providers.rsa.authenticator;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataAccessException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class BindAuthenticator extends AbstractRSAAuthenticator {
	//~ Instance fields ================================================================================================
	private static final Log logger = LogFactory.getLog(BindAuthenticator.class);
	private UserDetailsService userDetailsService;
	
	//~ Constructors ===================================================================================================
	public BindAuthenticator(String primaryURL, String secondaryURL, UserDetailsService userDetailsService) {		
		// TODO Auto-generated constructor stub
		super(primaryURL, secondaryURL);
		Assert.notNull(userDetailsService, "userDetailsService cannot be null");
		this.userDetailsService = userDetailsService; 
	}

	//~ Methods ========================================================================================================
	@Override
	public UserDetails authenticate(Authentication authentication) {
		Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
                "Can only process UsernamePasswordAuthenticationToken objects");
		
		String username = authentication.getName().toLowerCase();
		String password = (String) authentication.getCredentials();
		UserDetails user = null;
		
		if (!StringUtils.hasLength(username)) {
            throw new BadCredentialsException(messages.getMessage("RSAAuthenticationProvider.emptyUsername",
                    "Empty Username"));
        }
		
		if (password.length() == 0) {
            logger.debug("Rejecting empty password for user " + username);
            throw new BadCredentialsException(messages.getMessage("RSAAuthenticationProvider.emptyPassword",
                    "Empty Password"));
        }
		
		int res = vngAuthenticate(username, password);
		if (res == 0) {
		    throw new BadCredentialsException(
		            messages.getMessage("BindAuthenticator.badCredentials", "Bad credentials"));
		}
		else if (res == 3) {
			throw new BadCredentialsException(
		            messages.getMessage("BindAuthenticator.reCheckCredentials", "ReCheck credentials"));
		}
		else if (res == -1) {
			throw new BadCredentialsException(
		            messages.getMessage("BindAuthenticator.serverFault", "Server Fault"));
		}
		else {
			if (logger.isDebugEnabled()) {
		        logger.debug("login successfull with user: " + username);
		    }
		}
		
		try {
            user = this.getUserDetailsService().loadUserByUsername(username);
        }
        catch (DataAccessException repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
        }

        if (user == null) {
            throw new AuthenticationServiceException(
                    "UserDetailsService returned null, which is an interface contract violation");
        }
        return user;
	}

	public int vngAuthenticate(String username, String password) {
		// define parameters
		String primaryURL = String.format(getPrimaryURL(),username, password);
		String secondaryURL = String.format(getSecondaryURL(),username, password);
		int vngStatus = 0;
		HttpClient client = new HttpClient();
		GetMethod method = null;
		
		//primaryURL call
		try {
	        method = new GetMethod(primaryURL);
			// Send GET request
	        if (client.executeMethod(method) == HttpStatus.SC_OK){
	        	InputStream rstream = null;		        
		        // Get the response body
		        rstream = method.getResponseBodyAsStream();
		        BufferedReader br = new BufferedReader(new InputStreamReader(rstream));
		        String line;
		        while ((line = br.readLine()) != null) {
		            vngStatus = Integer.parseInt(line);
		            break;
		        }
		        br.close();
	        }
	        else {
	        	throw new Exception("Http Status: " + method.getStatusLine());
	        }	        
		} catch (Exception ex) {
			if (logger.isDebugEnabled()) {
	            logger.debug("Primary Server Fault: " + ex.getMessage());
	        }
			vngStatus = -1;
        }
		if (vngStatus == -1) {
			//secondaryURL call
			try {
		        method = new GetMethod(secondaryURL);
				// Send GET request
		        if (client.executeMethod(method) == HttpStatus.SC_OK) {
		        	InputStream rstream = null;
			        
			        // Get the response body
			        rstream = method.getResponseBodyAsStream();
			        BufferedReader br = new BufferedReader(new InputStreamReader(rstream));
			        String line;
			        while ((line = br.readLine()) != null) {
			            vngStatus = Integer.parseInt(line);
			            break;
			        }
			        br.close();
		        }
		        else {
		        	throw new Exception("Http Status: " + method.getStatusLine());
		        }
			} catch (Exception ex) {
				if (logger.isDebugEnabled()) {
		            logger.debug("Secondary Server Fault: " + ex.getMessage());
		        }
				vngStatus = -1;
	        }		
		}
		// change to debug mode for get vngStatus
		if (logger.isDebugEnabled()) {
            logger.debug("vngStatus is: " + Integer.toString(vngStatus));
		}
		return vngStatus;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		// TODO Auto-generated method stub
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		// TODO Auto-generated method stub
	}
	
	public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    protected UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }
}
