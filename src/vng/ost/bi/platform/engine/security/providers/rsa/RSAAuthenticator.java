package vng.ost.bi.platform.engine.security.providers.rsa;

import org.springframework.security.Authentication;
import org.springframework.security.userdetails.UserDetails;

public interface RSAAuthenticator {
	 //~ Methods ========================================================================================================

    /**
     * Authenticates as a user and obtains additional user information from the directory.
     *
     * @param authentication
     * @return the details of the successfully authenticated user.
     */
	UserDetails authenticate(Authentication authentication);
}
