import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Calendar;
import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/*
 * sample code for using auth0 java-jwt library
 * auth0 java-jwt library:	https://github.com/auth0/java-jwt
 * useful online decode site:	https://jwt.io/
 */
public class SampleRSA256 {

    public static void main(String[] args) {
    	
    	String token = "";
    	KeyStore ks = null;
    	InputStream is = null;
    	RSAPublicKey publicKey = null; //Get the key instance
        RSAPrivateKey privateKey = null; //Get the key instance
    	try {
    		ks = KeyStore.getInstance("JKS");
    		is = new FileInputStream("TestIdP.jks");
    		char[] keypwd = "demo1234".toCharArray();
    		ks.load(is, keypwd);
    		privateKey = (RSAPrivateKey) ks.getKey("test-idp", keypwd);
    		publicKey = (RSAPublicKey) ks.getCertificate("test-idp").getPublicKey();
    	}
    	catch (Exception ex) {
    		ex.printStackTrace();
    	}
    	
    	// create token
        try {
        	// issue at current date time
        	Calendar cal = Calendar.getInstance();
        	Date issueAt = cal.getTime();
        	// expires at 10 minutes later
        	long later = issueAt.getTime() + 600000;
        	cal.setTimeInMillis(later);
        	Date expiresAt = cal.getTime();
            
        	// pick your issuer name such as janus
            Algorithm algorithmRS = Algorithm.RSA256(null, privateKey);
            token = JWT.create()
            	.withIssuer("janus")
            	.withIssuedAt(issueAt)
            	.withExpiresAt(expiresAt)
            	.withClaim("email", "hanbin.pang@centurylink.com")
            	.withClaim("wtn", "16142154777")
                .sign(algorithmRS);
            System.out.println("token: " + token);
        } 
        catch (JWTCreationException ex) {
            //Invalid Signing configuration / Couldn't convert Claims.
        	ex.printStackTrace();
        }
        
        // verify token and get claim
        try {
        	Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
            	.withIssuer("janus")
            	// accept 600 seconds after issueAt (iat)
            	//.acceptLeeway(600)
            	.build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token);
            System.out.println("iss: " + jwt.getIssuer());
            System.out.println("iat: " + jwt.getIssuedAt());
            System.out.println("exp: " + jwt.getExpiresAt());
            System.out.println("email: " + jwt.getClaim("email").asString());
            System.out.println("wtn: " + jwt.getClaim("wtn").asString());
        }
        catch (JWTVerificationException ex) {
            //Invalid signature/claims
        	ex.printStackTrace();
        }
    }
}
