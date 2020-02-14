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
 * 
 */
public class SampleHMAC256 {

    public static void main(String[] args) {
    	String token = "";
    	// create token
        try {
        	// issue at current date time
        	Date issueAt = Calendar.getInstance().getTime();
        	// expires at 10 minutes later
        	long later = issueAt.getTime() + 600000;
        	Calendar cal = Calendar.getInstance();
        	cal.setTimeInMillis(later);
        	Date expiresAt = cal.getTime();
        	
        	// use HMAC256 algorithm with secret "secret" (choose the secret shared between two parties)
        	// pick your issuer name such as janus
            Algorithm algorithm = Algorithm.HMAC256("secret");
            token = JWT.create()
            	.withIssuer("janus")
            	.withIssuedAt(issueAt)
            	.withExpiresAt(expiresAt)
            	.withClaim("email", "hanbin.pang@centurylink.com")
            	.withClaim("phone", "16142154777")
                .sign(algorithm);
            System.out.println("token:" + token);
        } 
        catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
        	exception.printStackTrace();
        }
        
        // verify token and get claim
        try {
        	
        	// decode jwt token without knowing secret
        	/*
            DecodedJWT decoded_jwt = JWT.decode(token);
            System.out.println("iss: " + decoded_jwt.getIssuer());
            System.out.println("iat: " + decoded_jwt.getIssuedAt());
            System.out.println("exp: " + decoded_jwt.getExpiresAt());
            System.out.println("email: " + decoded_jwt.getClaim("email").asString());
            System.out.println("phone: " + decoded_jwt.getClaim("phone").asString());
            */
        	
            // use HMAC256 algorithm with secret "secret" (choose the secret shared between two parties)
        	// require issuer name to be janus to verify token
            Algorithm algorithm = Algorithm.HMAC256("secret");
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("janus")
                    // accept 600 seconds after issueAt (iat)
                    //.acceptLeeway(600)
                    .build(); //Reusable verifier instance
            DecodedJWT verified_jwt = verifier.verify(token);
            System.out.println("iss: " + verified_jwt.getIssuer());
            System.out.println("iat: " + verified_jwt.getIssuedAt());
            System.out.println("exp: " + verified_jwt.getExpiresAt());
            System.out.println("email: " + verified_jwt.getClaim("email").asString());
            System.out.println("phone: " + verified_jwt.getClaim("phone").asString());
            
        }
        catch (JWTVerificationException exception) {
            //Invalid signature/claims
        	exception.printStackTrace();
        }
    }
}
