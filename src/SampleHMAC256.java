import java.util.Calendar;
import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

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
        	
            Algorithm algorithm = Algorithm.HMAC256("secret");
            token = JWT.create()
            	.withIssuer("2xt")
            	.withIssuedAt(issueAt)
            	.withExpiresAt(expiresAt)
            	.withClaim("email", "hanbin.pang@centurylink.com")
            	.withClaim("wtn", "16142154777")
                .sign(algorithm);
            System.out.println("token:" + token);
        } 
        catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
        	exception.printStackTrace();
        }
        
        // verify token and get claim
        try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
            JWTVerifier verifier = JWT.require(algorithm)
            	.withIssuer("2xt")
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
        catch (JWTVerificationException exception) {
            //Invalid signature/claims
        	exception.printStackTrace();
        }
    }
}
