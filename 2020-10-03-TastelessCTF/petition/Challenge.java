import java.math.BigInteger;
import java.security.spec.DSAPublicKeySpec;
import java.security.KeyFactory;
import java.security.Signature;
import java.util.Random;
import java.util.Scanner;
import java.util.Base64;
import java.io.File;

public class Challenge {
    public static void main(String[] args) throws Exception {

        // Petition group params
        var p = new BigInteger("1732afa753c06fd916345a525ede89ba9d78a0a8b", 16);
        var q = new BigInteger("b9957d3a9e037ec8b1a2d292f6f44dd4ebc50545", 16);
        var g = new BigInteger("4");

        // Read input
        System.out.println("We heard some people may be interested in seeing certain flags.");
        System.out.println("If you can get a petition signed by at least 100 people, we will reveal our flag.");
        System.out.println("Please submit your petition:");
        var petition = Base64.getDecoder().decode(new Scanner(System.in).next());
        var message = "We want to see the flag!".getBytes();

        for (int i = 0; i < 100; i++) {

            // Create a new key
            BigInteger x;
            do {
                x = new BigInteger(q.bitLength(), new Random());
            } while (q.compareTo(x) <= 0);
            var y = g.modPow(x, p);
            var publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
            var keyFactory = KeyFactory.getInstance("DSA");
            var publicKey = keyFactory.generatePublic(publicKeySpec);

            // Verify signature
            var signature = Signature.getInstance("SHA1withDSA");
            signature.initVerify(publicKey);
            signature.update(message);
            if (!signature.verify(petition)) {
                System.out.println("This petition looks fraudulent!");
                return;
            }
        }

        System.out.println("OK, this has been signed by at least 100 people!");
        System.out.println(new Scanner(new File("flag.txt")).nextLine());
    }
}
