import java.util.*;
import java.net.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.io.*;
import javax.net.ssl.*;

/*
 * This example demostrates how to use a SSLSocket as client to
 * send a HTTP request and get response from an HTTPS server.
 * It assumes that the client is not behind a firewall
 */

public class SSLSocketClient {

    /*
     * $ java SSLSocketClient hostname port [sni-name] [NoTLSv1.3]
    */
    public static void main(final String[] args) throws Exception {
        try {
            final SSLSocketFactory factory =
                (SSLSocketFactory)SSLSocketFactory.getDefault();
            final SSLSocket socket =
                (SSLSocket)factory.createSocket(args[0], Integer.valueOf(args[1]));

            System.out.println("SSL Socket Info:");
            final SSLParameters sslParameters = new SSLParameters();
            // SNI
            if (args.length >= 3) {
                sslParameters.setServerNames(Arrays.asList(new SNIHostName[] { new SNIHostName(args[2]) }));
            }
            // Protocol
            if (args.length >= 4 && "NoTLSv1.3".equals(args[3])) {
                sslParameters.setProtocols(new String[] { "TLSv1.2", "TLSv1.1", "TLSv1" });
            }
            socket.setSSLParameters(sslParameters);
            System.out.println("Enabled Cipher Suites: " + Arrays.asList(socket.getEnabledCipherSuites()));
            System.out.println("Enabled Protocols: " + Arrays.asList(socket.getEnabledProtocols()));
            /*
             * send http request
             *
             * Before any application data is sent or received, the
             * SSL socket will do SSL handshaking first to set up
             * the security attributes.
             *
             * SSL handshaking can be initiated by either flushing data
             * down the pipe, or by starting the handshaking by hand.
             *
             * Handshaking is started manually in this example because
             * PrintWriter catches all IOExceptions (including
             * SSLExceptions), sets an internal error flag, and then
             * returns without rethrowing the exception.
             *
             * Unfortunately, this means any error messages are lost,
             * which caused lots of confusion for others using this
             * code.  The only way to tell there was an error is to call
             * PrintWriter.checkError().
             */
            socket.startHandshake();
            final SSLSession session = socket.getSession();
            System.out.println("");
            System.out.println("SSL Session Info:");
            System.out.println("Active Cipher Suite: " + session.getCipherSuite());
            System.out.println("Active Protocol: " + session.getProtocol());
            System.out.println("Principal: " + session.getPeerPrincipal().toString());
            System.out.println("Certificate chain:");
            final Certificate[] certificates = session.getPeerCertificates();
            for (final Certificate certificate : certificates) {
                if (certificate instanceof X509Certificate) {
                    final X509Certificate cert = (X509Certificate) certificate;
                    System.out.printf("Subject: %s\n", cert.getSubjectDN().getName());
                    if (cert.getSubjectAlternativeNames() != null) {
                        System.out.printf("Subject Alt Names: %s\n", cert.getSubjectAlternativeNames().toString());
                    }
                } else {
                    System.out.println("Certificate: " + certificate.toString());
                }
            }
            

            System.out.println("");
            System.out.println("Request:");
            System.out.println("GET / HTTP/1.1");
            if (args.length >= 3) {
                    System.out.println("Host: " + args[2]);
            } else {
                    System.out.println("Host: " + args[0]);
            }
            System.out.println("");
            final PrintWriter out = new PrintWriter(
                                  new BufferedWriter(
                                  new OutputStreamWriter(
                                  socket.getOutputStream())));

            out.println("GET / HTTP/1.1");
            if (args.length >= 3) {
                    out.println("Host: " + args[2]);
            } else {
                    out.println("Host: " + args[0]);
            }
            out.println("");
            out.println();
            out.flush();

            /*
             * Make sure there were no surprises
             */
            if (out.checkError())
                System.out.println("SSLSocketClient:  java.io.PrintWriter error");

            System.out.println("");
            System.out.println("Response:");
            /* read response */
            final BufferedReader in = new BufferedReader(
                                    new InputStreamReader(
                                    socket.getInputStream()));

            String inputLine;
            while ((inputLine = in.readLine()) != null)
                System.out.println(inputLine);

            in.close();
            out.close();
            socket.close();

        } catch (final Exception e) {
            e.printStackTrace();
        }
    }
}
