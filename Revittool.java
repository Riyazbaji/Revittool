import java.io.*;
import java.net.*;
import java.util.*;

public class Revittool {

    // --- Detect Cloud Provider from hostnames or IP ranges ---
    static String detectCloud(String text) {
        text = text.toLowerCase();
        if (text.contains("1e100.net") || text.contains("google"))
            return "Google Cloud";
        if (text.contains("amazonaws.com") || text.contains("aws"))
            return "Amazon AWS";
        if (text.contains("azure") || text.contains("microsoft"))
            return "Microsoft Azure";
        if (text.contains("cloudflare"))
            return "Cloudflare";
        if (text.contains("oraclecloud") || text.contains("ocicloud"))
            return "Oracle Cloud";
        return "Unknown";
    }

    // --- Forward DNS Lookup with reverse hostname check ---
    static String forwardDNS(String domain) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(domain);
            StringBuilder sb = new StringBuilder();
            StringBuilder hostnames = new StringBuilder();

            for (InetAddress addr : addresses) {
                if (sb.length() > 0) sb.append(";");
                sb.append(addr.getHostAddress());

                try {
                    String host = addr.getCanonicalHostName();
                    if (hostnames.length() > 0) hostnames.append(";");
                    hostnames.append(host);
                } catch (Exception ignore) {}
            }

            String detectFrom = hostnames.length() > 0 ? hostnames.toString() : sb.toString();
            String cloud = detectCloud(detectFrom);

            return sb.toString() + " | Cloud: " + cloud;

        } catch (Exception e) {
            return "No forward DNS found";
        }
    }

    // --- Reverse DNS Lookup ---
    static String reverseDNS(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String host = addr.getCanonicalHostName();
            if (host.equals(ip)) {
                return "No reverse DNS found for " + ip;
            }
            String cloud = detectCloud(host);
            return host + " | Cloud: " + cloud;
        } catch (Exception e) {
            return "No reverse DNS found for " + ip;
        }
    }

    // --- Batch Mode: process input file and save CSV ---
    static void batch(String inPath, String outPath) {
        try (
            BufferedReader br = new BufferedReader(new FileReader(inPath));
            PrintWriter pw = new PrintWriter(new FileWriter(outPath))
        ) {
            pw.println("Input,Type,Result");

            String line;
            while ((line = br.readLine()) != null) {
                String q = line.trim();
                if (q.isEmpty() || q.startsWith("#")) continue;

                if (q.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) { // IPv4
                    String res = reverseDNS(q);
                    pw.printf("%s,Reverse,%s%n", q, escapeCsv(res));
                } else {
                    String res = forwardDNS(q);
                    pw.printf("%s,Forward,%s%n", q, escapeCsv(res));
                }
            }
            System.out.println("Batch results saved to " + outPath);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    // Escape CSV values properly
    static String escapeCsv(String s) {
        if (s.contains(",") || s.contains("\"")) {
            s = s.replace("\"", "\"\"");
            return "\"" + s + "\"";
        }
        return s;
    }

    // --- Main entrypoint ---
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage:");
            System.out.println("  java Revittool -forward <domain>");
            System.out.println("  java Revittool -reverse <ip>");
            System.out.println("  java Revittool -batch <input.txt> <output.csv>");
            return;
        }

        switch (args[0]) {
            case "-forward":
                System.out.println("Forward DNS for " + args[1] + " → " + forwardDNS(args[1]));
                break;
            case "-reverse":
                System.out.println("Reverse DNS for " + args[1] + " → " + reverseDNS(args[1]));
                break;
            case "-batch":
                if (args.length < 3) {
                    System.out.println("Usage: java Revittool -batch <input.txt> <output.csv>");
                } else {
                    batch(args[1], args[2]);
                }
                break;
            default:
                System.out.println("Unknown command");
        }
    }
}





