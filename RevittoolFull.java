import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.SocketAddress;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class RevittoolFull {

    public static void main(String[] args) {
        if (args.length < 2 || !"-fullscan".equals(args[0])) {
            System.out.println("Usage: java RevittoolFull -fullscan <domain>");
            System.out.println();
            System.out.println("Example:");
            System.out.println("  java RevittoolFull -fullscan kietgroup.com");
            return;
        }

        String domain = args[1].trim();

        System.out.println();
        System.out.println("==================================================");
        System.out.println("        Revittool – Full Domain Scan Report       ");
        System.out.println("==================================================");
        System.out.println("Target: " + domain);
        System.out.println("Time  : " + new Date());
        System.out.println("--------------------------------------------------");
        System.out.println();

        forwardReverseLookup(domain);
        fullEnumeration(domain);
        whoisLookup(domain);
        serviceDetection(domain);
        tlsCertificate(domain);
        emailSecurityChecks(domain);
        dnssecCheck(domain);
        lightweightPortReachability(domain);
        runATCE(domain);

        System.out.println("==================================================");
        System.out.println("                 End of Report                    ");
        System.out.println("==================================================");
    }

    // ----------------------------------------------------
    // [1] Basic DNS – Forward & Reverse Lookup
    // ----------------------------------------------------
    private static void forwardReverseLookup(String domain) {
        System.out.println("[1] Basic DNS – Forward & Reverse Lookup");
        System.out.println("----------------------------------------");
        try {
            InetAddress[] addrs = InetAddress.getAllByName(domain);
            if (addrs.length == 0) {
                System.out.println("No IP addresses found for " + domain);
                System.out.println();
                return;
            }
            for (InetAddress addr : addrs) {
                String ip = addr.getHostAddress();
                System.out.println("IP: " + ip);
                try {
                    String rev = InetAddress.getByName(ip).getCanonicalHostName();
                    if (!rev.equals(ip)) {
                        System.out.println("  PTR (reverse DNS): " + rev);
                    } else {
                        System.out.println("  PTR (reverse DNS): No reverse DNS found");
                    }
                } catch (Exception e) {
                    System.out.println("  PTR (reverse DNS): lookup failed");
                }
            }
        } catch (Exception e) {
            System.out.println("Error during DNS lookup: " + e.getMessage());
        }
        System.out.println();
    }

    // ----------------------------------------------------
    // [2] DNS Enumeration – A / AAAA / MX / NS / TXT / CNAME
    // ----------------------------------------------------
    private static void fullEnumeration(String domain) {
        System.out.println("[2] DNS Enumeration – A / AAAA / MX / NS / TXT / CNAME");
        System.out.println("------------------------------------------------------");
        String[] types = {"A", "AAAA", "MX", "NS", "TXT", "CNAME"};

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext ictx = new InitialDirContext(env);

            for (String type : types) {
                try {
                    Attributes attrs = ictx.getAttributes(domain, new String[]{type});
                    Attribute a = attrs.get(type);
                    if (a == null || a.size() == 0) {
                        System.out.println(type + ": (no records found)");
                    } else {
                        System.out.println(type + " records:");
                        if ("TXT".equals(type)) {
                            int shown = 0;
                            for (int i = 0; i < a.size(); i++) {
                                String val = a.get(i).toString();
                                String lower = val.toLowerCase();
                                if (lower.contains("v=spf1") ||
                                    lower.contains("v=dmarc1") ||
                                    lower.contains("google-site-verification") ||
                                    lower.contains("domain-verification")) {
                                    System.out.println("  - " + val);
                                    shown++;
                                }
                            }
                            if (shown == 0) {
                                System.out.println("  (TXT records present but not security-related; omitted for brevity)");
                            }
                        } else {
                            for (int i = 0; i < a.size(); i++) {
                                System.out.println("  - " + a.get(i));
                            }
                        }
                    }
                } catch (Exception e) {
                    System.out.println(type + ": lookup failed (" + e.getMessage() + ")");
                }
            }
        } catch (Exception e) {
            System.out.println("DNS enumeration failed: " + e.getMessage());
        }
        System.out.println();
    }

    // ----------------------------------------------------
    // [3] Domain Ownership – WHOIS (Summary, no API)
    // ----------------------------------------------------
    private static void whoisLookup(String domain) {
        System.out.println("[3] Domain Ownership – WHOIS (Summary)");
        System.out.println("--------------------------------------");

        String domainName = null;
        String registrar = null;
        String created = null;
        String updated = null;
        String expires = null;
        List<String> nameServers = new ArrayList<>();

        try {
            // Good for .com / .net via Verisign
            Socket s = new Socket("whois.verisign-grs.com", 43);
            s.getOutputStream().write((domain + "\r\n").getBytes());
            s.getOutputStream().flush();

            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
            String line;
            int lines = 0;

            while ((line = br.readLine()) != null && lines < 500) {
                String trimmed = line.trim();
                String lower = trimmed.toLowerCase();

                if (lower.startsWith("domain name:") && domainName == null) {
                    domainName = trimmed.substring("domain name:".length()).trim();
                } else if (lower.startsWith("registrar:") && registrar == null &&
                           !lower.startsWith("registrar whois server") &&
                           !lower.startsWith("registrar url")) {
                    registrar = trimmed.substring("registrar:".length()).trim();
                } else if ((lower.startsWith("creation date:") || lower.startsWith("created on:")) && created == null) {
                    int idx = trimmed.indexOf(':');
                    if (idx != -1) created = trimmed.substring(idx + 1).trim();
                } else if ((lower.startsWith("registry expiry date:") || lower.startsWith("expiry date:")) && expires == null) {
                    int idx = trimmed.indexOf(':');
                    if (idx != -1) expires = trimmed.substring(idx + 1).trim();
                } else if ((lower.startsWith("updated date:") || lower.startsWith("last updated on:")) && updated == null) {
                    int idx = trimmed.indexOf(':');
                    if (idx != -1) updated = trimmed.substring(idx + 1).trim();
                } else if (lower.startsWith("name server:")) {
                    int idx = trimmed.indexOf(':');
                    if (idx != -1) {
                        String ns = trimmed.substring(idx + 1).trim();
                        if (!nameServers.contains(ns)) {
                            nameServers.add(ns);
                        }
                    }
                }

                lines++;
            }
            s.close();

            boolean any = false;
            if (domainName != null) {
                System.out.println("Domain Name : " + domainName);
                any = true;
            }
            if (registrar != null) {
                System.out.println("Registrar   : " + registrar);
                any = true;
            }
            if (created != null) {
                System.out.println("Created On  : " + created);
                any = true;
            }
            if (updated != null) {
                System.out.println("Updated On  : " + updated);
                any = true;
            }
            if (expires != null) {
                System.out.println("Expires On  : " + expires);
                any = true;
            }
            if (!nameServers.isEmpty()) {
                System.out.println("Name Servers:");
                for (String ns : nameServers) {
                    System.out.println("  - " + ns);
                }
                any = true;
            }

            if (!any) {
                System.out.println("WHOIS summary not available or format not recognized for this TLD.");
                System.out.println("You can also check via browser: https://whois.icann.org/");
            }

        } catch (Exception e) {
            System.out.println("WHOIS lookup failed: " + e.getMessage());
        }
        System.out.println();
    }

    // ----------------------------------------------------
    // [4] Service Detection – DNS & Mail Providers
    // ----------------------------------------------------
    private static void serviceDetection(String domain) {
        System.out.println("[4] Service Detection – DNS & Mail Providers");
        System.out.println("-------------------------------------------");
        String dnsProvider = "Unknown";
        String mailProvider = "Unknown";

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext ictx = new InitialDirContext(env);

            // DNS Provider from NS
            try {
                Attributes nsAttrs = ictx.getAttributes(domain, new String[]{"NS"});
                Attribute ns = nsAttrs.get("NS");
                if (ns != null && ns.size() > 0) {
                    String nsHost = ns.get(0).toString();
                    dnsProvider = nsHost;
                }
            } catch (Exception ignored) {}

            // Mail Provider from MX
            try {
                Attributes mxAttrs = ictx.getAttributes(domain, new String[]{"MX"});
                Attribute mx = mxAttrs.get("MX");
                if (mx != null && mx.size() > 0) {
                    String mxStr = mx.get(0).toString().toLowerCase();
                    if (mxStr.contains("google")) {
                        mailProvider = "Google Workspace";
                    } else if (mxStr.contains("outlook") || mxStr.contains("office365") || mxStr.contains("protection.outlook.com")) {
                        mailProvider = "Microsoft 365 / Exchange Online";
                    } else if (mxStr.contains("zoho")) {
                        mailProvider = "Zoho Mail";
                    } else {
                        mailProvider = mx.get(0).toString();
                    }
                }
            } catch (Exception ignored) {}

        } catch (Exception e) {
            // ignore, keep defaults
        }

        System.out.println("DNS Provider : " + dnsProvider);
        System.out.println("Mail Provider: " + mailProvider);
        System.out.println();
    }

    // ----------------------------------------------------
    // [5] TLS / SSL Certificate
    // ----------------------------------------------------
    private static void tlsCertificate(String domain) {
        System.out.println("[5] TLS / SSL Certificate");
        System.out.println("-------------------------");
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(domain, 443)) {
                socket.setSoTimeout(5000);
                socket.startHandshake();
                SSLSession session = socket.getSession();
                X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];

                System.out.println("Subject : " + cert.getSubjectDN());

                Date exp = cert.getNotAfter();
                long diffMs = exp.getTime() - System.currentTimeMillis();
                long days = diffMs / (1000L * 60 * 60 * 24);
                SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy");
                System.out.println("Expires : " + sdf.format(exp) + " (" + days + " days remaining)");

                Collection<List<?>> sans = null;
                try {
                    sans = cert.getSubjectAlternativeNames();
                } catch (Exception ignored) {}

                if (sans != null) {
                    StringBuilder sb = new StringBuilder();
                    for (List<?> l : sans) {
                        if (l.size() >= 2) {
                            if (sb.length() > 0) sb.append("; ");
                            sb.append(l.get(1));
                        }
                    }
                    if (sb.length() > 0) {
                        System.out.println("SANs    : " + sb.toString());
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("TLS fetch failed: " + e.getMessage());
        }
        System.out.println();
    }

    // ----------------------------------------------------
    // [6] Email Security – MX / SPF / DMARC
    // ----------------------------------------------------
    private static void emailSecurityChecks(String domain) {
        System.out.println("[6] Email Security – MX / SPF / DMARC");
        System.out.println("-------------------------------------");
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext ictx = new InitialDirContext(env);

            // MX records
            try {
                Attributes mxAttrs = ictx.getAttributes(domain, new String[]{"MX"});
                Attribute mx = mxAttrs.get("MX");
                System.out.println("MX records:");
                if (mx != null && mx.size() > 0) {
                    for (int i = 0; i < mx.size(); i++) {
                        System.out.println("  - " + mx.get(i));
                    }
                } else {
                    System.out.println("  (no MX records)");
                }
            } catch (Exception e) {
                System.out.println("MX lookup failed: " + e.getMessage());
            }

            boolean spf = hasSpfRecord(ictx, domain);
            String dmarcPolicy = getDmarcPolicy(ictx, domain);
            boolean dmarc = dmarcPolicy != null;

            System.out.println();
            System.out.println("SPF present  : " + (spf ? "YES" : "NO"));
            if (spf) {
                System.out.println("  (SPF record is stored in TXT for " + domain + ")");
            }

            System.out.println("DMARC present: " + (dmarc ? "YES" : "NO"));
            if (dmarc) {
                System.out.println("  DMARC TXT  : " + dmarcPolicy);
            } else {
                System.out.println("  Hint: Add a DMARC record at _dmarc." + domain);
            }

        } catch (Exception e) {
            System.out.println("Email security check failed: " + e.getMessage());
        }
        System.out.println();
    }

    private static boolean hasSpfRecord(DirContext ictx, String domain) {
        try {
            Attributes txtAttrs = ictx.getAttributes(domain, new String[]{"TXT"});
            Attribute txt = txtAttrs.get("TXT");
            if (txt != null) {
                for (int i = 0; i < txt.size(); i++) {
                    String val = txt.get(i).toString().toLowerCase();
                    if (val.contains("v=spf1")) {
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private static String getDmarcPolicy(DirContext ictx, String domain) {
        String host = "_dmarc." + domain;
        try {
            Attributes txtAttrs = ictx.getAttributes(host, new String[]{"TXT"});
            Attribute txt = txtAttrs.get("TXT");
            if (txt != null) {
                for (int i = 0; i < txt.size(); i++) {
                    String val = txt.get(i).toString();
                    if (val.toLowerCase().contains("v=dmarc1")) {
                        return val;
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ----------------------------------------------------
    // [7] DNSSEC Status – using Google DNS JSON API
    // ----------------------------------------------------
    private static void dnssecCheck(String domain) {
        System.out.println("[7] DNSSEC Status");
        System.out.println("-----------------");

        try {
            String urlStr = "https://dns.google/resolve?name=" + domain + "&type=DS";
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(8000);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Revittool-DNSSEC");

            int code = conn.getResponseCode();
            if (code != 200) {
                System.out.println("Could not query DNSSEC (HTTP " + code + " from dns.google).");
                System.out.println();
                return;
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            br.close();

            String body = sb.toString();

            boolean hasAnswer = body.contains("\"Answer\"");
            boolean hasDS = body.contains("\"type\":43");

            if (hasAnswer && hasDS) {
                System.out.println("DNSSEC: ENABLED (DS records found via Google Public DNS)");
            } else {
                System.out.println("DNSSEC: NOT ENABLED (no DS records found via Google Public DNS)");
            }

        } catch (Exception e) {
            System.out.println("Could not query DNSSEC (error: " + e.getMessage() + ")");
        }

        System.out.println();
    }

    // ----------------------------------------------------
    // [8] Port Reachability – Basic Service Exposure
    // ----------------------------------------------------
    private static void lightweightPortReachability(String domain) {
        System.out.println("[8] Port Reachability – Basic Service Exposure");
        System.out.println("---------------------------------------------");
        try {
            InetAddress[] addrs = InetAddress.getAllByName(domain);
            int[] ports = {80, 443, 22, 21};

            for (InetAddress addr : addrs) {
                String ip = addr.getHostAddress();
                System.out.println("Host/IP: " + ip);
                for (int p : ports) {
                    boolean open = false;
                    try (Socket s = new Socket()) {
                        SocketAddress sa = new InetSocketAddress(ip, p);
                        s.connect(sa, 1500);
                        open = true;
                    } catch (SocketTimeoutException e) {
                        open = false;
                    } catch (Exception e) {
                        open = false;
                    }
                    String svc = (p == 80 ? "HTTP" :
                                  p == 443 ? "HTTPS" :
                                  p == 22 ? "SSH" :
                                  p == 21 ? "FTP" : "port");
                    System.out.println("  " + svc + " (port " + p + "): " + (open ? "REACHABLE" : "closed/unreachable"));
                }
                System.out.println();
            }
        } catch (Exception e) {
            System.out.println("Port check failed: " + e.getMessage());
        }
        System.out.println();
    }

    // ----------------------------------------------------
    // [9] ATCE – Attack Surface Temporal Correlation Engine
    // ----------------------------------------------------
    private static void runATCE(String domain) {
        System.out.println("[9] ATCE – Attack Surface Temporal Correlation Engine");
        System.out.println("----------------------------------------------------");

        try {
            List<String> subs = fetchCTSubdomains(domain);
            if (subs.isEmpty()) {
                System.out.println("ATCE: No Certificate Transparency (CT) entries found for this domain.");
                System.out.println();
                return;
            }

            File snapDir = new File("snapshots");
            if (!snapDir.exists()) {
                snapDir.mkdirs();
            }

            System.out.println("ATCE: Found " + subs.size() + " subdomains from crt.sh (showing up to 15).");
            System.out.println();
            System.out.println("Subdomain Findings:");

            int count = 0;
            for (String sub : subs) {
                if (count >= 15) break;
                count++;

                String risk = classifyRisk(sub, domain);
                String banner = "";
                String favHash = "";

                try {
                    banner = fetchHttpBanner(sub, snapDir);
                } catch (Exception ignored) {}

                try {
                    favHash = fetchFaviconHash(sub);
                } catch (Exception ignored) {}

                System.out.println("  " + sub);
                System.out.println("    Risk    : " + risk);

                if (favHash != null && !favHash.isEmpty()) {
                    System.out.println("    Favicon : MD5=" + favHash);
                }

                if (banner != null && !banner.isEmpty()) {
                    String snapName = "snapshot_" + sanitizeFilename(sub) + ".html";
                    System.out.println("    Snapshot: saved to snapshots/" + snapName);
                }
                System.out.println();
            }

        } catch (Exception e) {
            System.out.println("ATCE: crt.sh did not respond in time — please try again later.");
            System.out.println();
        }
    }

    // Fetch CT subdomains from crt.sh with extended timeout + clean error path
    private static List<String> fetchCTSubdomains(String domain) throws Exception {
        List<String> result = new ArrayList<>();
        Set<String> unique = new HashSet<>();

        String urlStr = "https://crt.sh/?q=%25." + domain + "&output=json";
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(40000); // 40 seconds
        conn.setReadTimeout(40000);    // 40 seconds
        conn.setRequestProperty("User-Agent", "Revittool-ATCE");

        int code = conn.getResponseCode();
        if (code != 200) {
            throw new RuntimeException("crt.sh HTTP " + code);
        }

        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();

        String body = sb.toString();

        Pattern p = Pattern.compile("\"name_value\":\"(.*?)\"");
        Matcher m = p.matcher(body);
        while (m.find()) {
            String block = m.group(1);
            String[] linesArr = block.split("\\\\n");
            for (String name : linesArr) {
                name = name.trim();
                if (name.isEmpty()) continue;
                if (!name.toLowerCase().endsWith(domain.toLowerCase())) continue;
                if (!unique.contains(name)) {
                    unique.add(name);
                    result.add(name);
                }
            }
        }

        return result;
    }

    private static String classifyRisk(String sub, String rootDomain) {
        String lower = sub.toLowerCase();
        rootDomain = rootDomain.toLowerCase();

        if (lower.equals(rootDomain) || lower.equals("www." + rootDomain)) {
            return "LOW – main/root domain (informational)";
        }

        boolean high = false;
        boolean medium = false;
        String reason = "LOW – informational asset";

        if (lower.contains("admin") || lower.startsWith("login.") ||
            lower.contains("portal") || lower.contains("secure")) {
            high = true;
            reason = "HIGH – admin/login/portal-style subdomain, possible sensitive panel";
        } else if (lower.startsWith("dev.") || lower.startsWith("test.") ||
                   lower.startsWith("staging.") || lower.contains("beta") ||
                   lower.contains("demo")) {
            medium = true;
            reason = "MEDIUM – dev/staging/test-style environment";
        }

        if (high) return reason;
        if (medium) return reason;
        return reason;
    }

    private static String fetchHttpBanner(String host, File snapDir) {
        String[] schemes = {"https://", "http://"};
        for (String scheme : schemes) {
            try {
                URL url = new URL(scheme + host + "/");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(4000);
                conn.setReadTimeout(4000);
                conn.setInstanceFollowRedirects(true);
                conn.setRequestProperty("User-Agent", "Revittool-ATCE");
                int code = conn.getResponseCode();
                if (code >= 200 && code < 500) {
                    BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    int lines = 0;
                    while ((line = br.readLine()) != null && lines < 80) {
                        sb.append(line).append("\n");
                        lines++;
                    }
                    br.close();
                    String html = sb.toString();

                    String filename = "snapshot_" + sanitizeFilename(host) + ".html";
                    File out = new File(snapDir, filename);
                    try (FileWriter fw = new FileWriter(out)) {
                        fw.write(html);
                    }

                    return html;
                }
            } catch (Exception ignored) {
            }
        }
        return "";
    }

    private static String fetchFaviconHash(String host) {
        String[] schemes = {"https://", "http://"};
        for (String scheme : schemes) {
            try {
                URL url = new URL(scheme + host + "/favicon.ico");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(4000);
                conn.setReadTimeout(4000);
                conn.setInstanceFollowRedirects(true);
                conn.setRequestProperty("User-Agent", "Revittool-ATCE");
                int code = conn.getResponseCode();
                if (code == 200) {
                    byte[] data = conn.getInputStream().readAllBytes();
                    return md5Hex(data);
                }
            } catch (Exception ignored) {
            }
        }
        return "";
    }

    private static String md5Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                String hex = Integer.toHexString((b & 0xff) | 0x100).substring(1);
                sb.append(hex);
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String sanitizeFilename(String s) {
        return s.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
