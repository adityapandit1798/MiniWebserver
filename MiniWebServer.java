// Copyright (c) 2022, Pragmatic Data LLC. All rights reserved. CONFIDENTIAL
import java.net.ServerSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import java.security.KeyStore;
import java.net.Socket;
import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.URL;
import java.net.URLConnection;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.io.PrintWriter;
import java.io.Closeable;
import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.time.OffsetDateTime;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import java.util.Random;
import java.util.Enumeration;
import java.net.NetworkInterface;

public class MiniWebServer {
	private static String sslKeyStore = "ssl.p12";
	private static String sslKeyPassphrase = "changeit";

	private static final ZoneId UTC = ZoneId.of("UTC");
	private static final String HTTPTimeFromEpochMillis(long epochMillis) {
		if(epochMillis == 0)
			return null;
		else
			return OffsetDateTime
				.ofInstant(InstantFromEpochMillis(epochMillis), UTC)
				.format(DateTimeFormatter.RFC_1123_DATE_TIME);
	}
	private static final String HTTPTimeFromInstant(Instant instant) {
		if(instant == null)
			return null;
		else
			return OffsetDateTime
				.ofInstant(instant, UTC)
				.format(DateTimeFormatter.RFC_1123_DATE_TIME);
	}
	private static final Instant InstantFromEpochMillis(long epochMillis) {
		if(epochMillis == 0)
			return null;
		else
			return Instant.ofEpochMilli(epochMillis);
	}
	private static final Instant InstantFromHTTPTime(String httpTime) {
		if(httpTime == null)
			return null;
		else 
			return OffsetDateTime.parse(httpTime, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
	}
	
	public static void main(String args[]) throws Exception {
		// options
		InetAddress bindAddress = InetAddress.getByName("127.0.0.1");
		int portNumber = 8080;
		URL resourceRootURLsetup = new java.io.File("./").toURL();
		Pattern delayPattern = null;
		boolean useSSL = false;
		boolean	portNumberOptionInvoked = false;

		// argument handling
		for(int argi = 0; argi < args.length; argi++) {
			final String arg = args[argi];
			if(arg.charAt(0) == '-') {
				final char opt = arg.charAt(1);
				if('p' == opt || arg.equals("--port")) {
					portNumber = Integer.parseInt(args[++argi]);
					portNumberOptionInvoked = true;
				} else if('r' == opt || arg.equals("--root"))
					resourceRootURLsetup = new java.io.File(args[++argi]).toURL();
				else if('d' == opt || "--delay".equals(arg))
					delayPattern = Pattern.compile(args[++argi]);
				else if('s' == opt || "--ssl".equals(arg)) {
					useSSL = true;
					if(argi + 1 < args.length && args[argi + 1].charAt(0) != '-') {
						final String sslParams[] = args[++argi].split(":");
						sslKeyStore = sslParams[0].length() > 0 ? sslParams[0] : sslKeyStore;
						if(sslParams.length > 1 && sslParams[1].length() > 0) {
							sslKeyPassphrase = sslParams[1];
							if(sslKeyPassphrase.equals("?")) {
								System.err.print("Passphrase: ");
								System.err.flush();
								BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
								sslKeyPassphrase = userInput.readLine();
							}
						}
					}
				} else if('h' == opt || "--host".equals(arg))
					bindAddress = InetAddress.getByName(args[++argi]);
			  else if('C' == opt || "--mkcert".equals(arg)) {
					mkcert();
					return;
				}
				else /* or ('?' == opt || arg.equals("--help")) */ {
					System.err.println("MiniWebServer -- a super simple web server");
					System.err.println("Copyright (c) 2022. Pragmatic Data LLC. All rights reserved.");
					System.err.println("Options:");
					//                  0        1         2         3         4         5         6         7         8  
					//                  12345678901234567890123456789012345678901234567890123456789012345678901234567890
					System.err.println("-? --help      this help");
					System.err.println("-p --port num  the port number to listen to");
					System.err.println("-h --host host the listener bind ip address");
					System.err.println("               For security, only localhost by default.");
					System.err.println("               To listen to outside clients, use 0.0.0.0.");
					System.err.println("-r --root path the root directory whose files are served ");
					System.err.println("-d --delay rgx artificially delay whatever matches the reges");					
					System.err.println("-s --ssl cert  serve HTTPS instead of HTTP using the provided certificate");
					System.err.println("-C --mkcert    creates the HTTPS certificate (openssl required in path)");
				}
			}
		}

		if(useSSL && !portNumberOptionInvoked)
			portNumber = 443;
		
		final URL resourceRootURL = resourceRootURLsetup;
		final Matcher delayMatcher = delayPattern != null ? delayPattern.matcher("") : null;
		ServerSocket serverSocket = useSSL ? createServerSocket(portNumber, 10, bindAddress) : new ServerSocket(portNumber, 10, bindAddress);
		
		while(true) {
			final Socket clientSocket = serverSocket.accept();

			(new Thread() {
					public void run() {
						Stack<Closeable> closeables = new Stack<Closeable>();
						StringBuilder logLine = new StringBuilder();
						logLine.append("" + clientSocket.getRemoteSocketAddress() + "|");
						try {
							BufferedReader request = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
							closeables.push(request);
							String requestLine = request.readLine();
							if(requestLine != null && requestLine.length() > 3) {
								final String requestParts[] = requestLine.split("\\s+");
								final String requestMethod = requestParts[0];
								final String rawRequestPath = requestParts[1];
								int queryPos = rawRequestPath.indexOf('?');
								final String requestPath = queryPos > -1 ? rawRequestPath.substring(0, queryPos) : rawRequestPath;
								final String requestQuery = queryPos > -1 ? rawRequestPath.substring(queryPos+1) : "";

								// capture the request headers
								Map<String, String> requestHeaders = new java.util.HashMap<String, String>();
								while(true) {
									String line = request.readLine();
									if(line == null || line.length() == 0)
										break;
									int colonPosition = line.indexOf(":");
									final String name = line.substring(0, colonPosition).trim().toLowerCase();
									final String value = line.substring(colonPosition + 1).trim();
									requestHeaders.put(name, value);
								}

								String ifModifiedSinceString = requestHeaders.get("if-modified-since");
								Instant ifModifiedSince = ifModifiedSinceString == null ? null : Instant.parse(ifModifiedSinceString);
								//if(ifModifiedSince != null)
								//	System.err.println("IF-MOD-SI:" + HTTPTimeFromInstant(ifModifiedSince));

								if(delayMatcher != null) {
									delayMatcher.reset(requestPath);
									if(delayMatcher.find()) {
										System.err.println("delay: " + requestPath);
										try {
											Thread.sleep(2000);
										} catch(InterruptedException ex) {
										}
									}
								}

								OutputStream responseOutputStream = clientSocket.getOutputStream();
								closeables.push(responseOutputStream);
								PrintWriter responsePrintWriter = new PrintWriter(new OutputStreamWriter(responseOutputStream));
								closeables.push(responsePrintWriter);
								boolean encodingGzip = false;
								
								if("GET".equals(requestMethod)) {					
									URL requestedResourceURL = new URL(resourceRootURL, requestPath.substring(1));
									logLine.append(requestMethod + "|" + requestPath + "|" /* + requestedResourceURL */);

									{ // add the index.html if is a directory
										File requestedFile = new File(requestedResourceURL.toURI());
										if(!requestedFile.exists()) {
											requestedFile = new File(requestedFile.getPath() + ".gz");
											if(requestedFile.exists()) {
												requestedResourceURL = requestedFile.toURI().toURL();
												encodingGzip = true;
											} else {
												logLine.append("|404||");
												responsePrintWriter.println("HTTP/1.1 404 Not Found\n");
												responsePrintWriter.flush();
												return;
											}
										} else {										
											if(requestedFile.isDirectory()) {
												final String requestedPath = requestedResourceURL.getPath();
												if(requestedPath.endsWith("/"))
													requestedResourceURL = (new File(requestedFile, "index.html")).toURI().toURL();
												else { // need to send a redirect to not mess up client's URL logic
													final String correctedPath = (new URL("http", "localhost", requestPath)).getPath() + "/";
													logLine.append("|301|" + correctedPath + "||0|");
													responsePrintWriter.println("HTTP/1.1 301 Moved Permanently");
													responsePrintWriter.println("Location:" + correctedPath + "\n");
													responsePrintWriter.flush();
													return;
												}
											}
										}
									}

									final URLConnection requestedResource = requestedResourceURL.openConnection();
									try {									 
										InputStream requestedResourceInputStream = requestedResource.getInputStream();
										closeables.push(requestedResourceInputStream);

										String contentType = requestedResource.getContentType();						

										if(contentType == null || "content/unknown".equals(contentType) || "application/octet-stream".equals(contentType)) {
											if(!requestedResourceInputStream.markSupported())
												requestedResourceInputStream = new BufferedInputStream(requestedResourceInputStream);							
											contentType = URLConnection.guessContentTypeFromStream(requestedResourceInputStream);
										}
										if("application/octet-stream".equals(contentType))
											contentType = null;
										
										{ // override what contentType was guessed based on file "extension"
											String fileName = requestedResourceURL.getPath(); // getFile would have the query part if any
											if(encodingGzip == true && fileName.endsWith(".gz"))
												fileName = fileName.substring(0, fileName.length() - 3);										
											if(contentType == null)
												contentType = URLConnection.guessContentTypeFromName(fileName);
											if(fileName.endsWith(".svg"))
												contentType = "image/svg+xml";
											if(contentType == null) {
												if(fileName.endsWith(".js"))
													contentType = "text/javascript";
												if(fileName.endsWith(".json"))
													contentType = "application/json";
												else if(fileName.endsWith(".css"))
													contentType = "text/css";
												else 
													contentType = "application/octet-stream";
											}
										}

										final String contentEncoding = encodingGzip ? "gzip" : requestedResource.getContentEncoding();
										final long contentLength = requestedResource.getContentLength();
										final Instant lastModified = InstantFromEpochMillis(requestedResource.getLastModified());

										if(lastModified == null || ifModifiedSince == null || lastModified.compareTo(ifModifiedSince) > 0) {

											logLine.append("|200||" + contentType + "|" + contentLength + "|" + vob(contentEncoding) + "|" + lastModified + "|" + ifModifiedSince);
											responsePrintWriter.println("HTTP/1.1 200 OK");
											responsePrintWriter.println("Content-type: " + contentType);
											responsePrintWriter.println("Content-length: " + contentLength);
											if(contentEncoding != null)
												responsePrintWriter.println("Content-encoding: " + contentEncoding);
											responsePrintWriter.println("Last-modified: " + lastModified);
											responsePrintWriter.println();
											responsePrintWriter.flush();
											
											try {
												final byte buffer[] = new byte[BUFFER_SIZE];
												while(true) {
													int length = requestedResourceInputStream.read(buffer);
													if(length <= 0)
														break;
													responseOutputStream.write(buffer, 0, length);
												}
											} catch(Exception ex) {
												logLine.append("|FAULT|" + ex);
											}
										} else { 
											logLine.append("|304|||||" + lastModified + "|" + ifModifiedSince);
											responsePrintWriter.println("HTTP/1.1 304 Not Modified\n");
										}
									} catch(java.io.FileNotFoundException ex) {
										logLine.append("|404||");
										responsePrintWriter.println("HTTP/1.1 404 Not Found\n");
									}
								} else {
									logLine.append("|405||");
									responsePrintWriter.println("HTTP/1.1 405 Method Not Allowed\n");
								}
								responsePrintWriter.flush();
							} // else illegal request format
						} catch(Exception ex) {
							ex.printStackTrace();
						} finally {
							System.out.println(logLine);
							while(!closeables.empty())
								try {
									closeables.pop().close();
								} catch(Exception ex) {
									ex.printStackTrace();
								}
						}
					}
				}).start();
		}
	}

	private static final int BUFFER_SIZE = 1024;
	private static final String vob(Object value) {
		return value == null ? "" : value.toString();
	}

  private static ServerSocket createServerSocket(int portNumber, int backlog, InetAddress bindAddress) throws Exception {
		SSLServerSocket socket = (SSLServerSocket)getSSLServerSocketFactory().createServerSocket(portNumber, backlog, bindAddress);
		socket.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2", "TLSv1.1"});
		// socket.setEnabledCipherSuites(new String[] {"TLS_AES_128_GCM_SHA256"});
		return socket;
	}

	private static final SSLServerSocketFactory getSSLServerSocketFactory() throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream(sslKeyStore), sslKeyPassphrase.toCharArray());
		
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		keyManagerFactory.init(keyStore, sslKeyPassphrase.toCharArray());
		
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
		
		return sslContext.getServerSocketFactory();
	}

	public static void mkcert() throws Exception {
		exec("openssl req -newkey rsa:4096 -sha256 -keyout sslkey.pem -out sslreq.pem -days 365 -subj /CN=TestServer -passout pass:changeit");

		// create the certificate extensions (ip address)
		Writer ext = new OutputStreamWriter(new FileOutputStream("ssl.ext"));
		ext.write("extendedKeyUsage = serverAuth\nsubjectAltName=DNS:localhost");
		Enumeration<NetworkInterface> nifs = NetworkInterface.getNetworkInterfaces();
		while(nifs.hasMoreElements()) {
				Enumeration<InetAddress> addrs = nifs.nextElement().getInetAddresses();
				while(addrs.hasMoreElements()) {
					InetAddress addr = addrs.nextElement();
					if(addr instanceof Inet4Address) {
						ext.write(",IP:");
						ext.write(addr.getHostAddress());
						System.out.println(addr.getHostAddress());
					}
				}
		}
		ext.close();

		StringBuilder cmd = new StringBuilder("openssl x509 -sha256 -req -in sslreq.pem -out sslcert.pem -CA cacert.pem -CAkey cakey.pem -extfile ssl.ext -set_serial 0x");
		// make random serial 
		byte[] randomSerial = new byte[20];
		(new Random()).nextBytes(randomSerial);
		for(int i = 0; i < randomSerial.length; i++)
			cmd.append(Integer.toString(((int)randomSerial[i] & 0xff), 16));
		cmd.append(" -passin pass:changeit");
		exec(cmd);

		exec("openssl pkcs12 -export -in sslcert.pem -inkey sslkey.pem -CAfile cacert.pem -out ssl.p12 -passin pass:changeit -passout pass:changeit");
	}

	private static final void exec(CharSequence cmd) throws Exception {
		final String cmds = cmd.toString();
		final Process process = Runtime.getRuntime().exec(cmds);
		final InputStream processResult = process.getErrorStream();
		int ch;		
		while((ch = processResult.read()) > 0)
			System.out.write(ch);
		int status = process.waitFor();
		if(status != 0)
			throw new RuntimeException(cmds);
	}		
		
	
	/* Install the file cacert.pem on your dev/test clients.


     You need to make a new server certificate for every ip address you have:
     simply run this program with the -C option.

     The root certificate was made with this, but it's committed in svn, and installed on clients, so don't remake it

		 openssl req -x509 -newkey rsa:4096 -sha256 -keyout cakey.pem -out cacert.pem -days 365 -subj "/C=IN/ST=MH/L=Pune/O=Pragmatic Data/OU=Development and Testing Only/CN=Pragmatic CA Development and Testing Only" -passout pass:changeit
	*/
}
