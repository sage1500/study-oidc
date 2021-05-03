package example;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Base64;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.json.BasicJsonParser;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@ConfigurationProperties("my")
@Slf4j
public class Application {
	@Setter
	String issuerUri;
	@Setter
	String clientId;
	@Setter
	String clientSecret;
	@Setter
	String accessToken;

	public static void main(String[] args) throws Exception {
		try (var context = SpringApplication.run(Application.class, args)) {
			context.getBean(Application.class).execute();
		}
	}

	private void execute() throws Exception {
		var parser = new BasicJsonParser();
		log.info("Settings:");
		log.info("  issuerUri:    {}", issuerUri);
		log.info("  clientId:     {}", clientId);
		log.info("  clientSecret: {}", clientSecret);
		log.info("  accessToken:  {}", accessToken);

		var httpclient = HttpClient.newBuilder().build();

		//
		// OpenID Provider Configuration
		//
		// @formatter:off
		var idpConfResponse = httpclient.send(
			HttpRequest.newBuilder()
				.GET()
				.uri(URI.create(issuerUri + "/.well-known/openid-configuration"))
				.build(),
			BodyHandlers.ofString());
		// @formatter:on
		var idpConfRspMap = parser.parseMap(idpConfResponse.body());
		String introspection_endpoint = (String) idpConfRspMap.get("introspection_endpoint");
		log.info("introspection_endpoint: {}", introspection_endpoint);
		// KeyCloak
		// の場合は、http://localhost:18080/auth/realms/demo/protocol/openid-connect/token/introspect

		//
		// Token Introspection
		//
		// @formatter:off
		var response = httpclient.send(
			HttpRequest.newBuilder()
				.uri(URI.create(introspection_endpoint))
				.header("Authorization", "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("token=" + URLEncoder.encode(accessToken, "UTF-8")))
				.build(),
			BodyHandlers.ofString());
		// @formatter:on
		var responseMap = parser.parseMap(response.body());
		log.info("response: {}", responseMap);
		log.info("  active: {}", responseMap.get("active"));
	}

}
